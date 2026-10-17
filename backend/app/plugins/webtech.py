"""Web technology fingerprinting plugin (Milestone 3).

Fetches HTML + headers, fingerprints framework/CMS/analytics/CDN via
header, cookie, meta, script-path and DOM signatures (Wappalyzer-style
ruleset authored here). Parses robots.txt, sitemap.xml, security.txt,
humans.txt, manifest.json, ads.txt. Computes favicon hash for pivoting.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (tech name, where to look, regex) - authored ruleset
RULES = [
    ("Next.js", "html", r"_next/static"),
    ("Nuxt.js", "html", r"_nuxt/"),
    ("React", "html", r"react|__REACT"),
    ("Vue.js", "html", r"vue(\.min)?\.js|__vue__"),
    ("Angular", "html", r"ng-version|angular\.min\.js"),
    ("WordPress", "html", r"wp-content|wp-includes"),
    ("WordPress", "headers", r"wp-"),
    ("Drupal", "html", r"drupal\.js|sites/default/files"),
    ("Shopify", "html", r"cdn\.shopify\.com"),
    ("Wix", "html", r"wixstatic\.com|wix\.com"),
    ("Squarespace", "html", r"squarespace"),
    ("Webflow", "html", r"webflow"),
    ("Ghost", "headers", r"ghost"),
    ("Django", "headers", r"csrftoken|django"),
    ("Django", "html", r"csrfmiddlewaretoken"),
    ("Ruby on Rails", "headers", r"_rails_|_session_id.*rails"),
    ("Laravel", "headers", r"laravel_session"),
    ("Laravel", "html", r"laravel"),
    ("ASP.NET", "headers", r"asp\.net|__viewstate"),
    ("PHP", "headers", r"phpsessid|x-powered-by: php"),
    ("Nginx", "headers", r"^server: nginx"),
    ("Apache", "headers", r"^server: apache"),
    ("Cloudflare", "headers", r"cf-ray|__cf_bm|cloudflare"),
    ("Cloudflare", "html", r"cdnjs\.cloudflare\.com"),
    ("AWS CloudFront", "headers", r"via:.*cloudfront|x-amz-cf"),
    ("Fastly", "headers", r"fastly"),
    ("Vercel", "headers", r"vercel|x-vercel"),
    ("Netlify", "headers", r"netlify"),
    ("Google Analytics", "html", r"googletagmanager\.com|google-analytics\.com|ga\("),
    ("Google Tag Manager", "html", r"googletagmanager\.com/gtm\.js"),
    ("Facebook Pixel", "html", r"connect\.facebook\.net.*fbevents"),
    ("Hotjar", "html", r"static\.hotjar\.com"),
    ("Segment", "html", r"cdn\.segment\.com"),
    ("Stripe", "html", r"js\.stripe\.com"),
    ("Sentry", "html", r"sentry"),
    ("jQuery", "html", r"jquery"),
    ("Bootstrap", "html", r"bootstrap"),
    ("Tailwind", "html", r"tailwind"),
    ("Cloudflare Turnstile", "html", r"challenges\.cloudflare\.com"),
    ("reCAPTCHA", "html", r"google\.com/recaptcha"),
    ("hCaptcha", "html", r"hcaptcha\.com"),
]

WELLKNOWN = {
    "robots.txt": "/robots.txt",
    "sitemap.xml": "/sitemap.xml",
    "security.txt": "/.well-known/security.txt",
    "humans.txt": "/humans.txt",
    "manifest.json": "/manifest.json",
    "ads.txt": "/ads.txt",
}


def _mmh3_32(data: bytes) -> int:
    """Pure-python murmur3 x86 32-bit (Shodan-style favicon hash)."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h = 0
    n = len(data) - (len(data) % 4)
    for i in range(0, n, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[n:]
    k = 0
    for i, b in enumerate(tail):
        k |= b << (8 * i)
    if tail:
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


class WebTechPlugin(Plugin):
    id = "webtech"
    label = "Web Tech Fingerprint"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Framework/CMS/CDN/analytics fingerprint + robots/sitemap/security.txt + favicon hash."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        async def get_home():
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                                follow_redirects=True)
                return {"status": r.status_code, "headers": dict(r.headers),
                        "html": r.text[:500000], "url": str(r.url)}
            except Exception as e:
                return {"error": str(e)[:200]}

        home, _ = await ctx.cache.cached("http", f"home:{base}", get_home)
        if home.get("error"):
            res = self._error(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        headers_blob = "\n".join(f"{k}: {v}" for k, v in home["headers"].items())
        blob_html = html[:200000]

        seen_tech = set()
        for name, where, pattern in RULES:
            hay = blob_html if where == "html" else headers_blob
            if re.search(pattern, hay, re.I | re.M):
                if name not in seen_tech:
                    seen_tech.add(name)
                    findings.append(self._f("web", "tech", name,
                                            source="signature match", confidence=75,
                                            passive=passive))
        # server header as its own finding
        server = home["headers"].get("server", "")
        if server:
            findings.append(self._f("web", "server_header", server[:200],
                                    source="HTTP headers", confidence=95, passive=passive))
        powered = home["headers"].get("x-powered-by", "")
        if powered:
            findings.append(self._f("web", "x_powered_by", powered[:200],
                                    source="HTTP headers", confidence=95, passive=passive))
        # cookies hint at stack
        set_cookie = home["headers"].get("set-cookie", "")
        if set_cookie:
            names = re.findall(r"^([^=;]+)=", set_cookie, re.M)[:10]
            if names:
                findings.append(self._f("web", "cookies", ", ".join(names)[:300],
                                        source="Set-Cookie", confidence=90, passive=passive))
        # page title
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m:
            findings.append(self._f("web", "page_title", m.group(1).strip()[:200],
                                    source="HTML", confidence=95, passive=passive))
        # tracking IDs for pivoting
        for m in re.finditer(r"UA-\d{4,10}-\d{1,4}", html):
            findings.append(self._f("identity", "ga_id", m.group(0),
                                    source="HTML/JS", confidence=95, passive=passive))
        for m in re.finditer(r"GTM-[A-Z0-9]{4,10}", html):
            findings.append(self._f("identity", "gtm_id", m.group(0),
                                    source="HTML/JS", confidence=95, passive=passive))
        for m in re.finditer(r"ca-pub-\d{10,20}", html):
            findings.append(self._f("identity", "adsense_id", m.group(0),
                                    source="HTML/JS", confidence=95, passive=passive))

        # well-known files
        for label, path in WELLKNOWN.items():
            url = base.rstrip("/") + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
                if r.status_code == 200 and len(r.text.strip()) > 0:
                    findings.append(self._f("web", f"wellknown_{label}",
                                            r.text.strip()[:600],
                                            source=label, source_url=url,
                                            confidence=90, passive=passive))
            except Exception:
                continue

        # disallowed paths in robots.txt become leads
        for f in findings:
            if f.key == "wellknown_robots.txt":
                for dm in re.finditer(r"Disallow:\s*(\S+)", f.value):
                    p = dm.group(1)
                    if p != "/":
                        findings.append(self._f("web", "robots_disallow", p,
                                                source="robots.txt",
                                                source_url=base.rstrip("/") + "/robots.txt",
                                                confidence=80, passive=passive))
                break

        # favicon hash (for Shodan-style pivoting)
        try:
            fav = await fetch(ctx.http, ctx.limiter, "GET",
                              base.rstrip("/") + "/favicon.ico", timeout=12)
            if fav.status_code == 200 and len(fav.content) > 100:
                h = _mmh3_32(fav.content)
                findings.append(self._f("identity", "favicon_mmh3", str(h),
                                        source="favicon.ico", confidence=95, passive=passive))
        except Exception:
            pass

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(seen_tech)} tech signatures on {domain}")
        res.duration_ms = dur
        return res
