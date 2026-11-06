"""BuiltWith-style technology fingerprinting (Tier-1 OSINT).

Native detection (no BuiltWith API key, no external service): fetch
the target page once through the shared page cache and match a
bundled signature DB against response headers, HTML meta/script/link
markers, JS bundle URLs and cookie names - CMS, frameworks,
analytics, CDNs, ad networks, JS libraries. Each detection is a
"tech" finding published to the discovery bus ("tech") for chain
plugins, exactly the role BuiltWith plays in a recon stack.
"""
from __future__ import annotations

import re
import time
from typing import List, Tuple
from urllib.parse import urlparse

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (name, where, pattern) - where: header:<name> | html | cookie
SIGNATURES: List[Tuple[str, str, str]] = [
    ("WordPress", "html", r"wp-content|wp-includes|name=\"generator\" "
                          r"content=\"WordPress"),
    ("WordPress", "header:x-powered-by", r"WordPress"),
    ("Drupal", "html", r"Drupal|/sites/default/files|drupal\.js"),
    ("Joomla", "html", r"Joomla|/media/jui/|com_content"),
    ("Shopify", "html", r"cdn\.shopify\.com|Shopify\.theme|myshopify\.com"),
    ("Shopify", "header:x-shopid", r".+"),
    ("Wix", "html", r"wix\.com|_wixCssStates|wix-image"),
    ("Squarespace", "html", r"squarespace\.com|Static\.SQUARESPACE_CONTEXT"),
    ("Ghost", "html", r"ghost/|content=\"Ghost "),
    ("React", "html", r"react(\.production)?\.min\.js|data-reactroot|"
                      r"_next/static|__NEXT_DATA__"),
    ("Next.js", "html", r"__NEXT_DATA__|/_next/static/"),
    ("Vue.js", "html", r"vue(\.runtime)?(\.min)?\.js|data-v-[0-9a-f]{6,}"),
    ("Nuxt.js", "html", r"__NUXT__|/_nuxt/"),
    ("Angular", "html", r"ng-version|angular(\.min)?\.js|<app-root"),
    ("Svelte", "html", r"svelte-[0-9a-z]{6,}|/_app/immutable/"),
    ("jQuery", "html", r"jquery[-.][0-9]|jquery\.min\.js"),
    ("Bootstrap", "html", r"bootstrap(\.min)?\.(css|js)"),
    ("Tailwind CSS", "html", r"tailwindcss|cdn\.tailwindcss\.com"),
    ("Google Analytics", "html", r"googletagmanager\.com/gtag|"
                                  r"google-analytics\.com|gtag\('config'|"
                                  r"G-[A-Z0-9]{8,}"),
    ("Google Tag Manager", "html", r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+"),
    ("Meta Pixel", "html", r"connect\.facebook\.net|fbq\('init'"),
    ("Hotjar", "html", r"static\.hotjar\.com|hjBootstrap"),
    ("Intercom", "html", r"widget\.intercom\.io|intercomcdn\.com"),
    ("Cloudflare", "header:server", r"^cloudflare$"),
    ("Cloudflare", "html", r"cdn-cgi/|cloudflare-static"),
    ("Akamai", "header:x-akamai-transformed", r".+"),
    ("Fastly", "header:x-served-by", r"cache-"),
    ("PHP", "header:x-powered-by", r"PHP/"),
    ("ASP.NET", "header:x-powered-by", r"ASP\.NET"),
    ("Express", "header:x-powered-by", r"Express"),
    ("Apache", "header:server", r"Apache"),
    ("Nginx", "header:server", r"nginx"),
    ("Microsoft IIS", "header:server", r"Microsoft-IIS"),
    ("LiteSpeed", "header:server", r"LiteSpeed"),
    ("Laravel", "cookie", r"laravel_session"),
    ("Django", "cookie", r"csrftoken|sessionid.*django"),
    ("Ruby on Rails", "cookie", r"_session_id.*|plack\.session"),
    ("Stripe", "html", r"js\.stripe\.com|checkout\.stripe\.com"),
    ("reCAPTCHA", "html", r"google\.com/recaptcha|grecaptcha"),
    ("HubSpot", "html", r"js\.hs-scripts\.com|hs-analytics"),
    ("Segment", "html", r"cdn\.segment\.com|analytics\.load"),
]

_COMPILED = [(name, where, re.compile(pat, re.I))
             for name, where, pat in SIGNATURES]


def detect_tech(headers: dict, html: str, cookies: str = "") -> List[str]:
    """Return the sorted set of technology names detected."""
    found = []
    seen = set()
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookie_blob = cookies or hdrs.get("set-cookie", "")
    for name, where, pat in _COMPILED:
        if name in seen:
            continue
        if where.startswith("header:"):
            value = hdrs.get(where.split(":", 1)[1], "")
            hit = bool(value and pat.search(value))
        elif where == "cookie":
            hit = bool(pat.search(cookie_blob))
        else:
            hit = bool(pat.search(html or ""))
        if hit:
            seen.add(name)
            found.append(name)
    return sorted(found)


def base_url(target: Target) -> str:
    if target.type == "url":
        p = urlparse(target.normalized)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}/"
    return f"https://{target.normalized.strip('/')}/"


class BuiltwithScanPlugin(Plugin):
    timeout_s = 60
    id = "builtwith_scan"
    label = "Technology Fingerprint (BuiltWith-style)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Native BuiltWith-style tech fingerprinting from "
                   "the target page itself: headers, HTML/JS "
                   "signatures and cookies matched against a bundled "
                   "detection DB (CMS, frameworks, analytics, CDN).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        url = base_url(target)
        page = await ctx.fetch_page(url)
        if page is None:
            return self._degraded(f"could not fetch {url}")
        headers = dict(page.get("headers") or {})
        html = page.get("text") or ""
        cookies = ""
        try:
            cookies = "; ".join(headers.get("set-cookie", "") if isinstance(
                headers.get("set-cookie", ""), list) else
                [str(headers.get("set-cookie", ""))])
        except Exception:
            cookies = str(headers.get("set-cookie", ""))
        techs = detect_tech(headers, html, cookies)
        findings: List[Finding] = []
        for tech in techs:
            ctx.publish("tech", tech.lower())
            findings.append(self._f(
                "web", "tech", tech, source="builtwith_scan/page",
                source_url=url, confidence=80, passive=True,
                evidence={"technology": tech, "severity": "low"}))
            self._checkpoint(findings)
        res = self._ok(findings, f"{len(techs)} technologies detected"
                                 if techs else "no known tech signatures")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
