"""Urlscan-style URL analyzer (native, keyless).

Records the full HTTP transaction picture for a URL using our own
fetching: request/response chain (redirects), every background
resource loaded (scripts, images, stylesheets, fonts, media, XHR
endpoints), server identity (headers, cert info), and third-party
domains contacted. No urlscan.io API, no keys.

GET only. Bounded to keep under the 30s ceiling.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, bounded

RES_RE = re.compile(
    r'''(?:href|src|data-src|poster|content)\s*=\s*["']([^"'\s<>]+)["']''', re.I)
FETCH_RE = re.compile(
    r'''(?:fetch|axios\.(?:get|post)|XMLHttpRequest|\.ajax)\s*\(\s*["'`]([^"'`]+)["'`]''', re.I)

KIND_EXTS = {
    "script": (".js", ".mjs"),
    "stylesheet": (".css",),
    "image": (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp"),
    "font": (".woff", ".woff2", ".ttf", ".eot", ".otf"),
    "media": (".mp4", ".webm", ".mp3", ".wav"),
    "document": (".pdf", ".doc", ".docx", ".xls", ".xlsx"),
}


def _kind(url: str) -> str:
    low = url.lower().split("?")[0]
    for kind, exts in KIND_EXTS.items():
        if low.endswith(exts):
            return kind
    return "other"


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


class UrlscanPlugin(Plugin):
    id = "urlscan"
    label = "URL Analyzer"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Full HTTP transaction record: redirect chain, "
                   "background resources, third-party domains. Keyless.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []

        try:
            # hard wall-clock cap: a trickling server can keep the
            # connection alive past the per-operation timeout
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", base,
                timeout=12, follow_redirects=True, max_retries=0), 20)
            if r is None:
                return self._degraded("fetch timed out (20s wall-clock)")
        except Exception as e:
            return self._degraded(f"could not fetch: {str(e)[:120]}")

        # Transaction record
        chain = [str(h.request.url) for h in r.history] + [str(r.url)]
        server = r.headers.get("server", "")
        powered = r.headers.get("x-powered-by", "")
        findings.append(self._f(
            "web", "http_transaction", str(r.url),
            "urlscan", source_url=str(r.url), confidence=95,
            evidence={"severity": "low",
                      "final_status": r.status_code,
                      "redirect_chain": chain,
                      "redirect_count": len(r.history),
                      "server": server, "x_powered_by": powered,
                      "content_length": len(r.content),
                      "remediation": "Review redirect chains for open "
                                     "redirects; hide server version banners."},
            passive=True))

        html = r.text[:400000] if "text/html" in \
            r.headers.get("content-type", "") else ""
        resources: Dict[str, Set[str]] = {}
        third_party: Set[str] = set()
        if html:
            for m in RES_RE.finditer(html):
                link = urljoin(str(r.url), m.group(1).strip())
                if not link.startswith(("http://", "https://")):
                    continue
                k = _kind(link)
                resources.setdefault(k, set()).add(link)
                h = _host(link)
                if h and h != domain and not h.endswith("." + domain):
                    third_party.add(h)
                ctx.publish("assets", link)
            for m in FETCH_RE.finditer(html):
                ep = m.group(1).strip()
                if ep.startswith("/"):
                    ep = urljoin(str(r.url), ep)
                if ep.startswith(("http://", "https://")):
                    resources.setdefault("xhr", set()).add(ep)
                    ctx.publish("endpoints", ep)

        for kind, urls in resources.items():
            if kind == "other":
                continue
            for u in sorted(urls)[:20]:
                findings.append(self._f(
                    "web", f"bg_{kind}", u,
                    "urlscan", source_url=u, confidence=85,
                    evidence={"severity": "low",
                              "remediation": "Audit background resources; "
                                             "remove unused ones."},
                    passive=True))

        for h in sorted(third_party)[:30]:
            findings.append(self._f(
                "web", "third_party_domain", h,
                "urlscan", source_url=f"https://{h}", confidence=80,
                evidence={"severity": "low",
                          "remediation": "Third-party domains expand attack "
                                         "surface; verify each is intended."},
                passive=True))

        total_res = sum(len(v) for v in resources.values())
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"{r.status_code} {str(r.url)[:60]}, {len(r.history)} redirects, "
            f"{total_res} background resources, {len(third_party)} third-party")
        res.duration_ms = dur
        return res
