"""robots.txt and sitemap.xml parser plugin.

Fetches robots.txt and sitemap.xml, extracts disallowed paths and URLs.
These often reveal hidden admin panels, backup dirs, and API endpoints.
Custom-built, no API keys needed.
"""
from __future__ import annotations

import re
import time
from typing import List
from xml.etree import ElementTree

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class RobotsPlugin(Plugin):
    id = "robots"
    label = "Robots / Sitemap"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Parse robots.txt and sitemap.xml for hidden paths."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []

        # robots.txt
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base + "/robots.txt", timeout=12)
            if r.status_code == 200 and r.text.strip():
                findings.append(self._f(
                    "web", "robots_txt",
                    f"robots.txt found ({len(r.text)} bytes)",
                    source="robots parser", source_url=base + "/robots.txt",
                    confidence=80, passive=True))
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            findings.append(self._f(
                                "web", "robots_disallow",
                                f"Disallowed path (may hide interesting content): {path}",
                                source="robots parser", source_url=base + "/robots.txt",
                                confidence=65, passive=True))
                    elif line.lower().startswith("sitemap:"):
                        sm = line.split(":", 1)[1].strip()
                        findings.append(self._f(
                            "web", "robots_sitemap",
                            f"Sitemap declared: {sm}",
                            source="robots parser", source_url=base + "/robots.txt",
                            confidence=70, passive=True))
        except Exception:
            pass

        # sitemap.xml
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base + "/sitemap.xml", timeout=12)
            if r.status_code == 200 and "<url" in r.text[:2000]:
                try:
                    root = ElementTree.fromstring(r.text[:500000])
                    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                    urls = root.findall(".//s:loc", ns) or root.findall(".//loc")
                    findings.append(self._f(
                        "web", "sitemap",
                        f"sitemap.xml found with {len(urls)} URLs",
                        source="sitemap parser", source_url=base + "/sitemap.xml",
                        confidence=80, passive=True))
                    interesting = [u.text for u in urls[:500] if u.text and
                                   any(k in u.text.lower() for k in
                                       ["admin", "login", "api", "dashboard", "private", "test"])]
                    for u in interesting[:20]:
                        findings.append(self._f(
                            "web", "sitemap_interesting",
                            f"Interesting sitemap URL: {u}",
                            source="sitemap parser", source_url=base + "/sitemap.xml",
                            confidence=65, passive=True))
                except Exception:
                    findings.append(self._f(
                        "web", "sitemap",
                        "sitemap.xml found but could not parse",
                        source="sitemap parser", source_url=base + "/sitemap.xml",
                        confidence=60, passive=True))
        except Exception:
            pass

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, "parsed robots.txt and sitemap.xml")
        res.duration_ms = dur
        return res
