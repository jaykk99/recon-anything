"""Waybackurls-style: every URL the Wayback Machine cached (native, keyless).

Lightweight single-purpose fetch: asks the Wayback CDX API for all
archived URLs under the domain, collapses duplicates, and reports the
full set plus the interesting ones (params, file extensions,
API/admin shapes). Uses the shared ctx cache so the wayback and gau
plugins do not pay for the same CDX query twice.

Read-only, no keys. Bounded to keep under the 30s ceiling.
"""
from __future__ import annotations

import time
from typing import List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

JUICY_EXTS = (".bak", ".old", ".zip", ".sql", ".env", ".log", ".txt",
              ".json", ".xml", ".yaml", ".yml", ".conf", ".swp",
              ".git", ".php", ".asp", ".aspx", ".jsp")
API_HINT = ("/api", "/v1", "/v2", "/rest", "/graphql", "/admin",
            "/debug", "/test", "/dev", "/staging", "/backup")


def _interesting(url: str) -> bool:
    low = url.lower()
    if "?" in low and "=" in low:
        return True
    if low.endswith(JUICY_EXTS):
        return True
    return any(h in low for h in API_HINT)


class WaybackurlsPlugin(Plugin):
    id = "waybackurls"
    label = "Wayback URLs"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Every URL Wayback cached for the site. "
                   "Keyless CDX API.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        async def cdx():
            url = ("https://web.archive.org/cdx/search/cdx?url="
                   + quote(domain) + "/*&output=json&fl=timestamp,original"
                     "&collapse=urlkey&limit=5000")
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                timeout=25, max_retries=1)
                if r.status_code != 200:
                    return {"error": f"HTTP {r.status_code}"}
                return r.json()
            except Exception as e:
                return {"error": str(e)[:150]}

        rows, _ = await ctx.cache.cached("waybackurls", domain, cdx)
        if isinstance(rows, dict) and rows.get("error"):
            return self._degraded(f"CDX unavailable: {rows['error']}")

        urls: Set[str] = set()
        first_seen = {}
        for row in (rows or [])[1:]:
            if not row or len(row) < 2 or not row[1]:
                continue
            u = str(row[1])
            urls.add(u)
            ts = str(row[0]) if len(row) > 0 else ""
            if u not in first_seen or ts < first_seen[u]:
                first_seen[u] = ts

        findings: List[Finding] = []
        for u in sorted(urls):
            ctx.publish("urls", u)
        for u in sorted(u for u in urls if _interesting(u))[:80]:
            findings.append(self._f(
                "web", "wayback_url", u,
                "waybackurls", source_url=u, confidence=70,
                evidence={"severity": "low",
                          "first_seen": first_seen.get(u, ""),
                          "remediation": "Old/archived URLs often expose "
                                         "forgotten endpoints; verify live "
                                         "and intended."},
                passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{len(urls)} archived URLs, "
                       f"{len([u for u in urls if _interesting(u)])} interesting")
        res.duration_ms = dur
        return res
