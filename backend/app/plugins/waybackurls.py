"""Waybackurls-style: every URL the Wayback Machine cached (native, keyless).

Lightweight single-purpose fetch: asks the Wayback CDX API for all
archived URLs under the domain, collapses duplicates, and reports the
full set plus the interesting ones (params, file extensions,
API/admin shapes). Uses the shared ctx cache so the wayback and gau
plugins do not pay for the same CDX query twice.

Read-only, no keys. Bounded to keep under the 30s ceiling.
"""
from __future__ import annotations

import asyncio
import time
from typing import List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, bounded

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
            # limit 2000: smaller payload = faster. The CDX API can
            # trickle 600KB+ over 30s+ for busy domains, so the fetch
            # gets a hard 24s wall-clock cap (battle-test 2026-10-18:
            # httpbin.org took 34s and blew the plugin ceiling; 24s
            # keeps the whole plugin under 30s with parse time to spare).
            url = ("https://web.archive.org/cdx/search/cdx?url="
                   + quote(domain) + "/*&output=json&fl=timestamp,original"
                     "&collapse=urlkey&limit=2000")
            try:
                r = await bounded(fetch(
                    ctx.http, ctx.limiter, "GET", url,
                    timeout=15, max_retries=0), 24)
                if r is None or r.status_code != 200:
                    return {"error": f"HTTP {r.status_code if r else 'timeout'}"}
                return r.json()
            except asyncio.TimeoutError:
                return {"error": "CDX query exceeded 24s wall-clock"}
            except Exception as e:
                return {"error": str(e)[:150]}

        rows, _ = await ctx.cache.cached("waybackurls", domain, cdx)
        if isinstance(rows, dict):
            # CDX sometimes returns a JSON error object instead of the
            # row list (e.g. rate-limit bodies without an "error" key).
            # Battle-test 2026-10-18: `rows[1:]` on such a dict raised
            # KeyError: slice(1, None, None) and crashed the plugin.
            if "error" in rows:
                return self._degraded(
                    f"CDX unavailable: {rows.get('error') or 'unknown error'}")
            return self._ok(
                [], f"CDX returned unexpected shape: {str(rows)[:120]}")

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
