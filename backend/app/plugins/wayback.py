"""Wayback Machine plugin (Milestone 2).

Historical snapshots via the CDX API: first/last seen, snapshot count,
old URLs (great for finding forgotten endpoints). Free, no key.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


async def fetch_cdx(ctx: Ctx, domain: str):
    """Single wildcard CDX query for a domain, shared across plugins.

    artifacts.py reuses this (via ctx.cache) instead of firing one CDX
    query per sensitive path: same archive data, ~160 fewer requests.
    Returns the parsed JSON rows (header + data) or {"error": ...}.
    """
    async def cdx():
        url = ("https://web.archive.org/cdx/search/cdx?url="
               + quote(domain) + "/*&output=json&fl=timestamp,original,statuscode"
                 "&collapse=urlkey&limit=2000")
        try:
            # Single informational call: tight timeout, one retry max.
            # A slow CDX API must not stall the whole plugin.
            resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                               timeout=25, max_retries=1)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            return resp.json()
        except Exception as e:
            return {"error": str(e)[:200]}

    rows, _ = await ctx.cache.cached("wayback", domain, cdx)
    return rows


class WaybackPlugin(Plugin):
    timeout_s = 30  # capped: 30s per-plugin ceiling (Jay's order 2026-10-18)
    id = "wayback"
    label = "Wayback History"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "Historical snapshots and old URLs via the Wayback CDX API."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        rows = await fetch_cdx(ctx, domain)
        if isinstance(rows, dict) and rows.get("error"):
            res = self._degraded(f"Wayback: {rows['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        if not isinstance(rows, list) or len(rows) < 2:
            return self._skipped("no archived snapshots found")

        header, data = rows[0], rows[1:]
        ts_i = header.index("timestamp") if "timestamp" in header else 0
        url_i = header.index("original") if "original" in header else 1
        stamps = sorted(r[ts_i] for r in data if len(r) > ts_i)
        findings.append(self._f("infra", "wayback_first_seen", stamps[0],
                                source="Wayback CDX",
                                source_url=f"https://web.archive.org/web/{stamps[0]}/{domain}",
                                confidence=95, passive=True))
        findings.append(self._f("infra", "wayback_last_seen", stamps[-1],
                                source="Wayback CDX", confidence=95, passive=True))
        findings.append(self._f("infra", "wayback_snapshot_count", str(len(data)),
                                source="Wayback CDX", confidence=95, passive=True))

        # interesting old URLs: admin, api, backup-ish paths
        interesting = []
        for r in data:
            if len(r) <= url_i:
                continue
            u = r[url_i].lower()
            if any(k in u for k in ("admin", "api", "backup", "old", "test",
                                    "dev", "staging", ".bak", ".zip", ".sql",
                                    "swagger", "graphql")):
                interesting.append(r[url_i])
        for u in sorted(set(interesting))[:25]:
            findings.append(self._f("leak", "wayback_interesting_url", u,
                                    source="Wayback CDX",
                                    source_url=f"https://web.archive.org/web/*/{u}",
                                    confidence=70, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(data)} snapshots, {len(interesting)} interesting URLs")
        res.duration_ms = dur
        return res
