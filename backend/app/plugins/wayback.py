"""Wayback Machine plugin (Milestone 2).

Historical snapshots via the CDX API: first/last seen, snapshot count,
old URLs (great for finding forgotten endpoints). Free, no key.
"""
from __future__ import annotations

import asyncio

import time
from typing import List
from urllib.parse import quote, urlparse

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


async def fetch_commoncrawl(ctx: Ctx, domain: str):
    """Common Crawl index API: historical URLs from the petabyte-scale
    crawl corpus. Keyless. Returns list of URLs or {"error": ...}.
    """
    async def cc():
        url = ("https://index.commoncrawl.org/collinfo.json")
        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                               timeout=15, max_retries=1)
            if resp.status_code != 200:
                return {"error": f"collinfo HTTP {resp.status_code}"}
            colls = resp.json()
            # Use the 3 most recent crawl indexes
            idxs = [c.get("id") for c in colls[:3] if c.get("id")]
        except Exception as e:
            return {"error": str(e)[:200]}
        urls = set()
        for idx in idxs:
            q = (f"https://index.commoncrawl.org/{idx}-index?url="
                 + quote(domain) + "/*&output=json&limit=1000")
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", q,
                                timeout=20, max_retries=1)
                if r.status_code != 200:
                    continue
                for line in r.text.splitlines():
                    try:
                        import json as _json
                        u = _json.loads(line).get("url")
                        if u:
                            urls.add(u)
                    except Exception:
                        continue
            except Exception:
                continue
        return sorted(urls)

    urls, _ = await ctx.cache.cached("commoncrawl", domain, cc)
    return urls


async def fetch_arquivo(ctx: Ctx, domain: str):
    """Arquivo.pt textsearch API: Portuguese web archive, good coverage
    of EU/LatAm targets the Wayback Machine sometimes misses. Keyless.
    Returns list of URLs or {"error": ...}.
    """
    async def aq():
        url = ("https://arquivo.pt/textsearch?versionHistory="
               + quote(domain) + "&maxItems=200")
        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                               timeout=20, max_retries=1,
                               headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            data = resp.json()
            urls = set()
            for item in data.get("response_items", []):
                u = item.get("originalURL") or item.get("linkToArchive")
                if u:
                    urls.add(u)
            return sorted(urls)
        except Exception as e:
            return {"error": str(e)[:200]}

    urls, _ = await ctx.cache.cached("arquivo", domain, aq)
    return urls


class WaybackPlugin(Plugin):
    timeout_s = 90  # raised 2026-10-20: 30s cap truncated this enumerator mid-work (Jay: find more)
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

        # The three archive sources are independent -> query in parallel
        rows, cc_urls, arq_urls = await asyncio.gather(
            fetch_cdx(ctx, domain),
            fetch_commoncrawl(ctx, domain),
            fetch_arquivo(ctx, domain),
        )
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
                                    "swagger", "graphql", "login", "dashboard",
                                    "config", ".env", "debug", "internal",
                                    "private", "secret", "key", "token",
                                    "upload", "download", "export", "report",
                                    "v1", "v2", "beta", "demo", "cms",
                                    "wp-admin", "phpmyadmin", "console")):
                interesting.append(r[url_i])
        for u in sorted(set(interesting))[:25]:
            findings.append(self._f("leak", "wayback_interesting_url", u,
                                    source="Wayback CDX",
                                    source_url=f"https://web.archive.org/web/*/{u}",
                                    confidence=70, passive=True))

        # Common Crawl: historical URLs from the crawl corpus (cached,
        # 3 newest indexes). Publishes interesting URLs to the bus.
        if isinstance(cc_urls, list) and cc_urls:
            findings.append(self._f(
                "infra", "commoncrawl_urls",
                f"Common Crawl has {len(cc_urls)} URLs for {domain}",
                source="Common Crawl index", confidence=80, passive=True))
            cc_interesting = 0
            for u in cc_urls:
                ul = u.lower()
                if domain not in urlparse(ul).netloc:
                    continue
                if any(k in ul for k in ("admin", "api", "backup", "config",
                                         ".env", "swagger", "graphql", "old",
                                         "dev", "staging", "test", "login",
                                         "dashboard", "internal", "private",
                                         "secret", "key", "token", ".bak",
                                         ".zip", ".sql", "v1", "v2", "beta",
                                         "wp-admin", "phpmyadmin", "console")):
                    findings.append(self._f(
                        "leak", "commoncrawl_interesting_url", u,
                        source="Common Crawl index", confidence=65,
                        passive=True))
                    ctx.publish("endpoints", u)
                    cc_interesting += 1
                    if cc_interesting >= 25:
                        break
                else:
                    ctx.publish("endpoints", u)

        # Arquivo.pt: Portuguese web archive, good for EU/LatAm targets
        if isinstance(arq_urls, list) and arq_urls:
            findings.append(self._f(
                "infra", "arquivo_hits",
                f"Arquivo.pt has {len(arq_urls)} archived URLs for {domain}",
                source="Arquivo.pt", confidence=75, passive=True))
            for u in arq_urls[:25]:
                ul = u.lower()
                if any(k in ul for k in ("admin", "api", "backup", "config",
                                         ".env", "swagger", "graphql")):
                    findings.append(self._f(
                        "leak", "arquivo_interesting_url", u,
                        source="Arquivo.pt", confidence=60, passive=True))
                ctx.publish("endpoints", u)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(data)} snapshots, {len(interesting)} interesting URLs")
        res.duration_ms = dur
        return res
