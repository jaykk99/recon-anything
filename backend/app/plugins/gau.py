"""GAU-style: Get All URLs from public archives (native, keyless).

Queries three keyless archive sources for every URL ever seen for a
domain: AlienVault OTX URL list, Wayback CDX API, and the latest
Common Crawl index. Deduplicates and flags interesting URLs
(parameters, juicy extensions, API shapes).

Read-only, no keys, no auth. Bounded to keep under the 30s ceiling.
"""
from __future__ import annotations

import time
from typing import Dict, List, Set
from urllib.parse import quote, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

JUICY_EXTS = (".bak", ".old", ".zip", ".sql", ".env", ".log", ".txt",
              ".json", ".xml", ".yaml", ".yml", ".conf", ".config",
              ".swp", ".git", ".svn")
API_HINT = ("/api", "/v1", "/v2", "/rest", "/graphql", "/admin",
            "/debug", "/test", "/dev", "/staging")


def _interesting(url: str) -> bool:
    low = url.lower()
    if "?" in low and "=" in low:
        return True
    if low.endswith(JUICY_EXTS):
        return True
    return any(h in low for h in API_HINT)


class GauPlugin(Plugin):
    id = "gau"
    label = "Get All URLs"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Known URLs from OTX + Wayback + Common Crawl. "
                   "Keyless archives only.")

    async def _otx(self, ctx: Ctx, domain: str) -> Set[str]:
        out: Set[str] = set()
        url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
               f"{quote(domain)}/urls?limit=500")
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url,
                            timeout=15, max_retries=1)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("url_list", []) or []:
                    u = item.get("url") if isinstance(item, dict) else item
                    if u:
                        out.add(str(u))
        except Exception:
            pass
        return out

    async def _wayback(self, ctx: Ctx, domain: str) -> Set[str]:
        out: Set[str] = set()
        url = ("https://web.archive.org/cdx/search/cdx?url="
               + quote(domain) + "/*&output=json&fl=original"
                 "&collapse=urlkey&limit=3000")
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url,
                            timeout=20, max_retries=1)
            if r.status_code == 200:
                rows = r.json()
                for row in rows[1:]:
                    if row and row[0]:
                        out.add(str(row[0]))
        except Exception:
            pass
        return out

    async def _commoncrawl(self, ctx: Ctx, domain: str) -> Set[str]:
        out: Set[str] = set()
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            "https://index.commoncrawl.org/collinfo.json",
                            timeout=12, max_retries=1)
            if r.status_code != 200:
                return out
            colls = r.json()
            idx = colls[0].get("id") if colls else None
            if not idx:
                return out
            url = (f"https://index.commoncrawl.org/{idx}-index?url="
                   + quote(domain) + "/*&output=json&limit=2000")
            r2 = await fetch(ctx.http, ctx.limiter, "GET", url,
                             timeout=20, max_retries=1)
            if r2.status_code == 200:
                for line in r2.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        import json as _j
                        u = _j.loads(line).get("url")
                        if u:
                            out.add(u)
                    except Exception:
                        continue
        except Exception:
            pass
        return out

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        import asyncio
        otx, wb, cc = await asyncio.gather(
            self._otx(ctx, domain),
            self._wayback(ctx, domain),
            self._commoncrawl(ctx, domain))

        all_urls = otx | wb | cc
        findings: List[Finding] = []
        for u in sorted(all_urls):
            ctx.publish("urls", u)
        interesting = sorted(u for u in all_urls if _interesting(u))
        for u in interesting[:80]:
            findings.append(self._f(
                "web", "archived_url", u,
                "gau archives", source_url=u, confidence=70,
                evidence={"severity": "low",
                          "sources": "+".join(
                              s for s, bag in
                              (("otx", otx), ("wayback", wb),
                               ("commoncrawl", cc)) if u in bag),
                          "remediation": "Archived URLs reveal forgotten "
                                         "endpoints; verify each is still "
                                         "live and intended."},
                passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"{len(all_urls)} archived URLs "
            f"(otx {len(otx)}, wayback {len(wb)}, commoncrawl {len(cc)}); "
            f"{len(interesting)} interesting")
        res.duration_ms = dur
        return res
