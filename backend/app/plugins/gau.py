"""GAU-style: Get All URLs from public archives (native, keyless).

Queries three keyless archive sources for every URL ever seen for a
domain: AlienVault OTX URL list, Wayback CDX API, and the latest
Common Crawl index. Deduplicates and flags interesting URLs
(parameters, juicy extensions, API shapes).

Read-only, no keys, no auth. Bounded to keep under the 30s ceiling.
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Set
from urllib.parse import quote, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, bounded
from .injutil import same_domain

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


def _archive_row_is_junk(url: str) -> bool:
    """True when an archive row is a captured payload, not a real URL.

    The Wayback CDX index holds captures of *payload strings* where the
    queried host appears as a placeholder - XSS/SQLi probe artifacts
    from archived exploit kits and scanner traffic. Tells (all observed
    live against IP-literal queries, 2026-10-22):
      - a second scheme embedded in the path/query
        (http://127.0.0.1/%EF%BF%BDhttp://static.streampad.com/x.js)
      - quotes, angle brackets or raw spaces (payload concatenation:
        http://127.0.0.1/" + url + "index.php?act=idx)
      - the unicode replacement char (corrupt captures)
    Real archived page URLs never contain these in path/query, so
    dropping them costs nothing and removes dozens of bogus findings.
    """
    try:
        parts = urlparse(url)
    except Exception:
        return True
    rest = (parts.path + "?" + parts.query).lower()
    for marker in ("http://", "https://", '"', "'", "<", ">", " ", "\u00a0",
                   "%22", "%27", "%3c", "%3e", "%ef%bf%bd", "\ufffd", "\ufeff"):
        if marker in rest:
            return True
    return False


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
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", url,
                timeout=10, max_retries=0), 12)
            if r is not None and r.status_code == 200:
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
                 "&collapse=urlkey&limit=2000")
        try:
            # CDX can trickle a huge payload for 30s+ (battle-test
            # 2026-10-18: httpbin.org took 34s). Hard wall-clock cap;
            # 20s keeps the 3-source gather under the 30s ceiling.
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", url,
                timeout=12, max_retries=0), 20)
            if r is not None and r.status_code == 200:
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
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET",
                "https://index.commoncrawl.org/collinfo.json",
                timeout=10, max_retries=0), 12)
            if r is None or r.status_code != 200:
                return out
            colls = r.json()
            idx = colls[0].get("id") if colls else None
            if not idx:
                return out
            url = (f"https://index.commoncrawl.org/{idx}-index?url="
                   + quote(domain) + "/*&output=json&limit=2000")
            r2 = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", url,
                timeout=12, max_retries=0), 15)
            if r2 is not None and r2.status_code == 200:
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

        # Each source is hard-capped inside its helper, so the gather
        # can never exceed ~16s: the plugin stays well under the 30s ceiling
        # even when an archive API trickles or stalls.
        otx, wb, cc = await asyncio.gather(
            self._otx(ctx, domain),
            self._wayback(ctx, domain),
            self._commoncrawl(ctx, domain))

        all_urls = otx | wb | cc
        # Gate every archive URL before it can become a finding or a
        # published discovery-bus asset:
        #  1. host must be the target domain (or a subdomain) - archive
        #     APIs return unfiltered off-target captures;
        #  2. not a captured payload string - CDX holds XSS/SQLi probe
        #     artifacts where the host is just a placeholder
        #     (see _archive_row_is_junk).
        gated = {u for u in all_urls
                 if same_domain(u, domain)
                 and not _archive_row_is_junk(u)}
        findings: List[Finding] = []
        for u in sorted(gated):
            ctx.publish("urls", u)
        interesting = sorted(u for u in gated if _interesting(u))
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
            f"{len(gated)} archived URLs "
            f"(otx {len(otx)}, wayback {len(wb)}, commoncrawl {len(cc)}, "
            f"dropped {len(all_urls) - len(gated)} off-target/junk); "
            f"{len(interesting)} interesting")
        res.duration_ms = dur
        return res
