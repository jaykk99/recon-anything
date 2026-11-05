"""Waymore/Waybackurls-style historical surface, verified live.

gau.py already pulls archived URLs from OTX + Wayback + Common
Crawl as passive inventory. This plugin is the post-recon step on
top of the Wayback Machine alone:

1. Mine the Wayback CDX index for the domain's historical URLs.
2. Keep only the interesting shapes (admin / api / backup / config /
   debug / upload paths, juicy extensions, id-bearing queries) and
   only rows that really belong to the target (host gate + the
   captured-payload junk gate shared with gau).
3. Verify each candidate is STILL LIVE today with one read-only
   probe. A forgotten endpoint that still answers is a finding;
   one that now 404s is history, not surface, and stays silent.
   401/403 answers are reported separately as "still exists,
   access-controlled" so they are not mistaken for open holes.

Keyless. Read-only probes only.
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, bounded
from .gau import _archive_row_is_junk
from .injutil import same_domain

JUICY_EXTS = (".bak", ".old", ".zip", ".sql", ".env", ".log", ".conf",
              ".config", ".swp", ".tar.gz", ".backup")
INTERESTING_HINTS = ("/admin", "/api", "/backup", "/config", "/debug",
                     "/upload", "/internal", "/old", "/dev", "/test",
                     "/.env", "/.git", "/phpmyadmin", "/manager",
                     "/console", "/setup", "/install")
HIGH_HINTS = ("/admin", "/backup", ".env", ".git", "/config", "/setup",
              "/install", "phpmyadmin")
MAX_CANDIDATES = 400
MAX_PROBES = 25


def _interesting(url: str) -> bool:
    pu = urlparse(url)
    low = (pu.path or "").lower()
    if low.endswith(JUICY_EXTS):
        return True
    if any(h in low for h in INTERESTING_HINTS):
        return True
    if pu.query and ("id=" in pu.query or "file=" in pu.query):
        return True
    return False


class WaybackSurfaceWaymorePlugin(Plugin):
    id = "wayback_surface_waymore"
    label = "Wayback Surface Verification (Waymore-style)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 90
    description = ("Mines Wayback CDX for historical URLs, then "
                   "verifies which interesting forgotten endpoints "
                   "still respond today. Archived-but-dead URLs stay "
                   "silent.")

    async def _cdx(self, ctx: Ctx, domain: str) -> List[Tuple[str, str]]:
        url = ("https://web.archive.org/cdx/search/cdx?url="
               + quote(domain) + "/*&output=json"
                 "&fl=original,timestamp&collapse=urlkey&limit=3000")
        try:
            r = await bounded(fetch(ctx.http, ctx.limiter, "GET", url,
                                    timeout=12, max_retries=0), 20)
        except Exception:
            return []
        if r is None or r.status_code != 200:
            return []
        try:
            rows = r.json()
        except Exception:
            return []
        out: List[Tuple[str, str]] = []
        for row in rows[1:]:
            if row and row[0]:
                out.append((str(row[0]),
                            str(row[1]) if len(row) > 1 else ""))
        return out

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        start = time.time()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        rows = await self._cdx(ctx, domain)
        if not rows:
            return self._degraded("wayback CDX returned no rows "
                                   "(archive unreachable or empty)")
        first_seen: Dict[str, str] = {}
        for u, ts in rows:
            if not same_domain(u, domain) or _archive_row_is_junk(u):
                continue
            if not _interesting(u):
                continue
            if u not in first_seen or (ts and ts < first_seen[u]):
                first_seen[u] = ts
        candidates = sorted(
            first_seen.items(),
            key=lambda kv: (0 if any(h in kv[0].lower()
                                     for h in HIGH_HINTS) else 1,
                            kv[0]))[:MAX_CANDIDATES]

        sem = asyncio.Semaphore(6)

        async def check(item: Tuple[str, str]) -> Optional[Tuple[str, str, Dict]]:
            u, ts = item
            async with sem:
                resp = await ctx.probe(u, timeout=8)
            if not resp or int(resp.get("status") or 0) == 0:
                return None
            return (u, ts, resp)

        probed = await asyncio.gather(
            *(check(c) for c in candidates[:MAX_PROBES]))
        findings: List[Finding] = []
        for item in probed:
            if not item:
                continue
            u, ts, resp = item
            status = int(resp.get("status") or 0)
            low = u.lower()
            if 200 <= status < 400:
                severity = "high" if any(h in low for h in HIGH_HINTS) \
                    else "medium"
                findings.append(self._f(
                    "web", "forgotten_live_endpoint",
                    f"Forgotten endpoint still live: {u} "
                    f"(archived since {ts or 'unknown'}, now HTTP "
                    f"{status})",
                    source="wayback surface verification",
                    source_url=u, confidence=80, passive=False,
                    evidence={"severity": severity,
                              "first_archived": ts,
                              "current_status": status,
                              "remediation": ("Remove this legacy "
                                              "endpoint or bring it "
                                              "under the same auth and "
                                              "patching as the current "
                                              "app; forgotten surface "
                                              "is unmonitored surface.")}))
                ctx.publish("endpoints", u)
            elif status in (401, 403):
                findings.append(self._f(
                    "web", "forgotten_protected_endpoint",
                    f"Forgotten endpoint still exists (access "
                    f"controlled): {u} (archived since "
                    f"{ts or 'unknown'}, now HTTP {status})",
                    source="wayback surface verification",
                    source_url=u, confidence=70, passive=False,
                    evidence={"severity": "low",
                              "first_archived": ts,
                              "current_status": status,
                              "remediation": ("Confirm this legacy "
                                              "endpoint is intentional "
                                              "and patched; delete it "
                                              "if it is retired.")}))
                ctx.publish("endpoints", u)
        result = self._ok(
            findings,
            f"{len(candidates)} archived candidates, "
            f"{min(len(candidates), MAX_PROBES)} probed, "
            f"{len(findings)} still live")
        result.duration_ms = int((time.time() - start) * 1000)
        return result
