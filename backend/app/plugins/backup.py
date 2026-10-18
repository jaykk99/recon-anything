"""Backup file sweeper (Milestone: critical findings).

Takes discovered base names (index, wp-config, config, .env, backup,
db, dump, site, www, etc.) and tries every common backup extension.
Also sweeps well-known backup paths directly. Passive mode uses the
Wayback Machine; active mode does read-only GETs. When a backup is
found, its first bytes are sniffed for secrets/config markers.
Authorized testing only.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List
from urllib.parse import quote, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

EXTENSIONS = [".bak", ".backup", ".old", ".orig", ".save", ".swp",
              ".tmp", "~", ".bkp", ".bac", ".copy", ".orig.bak"]

BASE_NAMES = ["index.php", "index.html", "wp-config.php", "config.php",
              "configuration.php", ".env", "settings.py", "settings.php",
              "application.properties", "web.config", "database.sql",
              "db.sql", "dump.sql", "backup.sql", "site.sql", "main.py",
              "app.py", "server.js"]

DIRECT_PATHS = [
    "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/site.zip",
    "/www.zip", "/public_html.zip", "/db_backup.sql", "/backup_db.sql",
    "/website.bak", "/old.zip", "/bak.zip",
]

SECRET_MARKERS = ["password", "secret", "api_key", "apikey", "private key",
                  "BEGIN PRIVATE", "mongodb://", "postgres://", "mysql://"]


class BackupPlugin(Plugin):
    timeout_s = 180  # slow enumerator: needs headroom
    id = "backup"
    label = "Backup File Sweeper"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Sweep backup extensions on common files; sniff for secrets."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        candidates = []
        for name in BASE_NAMES:
            for ext in EXTENSIONS:
                candidates.append(f"/{name}{ext}")
        candidates += DIRECT_PATHS

        def sniff(body: str) -> str:
            low = body.lower()[:2000]
            hits = [m for m in SECRET_MARKERS if m in low]
            return f" Contains secret markers: {', '.join(hits[:4])}." if hits else ""

        if passive:
            # Wayback lookup per path: zero packets to the target.
            # Concurrent (12 at a time): the old sequential loop took
            # 227 x retry-backoff on a dead network, blowing past the
            # 180s timeout. Same checks, same findings, bounded time.
            sem = asyncio.Semaphore(12)

            async def wprobe(path: str):
                full = base + path
                url = ("https://web.archive.org/cdx/search/cdx?url="
                       + quote(full, safe="") + "&output=json&fl=timestamp&limit=1")
                async with sem:
                    try:
                        r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                        timeout=12, max_retries=1)
                    except Exception:
                        return None
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except Exception:
                        return None
                    if isinstance(data, list) and len(data) > 1:
                        ts = data[1][0] if data[1] else ""
                        return (path, full, ts)
                return None

            probed = await asyncio.gather(*[wprobe(p) for p in candidates])
            for item in probed:
                if not item:
                    continue
                path, full, ts = item
                findings.append(self._f(
                    "leak", "backup_archived",
                    f"HIGH: backup file {path} was archived ({ts}).",
                    source="Wayback CDX",
                    source_url=f"https://web.archive.org/web/{ts}/{full}",
                    confidence=65, passive=True,
                    evidence={"severity": "high",
                              "remediation": "Remove backup files from web roots. "
                                             "Block backup extensions at the web server."}))
        else:
            # Concurrent sweep: 228 candidates at ~10 RPS = ~25s.
            # Short timeout + single retry: a blackholed path on a WAF
            # means "blocked", retrying just burns the time budget.
            # Uses ctx.probe: responses are shared per-run with artifacts.py
            # and hiddenpaths.py, so overlapping paths are fetched once.
            sem = asyncio.Semaphore(12)

            async def probe(path: str):
                full = base + path
                async with sem:
                    probed = await ctx.probe(full, timeout=8)
                status = probed["status"]
                text = probed["text"]
                if status == 200 and len(text.strip()) > 50:
                    ctype = probed["headers"].get("content-type", "")
                    if "text/html" in ctype and len(text) > 2000:
                        # probably a soft-404 page; check for backup markers
                        if not any(e in path for e in (".sql", ".zip", ".gz", ".tgz")):
                            return None
                    return (path, full, text, probed["length"])
                return None

            probed = await asyncio.gather(*[probe(p) for p in candidates])
            for item in probed:
                if not item:
                    continue
                path, full, body, length = item
                note = sniff(body)
                findings.append(self._f(
                    "leak", "backup_exposed",
                    f"CRITICAL: backup file {path} is downloadable ({length} bytes)."
                    + note,
                    source="backup sweep", source_url=full,
                    confidence=90, passive=False,
                    evidence={"severity": "critical",
                              "size": length,
                              "remediation": "Remove backup files from web roots immediately. "
                                             "Block backup extensions at the web server and audit what was exposed."}))
                if len(findings) >= 30:
                    break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"swept {len(candidates)} backup paths, "
                                 f"{len(findings)} hits")
        res.duration_ms = dur
        return res
