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
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .wayback import fetch_cdx

EXTENSIONS = [".bak", ".backup", ".old", ".orig", ".save", ".swp",
              ".tmp", "~", ".bkp", ".bac", ".copy", ".orig.bak",
              ".bak1", ".bak2", ".old1", ".orig1", ".txt", ".log",
              ".sql.bak", ".db.bak", ".conf.bak", ".config.bak",
              ".php.bak", ".js.bak", ".html.bak", "1", "2",
              ".backup1", ".backup2", ".tmp1", ".swp1"]

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
    timeout_s = 30  # capped: 30s per-plugin ceiling (Jay's order 2026-10-18)
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
        base = (f"https://{domain}" if target.type == "domain"
                else target.normalized.rstrip("/"))
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
            # Wayback lookup per candidate: zero packets to the target.
            # Reuses wayback.py's single wildcard CDX snapshot (cached
            # per-domain) instead of one CDX query per candidate: same
            # archive data, ~228 fewer requests to web.archive.org.
            rows = await fetch_cdx(ctx, domain)
            archived = {}  # path -> timestamp
            if isinstance(rows, list) and len(rows) > 1:
                header, data = rows[0], rows[1:]
                ts_i = header.index("timestamp") if "timestamp" in header else 0
                url_i = header.index("original") if "original" in header else 1
                for r in data:
                    if len(r) <= max(ts_i, url_i):
                        continue
                    p = urlparse(r[url_i]).path or "/"
                    if p not in archived or r[ts_i] < archived[p]:
                        archived[p] = r[ts_i]
            for path in candidates:
                ts = archived.get(path)
                if not ts:
                    continue
                full = base + path
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
