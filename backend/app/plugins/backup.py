"""Backup file sweeper (Milestone: critical findings).

Takes discovered base names (index, wp-config, config, .env, backup,
db, dump, site, www, etc.) and tries every common backup extension.
Also sweeps well-known backup paths directly. Passive mode uses the
Wayback Machine; active mode does read-only GETs. When a backup is
found, its first bytes are sniffed for secrets/config markers.

Deep backend sweep (Jay 2026-10-18): also probes backend source dirs
(/src/, /app/, /backend/, /api/, /server/, /lib/, /config/, /inc/,
/includes/) with backend extensions (.php, .asp, .aspx, .jsp, .py,
.rb, .pl, .cgi) plus admin consoles (/wp-admin/, /phpmyadmin/,
/server-status/, /actuator/, etc.).
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
              ".backup1", ".backup2", ".tmp1", ".swp1",
              # NEW: more archive + editor + numbered variants
              ".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar",
              ".bak3", ".old2", ".old3", ".save1", ".save2",
              ".bakup", ".bk", ".bk1", ".bk2", ".bck", ".bakup1",
              ".original", ".orig2", ".tmp2", ".temp", ".dmp",
              ".sql", ".sql.gz", ".sql.zip", ".sqlite", ".db",
              ".env.bak", ".env.old", ".env.save", ".env~",
              ".swo", ".swn", ".un~", ".kate-swp",
              "_bak", "_old", "_backup", "_copy", "_orig", "_tmp",
              "-bak", "-old", "-backup", "-copy", "-orig",
              ".inc", ".conf", ".cfg", ".ini.bak",
              ".2019", ".2020", ".2021", ".2022", ".2023", ".2024",
              ".2025", ".2026"]

# Priority-ordered: secret-bearing files first so the 30s plugin cap
# always covers the highest-value candidates before lower-value ones.
BASE_NAMES = [
    # Tier 1: secrets/config (check first)
    ".env", ".env.local", ".env.production", ".env.development",
    "wp-config.php", "config.php", "configuration.php",
    "settings.py", "settings.php", "application.properties",
    "secrets.json", "credentials.json", ".git-credentials", ".npmrc",
    "id_rsa", "id_dsa",
    # Tier 2: database dumps
    "database.sql", "db.sql", "dump.sql", "backup.sql", "site.sql",
    "users.sql", "data.sql", "wordpress.sql", "drupal.sql",
    "dump.rdb", "redis.rdb", "backup.db", "site.db", "app.db",
    # Tier 3: app config/code
    "config.json", "config.yaml", "config.yml", "config.ini",
    "config.inc.php", "connect.php", "db.php", "dbconn.php",
    "dbconfig.php", "database.php", "database.yml", "connection.php",
    "package.json", "composer.json", "requirements.txt",
    "docker-compose.yml", "Dockerfile", ".htaccess",
    "localsettings.py", "settings.ini",
    "wp-config-sample.php",
    # Tier 4: entry points
    "index.php", "index.html", "main.py", "app.py", "server.js",
    "web.config",
    # Tier 5: misc
    "passwd", "shadow", "mongodump",
]

DIRECT_PATHS = [
    "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/site.zip",
    "/www.zip", "/public_html.zip", "/db_backup.sql", "/backup_db.sql",
    "/website.bak", "/old.zip", "/bak.zip",
    # NEW: more well-known backup/archive paths
    "/backup.tar", "/backup.7z", "/backup.rar", "/site.tar.gz",
    "/site.tar", "/www.tar.gz", "/public_html.tar.gz",
    "/database.zip", "/db.zip", "/dump.zip", "/sql.zip",
    "/backup.sql.gz", "/db.sql.gz", "/site.sql.gz",
    "/old-site.zip", "/oldsite.zip", "/backup-old.zip",
    "/wp-content.zip", "/wp-content.tar.gz", "/uploads.zip",
    "/backup/", "/backups/", "/bak/", "/old/", "/tmp/backup.zip",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/server-status", "/server-info",
]

SECRET_MARKERS = ["password", "secret", "api_key", "apikey", "private key",
                  "BEGIN PRIVATE", "mongodb://", "postgres://", "mysql://"]

# DEEP backend discovery (Jay's order 2026-10-18): probe backend source
# dirs and backend file extensions directly. These are checked AFTER
# the secret/config tiers above so the 30s cap hits highest value first.
BACKEND_DIRS = ["/src", "/app", "/backend", "/api", "/server", "/lib",
                "/config", "/inc", "/includes", "/core", "/system",
                "/application", "/classes", "/models", "/controllers",
                "/protected", "/private", "/admin", "/manage",
                "/cgi-bin", "/scripts", "/bin"]

# Backend source file extensions probed directly (no backup suffix)
BACKEND_EXTS = [".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".pl",
                ".cgi"]

BACKEND_FILES = [
    # PHP
    "config.php", "configuration.php", "settings.php", "db.php",
    "database.php", "connect.php", "connection.php", "dbconn.php",
    "dbconfig.php", "config.inc.php", "index.php", "admin.php",
    "login.php", "wp-config.php", "local-config.php",
    # Python
    "settings.py", "config.py", "app.py", "main.py", "wsgi.py",
    "manage.py",
    # Node
    "server.js", "app.js", "index.js", "routes.js", ".env",
    # Ruby
    "config.ru", "application.rb", "database.yml", "secrets.yml",
    # Java
    "web.xml", "struts.xml", "application.properties",
    "application.yml", "pom.xml", "index.jsp", "login.jsp",
    # .NET
    "web.config", "global.asax", "default.aspx", "login.aspx",
    # Perl/CGI
    "index.pl", "admin.pl", "index.cgi",
]

# Admin/management consoles and server-info endpoints
ADMIN_PATHS = [
    "/wp-admin/", "/wp-login.php", "/administrator/", "/admin/",
    "/admin/login.php", "/manage/", "/management/", "/console/",
    "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/myadmin/",
    "/server-status", "/server-status/", "/server-info", "/server-info/",
    "/phpinfo.php", "/info.php", "/test.php", "/phpinfo/",
    "/.env", "/.env.local", "/.env.production",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/metrics", "/prometheus", "/healthz", "/readyz", "/livez",
    "/telescope/", "/horizon/", "/_debug/", "/debug/",
    "/xmlrpc.php", "/wp-json/", "/wp-json/wp/v2/",
    "/jmx-console/", "/web-console/", "/manager/html",
]


class BackupPlugin(Plugin):
    timeout_s = 90  # raised 2026-10-20: 30s cap truncated this enumerator mid-work (Jay: find more)
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

        # DIRECT_PATHS first: these are curated, well-known backup file
        # locations (/backup.zip, /db_backup.sql, ...) - the highest hit
        # rate per probe. They used to be appended AFTER the ~2,000
        # generated BASE_NAMES x EXTENSIONS combos, and the sweep's
        # chunking + 18s budget never reached them: the single most
        # likely backup exposures were silently never probed.
        candidates = list(DIRECT_PATHS)
        for name in BASE_NAMES:
            for ext in EXTENSIONS:
                candidates.append(f"/{name}{ext}")

        # Deep backend sweep: backend files with backend extensions at
        # root, backend dirs themselves, and admin/management paths.
        # Appended after secret/config tiers (priority order).
        for name in BACKEND_FILES:
            parts = name.rsplit(".", 1)
            base_name = parts[0] if len(parts) == 2 and parts[0] else name
            for ext in BACKEND_EXTS:
                candidates.append(f"/{base_name}{ext}")
        for d in BACKEND_DIRS:
            candidates.append(d + "/")
        candidates += ADMIN_PATHS

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
            # Concurrent tiered sweep: candidates are already priority-ordered
            # (secrets/config first, bulk backup extensions last). Probe in
            # chunks with a hard internal time budget: the old code launched
            # all ~5,800 probes at once and always burned the full 30s
            # plugin cap, stalling a whole concurrency slot. Now the
            # highest-value tiers finish in ~8-12s and the bulk tail only
            # runs if budget remains.
            # Uses ctx.probe: responses are shared per-run with artifacts.py
            # and hiddenpaths.py, so overlapping paths are fetched once.
            SWEEP_BUDGET_S = 18
            CHUNK = 150
            sem = asyncio.Semaphore(12)
            t_start = time.monotonic()

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

            swept = 0
            for i in range(0, len(candidates), CHUNK):
                if time.monotonic() - t_start >= SWEEP_BUDGET_S:
                    break
                chunk = candidates[i:i + CHUNK]
                probed = await asyncio.gather(*[probe(p) for p in chunk])
                swept += len(chunk)
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
                if len(findings) >= 30:
                    break
                # Checkpoint: keep confirmed findings if the runner kills
                # us on timeout mid-sweep.
                self._checkpoint(findings)

        dur = int((time.monotonic() - t0) * 1000)
        swept_n = swept if not passive else len(candidates)
        res = self._ok(findings, f"swept {swept_n} backup paths, "
                                 f"{len(findings)} hits")
        res.duration_ms = dur
        return res
