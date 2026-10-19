"""File Hunter (native, keyless).

Hunt for publicly exposed files on the target:
- backup files (.bak, .old, .orig, ~, .swp, .save)
- config files (.env, config.php, web.config, settings.py)
- source control metadata (.git/HEAD, .svn/entries, .hg)
- log files (access.log, error.log, debug.log)
- database dumps (.sql, .db, .sqlite, .dump)
- archive files (.zip, .tar, .rar, .7z, .bak.zip)

GET only, detection only. If a file returns 403/401 we note it exists
(protected) and never try to bypass. 404 baselining + soft-404 filtering
so we only report real hits.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

CONCURRENCY = 20
TIME_BUDGET = 25

# (path, category, severity, note)
TARGETS: List[Tuple[str, str, str, str]] = [
    # backups
    ("index.php.bak", "backup", "high", "PHP backup of front controller"),
    ("index.php.old", "backup", "high", "PHP backup of front controller"),
    ("index.php~", "backup", "high", "Editor backup of front controller"),
    ("index.html.bak", "backup", "medium", "HTML backup file"),
    ("wp-config.php.bak", "backup", "high", "WordPress config backup"),
    ("wp-config.php~", "backup", "high", "WordPress config editor backup"),
    (".env.bak", "backup", "high", "Env backup"),
    ("config.php.bak", "backup", "high", "Config backup"),
    ("backup.zip", "archive", "high", "Site backup archive"),
    ("backup.tar.gz", "archive", "high", "Site backup archive"),
    ("site.zip", "archive", "high", "Site archive"),
    ("www.zip", "archive", "high", "Site archive"),
    ("db.sql", "database", "high", "Database dump"),
    ("dump.sql", "database", "high", "Database dump"),
    ("database.sql", "database", "high", "Database dump"),
    ("backup.sql", "database", "high", "Database dump"),
    ("data.db", "database", "high", "SQLite database"),
    ("app.db", "database", "high", "SQLite database"),
    # configs
    (".env", "config", "high", "Environment secrets file"),
    (".env.local", "config", "high", "Local env secrets"),
    (".env.production", "config", "high", "Production env secrets"),
    ("config.php", "config", "medium", "PHP config (may 500 or download)"),
    ("web.config", "config", "medium", "IIS config"),
    ("settings.py", "config", "medium", "Django settings"),
    (".htpasswd", "config", "high", "HTTP basic-auth password file"),
    ("phpinfo.php", "config", "medium", "phpinfo disclosure page"),
    ("info.php", "config", "medium", "phpinfo disclosure page"),
    # source control
    (".git/HEAD", "vcs", "high", "Exposed git metadata"),
    (".git/config", "vcs", "high", "Exposed git config"),
    (".svn/entries", "vcs", "medium", "Exposed SVN metadata"),
    (".hg/requires", "vcs", "medium", "Exposed Mercurial metadata"),
    # logs
    ("error.log", "log", "medium", "Error log"),
    ("access.log", "log", "medium", "Access log"),
    ("debug.log", "log", "medium", "Debug log"),
    ("app.log", "log", "medium", "Application log"),
    ("logs/error.log", "log", "medium", "Error log in logs/"),
    # misc sensitive
    ("robots.txt", "disclosure", "low", "Robots file (info)"),
    ("sitemap.xml", "disclosure", "low", "Sitemap (info)"),
    (".well-known/security.txt", "disclosure", "low", "security.txt (info)"),
    ("composer.json", "disclosure", "low", "Composer manifest"),
    ("package.json", "disclosure", "low", "NPM manifest"),
    ("Dockerfile", "disclosure", "low", "Docker build file"),
    ("docker-compose.yml", "disclosure", "low", "Compose file"),
]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

SECRET_HINT_RE = re.compile(
    r'(?i)(password|passwd|secret|api[_-]?key|db[_-]?pass|token)\s*[:=]\s*\S{4,}')


class FileHunterPlugin(Plugin):
    id = "filehunter"
    label = "File Hunter"
    accepts = ["domain", "url"]
    passive = False  # sends enumeration probes
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    description = ("Hunt exposed backups, configs, VCS, logs, DB dumps, "
                   "archives. Notes 403s, never bypasses.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        if not base.endswith("/"):
            base += "/"

        # 404 baseline so we can filter soft-404s
        baseline: Optional[Tuple[int, int]] = None
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            base + "fh-nope-9f3a2b1c7d.html",
                            timeout=8, max_retries=0)
            baseline = (r.status_code, len(r.content))
        except Exception:
            pass

        def is_soft_404(status: int, body: bytes) -> bool:
            if baseline is None:
                return False
            bs, bl = baseline
            if status == 200 and bs == 200 and abs(len(body) - bl) < 200:
                return True
            if status == 200 and bs == 404:
                return True  # baseline 404s but this 200s -> soft-404
            return False

        sem = asyncio.Semaphore(CONCURRENCY)
        hits: List[Tuple[str, str, str, str, int, bytes]] = []
        protected: List[Tuple[str, str, str]] = []

        async def probe(path: str, cat: str, sev: str, note: str):
            nonlocal hits, protected
            if (time.monotonic() - t0) > TIME_BUDGET:
                return
            url = urljoin(base, path)
            async with sem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                    timeout=8, max_retries=0)
                except Exception:
                    return
            if r.status_code in (401, 403):
                protected.append((path, cat, note))
                return
            if r.status_code in (200, 206):
                body = r.content[:200000]
                if is_soft_404(r.status_code, body):
                    return
                hits.append((path, cat, sev, note, r.status_code, body))

        await asyncio.gather(*[probe(p, c, s, n) for p, c, s, n in TARGETS])

        findings: List[Finding] = []
        for path, cat, sev, note, status, body in sorted(
                hits, key=lambda h: SEVERITY_RANK.get(h[2], 0), reverse=True):
            url = urljoin(base, path)
            ev: Dict = {"severity": sev, "category": cat, "status": status,
                        "bytes": len(body),
                        "remediation": "Remove the exposed file from the web "
                                       "root or block it in the server config."}
            text = body[:4000].decode("utf-8", "ignore")
            if SECRET_HINT_RE.search(text):
                ev["contains_secrets_hint"] = True
                ev["severity"] = "high"
            findings.append(self._f(
                "web", "exposed_file", f"{path} -> HTTP {status} ({note})",
                "filehunter", source_url=url, confidence=90, evidence=ev))
            ctx.publish("assets", url)

        for path, cat, note in protected:
            url = urljoin(base, path)
            findings.append(self._f(
                "web", "protected_file",
                f"{path} exists but is access-protected (HTTP 401/403)",
                "filehunter", source_url=url, confidence=80,
                evidence={"severity": "medium", "category": cat,
                          "remediation": "Confirm the protection is "
                                         "intentional; remove the file if it "
                                         "should not be web-reachable at all."}))

        reason = (f"probed {len(TARGETS)} sensitive paths: {len(hits)} exposed, "
                  f"{len(protected)} protected-but-present")
        return self._ok(findings, reason)
