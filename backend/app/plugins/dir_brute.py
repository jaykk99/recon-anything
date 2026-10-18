"""Directory brute-forcing for hidden panels, backups, configs (GET only).

Probes a curated wordlist of admin panels, backup files, config files,
and dev artifacts. False-positive resistant: fingerprints the site's
404 baseline (status + body hash) first, and ignores responses that
match it. Soft-404 (200 with "not found" text) is also filtered.

GET only. No login attempts, no credential brute-forcing, no writes.
Rate-limited via the shared limiter + bounded concurrency.
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

WORDLIST = """admin administrator admin1 admin-panel adminpanel
admincp administrator-index adm manage management manager
moderator mod cp controlpanel control-panel dashboard
panel console backend system sys superuser root login
signin signin-admin login-admin auth-admin wp-admin
wp-login.php administrator.php admin.php admin.html
admin.asp admin.aspx umbraco sitecore adminer phpmyadmin
pma myadmin dbadmin sqladmin pgadmin adminmongo
.env .env.bak .env.backup .env.old .env.save .env.prod
.env.production .env.local .env.development config
config.php config.php.bak config.php.old config.bak
config.old config.inc config.ini configuration.php
settings.php settings.py settings.bak wp-config.php
wp-config.php.bak wp-config.php.old wp-config.bak
database.php database.yml db.php db.sql dump.sql
backup.sql site.sql backup backup.zip backup.tar.gz
backup.tgz site.zip www.zip public_html.zip old.zip
bak.zip db_backup.sql backup_db.sql website.bak
index.php.bak index.php.old index.html.bak main.py.bak
app.py.bak server.js.bak .bak .backup .old .orig .save
.swp .swo ~ .git .git/HEAD .git/config .svn .hg .bzr
.gitignore Dockerfile docker-compose.yml .dockerignore
package.json composer.json Gemfile requirements.txt
web.config .htaccess .htpasswd robots.txt.bak
sitemap.xml.bak readme.html readme.txt license.txt
CHANGELOG.txt changelog.md debug phpinfo.php info.php
test.php test.html debug.php _debug /debug console
profiler _profiler _wdt actuator actuator/health
health status metrics prometheus api api-docs
swagger swagger.json swagger-ui openapi.json
graphql graphiql altair .well-known/security.txt
server-status server-info .DS_Store Thumbs.db
WEB-INF WEB-INF/web.xml META-INF/MANIFEST.MF
crossdomain.xml clientaccesspolicy.xml
""".split()

SOFT404_HINTS = ("not found", "page not found", "404", "does not exist",
                 "couldn't be found", "no se encontr", "nichts gefunden")


class DirBrutePlugin(Plugin):
    id = "dir_brute"
    label = "Directory Brute Force"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 300
    description = ("Brute-force hidden paths (admin, backups, configs) with "
                   "404-baseline filtering. GET only, no login attempts.")

    async def _baseline(self, ctx: Ctx, base: str) -> Dict:
        """Fingerprint the site's 404 response (status + body signature)."""
        import random
        import string
        rand = "".join(random.choices(string.ascii_lowercase, k=16))
        probe = f"{base}/__no_such_path_{rand}__"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", probe, timeout=12,
                            follow_redirects=False, max_retries=1)
            body = r.text[:4000]
            return {"status": r.status_code,
                    "length": len(body),
                    "body": body[:2000]}
        except Exception:
            return {"status": 0, "length": 0, "body": ""}

    def _looks_like_hit(self, status: int, body: str,
                        baseline: Dict) -> bool:
        if status in (301, 302, 303, 307, 308):
            return True  # redirect to login etc. is interesting
        if status == 404 or status == 0:
            return False
        if status == baseline.get("status") and \
                abs(len(body) - baseline.get("length", 0)) < 64:
            # same shape as the 404 baseline -> wildcard/soft-404
            low = body[:2000].lower()
            base_low = (baseline.get("body") or "").lower()
            if low[:500] == base_low[:500]:
                return False
            if any(h in low for h in SOFT404_HINTS):
                return False
        if status == 200 and any(h in body[:2000].lower()
                                 for h in SOFT404_HINTS) \
                and len(body) < 3000:
            return False
        return status in (200, 201, 202, 204, 301, 302, 303, 307, 308,
                          401, 403, 405, 500)

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        if passive:
            res = self._ok(
                [], "directory brute force needs active mode (sends probes)")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        baseline = await self._baseline(ctx, base)
        sem = asyncio.Semaphore(10)
        hits: List[Dict] = []

        async def probe(path: str):
            url = base + (path if path.startswith("/") else "/" + path)
            async with sem:
                probed = await ctx.probe(url, timeout=10)
            status = probed["status"]
            body = probed["text"]
            if self._looks_like_hit(status, body, baseline):
                loc = probed["headers"].get("location", "")
                hits.append({"path": path, "url": url, "status": status,
                             "length": probed.get("length", len(body)),
                             "location": loc[:120],
                             "snippet": body[:300].replace("\n", " ")[:300]})

        await asyncio.gather(*[probe(p) for p in WORDLIST])

        for h in sorted(hits, key=lambda x: x["path"]):
            sev = "high" if h["status"] == 200 else "medium"
            label = {"401": "auth-gated", "403": "forbidden"}.get(
                str(h["status"]), f"HTTP {h['status']}")
            val = (f"{sev.upper()}: hidden path {h['path']} exists "
                   f"({label}, {h['length']} bytes)")
            if h["location"]:
                val += f" -> {h['location']}"
            findings.append(self._f(
                "web", "dir_brute_hit", val,
                source="directory brute force", source_url=h["url"],
                confidence=85 if h["status"] == 200 else 70,
                passive=False,
                evidence={"severity": sev, "path": h["path"],
                          "status": h["status"],
                          "remediation": ("Remove or access-control this path. "
                                          "Backup/config files must never be "
                                          "web-reachable; admin panels need "
                                          "auth + IP allowlisting.")}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"probed {len(WORDLIST)} paths, {len(hits)} hits")
        res.duration_ms = dur
        return res
