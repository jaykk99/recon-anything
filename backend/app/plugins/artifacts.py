"""Exposed-artifact probing plugin (Milestone 3).

Passive mode: looks up each sensitive path in the Wayback Machine
(no packets to the target). Active mode: probes the paths directly.
Probes are read-only GETs of well-known sensitive files.
"""
from __future__ import annotations

import asyncio
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .wayback import fetch_cdx

PATHS = [
    # version control
    ("/.git/config", "git repo exposed", 95),
    ("/.git/HEAD", "git repo exposed", 95),
    ("/.git/logs/HEAD", "git reflog exposed", 90),
    ("/.git/index", "git index exposed", 88),
    ("/.svn/entries", "svn metadata exposed", 90),
    ("/.svn/wc.db", "svn db exposed", 88),
    ("/.hg/requires", "mercurial repo exposed", 85),
    ("/.bzr/branch.conf", "bazaar repo exposed", 80),
    # env / secrets
    ("/.env", "env file exposed", 95),
    ("/.env.bak", "env backup exposed", 90),
    ("/.env.old", "env backup exposed", 90),
    ("/.env.orig", "env backup exposed", 88),
    ("/.env.local", "env file exposed", 90),
    ("/.env.production", "env file exposed", 90),
    ("/.env.development", "env file exposed", 90),
    ("/.env.staging", "env file exposed", 90),
    ("/.env.save", "env backup exposed", 88),
    ("/.env~", "env backup exposed", 85),
    # cloud configs
    ("/.aws/credentials", "aws creds exposed?", 95),
    ("/.aws/config", "aws config exposed?", 85),
    ("/.azure/credentials", "azure creds exposed?", 90),
    # framework / app configs
    ("/web.config", "web.config exposed", 90),
    ("/wp-config.php.bak", "wp config backup?", 90),
    ("/wp-config.php~", "wp config backup?", 90),
    ("/wp-config.php.old", "wp config backup?", 90),
    ("/wp-config.php.orig", "wp config backup?", 88),
    ("/wp-config.php.save", "wp config backup?", 88),
    ("/config.php.bak", "config backup?", 85),
    ("/config.php~", "config backup?", 85),
    ("/config.php.old", "config backup?", 85),
    ("/configuration.php.bak", "joomla config backup?", 85),
    ("/settings.py.bak", "django settings backup?", 85),
    ("/settings.php.bak", "settings backup?", 85),
    ("/application.properties.bak", "spring config backup?", 85),
    ("/.htaccess", "htaccess exposed?", 85),
    ("/.htpasswd", "htpasswd exposed?", 90),
    # database dumps
    ("/backup.sql", "backup file?", 80),
    ("/db.sql", "database dump?", 85),
    ("/dump.sql", "database dump?", 85),
    ("/database.sql", "database dump?", 85),
    ("/backup.db", "database file?", 85),
    ("/dump.db", "database file?", 85),
    ("/data.sqlite", "sqlite db exposed?", 88),
    ("/db.sqlite", "sqlite db exposed?", 88),
    ("/database.sqlite", "sqlite db exposed?", 88),
    ("/backup.dump", "db dump?", 80),
    # backups / archives
    ("/backup.zip", "backup archive?", 75),
    ("/backup.tar.gz", "backup archive?", 75),
    ("/backup.tgz", "backup archive?", 75),
    ("/site.zip", "site archive?", 75),
    ("/www.zip", "site archive?", 75),
    ("/backup.bak", "backup file?", 80),
    ("/index.php.bak", "index backup?", 80),
    ("/index.php.old", "index backup?", 80),
    ("/index.php~", "index backup?", 78),
    ("/index.html.bak", "index backup?", 78),
    # logs
    ("/access.log", "access log exposed?", 85),
    ("/error.log", "error log exposed?", 85),
    ("/error_log", "error log exposed?", 85),
    ("/debug.log", "debug log exposed?", 85),
    ("/php_error.log", "php error log?", 85),
    ("/logs/access.log", "access log exposed?", 80),
    # debug / info
    ("/phpinfo.php", "phpinfo exposed", 90),
    ("/info.php", "phpinfo exposed", 90),
    ("/server-status", "server status exposed", 85),
    ("/server-info", "server info exposed", 85),
    ("/debug", "debug endpoint?", 70),
    ("/console", "console endpoint?", 70),
    ("/actuator", "spring actuator?", 85),
    ("/actuator/health", "spring actuator?", 85),
    ("/actuator/env", "spring actuator env?", 90),
    ("/actuator/beans", "spring actuator beans?", 85),
    ("/_profiler", "symfony profiler?", 85),
    # CI/CD
    ("/.github/workflows/main.yml", "github workflow exposed?", 70),
    ("/.gitlab-ci.yml", "gitlab ci config?", 80),
    ("/Jenkinsfile", "jenkinsfile exposed?", 80),
    ("/.travis.yml", "travis config?", 75),
    ("/circle.yml", "circleci config?", 75),
    ("/.circleci/config.yml", "circleci config?", 75),
    # docker
    ("/Dockerfile", "dockerfile exposed?", 80),
    ("/docker-compose.yml", "compose file exposed?", 80),
    ("/docker-compose.yaml", "compose file exposed?", 80),
    ("/.dockerignore", "dockerignore exposed?", 60),
    # package managers
    ("/package.json", "package.json exposed", 90),
    ("/package-lock.json", "package lock exposed", 70),
    ("/composer.json", "composer.json exposed", 90),
    ("/composer.lock", "composer lock exposed", 70),
    ("/requirements.txt", "python requirements exposed", 80),
    ("/Gemfile", "gemfile exposed", 60),
    ("/Gemfile.lock", "gemfile lock exposed", 60),
    ("/yarn.lock", "yarn lock exposed", 60),
    ("/go.mod", "go.mod exposed", 70),
    # api docs
    ("/api/docs", "api docs exposed?", 70),
    ("/api/swagger", "swagger exposed?", 70),
    ("/swagger.json", "swagger json exposed?", 75),
    ("/openapi.json", "openapi spec exposed?", 75),
    ("/api-docs", "api docs exposed?", 70),
    ("/graphql", "graphql endpoint?", 70),
    ("/.well-known/openid-configuration", "openid config", 50),
    ("/.well-known/change-password", "well-known file", 40),
    ("/.well-known/security.txt", "security.txt found", 50),
    # admin panels
    ("/admin/", "admin panel?", 70),
    ("/administrator/", "admin panel?", 70),
    ("/wp-admin/", "wp admin?", 65),
    ("/wp-login.php", "wp login?", 65),
    ("/phpmyadmin/", "phpmyadmin?", 80),
    ("/pma/", "phpmyadmin?", 80),
    ("/adminer.php", "adminer?", 80),
    # misc
    ("/.DS_Store", "DS_Store exposed", 70),
    ("/robots.txt", "robots.txt found", 40),
    ("/sitemap.xml", "sitemap found", 40),
    ("/crossdomain.xml", "crossdomain policy", 60),
    ("/clientaccesspolicy.xml", "client access policy", 60),
    ("/security.txt", "security.txt found", 50),
    ("/humans.txt", "humans.txt found", 40),
    # more backups and swaps
    ("/index.php.bak", "index backup?", 85),
    ("/index.html.bak", "index backup?", 85),
    ("/default.php.bak", "default backup?", 80),
    ("/main.php.bak", "main backup?", 80),
    ("/app.php.bak", "app backup?", 80),
    ("/.gitignore", "gitignore exposed (info)", 40),
    ("/.gitlab-ci.yml", "gitlab CI config?", 75),
    ("/.github/workflows/main.yml", "github workflow?", 70),
    ("/Jenkinsfile", "jenkinsfile?", 75),
    ("/Dockerfile", "dockerfile exposed?", 70),
    ("/docker-compose.yml", "compose file?", 75),
    ("/docker-compose.yaml", "compose file?", 75),
    ("/package.json", "package.json exposed", 65),
    ("/package-lock.json", "lockfile exposed", 55),
    ("/composer.json", "composer.json exposed", 65),
    ("/composer.lock", "composer lock exposed", 55),
    ("/requirements.txt", "requirements exposed", 60),
    ("/Gemfile", "gemfile exposed", 60),
    ("/yarn.lock", "yarn lock exposed", 50),
    ("/CHANGELOG.md", "changelog (version intel)", 45),
    ("/README.md", "readme exposed", 40),
    ("/LICENSE", "license file", 35),
    ("/phpinfo.php", "phpinfo exposed!", 95),
    ("/info.php", "phpinfo exposed!", 95),
    ("/test.php", "test script?", 75),
    ("/debug.php", "debug script?", 80),
    ("/console", "symfony console?", 75),
    ("/_profiler", "symfony profiler?", 80),
    ("/server-status", "apache status?", 85),
    ("/server-info", "apache info?", 85),
    ("/.well-known/change-password", "change password well-known", 40),
    ("/.well-known/assetlinks.json", "assetlinks (app intel)", 50),
    ("/manifest.json", "web manifest", 45),
    ("/browserconfig.xml", "browserconfig", 40),
    ("/sitemap_index.xml", "sitemap index", 40),
    ("/wp-json/wp/v2/users", "wp users enum?", 85),
    ("/xmlrpc.php", "xmlrpc (wp attack surface)", 75),
    ("/.travis.yml", "travis config?", 70),
    ("/circle.yml", "circle config?", 70),
    ("/appveyor.yml", "appveyor config?", 65),
    ("/.editorconfig", "editorconfig", 35),
    ("/web.config.bak", "web.config backup?", 85),
    ("/.htpasswd", "htpasswd exposed!", 90),
    ("/.htpasswds", "htpasswd exposed!", 90),
    ("/passwd", "passwd-like file?", 80),
    ("/shadow", "shadow-like file?", 85),
]


class ArtifactsPlugin(Plugin):
    timeout_s = 90  # raised 2026-10-20: 30s cap truncated this enumerator mid-work (Jay: find more)
    id = "artifacts"
    label = "Exposed Artifacts"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Sensitive-file exposure check (Wayback in passive, direct probe in active)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        if mode == "passive":
            # Wayback lookup per path: zero packets to the target.
            # Reuses wayback.py's single wildcard CDX snapshot (cached
            # per-domain) instead of one CDX query per path: same archive
            # data, ~160 fewer requests to web.archive.org.
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
                    # keep the earliest snapshot per path
                    if p not in archived or r[ts_i] < archived[p]:
                        archived[p] = r[ts_i]
            for path, label, conf in PATHS:
                ts = archived.get(path)
                if not ts:
                    continue
                full = base + path
                findings.append(self._f(
                    "leak", "artifact_archived",
                    f"{path} was archived ({ts}) - {label}",
                    source="Wayback CDX",
                    source_url=f"https://web.archive.org/web/{ts}/{full}",
                    confidence=conf - 15, passive=True))
        else:
            # Concurrent direct probe: 165 paths, short timeout, one retry.
            # Uses ctx.probe: responses are shared per-run with backup.py
            # and hiddenpaths.py, so overlapping paths are fetched once.
            sem = asyncio.Semaphore(12)

            async def dprobe(item):
                path, label, conf = item
                full = base + path
                async with sem:
                    probed = await ctx.probe(full, timeout=8)
                status = probed["status"]
                if status == 200 and len(probed["text"].strip()) > 0:
                    body = probed["text"][:300]
                    # sanity: skip generic 200 pages for odd paths
                    if path == "/.git/config" and "[core]" not in probed["text"]:
                        return None
                    if path == "/.env" and "=" not in probed["text"]:
                        return None
                    return ("exposed", path, label, conf, full, body)
                elif status in (401, 403):
                    return ("guarded", path, label, conf, full, status)
                return None

            dprobed = await asyncio.gather(*[dprobe(p) for p in PATHS])
            for item in dprobed:
                if not item:
                    continue
                kind = item[0]
                if kind == "exposed":
                    _, path, label, conf, full, body = item
                    findings.append(self._f(
                        "leak", "artifact_exposed",
                        f"{path} returned 200 - {label}: {body[:150]}",
                        source="direct probe", source_url=full,
                        confidence=conf, passive=False))
                else:
                    _, path, label, conf, full, status = item
                    findings.append(self._f(
                        "web", "artifact_guarded",
                        f"{path} returned {status} (exists but guarded)",
                        source="direct probe", source_url=full,
                        confidence=60, passive=False))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(PATHS)} paths ({mode})")
        res.duration_ms = dur
        return res
