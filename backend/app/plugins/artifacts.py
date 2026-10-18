"""Exposed-artifact probing plugin (Milestone 3).

Passive mode: looks up each sensitive path in the Wayback Machine
(no packets to the target). Active mode: probes the paths directly.
Probes are read-only GETs of well-known sensitive files.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

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
]


class ArtifactsPlugin(Plugin):
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
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        if mode == "passive":
            # Wayback lookup per path: zero packets to the target
            for path, label, conf in PATHS:
                full = base + path
                url = ("https://web.archive.org/cdx/search/cdx?url="
                       + quote(full, safe="") + "&output=json&fl=timestamp,statuscode&limit=1")
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
                    if r.status_code == 200:
                        data = r.json()
                        if isinstance(data, list) and len(data) > 1:
                            ts = data[1][0] if len(data[1]) > 0 else ""
                            findings.append(self._f(
                                "leak", "artifact_archived",
                                f"{path} was archived ({ts}) - {label}",
                                source="Wayback CDX",
                                source_url=f"https://web.archive.org/web/{ts}/{full}",
                                confidence=conf - 15, passive=True))
                except Exception:
                    continue
        else:
            for path, label, conf in PATHS:
                full = base + path
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=12)
                    if r.status_code == 200 and len(r.text.strip()) > 0:
                        body = r.text[:300]
                        # sanity: skip generic 200 pages for odd paths
                        if path == "/.git/config" and "[core]" not in r.text:
                            continue
                        if path == "/.env" and "=" not in r.text:
                            continue
                        findings.append(self._f(
                            "leak", "artifact_exposed",
                            f"{path} returned 200 - {label}: {body[:150]}",
                            source="direct probe", source_url=full,
                            confidence=conf, passive=False))
                    elif r.status_code in (401, 403):
                        findings.append(self._f(
                            "web", "artifact_guarded",
                            f"{path} returned {r.status_code} (exists but guarded)",
                            source="direct probe", source_url=full,
                            confidence=60, passive=False))
                except Exception:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(PATHS)} paths ({mode})")
        res.duration_ms = dur
        return res
