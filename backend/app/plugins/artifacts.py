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
    ("/.git/config", "git repo exposed", 95),
    ("/.git/HEAD", "git repo exposed", 95),
    ("/.env", "env file exposed", 95),
    ("/.env.bak", "env backup exposed", 90),
    ("/.env.local", "env file exposed", 90),
    ("/.env.production", "env file exposed", 90),
    ("/.svn/entries", "svn metadata exposed", 90),
    ("/.DS_Store", "DS_Store exposed", 70),
    ("/package.json", "package.json exposed", 90),
    ("/composer.json", "composer.json exposed", 90),
    ("/web.config", "web.config exposed", 90),
    ("/server-status", "server status exposed", 85),
    ("/phpinfo.php", "phpinfo exposed", 90),
    ("/.well-known/change-password", "well-known file", 40),
    ("/.well-known/security.txt", "security.txt found", 50),
    ("/backup.zip", "backup archive?", 75),
    ("/backup.tar.gz", "backup archive?", 75),
    ("/backup.sql", "backup file?", 80),
    ("/db.sql", "database dump?", 85),
    ("/dump.sql", "database dump?", 85),
    ("/database.sql", "database dump?", 85),
    ("/wp-config.php.bak", "wp config backup?", 90),
    ("/wp-config.php~", "wp config backup?", 90),
    ("/config.php.bak", "config backup?", 85),
    ("/config.php~", "config backup?", 85),
    ("/.aws/credentials", "aws creds exposed?", 95),
    ("/actuator", "spring actuator?", 85),
    ("/actuator/health", "spring actuator?", 85),
    ("/actuator/env", "spring actuator env?", 90),
    ("/debug", "debug endpoint?", 70),
    ("/console", "console endpoint?", 70),
    ("/robots.txt", "robots.txt found", 40),
    ("/sitemap.xml", "sitemap found", 40),
    ("/crossdomain.xml", "crossdomain policy", 60),
    ("/clientaccesspolicy.xml", "client access policy", 60),
    ("/.htaccess", "htaccess exposed?", 85),
    ("/.htpasswd", "htpasswd exposed?", 90),
    ("/Dockerfile", "dockerfile exposed?", 80),
    ("/docker-compose.yml", "compose file exposed?", 80),
    ("/yarn.lock", "yarn lock exposed", 60),
    ("/Gemfile", "gemfile exposed", 60),
    ("/api/docs", "api docs exposed?", 70),
    ("/api/swagger", "swagger exposed?", 70),
    ("/swagger.json", "swagger json exposed?", 75),
    ("/openapi.json", "openapi spec exposed?", 75),
    ("/graphql", "graphql endpoint?", 70),
    ("/.well-known/openid-configuration", "openid config", 50),
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
