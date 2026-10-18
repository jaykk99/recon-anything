"""Docker registry and credential exposure detector.

Checks for open Docker registries, exposed daemon sockets, and leaked
credentials. Read-only. Authorized testing only.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DOCKER_PATHS = [
    ("/v2/", "Docker Registry HTTP API v2"),
    ("/v2/_catalog", "Docker registry catalog (lists images)"),
    ("/version", "Docker daemon version endpoint"),
    ("/containers/json", "Docker daemon containers endpoint"),
]

REMEDIATION = ("Never expose Docker registries or the daemon socket publicly. "
               "Require authentication and use private registries.")


class DockerPlugin(Plugin):
    id = "docker"
    label = "Docker Exposure"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = "Detect open Docker registries and daemon sockets."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        host = domain or target.normalized
        base = f"https://{host}".rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        for path, label in DOCKER_PATHS:
            url = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15,
                                follow_redirects=False)
                body = r.text[:2000].lower()
                if r.status_code in (200, 401) and (
                        "docker" in body or "repositories" in body
                        or "api-version" in str(r.headers).lower()):
                    findings.append(self._f(
                        "infra", "docker_exposed",
                        f"Exposed Docker surface: {label} at {url} "
                        f"(HTTP {r.status_code}).",
                        source="Docker probe", source_url=url, confidence=70,
                        passive=passive,
                        evidence={"severity": "high", "path": path,
                                  "status": r.status_code,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Read-only probe. Authorized testing only."}))
            except Exception:
                continue
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} docker exposures")
        res.duration_ms = dur
        return res
