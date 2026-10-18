"""Exposed database detector (Milestone: critical findings).

Non-destructive: HTTP-based databases get a single read-only GET /
(Elasticsearch, CouchDB). For binary-protocol databases we only check
TCP reachability and grab a banner if the server volunteers one - we
never authenticate, never run commands. An internet-reachable DB port
is itself the finding. Authorized testing only.
"""
from __future__ import annotations

import asyncio
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (port, name, http_check_path or None, remediation)
DBS = [
    (27017, "MongoDB", None,
     "Bind to localhost or VPN only, enable authentication, never expose 27017 to the internet."),
    (6379, "Redis", None,
     "Bind to localhost, set requirepass, disable dangerous commands, never expose 6379."),
    (9200, "Elasticsearch", "/",
     "Enable X-Pack security, bind to localhost, put behind auth proxy. Open ES = full data read."),
    (5984, "CouchDB", "/",
     "Set require_valid_user, bind to localhost. Open CouchDB allows DB creation."),
    (3306, "MySQL", None,
     "Bind to localhost, use strong passwords, never expose 3306 to the internet."),
    (5432, "PostgreSQL", None,
     "Bind to localhost, enforce SCRAM auth, never expose 5432 to the internet."),
    (1433, "MSSQL", None,
     "Bind to localhost or VPN, disable sa or set a strong password."),
    (8086, "InfluxDB", "/ping",
     "Enable auth, bind to localhost. Open InfluxDB allows arbitrary writes."),
]


class DbPlugin(Plugin):
    id = "db"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "Exposed Databases"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = "Check if database ports are internet-reachable (no auth attempted)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        host = domain or (target.normalized if target.type == "ip" else None)
        if not host:
            return self._skipped("no host for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (TCP connects)")
        findings: List[Finding] = []

        async def check_one(port: int, name: str, http_path, remed):
            """Check one DB port. Returns a finding or None."""
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=6)
                w.close()
            except Exception:
                return None
            detail = f"port {port} is reachable from the internet"
            conf = 80
            if http_path is not None:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET",
                                    f"http://{host}:{port}{http_path}", timeout=10)
                    if r.status_code < 500:
                        body = r.text[:200]
                        detail += f" and responds to HTTP GET {http_path} ({r.status_code})"
                        conf = 95
                        if "cluster_name" in body or "version" in body:
                            detail += " - version info disclosed"
                except Exception:
                    pass
            return self._f(
                "infra", "exposed_database",
                f"CRITICAL: {name} {detail}. Verify authentication is enforced.",
                source="db port check", confidence=conf, passive=False,
                evidence={"severity": "critical", "service": name, "port": port,
                          "remediation": remed,
                          "scope_note": "Authorized testing only. No auth attempted, no commands run."})

        # All 8 ports concurrently: sequential 8x6s timeouts become one 6s window.
        # Same checks, same findings, fraction of the time.
        results = await asyncio.gather(
            *[check_one(port, name, http_path, remed)
              for port, name, http_path, remed in DBS])
        findings.extend([f for f in results if f])

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} exposed databases")
        res.duration_ms = dur
        return res
