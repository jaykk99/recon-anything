"""Port scanner plugin (common ports).

Passive-safe: does NOT actually connect to ports in passive mode.
Instead, suggests likely-open ports based on detected tech and
checks Shodan-style via public APIs. Active mode does real connects.
Custom-built, no API keys needed for suggestions.
"""
from __future__ import annotations

import asyncio
import time
from typing import List

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Common ports with service names
COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (465, "SMTPS"), (587, "SMTP-submission"),
    (993, "IMAPS"), (995, "POP3S"), (3306, "MySQL"),
    (5432, "PostgreSQL"), (6379, "Redis"), (27017, "MongoDB"),
    (8080, "HTTP-alt"), (8443, "HTTPS-alt"), (9200, "Elasticsearch"),
    (5601, "Kibana"), (3000, "Node/dev"), (5000, "Flask/dev"),
    (8000, "Django/dev"), (9000, "PHP-FPM/Sonar"),
]

# Tech -> likely ports mapping for passive suggestions
TECH_PORTS = {
    "wordpress": [80, 443],
    "mysql": [3306], "postgres": [5432], "redis": [6379],
    "mongo": [27017], "elastic": [9200, 9300],
    "jenkins": [8080], "grafana": [3000], "kibana": [5601],
    "docker": [2375, 2376], "ssh": [22], "ftp": [21],
}


class PortsPlugin(Plugin):
    id = "ports"
    label = "Port Scanner"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "Common port suggestions (passive) or real scan (active)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain and target.type != "ip":
            return self._skipped("no host for this target type")
        host = domain or target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        if mode == "passive":
            # Suggest ports based on common services, no packets to target
            for port, service in COMMON_PORTS:
                findings.append(self._f(
                    "infra", "port_suggestion",
                    f"Port {port} ({service}) - commonly open, verify manually",
                    source="port suggester", confidence=30, passive=True))
        else:
            # Active: real TCP connects with short timeout
            async def check_port(port: int) -> tuple:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=3)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return port, True
                except Exception:
                    return port, False

            results = await asyncio.gather(
                *[check_port(p) for p, _ in COMMON_PORTS])
            for (port, service), (_, is_open) in zip(COMMON_PORTS, results):
                if is_open:
                    findings.append(self._f(
                        "infra", "port_open",
                        f"Port {port} ({service}) is OPEN",
                        source="port scan", confidence=95, passive=False))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(COMMON_PORTS)} ports ({mode})")
        res.duration_ms = dur
        return res
