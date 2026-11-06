"""naabu-style fast TCP connect port scan (native, keyless).

Curated top-ports list scanned against the target's OWN resolved IPs
only - never a range, never third-party addresses. Short timeouts,
bounded concurrency. Open ports are reported with their service label;
dangerous services (telnet, docker, redis, mongo, databases, RDP/VNC)
rate a medium severity, the rest low.
"""
from __future__ import annotations

import time
from typing import List

from ._tier2_common import (RISKY_PORTS, SERVICE_LABELS, host_of,
                            resolve_ips, tcp_state)
from .base import Cost, Ctx, Plugin, PluginResult, Target

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 587, 631, 993, 995, 1433, 1521, 1723, 1883, 2049, 2375,
    3000, 3128, 3306, 3389, 5060, 5432, 5900, 6379, 8000, 8080,
    8443, 8500, 8888, 9000, 9090, 9200, 10000, 11211, 27017,
]


class NaabuPlugin(Plugin):
    id = "naabu"
    label = "naabu Port Scan"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    timeout_s = 90
    description = ("Fast TCP connect scan of a curated top-ports list "
                   "on the target's own IPs, with service labels.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = host_of(target)
        if not host:
            return self._skipped("no host for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("port scans need active mode")
        ips = await resolve_ips(host, cap=4)
        if not ips:
            res = self._degraded(f"could not resolve {host}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        import asyncio
        sem = asyncio.Semaphore(40)

        async def probe(ip, port):
            async with sem:
                return await tcp_state(ip, port, timeout=1.2)

        findings = []
        tasks = {}
        for ip in ips:
            for port in TOP_PORTS:
                tasks[(ip, port)] = asyncio.ensure_future(probe(ip, port))
        for (ip, port), task in tasks.items():
            try:
                state = await task
            except Exception:
                state = "error"
            if state != "open":
                continue
            label = SERVICE_LABELS.get(port, "unknown")
            risky = port in RISKY_PORTS
            findings.append(self._f(
                "infra", "naabu_open_port",
                f"{ip}:{port} ({label}) open on {host}",
                source="naabu tcp connect", confidence=92, passive=False,
                evidence={
                    "severity": "medium" if risky else "low",
                    "ip": ip, "port": port, "service": label,
                    "remediation": "Close this port at the firewall if "
                                   "it is not intentionally public; "
                                   "restrict management/data services to "
                                   "trusted IPs or a VPN."}))
            ctx.publish("endpoints", f"{ip}:{port}")
        findings.sort(key=lambda f: f.evidence.get("port", 0))
        res = self._ok(findings,
                       f"scanned {len(TOP_PORTS)} ports x {len(ips)} IPs, "
                       f"{len(findings)} open")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
