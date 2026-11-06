"""rustscan-style adaptive-timeout fast port scan (native, keyless).

First pass: aggressive concurrency with a short timeout over a
curated port list on the target's own IPs. Ports that time out
(filtered or just slow) are retried once with a longer timeout -
rustscan's adaptive trick - so slow services are not missed. Open
ports get a banner grab. Target's own resolved IPs only.
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Tuple

from ._tier2_common import (RISKY_PORTS, SERVICE_LABELS, host_of,
                            resolve_ips, tcp_banner)
from .base import Cost, Ctx, Plugin, PluginResult, Target

SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 587, 993, 995, 1433, 1521, 1883, 2049, 2375, 2376, 3000,
    3128, 3306, 3389, 5432, 5900, 5984, 6379, 8000, 8080, 8443, 8500,
    8888, 9000, 9090, 9200, 10000, 11211, 15672, 27017,
]


class RustscanPlugin(Plugin):
    id = "rustscan"
    label = "rustscan Adaptive Scan"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    timeout_s = 120
    description = ("Adaptive-timeout fast port scan: aggressive first "
                   "pass, longer-timeout retry for slow ports, banner "
                   "grab on open ports. Target's own IPs only.")

    async def _sweep(self, pairs, timeout, concurrency):
        sem = asyncio.Semaphore(concurrency)

        async def one(ip, port):
            async with sem:
                state, banner = await tcp_banner(
                    ip, port, timeout=timeout, read_len=256)
                return (ip, port, state, banner)

        return await asyncio.gather(*[one(ip, p) for ip, p in pairs])

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
        pairs = [(ip, p) for ip in ips for p in SCAN_PORTS]
        first = await self._sweep(pairs, timeout=0.8, concurrency=64)
        timed_out = [(ip, p) for ip, p, s, _b in first if s == "timeout"]
        retried = 0
        by_pair: Dict[Tuple[str, int], Tuple[str, str]] = {
            (ip, p): (s, b) for ip, p, s, b in first}
        if timed_out:
            second = await self._sweep(timed_out, timeout=2.5,
                                       concurrency=16)
            retried = len(timed_out)
            for ip, p, s, b in second:
                by_pair[(ip, p)] = (s, b)
        findings = []
        for (ip, port), (state, banner) in sorted(by_pair.items()):
            if state != "open":
                continue
            label = SERVICE_LABELS.get(port, "unknown")
            clean = " ".join((banner or "").split())[:100]
            findings.append(self._f(
                "infra", "rustscan_open_port",
                f"{ip}:{port} ({label}) open on {host}"
                + (f" - {clean}" if clean else ""),
                source="rustscan adaptive scan", confidence=92,
                passive=False,
                evidence={"severity": "medium" if port in RISKY_PORTS
                          else "low",
                          "ip": ip, "port": port, "service": label,
                          "banner": clean,
                          "remediation": "Close unneeded ports at the "
                                         "firewall; restrict data and "
                                         "management services to "
                                         "trusted IPs or a VPN."}))
            ctx.publish("endpoints", f"{ip}:{port}")
        res = self._ok(findings,
                       f"scanned {len(SCAN_PORTS)} ports x {len(ips)} IPs "
                       f"({retried} retried slow), {len(findings)} open")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
