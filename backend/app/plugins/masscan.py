"""masscan-style high-rate connect sweep (native, keyless).

A wider curated port list than naabu, swept in chunks with adaptive
concurrency: when a chunk comes back mostly timeouts (filtered /
slow host) the concurrency is halved so the sweep degrades politely
instead of hammering; when chunks answer fast it ramps back up.
Banner-lite: open ports get one short read of whatever the service
volunteers. Scope is still ONLY the target's own resolved IPs.
"""
from __future__ import annotations

import asyncio
import time
from typing import List

from ._tier2_common import (RISKY_PORTS, SERVICE_LABELS, host_of,
                            resolve_ips, tcp_banner)
from .base import Cost, Ctx, Plugin, PluginResult, Target

WIDE_PORTS = sorted(set([
    21, 22, 23, 25, 53, 69, 79, 80, 81, 88, 110, 111, 119, 123, 135,
    139, 143, 161, 179, 389, 427, 443, 445, 465, 514, 515, 548, 554,
    587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1883, 1900, 2000, 2049, 2121, 2375,
    2376, 2483, 2484, 3000, 3128, 3306, 3389, 4369, 4444, 5000, 5001,
    5060, 5432, 5555, 5631, 5632, 5672, 5900, 5984, 6006, 6379, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8088, 8118, 8443, 8500, 8888,
    9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9999, 10000,
    11211, 15672, 27017, 27018, 51820,
]))


class MasscanPlugin(Plugin):
    id = "masscan"
    label = "masscan Sweep"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    timeout_s = 120
    description = ("High-rate connect sweep over a wide curated port "
                   "list on the target's own IPs, adaptive concurrency, "
                   "banner-lite reads.")

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

        findings = []
        concurrency = 64
        chunk_size = 32
        pairs = [(ip, p) for ip in ips for p in WIDE_PORTS]
        for i in range(0, len(pairs), chunk_size):
            chunk = pairs[i:i + chunk_size]
            sem = asyncio.Semaphore(concurrency)

            async def probe(ip, port):
                async with sem:
                    return port, await tcp_banner(ip, port, timeout=1.0,
                                                  read_len=128)

            results = await asyncio.gather(
                *[probe(ip, p) for ip, p in chunk])
            states = {p: s for p, (s, _b) in
                      zip([p for _ip, p in chunk],
                          [(r[1][0], r[1][1]) for r in results])}
            timeouts = sum(1 for s in states.values() if s == "timeout")
            # Adapt: mostly-timeouts => slow/filtered host, back off.
            if timeouts > 0.8 * max(1, len(chunk)):
                concurrency = max(8, concurrency // 2)
            elif timeouts < 0.2 * len(chunk):
                concurrency = min(96, concurrency + 16)
            for (ip, port), (_p, (state, banner)) in zip(chunk, results):
                if state != "open":
                    continue
                label = SERVICE_LABELS.get(port, "unknown")
                clean = " ".join((banner or "").split())[:80]
                findings.append(self._f(
                    "infra", "masscan_open_port",
                    f"{ip}:{port} ({label}) open on {host}"
                    + (f" - banner: {clean}" if clean else ""),
                    source="masscan connect sweep", confidence=90,
                    passive=False,
                    evidence={
                        "severity": "medium" if port in RISKY_PORTS
                        else "low",
                        "ip": ip, "port": port, "service": label,
                        "banner": clean,
                        "remediation": "Close unneeded ports at the "
                                       "firewall; restrict data and "
                                       "management services to trusted "
                                       "IPs or a VPN."}))
                ctx.publish("endpoints", f"{ip}:{port}")
        findings.sort(key=lambda f: f.evidence.get("port", 0))
        res = self._ok(findings,
                       f"swept {len(WIDE_PORTS)} ports x {len(ips)} IPs, "
                       f"{len(findings)} open")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
