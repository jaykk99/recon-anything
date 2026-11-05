"""zmap-style single-port sweep across the target's own IP set (native).

IMPORTANT SCOPE NOTE: real zmap sweeps the whole internet. This
plugin does NOT. It sweeps exactly one well-known port across only
the IPs the target itself resolves to (multi-IP targets: CDNs,
round-robin DNS, dual-stack) and reports which of the target's own
addresses answer on that port. Nothing outside the target's resolved
IP set is ever probed.
"""
from __future__ import annotations

import asyncio
import time
from typing import List

from ._tier2_common import SERVICE_LABELS, host_of, resolve_ips, tcp_state
from .base import Cost, Ctx, Plugin, PluginResult, Target

SWEEP_PORTS = [443, 80]


class ZmapPlugin(Plugin):
    id = "zmap"
    label = "zmap IP Sweep (target-scoped)"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    timeout_s = 60
    description = ("Single-port fast sweep across the target's OWN "
                   "resolved IP set only (multi-IP targets). Not an "
                   "internet-wide sweep.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = host_of(target)
        if not host:
            return self._skipped("no host for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("port sweeps need active mode")
        ips = await resolve_ips(host, cap=8)
        if not ips:
            res = self._degraded(f"could not resolve {host}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings = []
        for port in SWEEP_PORTS:
            states = await asyncio.gather(
                *[tcp_state(ip, port, timeout=1.2) for ip in ips])
            answering = [ip for ip, s in zip(ips, states) if s == "open"]
            for ip in answering:
                findings.append(self._f(
                    "infra", "zmap_hit",
                    f"{ip}:{port} ({SERVICE_LABELS.get(port, 'tcp')}) "
                    f"answers for {host}",
                    source="zmap target-scoped sweep", confidence=92,
                    passive=False,
                    evidence={"severity": "low", "ip": ip, "port": port,
                              "answering_ips": answering,
                              "total_ips": len(ips),
                              "remediation": "Informational: every "
                                             "address a name resolves to "
                                             "should serve the same "
                                             "hardened configuration."}))
            if len(ips) > 1 and answering and len(answering) < len(ips):
                findings.append(self._f(
                    "infra", "zmap_partial_coverage",
                    f"Only {len(answering)}/{len(ips)} IPs for {host} "
                    f"answer on port {port}: "
                    f"{', '.join(answering)}",
                    source="zmap target-scoped sweep", confidence=85,
                    passive=False,
                    evidence={"severity": "low", "port": port,
                              "answering_ips": answering,
                              "total_ips": len(ips),
                              "remediation": "Check for inconsistent "
                                             "backends behind round-robin "
                                             "DNS; a stale node may run "
                                             "different software."}))
        res = self._ok(findings,
                       f"swept {len(SWEEP_PORTS)} ports x {len(ips)} "
                       f"target IPs, {len(findings)} findings")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
