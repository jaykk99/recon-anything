"""IPv6 support check plugin.

Checks AAAA records and whether the host actually answers over IPv6
(TCP connect to port 443 on the AAAA address). Reports: IPv6-ready,
AAAA-without-connectivity (broken dual-stack), or IPv4-only.

Detection only: DNS lookups + TCP connects to the target's own web
port, the same as any browser would do.
"""
from __future__ import annotations

import asyncio
import socket
import time
from typing import List

import dns.asyncresolver

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target


def _probe(ip: str) -> bool:
    """TCP connect to port 443 on an IPv6 address. Module-level so tests
    can stub it; blocking, runs in a thread."""
    try:
        s = socket.create_connection((ip, 443), timeout=5)
        s.close()
        return True
    except Exception:
        return False


class Ipv6CheckPlugin(Plugin):
    id = "ipv6_check"
    label = "IPv6 Support"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("AAAA records + real IPv6 connectivity: ready, broken "
                   "dual-stack, or IPv4-only.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        res = dns.asyncresolver.Resolver(configure=False)
        res.nameservers = ["8.8.8.8", "1.1.1.1"]
        res.timeout = 6
        res.lifetime = 10
        try:
            ans = await res.resolve(domain, "AAAA")
            aaaa = [str(rr) for rr in ans]
        except Exception:
            aaaa = []
        findings: List = []
        if not aaaa:
            findings.append(self._f(
                "network", "ipv6_no_aaaa",
                f"{domain} has no AAAA records - IPv4-only",
                source="IPv6 check", confidence=95, passive=True,
                evidence={"severity": "low",
                          "remediation": ("Informational: add AAAA records if "
                                          "the hosting supports IPv6.")}))
        else:
            results = await asyncio.gather(
                *(asyncio.to_thread(_probe, ip) for ip in aaaa[:4]))
            ok = [ip for ip, good in zip(aaaa[:4], results) if good]
            if ok:
                findings.append(self._f(
                    "network", "ipv6_ready",
                    f"{domain} answers over IPv6 ({len(ok)}/{len(aaaa[:4])} "
                    "addresses reachable)",
                    source="IPv6 check", confidence=90, passive=True,
                    evidence={"severity": "low", "reachable": ok,
                              "remediation": "Informational: no action."}))
            else:
                findings.append(self._f(
                    "network", "ipv6_broken",
                    f"{domain} publishes AAAA records but nothing answers "
                    "on IPv6 port 443 - broken dual-stack",
                    source="IPv6 check", confidence=85, passive=True,
                    evidence={"severity": "medium", "aaaa": aaaa[:4],
                              "remediation": ("Fix the IPv6 path (firewall / "
                                              "server bind) or remove the "
                                              "AAAA records; broken AAAA "
                                              "causes timeouts for IPv6 "
                                              "clients.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"{len(aaaa)} AAAA records, {len(findings)} findings")
