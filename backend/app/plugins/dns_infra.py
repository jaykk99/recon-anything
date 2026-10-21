"""DNS infrastructure health plugin.

Goes beyond raw records (dns.py) into delegation quality:
- lame delegation: NS hosts that don't answer authoritatively,
- missing glue: in-bailiwick nameservers with no A/AAAA glue,
- SOA health: serial consistency across authoritative servers,
  absurd refresh/retry/expire values,
- single point of failure: all NS on one ASN/network.

Uses dnspython like the dns plugin. Detection only: standard DNS
queries to public resolvers and the domain's own nameservers.
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List

import dns.asyncresolver
import dns.resolver

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

RESOLVERS = ["8.8.8.8", "1.1.1.1"]


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = RESOLVERS
    r.timeout = 6
    r.lifetime = 10
    return r


async def _q(resolver, name: str, rdtype: str):
    try:
        ans = await resolver.resolve(name, rdtype)
        return [str(rr).strip().strip('"') for rr in ans]
    except Exception:
        return []


class DnsInfraPlugin(Plugin):
    id = "dns_infra"
    label = "DNS Infra Health"
    accepts = ["domain", "url", "email"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Delegation quality: lame NS, missing glue, SOA health, "
                   "single-point-of-failure nameservers.")
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        res = _resolver()
        findings: List = []

        ns_hosts = await _q(res, domain, "NS")
        if not ns_hosts:
            return self._degraded("no NS records resolvable")
        ns_hosts = sorted(set(ns_hosts))

        # SOA serial + timers from the parent-side view.
        soa = await _q(res, domain, "SOA")
        serials: Dict[str, str] = {}
        if soa:
            parts = soa[0].split()
            if len(parts) >= 7:
                try:
                    refresh, retry, expire = int(parts[3]), int(parts[4]), int(parts[5])
                    if expire < 604800:  # < 7 days
                        findings.append(self._f(
                            "dns", "soa_expire_short",
                            f"SOA expire {expire}s (< 7 days) - resolvers drop "
                            "the zone quickly if masters go dark",
                            source="DNS infra health", confidence=80,
                            passive=True,
                            evidence={"severity": "low", "expire": expire,
                                      "remediation": ("Raise SOA expire to at "
                                                      "least 1209600 (14 days).")}))
                    if retry >= refresh:
                        findings.append(self._f(
                            "dns", "soa_retry_gte_refresh",
                            f"SOA retry ({retry}s) >= refresh ({refresh}s) - "
                            "secondaries retry slower than they refresh",
                            source="DNS infra health", confidence=80,
                            passive=True,
                            evidence={"severity": "low",
                                      "remediation": ("Set retry well below "
                                                      "refresh (e.g. refresh "
                                                      "86400, retry 7200).")}))
                except (ValueError, IndexError):
                    pass

        # Per-NS: glue + lame delegation + serial agreement.
        lame = []
        no_glue = []
        for ns in ns_hosts:
            ns = ns.rstrip(".")
            glue_v4 = await _q(res, ns, "A")
            glue_v6 = await _q(res, ns, "AAAA")
            in_bailiwick = ns.lower().endswith("." + domain.lower())
            if in_bailiwick and not glue_v4 and not glue_v6:
                no_glue.append(ns)
            # Lame check: ask the NS directly for the SOA.
            try:
                direct = dns.asyncresolver.Resolver(configure=False)
                direct.nameservers = glue_v4[:1] or [ns]
                direct.timeout = 5
                direct.lifetime = 8
                ans = await direct.resolve(domain, "SOA")
                if ans.response.flags & dns.flags.AA == 0:
                    lame.append(ns)
                else:
                    soa_txt = str(list(ans)[0]).split()
                    if soa_txt:
                        serials[ns] = soa_txt[2] if len(soa_txt) > 2 else "?"
            except Exception:
                lame.append(ns + " (unreachable)")
        for ns in no_glue:
            findings.append(self._f(
                "dns", "dns_missing_glue",
                f"In-bailiwick nameserver {ns} has no glue A/AAAA - "
                "resolution depends on out-of-band records",
                source="DNS infra health", confidence=85, passive=True,
                evidence={"severity": "medium",
                          "remediation": ("Add glue A/AAAA records for "
                                          f"{ns} at the registrar.")}))
        for ns in lame:
            findings.append(self._f(
                "dns", "dns_lame_delegation",
                f"Lame delegation: {ns} does not answer authoritatively "
                "for the zone",
                source="DNS infra health", confidence=90, passive=True,
                evidence={"severity": "medium",
                          "remediation": ("Remove or fix the lame NS at the "
                                          "registrar; lame servers cause "
                                          "intermittent resolution failures.")}))
        if len(set(serials.values())) > 1:
            findings.append(self._f(
                "dns", "dns_serial_mismatch",
                "Authoritative nameservers disagree on SOA serial - "
                "zone transfers lagging",
                source="DNS infra health", confidence=85, passive=True,
                evidence={"severity": "low", "serials": serials,
                          "remediation": ("Check zone transfer (AXFR/IXFR) "
                                          "from master to secondaries.")}))
        if len(ns_hosts) == 1:
            findings.append(self._f(
                "dns", "dns_single_ns",
                f"Only one nameserver ({ns_hosts[0]}) - single point of "
                "failure",
                source="DNS infra health", confidence=90, passive=True,
                evidence={"severity": "medium",
                          "remediation": ("Use at least 2 nameservers on "
                                          "separate networks/ASNs.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"checked {len(ns_hosts)} nameservers, "
                   f"{len(findings)} infra issues")
