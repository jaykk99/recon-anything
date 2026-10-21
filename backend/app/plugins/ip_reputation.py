"""IP reputation check plugin (DNSBL).

Looks up the target's public IP(s) against major DNS blocklists
(Spamhaus ZEN, Barracuda, SpamCop) via standard DNS queries - the same
lookups every mail server does. A listing means the IP was seen
sending spam or hosting malware; it kills email deliverability and is
a compromise indicator.

Detection only: DNS TXT/A queries to public blocklist zones. No
packets to the target beyond normal resolution.
"""
from __future__ import annotations

import asyncio
import time
from typing import List

import dns.asyncresolver

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

# zone -> (friendly name, info URL)
DNSBLS = {
    "zen.spamhaus.org": ("Spamhaus ZEN",
                         "https://www.spamhaus.org/query/ip/"),
    "b.barracudacentral.org": ("Barracuda",
                                "https://www.barracudacentral.org/lookups"),
    "bl.spamcop.net": ("SpamCop", "https://www.spamcop.net/w3m?action=blcheck"),
    "dnsbl.sorbs.net": ("SORBS", "https://www.sorbs.net/lookup.shtml"),
}


def _reversed_ip(ip: str) -> str | None:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(reversed(parts))
    return None


class IpReputationPlugin(Plugin):
    id = "ip_reputation"
    label = "IP Reputation (DNSBL)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Check the target's IPs against Spamhaus, Barracuda, "
                   "SpamCop and SORBS blocklists.")
    timeout_s = 90

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
            ans = await res.resolve(domain, "A")
            ips = list({str(rr) for rr in ans})[:4]
        except Exception:
            return self._degraded("no A records to check")
        findings: List = []
        listed_any = False

        async def _check(ip: str, zone: str):
            rev = _reversed_ip(ip)
            if not rev:
                return None
            try:
                q = f"{rev}.{zone}"
                ans = await res.resolve(q, "A")
                txt = ""
                try:
                    tans = await res.resolve(q, "TXT")
                    txt = " ".join(str(rr).strip('"')
                                   for rr in tans)[:200]
                except Exception:
                    pass
                return (zone, [str(rr) for rr in ans], txt)
            except Exception:
                return None

        for ip in ips:
            results = await asyncio.gather(
                *(_check(ip, z) for z in DNSBLS))
            for hit in results:
                if not hit:
                    continue
                listed_any = True
                zone, codes, txt = hit
                name, url = DNSBLS[zone]
                findings.append(self._f(
                    "network", "ip_blocklisted",
                    f"{ip} is listed on {name} ({zone})",
                    source="DNSBL check", confidence=90, passive=True,
                    evidence={"severity": "medium", "ip": ip,
                              "blocklist": name, "codes": codes[:4],
                              "detail": txt,
                              "lookup": f"{url}{ip}",
                              "remediation": (
                                  f"Investigate why {ip} was listed "
                                  "(compromised host sending spam/malware is "
                                  "the common cause), clean it, then request "
                                  f"delisting via {url}.")}))
        if not listed_any:
            findings.append(self._f(
                "network", "ip_reputation_clean",
                f"{', '.join(ips)}: not listed on {len(DNSBLS)} major "
                "blocklists",
                source="DNSBL check", confidence=85, passive=True,
                evidence={"severity": "low", "ips": ips,
                          "remediation": "Informational: no action."}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"checked {len(ips)} IPs against {len(DNSBLS)} "
                   f"blocklists, {len(findings)} findings")
