"""Shodan InternetDB lookup (Tier-1 OSINT).

Keyless-first: for each IP the target resolves to (and for direct IP
targets), query Shodan's free InternetDB (internetdb.shodan.io) -
open ports, CPEs, hostnames, tags and known CVE ids for that host.
No API key needed. When SHODAN_API_KEY is configured (key vault or
environment) the plugin notes that the richer host endpoint is
available, but the InternetDB path is the deliverable and always
runs. Passive third-party index data only; nothing is probed.
"""
from __future__ import annotations

import os
import time
from typing import List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, \
    safe_json_dict

MAX_IPS = 8
HIGH_PORTS = {22, 23, 3389, 5900, 6379, 27017, 9200, 2375}


def parse_internetdb(data: dict) -> dict:
    """InternetDB payload -> flat facts ({} when no data)."""
    if not isinstance(data, dict) or not data.get("ip"):
        return {}
    return {
        "ip": str(data.get("ip")),
        "ports": [int(p) for p in data.get("ports") or []
                  if str(p).isdigit()],
        "vulns": [str(v) for v in data.get("vulns") or []],
        "tags": [str(t) for t in data.get("tags") or []],
        "hostnames": [str(h) for h in data.get("hostnames") or []],
        "cpes": [str(c) for c in data.get("cpes") or []],
    }


async def resolve_a(ctx: Ctx, name: str) -> List[str]:
    try:
        resp = await fetch(
            ctx.http, ctx.limiter, "GET",
            f"https://dns.google/resolve?name={quote(name)}&type=A",
            timeout=20, max_retries=1,
            headers={"accept": "application/dns-json"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [str(a.get("data")) for a in data.get("Answer", [])
                if isinstance(a, dict) and a.get("type") == 1
                and a.get("data")]
    except Exception:
        return []


class ShodanLookupPlugin(Plugin):
    timeout_s = 60
    id = "shodan_lookup"
    label = "Shodan InternetDB Lookup"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Keyless Shodan InternetDB per resolved IP: open "
                   "ports, known CVEs, tags and hostnames. Optional "
                   "SHODAN_API_KEY enables the richer host endpoint.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        ips: List[str] = []
        if target.type == "ip":
            ips = [target.normalized.strip()]
        else:
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no domain or IP for this target type")
            seen: Set[str] = set()
            names = [domain] + list(ctx.consume("subdomains"))[:6]
            for name in names:
                for ip in await resolve_a(ctx, name):
                    if ip not in seen:
                        seen.add(ip)
                        ips.append(ip)
            ips = ips[:MAX_IPS]
        if not ips:
            return self._degraded("target did not resolve to any IP")

        findings: List[Finding] = []
        for ip in ips:
            facts = await self._internetdb(ctx, ip)
            if not facts:
                continue
            ports_txt = ", ".join(str(p) for p in facts["ports"]) or "none"
            findings.append(self._f(
                "infra", "shodan_host",
                f"{ip}: ports {ports_txt}",
                source="Shodan InternetDB",
                source_url=f"https://internetdb.shodan.io/{ip}",
                confidence=85, passive=True,
                evidence={"ip": ip, "ports": facts["ports"],
                          "hostnames": facts["hostnames"],
                          "tags": facts["tags"], "severity": "low"}))
            risky = [p for p in facts["ports"] if p in HIGH_PORTS]
            if risky:
                findings.append(self._f(
                    "infra", "exposed_service_port",
                    f"{ip}: sensitive port(s) open: "
                    f"{', '.join(str(p) for p in risky)}",
                    source="Shodan InternetDB",
                    source_url=f"https://internetdb.shodan.io/{ip}",
                    confidence=85, passive=True,
                    evidence={"ip": ip, "ports": risky,
                              "severity": "medium",
                              "remediation": "Restrict these services to "
                                             "trusted IPs or a VPN; they "
                                             "are indexed as internet-"
                                             "exposed."}))
            for cve in facts["vulns"][:10]:
                findings.append(self._f(
                    "infra", "known_cve", f"{ip}: {cve}",
                    source="Shodan InternetDB",
                    source_url=f"https://internetdb.shodan.io/{ip}",
                    confidence=80, passive=True,
                    evidence={"ip": ip, "cve": cve, "severity": "medium",
                              "remediation": "Patch the service on this "
                                             "host to a version without "
                                             f"{cve}, then re-scan."}))
            self._checkpoint(findings)

        note = f"{len(findings)} InternetDB findings for {len(ips)} IP(s)"
        if (ctx.keys.get("SHODAN_API_KEY")
                or os.environ.get("SHODAN_API_KEY")):
            note += "; SHODAN_API_KEY present (host endpoint available)"
        res = self._ok(findings, note)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _internetdb(self, ctx: Ctx, ip: str) -> dict:
        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET",
                               f"https://internetdb.shodan.io/{quote(ip)}",
                               timeout=25, max_retries=1)
            if resp.status_code != 200:
                return {}
            return parse_internetdb(safe_json_dict(resp))
        except Exception:
            return {}
