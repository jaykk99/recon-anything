"""ASN + infrastructure mapper (passive lookups, gentle port checks).

Looks up the target's ASN and announced prefix (keyless API), resolves the
target's own IPs, and checks web ports (80, 443, 8080, 8443) on those IPs
only. Flags staging/dev/login-looking hosts from the discovery bus.

Respectful: never scans whole ranges, only the target's resolved IPs.
TCP connect checks with short timeouts, rate-limited like everything else.
"""
from __future__ import annotations

import asyncio
import socket
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

WEB_PORTS = [80, 443, 8080, 8443]
PORT_LABELS = {80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt"}

INTERESTING_HOST_HINTS = ["staging", "stage", "dev", "development", "test",
                          "qa", "uat", "login", "auth", "sso", "admin",
                          "portal", "vpn", "internal", "corp", "beta"]

REMEDIATION_PORTS = ("Close unneeded ports at the firewall/security group. "
                     "Staging and dev hosts must not be internet-reachable; "
                     "put them behind VPN or IP allowlists.")


async def _tcp_check(ip: str, port: int, timeout: float = 4.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


class AsnScanPlugin(Plugin):
    id = "asn_scan"
    label = "ASN + Infra Map"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "ASN/prefix lookup and web-port check on the target's own IPs."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain and target.type != "ip":
            return self._skipped("no domain or ip for this target type")
        host = domain or target.normalized
        findings: List[Finding] = []

        # -- resolve target IPs (target's own IPs only) -------------------------
        ips: List[str] = []
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(
                host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            seen = set()
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
            ips = ips[:4]
        except Exception:
            pass
        if ips:
            findings.append(self._f(
                "infra", "target_ips",
                f"Target resolves to: {', '.join(ips)}",
                source="DNS", confidence=95, passive=True))

        # -- ASN + prefix lookup (keyless API) ------------------------------------
        if ips:
            try:
                r = await fetch(
                    ctx.http, ctx.limiter, "GET",
                    f"https://api.hackertarget.com/aslookup/?q={ips[0]}",
                    timeout=12)
                if r.status_code == 200 and "AS" in r.text:
                    line = r.text.strip().splitlines()[0][:160]
                    findings.append(self._f(
                        "infra", "asn_info",
                        f"ASN/prefix for {ips[0]}: {line}",
                        source="hackertarget aslookup",
                        source_url=f"https://api.hackertarget.com/aslookup/?q={ips[0]}",
                        confidence=85, passive=True))
            except Exception:
                pass

        # -- web port checks on the target's own IPs ------------------------------
        for ip in ips:
            open_ports = []
            for port in WEB_PORTS:
                if await _tcp_check(ip, port):
                    open_ports.append(port)
            if open_ports:
                labels = ", ".join(f"{p} ({PORT_LABELS[p]})" for p in open_ports)
                findings.append(self._f(
                    "infra", "web_ports_open",
                    f"Open web ports on {ip} ({host}): {labels}",
                    source="tcp connect", confidence=90, passive=False,
                    evidence={"severity": "low",
                              "remediation": REMEDIATION_PORTS}))

        # -- interesting hosts from the discovery bus --------------------------------
        subs = [s for s in ctx.consume("subdomains") if isinstance(s, str)]
        flagged = []
        for s in subs:
            low = s.lower()
            if any(h in low for h in INTERESTING_HOST_HINTS):
                flagged.append(s)
        for s in sorted(set(flagged))[:15]:
            findings.append(self._f(
                "infra", "interesting_host",
                f"Staging/dev/login-looking host: {s} - verify it is not "
                f"publicly reachable with weak auth",
                source="subdomain bus", source_url=f"https://{s}",
                confidence=70, passive=True,
                evidence={"severity": "medium",
                          "remediation": REMEDIATION_PORTS}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"mapped {len(ips)} IP(s), checked {len(WEB_PORTS)} ports each")
        res.duration_ms = dur
        return res
