"""Passive DNS history plugin (hunter source plugin).

Current DNS only shows where a domain points NOW. Passive DNS
datasets remember where it pointed before: AlienVault OTX passive DNS
records and ThreatCrowd resolution history, both free and keyless.

That history is expansion fuel the live-DNS plugins cannot produce:
- historical IPs (old hosting, pre-CDN origin addresses) -> emitted
  as "passive_ip" findings, which the hunter engine turns into ip
  assets (ports, banners, reverse-IP neighbours);
- hostnames seen in history that live DNS no longer returns ->
  "subdomain" findings;
- CNAME targets in history -> "passive_host" findings, promoted to
  domain assets (chains that reveal the real hosting platform).

No packets to the target: the queries go to the datasets. Detection
only.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Dict, List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_IPS = 200
MAX_HOSTS = 300


def _as_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return ""


def parse_otx_domain_passive(data, domain: str) -> Dict[str, List[str]]:
    """OTX passive_dns for a domain -> {ips, hosts, cname_targets}."""
    out = {"ips": [], "hosts": [], "cname_targets": []}
    if not isinstance(data, dict):
        return out
    ips: Set[str] = set()
    hosts: Set[str] = set()
    cnames: Set[str] = set()
    for rec in data.get("passive_dns", []) or []:
        host = (rec.get("hostname") or "").strip().lower().rstrip(".")
        addr = (rec.get("address") or "").strip().lower().rstrip(".")
        rtype = (rec.get("record_type") or "").upper()
        if host and host != domain and host.endswith(domain):
            hosts.add(host)
        if rtype in ("A", "AAAA"):
            ip = _as_ip(addr)
            if ip:
                ips.add(ip)
        elif rtype == "CNAME" and addr and not _as_ip(addr):
            cnames.add(addr)
    out["ips"] = sorted(ips)
    out["hosts"] = sorted(hosts)
    out["cname_targets"] = sorted(cnames)
    return out


def parse_threatcrowd_domain(data) -> Dict[str, List[str]]:
    """ThreatCrowd domain report -> {ips, hosts} from resolutions and
    the subdomain list."""
    out = {"ips": [], "hosts": []}
    if not isinstance(data, dict):
        return out
    ips: Set[str] = set()
    hosts: Set[str] = set()
    for res in data.get("resolutions", []) or []:
        ip = _as_ip(str(res.get("ip_address") or ""))
        if ip:
            ips.add(ip)
    for sub in data.get("subdomains", []) or []:
        host = str(sub).strip().lower().rstrip(".")
        if host:
            hosts.add(host)
    out["ips"] = sorted(ips)
    out["hosts"] = sorted(hosts)
    return out


class PassiveDnsPlugin(Plugin):
    id = "passive_dns"
    label = "Passive DNS History"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Historical DNS from AlienVault OTX + ThreatCrowd: "
                   "past IPs, vanished hostnames, CNAME chains. "
                   "Keyless, passive.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        async def gather_all():
            merged = {"ips": [], "hosts": [], "cname_targets": []}
            seen_ip: Set[str] = set()
            seen_host: Set[str] = set()
            seen_cname: Set[str] = set()

            def merge(part: Dict[str, List[str]]):
                for ip in part.get("ips", []):
                    if ip not in seen_ip:
                        seen_ip.add(ip)
                        merged["ips"].append(ip)
                for h in part.get("hosts", []):
                    if h not in seen_host:
                        seen_host.add(h)
                        merged["hosts"].append(h)
                for c in part.get("cname_targets", []):
                    if c not in seen_cname:
                        seen_cname.add(c)
                        merged["cname_targets"].append(c)

            try:
                resp = await fetch(
                    ctx.http, ctx.limiter, "GET",
                    "https://otx.alienvault.com/api/v1/indicators/domain/"
                    f"{quote(domain)}/passive_dns", timeout=25)
                if resp.status_code == 200:
                    merge(parse_otx_domain_passive(resp.json(), domain))
            except Exception:
                pass
            try:
                resp = await fetch(
                    ctx.http, ctx.limiter, "GET",
                    "https://www.threatcrowd.org/searchApi/v2/domain/"
                    f"report/?domain={quote(domain)}", timeout=25)
                if resp.status_code == 200:
                    merge(parse_threatcrowd_domain(resp.json()))
            except Exception:
                pass
            return merged

        data, _ = await ctx.cache.cached("pdns", domain, gather_all)
        if not isinstance(data, dict):
            data = {"ips": [], "hosts": [], "cname_targets": []}

        findings: List[Finding] = []
        for ip in (data.get("ips") or [])[:MAX_IPS]:
            findings.append(self._f(
                "dns", "passive_ip", ip,
                source="passive DNS history (OTX/ThreatCrowd)",
                source_url=("https://otx.alienvault.com/indicator/domain/"
                            f"{domain}"),
                confidence=70, passive=True,
                evidence={"domain": domain,
                          "remediation": "Historical IPs may expose the "
                                         "origin behind a CDN or retired "
                                         "hosting that still serves the "
                                         "site. Verify each is "
                                         "intentional and hardened."}))
        for host in (data.get("hosts") or [])[:MAX_HOSTS]:
            ctx.publish("subdomains", host)
            findings.append(self._f(
                "dns", "subdomain", host,
                source="passive DNS history (OTX/ThreatCrowd)",
                source_url=("https://otx.alienvault.com/indicator/domain/"
                            f"{domain}"),
                confidence=70, passive=True))
        for cname in (data.get("cname_targets") or [])[:MAX_HOSTS]:
            findings.append(self._f(
                "dns", "passive_host", cname,
                source="passive DNS history (OTX/ThreatCrowd)",
                confidence=65, passive=True,
                evidence={"domain": domain,
                          "remediation": "CNAME chains reveal the real "
                                         "hosting platform; an unclaimed "
                                         "target is a subdomain-takeover "
                                         "candidate."}))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"passive DNS: {len(data.get('ips') or [])} "
                       f"historical IPs, {len(data.get('hosts') or [])} "
                       f"hosts, {len(data.get('cname_targets') or [])} "
                       f"CNAME targets for {domain}")
        res.duration_ms = dur
        return res
