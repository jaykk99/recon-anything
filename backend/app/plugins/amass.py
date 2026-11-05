"""Amass-style passive enumeration + ASN/org mapping (Tier-1 OSINT).

Native, keyless take on OWASP Amass's passive mode:
  1. Enumerate subdomains from certificate transparency (crt.sh) and
     HackerTarget hostsearch (same passive spirit as Amass intel).
  2. Resolve the domain and a sample of subdomains to IPs via
     DNS-over-HTTPS (dns.google).
  3. Attribute each IP to its owner org and ASN via keyless RDAP
     (rdap.org bootstrap -> authoritative registry), emitting
     asn_org findings Amass is known for.

Read-only public data only; no brute force, no scanning.
"""
from __future__ import annotations

import time
from typing import Dict, List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, \
    safe_json_dict, safe_json_list

MAX_RESOLVE = 12


def clean_subdomain(raw: str, domain: str) -> str:
    s = (raw or "").strip().lower()
    s = s.lstrip("*.")
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0].split(":")[0].strip(".")
    if not s or s == domain or not s.endswith("." + domain):
        return ""
    if "*" in s or " " in s or ".." in s:
        return ""
    return s


def parse_rdap_org(data: dict) -> Dict[str, str]:
    """Extract org / ASN / network name from an RDAP IP document."""
    out: Dict[str, str] = {}
    if not isinstance(data, dict):
        return out
    if data.get("name"):
        out["network"] = str(data["name"])
    if data.get("handle"):
        out["handle"] = str(data["handle"])
    for ent in data.get("entities", []) or []:
        if not isinstance(ent, dict):
            continue
        v = ent.get("vcardArray") or []
        if len(v) > 1 and isinstance(v[1], list):
            for item in v[1]:
                if isinstance(item, list) and len(item) > 3 \
                        and item[0] == "fn" and item[3]:
                    out.setdefault("org", str(item[3]))
        if ent.get("handle") and str(ent["handle"]).upper().startswith("AS"):
            out.setdefault("asn", str(ent["handle"]).upper())
    # Some registries expose origin ASNs as plain fields.
    for key in ("originAS", "origin_as", "asn"):
        if data.get(key):
            out.setdefault("asn", str(data[key]).upper())
    return out


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


class AmassPlugin(Plugin):
    timeout_s = 90
    id = "amass"
    label = "Amass Passive Enum + ASN Map"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Passive subdomain enumeration (CT + hostsearch) "
                   "with ASN/org attribution of resolved IPs via RDAP, "
                   "in the style of OWASP Amass passive mode.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        subs: Set[str] = set()

        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET",
                               f"https://crt.sh/?q=%25.{quote(domain)}"
                               f"&output=json", timeout=20, max_retries=1)
            if resp.status_code == 200:
                for row in safe_json_list(resp):
                    for field in ("name_value", "common_name"):
                        for name in str(row.get(field) or "").splitlines():
                            sub = clean_subdomain(name, domain)
                            if sub:
                                subs.add(sub)
        except Exception:
            pass
        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET",
                               f"https://api.hackertarget.com/hostsearch/"
                               f"?q={quote(domain)}", timeout=15,
                               max_retries=1)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    sub = clean_subdomain(line.split(",")[0], domain)
                    if sub:
                        subs.add(sub)
        except Exception:
            pass

        seen: Set[str] = set(ctx.consume("subdomains"))
        for sub in sorted(subs):
            if sub not in seen:
                ctx.publish("subdomains", sub)
                findings.append(self._f(
                    "dns", "subdomain", sub, source="amass/passive",
                    confidence=70, passive=True))

        # Resolve the apex + a sample of subdomains, attribute IPs.
        names = [domain] + sorted(subs)[:MAX_RESOLVE]
        ip_hosts: Dict[str, List[str]] = {}
        for name in names:
            for ip in await resolve_a(ctx, name):
                ip_hosts.setdefault(ip, []).append(name)
        for ip, hosts in sorted(ip_hosts.items()):
            info = await self._rdap_ip(ctx, ip)
            org = info.get("org") or info.get("network") or "unknown org"
            asn = info.get("asn", "")
            label = f"{ip} -> {org}" + (f" ({asn})" if asn else "")
            findings.append(self._f(
                "infra", "asn_org", label, source="amass/RDAP",
                source_url=f"https://rdap.org/ip/{ip}", confidence=80,
                passive=True,
                evidence={"ip": ip, "org": org, "asn": asn,
                          "hosts": hosts[:8], "severity": "low"}))
            self._checkpoint(findings)

        res = self._ok(findings, f"{len(subs)} subdomains, "
                                 f"{len(ip_hosts)} IPs attributed")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _rdap_ip(self, ctx: Ctx, ip: str) -> Dict[str, str]:
        for url in (f"https://rdap.org/ip/{quote(ip)}",
                    f"https://data.iana.org/rdap/ip/{quote(ip)}"):
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                                   timeout=15, max_retries=1,
                                   follow_redirects=True)
                if resp.status_code == 200:
                    info = parse_rdap_org(safe_json_dict(resp))
                    if info:
                        return info
            except Exception:
                continue
        return {}
