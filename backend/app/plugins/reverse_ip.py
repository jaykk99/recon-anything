"""Reverse-IP / co-hosted domain discovery (hunter source plugin).

Given an IP, find the OTHER domains hosted on it from public passive
datasets: hackertarget reverse lookup, AlienVault OTX passive DNS for
the IP, and RapidDNS same-IP listings. All free, no API keys, and no
packets to the target itself - the queries go to the datasets.

Co-hosted domains are how one scanned IP turns into the rest of an
operator's footprint: shared hosting neighbours, forgotten sibling
brands, staging hosts on the same box. Each hit is emitted as a
"cohosted_domain" finding, which the hunter engine promotes into a
new domain asset for expansion. Detection only: this reads public
listings, it never probes the neighbours.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Dict, List, Set
from urllib.parse import quote

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24}$")
_HOST_IN_TEXT_RE = re.compile(r"([a-z0-9][a-z0-9.-]*\.[a-z]{2,24})")

MAX_DOMAINS = 300


def _valid_host(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if not host or len(host) > 253:
        return False
    if host.endswith(("rapiddns.io", "hackertarget.com",
                      "alienvault.com", "otx.alienvault.com")):
        return False
    return bool(_DOMAIN_RE.match(host))


def parse_hackertarget_reverse(text: str) -> Set[str]:
    """hackertarget reverseiplookup returns one domain per line (or an
    'error ...' line on quota/validation failure)."""
    out: Set[str] = set()
    for line in (text or "").splitlines():
        host = line.strip().lower().rstrip(".")
        if host.startswith(("error", "api count", "no records")):
            continue
        if _valid_host(host):
            out.add(host)
    return out


def parse_otx_ip_passive(data) -> Set[str]:
    """OTX passive_dns payload for an IP indicator: hostnames that have
    resolved to this address."""
    out: Set[str] = set()
    if not isinstance(data, dict):
        return out
    for rec in data.get("passive_dns", []) or []:
        host = (rec.get("hostname") or "").strip().lower().rstrip(".")
        if _valid_host(host):
            out.add(host)
    return out


def parse_rapiddns_sameip(html: str) -> Set[str]:
    """RapidDNS same-IP page: hostnames appear as subdomain links and
    table cells. Extract both shapes, keep valid hosts only."""
    out: Set[str] = set()
    text = html or ""
    for m in re.finditer(r"rapiddns\.io/subdomain/([a-z0-9.-]+\.[a-z]{2,24})",
                         text):
        if _valid_host(m.group(1)):
            out.add(m.group(1).lower())
    for m in re.finditer(r"<td[^>]*>\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,24})\s*</td>",
                         text):
        if _valid_host(m.group(1)):
            out.add(m.group(1).lower())
    return out


class ReverseIpPlugin(Plugin):
    id = "reverse_ip"
    label = "Reverse IP (Co-hosted Domains)"
    accepts = ["ip"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Co-hosted domains for an IP from hackertarget, "
                   "AlienVault OTX passive DNS and RapidDNS same-IP "
                   "listings. Keyless, passive.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        ip = (target.normalized or "").strip()
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return self._skipped(f"not an IP target: {ip!r}")
        is_v6 = parsed.version == 6

        async def gather_all():
            results: Dict[str, Set[str]] = {}

            async def from_hackertarget():
                if is_v6:
                    return  # endpoint is IPv4-only
                url = ("https://api.hackertarget.com/reverseiplookup/"
                       f"?q={quote(ip)}")
                try:
                    resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                                       timeout=25)
                    if resp.status_code == 200:
                        results["hackertarget"] = parse_hackertarget_reverse(
                            resp.text)
                except Exception:
                    pass

            async def from_otx():
                kind = "IPv6" if is_v6 else "IPv4"
                url = (f"https://otx.alienvault.com/api/v1/indicators/"
                       f"{kind}/{quote(ip)}/passive_dns")
                try:
                    resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                                       timeout=25)
                    if resp.status_code == 200:
                        results["otx"] = parse_otx_ip_passive(resp.json())
                except Exception:
                    pass

            async def from_rapiddns():
                url = f"https://rapiddns.io/sameip/{quote(ip)}?full=1"
                try:
                    resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                                       timeout=25)
                    if resp.status_code == 200:
                        results["rapiddns"] = parse_rapiddns_sameip(resp.text)
                except Exception:
                    pass

            await asyncio.gather(from_hackertarget(), from_otx(),
                                 from_rapiddns())
            # JSON-friendly shape for the cache layer
            return {src: sorted(hosts) for src, hosts in results.items()}

        data, _ = await ctx.cache.cached("revip", ip, gather_all)
        if not isinstance(data, dict):
            data = {}

        by_host: Dict[str, str] = {}
        for src, hosts in data.items():
            for host in hosts or []:
                by_host.setdefault(host, src)

        findings: List[Finding] = []
        for host in sorted(by_host)[:MAX_DOMAINS]:
            src = by_host[host]
            ctx.publish("domains", host)
            findings.append(self._f(
                "graph", "cohosted_domain", host,
                source=f"reverse IP via {src}",
                source_url=f"https://rapiddns.io/sameip/{ip}",
                confidence=70, passive=True,
                evidence={"ip": ip,
                          "remediation": "Review co-hosted domains on "
                                         "shared infrastructure: a weak "
                                         "neighbour can expose the whole "
                                         "box, and forgotten sibling "
                                         "sites are part of the real "
                                         "attack surface."}))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{len(findings)} co-hosted domains for {ip} "
                       f"from {len(data)} passive sources")
        res.duration_ms = dur
        return res
