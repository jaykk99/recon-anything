"""Origin-IP discovery plugin (ported from ARTEX real_ip_discovery.py).

Finds the real server IP behind a CDN/WAF. A CDN hides the origin, but
the origin leaks through subdomain DNS, mail-server DNS, certificate-
transparency hostnames, and HTTP headers that disclose an IP. An exposed
origin lets an attacker bypass the CDN/WAF entirely, so this is a
high-value detection-only finding.

Ported from ARTEX (IlyassCODEX/ARTEX):
- modules/real_ip_discovery.py: the five discovery methods + confidence
  scoring (mail 10, headers 8, DNS 6, CT 4, subdomains 3; +5 per extra
  method; +10 if the IP answers TCP; threshold >= 8).
- core/constants.py: CDN CIDR ranges (Cloudflare/Akamai/Fastly/CloudFront)
  and IP-disclosure headers.
- core/ip_utils.py: public / non-CDN classification.

ARTEX fixes applied in the port: ARTEX's `_verify_ip_responds` blocks on
socket calls in the request thread; here it runs in the executor. ARTEX
verifies with `verify=False` requests; here DNS/TLS use the repo's own
clients. Nothing here attacks anything: DNS lookups, one crt.sh read,
one homepage fetch, TCP connects to see if a port answers.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from typing import Dict, List, Set

import dns.asyncresolver
import dns.exception

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# CDN CIDR ranges (ARTEX core/constants.py). An IP inside one of these is
# a CDN edge node, not the origin.
CDN_RANGES = {
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "akamai": [
        "23.0.0.0/8", "104.64.0.0/10", "184.24.0.0/13",
        "2.16.0.0/13", "23.32.0.0/11", "23.64.0.0/14",
        "96.16.0.0/15", "184.50.0.0/15", "184.84.0.0/14",
    ],
    "fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18",
    ],
    "amazon_cloudfront": [
        "13.32.0.0/15", "13.35.0.0/16", "52.222.128.0/17",
        "54.230.0.0/16", "54.239.128.0/18", "99.86.0.0/16",
        "204.246.164.0/22", "204.246.168.0/22", "71.152.0.0/17",
    ],
}

_CDN_NETWORKS = [
    (provider, ipaddress.ip_network(cidr))
    for provider, cidrs in CDN_RANGES.items() for cidr in cidrs
]

# Headers that sometimes disclose a backend IP (ARTEX core/constants.py).
IP_HEADERS = [
    "X-Real-IP", "X-Original-URL", "X-Forwarded-For",
    "X-Cluster-Client-IP", "X-Forwarded", "Forwarded-For",
    "Forwarded", "Client-IP", "X-Client-IP", "Via",
]

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Method reliability weights, straight from ARTEX _enhanced_filtering.
_METHOD_WEIGHTS = {
    "mail_servers": 10,
    "http_headers": 8,
    "dns_records": 6,
    "cert_transparency": 4,
    "subdomains": 3,
}
_MIN_SCORE = 8
_MAX_HOSTS_PER_METHOD = 30


def cdn_provider_for(ip: str) -> str | None:
    """Name the CDN whose range contains this IP, or None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for provider, net in _CDN_NETWORKS:
        if addr in net:
            return provider
    return None


def is_potentially_real_ip(ip: str) -> bool:
    """Public, non-CDN, non-reserved IP: a plausible origin candidate."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not addr.is_global:
        return False
    return cdn_provider_for(ip) is None


class OriginIpPlugin(Plugin):
    id = "origin_ip"
    label = "Origin IP Discovery"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Find the real server IP behind a CDN/WAF via subdomain, "
                   "mail, CT-log, and header leaks.")
    # Phase 2: consumes the "subdomains" the phase-1 enumerator published.
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        # Step 1: is the target even behind a CDN? If every A/AAAA answer
        # is a public non-CDN IP, there is no origin to discover.
        try:
            own_ips = await self._resolve_all(domain, ("A", "AAAA"))
        except Exception:
            return self._degraded("DNS resolution failed for the target")
        if not own_ips:
            return self._degraded("no A/AAAA answers for the target")
        providers = {cdn_provider_for(ip) for ip in own_ips}
        providers.discard(None)
        if not providers:
            return self._ok(
                [], f"{domain} does not appear to sit behind a known CDN "
                    f"(A records are direct: {', '.join(sorted(own_ips)[:3])})")

        candidates: Dict[str, Set[str]] = {}

        def _add(ip: str, method: str) -> None:
            if is_potentially_real_ip(ip):
                candidates.setdefault(ip, set()).add(method)

        # Step 2: published subdomains (phase-1 bus; ARTEX subdomains_data).
        subs = [s for s in ctx.consume("subdomains") if isinstance(s, str)]
        for sub in subs[:_MAX_HOSTS_PER_METHOD]:
            for ip in await self._resolve_all(sub, ("A",)):
                _add(ip, "subdomains")

        # Step 3: mail servers — MX hosts usually point at real infra.
        try:
            mx_hosts = await self._resolve_mx(domain)
            for host in mx_hosts[:_MAX_HOSTS_PER_METHOD]:
                for ip in await self._resolve_all(host, ("A",)):
                    _add(ip, "mail_servers")
        except Exception:
            pass

        # Step 4: certificate transparency — crt.sh hostnames for the
        # domain, resolved; same source subdomains.py uses.
        try:
            for host in await self._crtsh_hosts(ctx, domain):
                for ip in await self._resolve_all(host, ("A",)):
                    _add(ip, "cert_transparency")
        except Exception:
            pass

        # Step 5: HTTP headers on the homepage that disclose an IP.
        try:
            page = await ctx.fetch_page(f"https://{domain}/")
            headers = (page or {}).get("headers") or {}
            for name in IP_HEADERS:
                value = headers.get(name) or headers.get(name.lower()) or ""
                for ip in _IPV4_RE.findall(str(value)):
                    _add(ip, "http_headers")
        except Exception:
            pass

        # Step 6: score every candidate ARTEX-style; verify liveness.
        for ip in sorted(candidates):
            methods = candidates[ip]
            score = sum(_METHOD_WEIGHTS.get(m, 0) for m in methods)
            if len(methods) > 1:
                score += 5 * len(methods)
            responds = await self._verify_ip_responds(ip)
            if responds:
                score += 10
            if score < _MIN_SCORE:
                continue
            conf = 90 if score >= 20 else 80 if score >= 15 else 70
            findings.append(self._f(
                "infra", "origin_ip_exposed",
                f"Possible origin IP {ip} behind {', '.join(sorted(providers))} "
                f"(score {score}, via {', '.join(sorted(methods))}"
                f"{', answers TCP' if responds else ', no TCP answer'})",
                source="origin IP discovery", confidence=conf,
                passive=True, bounty_value="high",
                evidence={"severity": "high", "score": score,
                          "methods": sorted(methods),
                          "responds": responds,
                          "cdn_provider": sorted(providers),
                          "why": "An origin IP reachable directly lets an "
                                 "attacker bypass the CDN/WAF in front of "
                                 "this site. Restrict origin access to the "
                                 "CDN edge ranges or put the origin behind "
                                 "a firewall that only accepts CDN traffic."}))
            ctx.publish("origin_ips", ip)

        res = self._ok(findings,
                       f"checked {domain} behind {', '.join(sorted(providers))}; "
                       f"{len(findings)} likely origin IP(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    # -- helpers (seams the unit tests monkeypatch) ----------------------

    async def _resolve_all(self, host: str, rtypes) -> List[str]:
        out: List[str] = []
        for rtype in rtypes:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.lifetime = 5
                answers = await resolver.resolve(host, rtype)
                out.extend(str(r) for r in answers)
            except Exception:
                continue
        return out

    async def _resolve_mx(self, domain: str) -> List[str]:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 5
            answers = await resolver.resolve(domain, "MX")
            hosts = []
            for r in answers:
                exchange = str(getattr(r, "exchange", "")).rstrip(".")
                if exchange:
                    hosts.append(exchange)
            return hosts
        except Exception:
            return []

    async def _crtsh_hosts(self, ctx: Ctx, domain: str) -> List[str]:
        from urllib.parse import quote
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"

        async def _fetch():
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
                if resp.status_code != 200:
                    return {"error": f"HTTP {resp.status_code}"}
                return resp.json()
            except Exception as e:
                return {"error": str(e)[:200] or type(e).__name__}

        rows, _ = await ctx.cache.cached("ct", domain, _fetch)
        hosts: Set[str] = set()
        if isinstance(rows, list):
            for r in rows:
                name = (r.get("name_value") or "").strip().lower()
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub and sub.endswith(domain):
                        hosts.add(sub)
        return sorted(hosts)[:_MAX_HOSTS_PER_METHOD]

    async def _verify_ip_responds(self, ip: str) -> bool:
        """TCP-connect probe on common web ports (ARTEX _verify_ip_responds).

        Runs in the executor so a 2s timeout per port never blocks the
        event loop. An answer only proves something listens, not that it
        serves this site.
        """
        def _check() -> bool:
            for port in (80, 443, 8080, 8443):
                try:
                    sock = socket.create_connection((ip, port), timeout=2)
                    sock.close()
                    return True
                except Exception:
                    continue
            return False

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _check)
        except Exception:
            return False
