"""Shodan crypto-infrastructure enumerator (defensive OSINT).

Queries Shodan for crypto-related exposure tied to the target: exposed
Ethereum JSON-RPC ports (8545), websocket RPC (8546), other node ports,
and open databases on crypto-flavoured hosts. Detection only: it reports
what Shodan already lists as exposed and never connects to any node RPC,
database, or host itself.

Needs SHODAN_API_KEY (ctx key "shodan" or the SHODAN_API_KEY env var).
Skips gracefully with a clear note when the key is missing.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SHODAN_API = "https://api.shodan.io"

# Crypto-relevant ports. Each maps to (label, severity).
# 8545/8546 on the public internet with unlocked accounts have been used
# to drain wallets; they are always HIGH when found open.
RISKY_PORTS = {
    8545: ("Ethereum JSON-RPC exposed", "high"),
    8546: ("Ethereum websocket RPC exposed", "high"),
    8547: ("Ethereum RPC over HTTPS exposed", "high"),
    8332: ("Bitcoin JSON-RPC exposed", "high"),
    8333: ("Bitcoin P2P port exposed", "medium"),
    18332: ("Bitcoin testnet RPC exposed", "high"),
    30303: ("Ethereum discovery port open", "medium"),
    6379: ("Redis open (often unauthenticated)", "high"),
    27017: ("MongoDB open (often unauthenticated)", "high"),
    9200: ("Elasticsearch open (cluster API exposed)", "high"),
    5984: ("CouchDB open", "medium"),
    5432: ("PostgreSQL exposed", "medium"),
    3306: ("MySQL exposed", "medium"),
    15672: ("RabbitMQ management exposed", "medium"),
}

# Port-based host search always inspects for these; Shodan returns the
# service list per host and we flag anything in RISKY_PORTS.
SEARCH_QUERIES = ["port:8545", "port:8546", "port:8332", "bitcoin", "ethereum"]


def _key(ctx: Ctx) -> Optional[str]:
    return ctx.keys.get("shodan") or os.environ.get("SHODAN_API_KEY") or None


class ShodanEnumPlugin(Plugin):
    id = "shodan_enum"
    label = "Shodan Crypto Enumerator"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = ["shodan"]
    description = ("Shodan search for exposed crypto infra: ETH RPC 8545, "
                   "WS 8546, node ports, open DBs. Detection only.")
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = _key(ctx)
        if not key:
            return self._skipped(
                "SHODAN_API_KEY not configured (set the 'shodan' key or "
                "SHODAN_API_KEY env var). Shodan crypto enumeration skipped.")

        findings: List[Finding] = []
        notes: List[str] = []
        try:
            # Validate the key first so a bad key is reported clearly.
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            f"{SHODAN_API}/api-info?key={key}", timeout=15,
                            max_retries=1)
            if r.status_code == 401:
                res = self._skipped("Shodan API key rejected (401). "
                                    "Check SHODAN_API_KEY and retry.")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res

            if target.type == "ip":
                hosts = await self._host_lookup(ctx, key, target.normalized.strip())
                findings.extend(self._flag_hosts(hosts))
                notes.append(f"{len(hosts)} Shodan host record(s)")
            else:
                domain = domain_from_target(target.type, target.normalized)
                if not domain:
                    return self._skipped("no domain for this target type")
                for q in SEARCH_QUERIES:
                    q_full = f"hostname:{domain} {q}"
                    hosts = await self._search(ctx, key, q_full)
                    before = len(findings)
                    findings.extend(self._flag_hosts(hosts, query=q_full))
                    if hosts:
                        notes.append(f"query '{q_full}': {len(hosts)} host(s), "
                                     f"{len(findings) - before} new flag(s)")
                # One broader catch: any Shodan record for this hostname,
                # scanned for risky ports even when the match query missed.
                hosts = await self._search(ctx, key, f"hostname:{domain}")
                before = len(findings)
                findings.extend(self._flag_hosts(hosts, query=f"hostname:{domain}"))
                if hosts:
                    notes.append(f"query 'hostname:{domain}': {len(hosts)} host(s), "
                                 f"{len(findings) - before} new flag(s)")
        except Exception as e:
            res = self._degraded(f"Shodan lookup failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        dur = int((time.monotonic() - t0) * 1000)
        summary = "; ".join(notes) if notes else "no Shodan records found"
        res = self._ok(findings, f"{len(findings)} crypto exposure(s). {summary}")
        res.duration_ms = dur
        return res

    async def _search(self, ctx: Ctx, key: str, query: str) -> List[Dict[str, Any]]:
        """Shodan host search, first page only. Returns match dicts."""
        from urllib.parse import quote_plus
        url = (f"{SHODAN_API}/shodan/host/search?key={key}"
               f"&query={quote_plus(query)}&page=1")
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20,
                        max_retries=1)
        if r.status_code != 200:
            if r.status_code == 429:
                raise RuntimeError("Shodan rate limit hit (429)")
            return []
        try:
            data = r.json()
        except Exception:
            return []
        return data.get("matches", []) or []

    async def _host_lookup(self, ctx: Ctx, key: str, ip: str) -> List[Dict[str, Any]]:
        r = await fetch(ctx.http, ctx.limiter, "GET",
                        f"{SHODAN_API}/shodan/host/{ip}?key={key}&minify=false",
                        timeout=20, max_retries=1)
        if r.status_code != 200:
            return []
        try:
            return [r.json()]
        except Exception:
            return []

    def _flag_hosts(self, hosts: List[Dict[str, Any]],
                    query: str = "") -> List[Finding]:
        out: List[Finding] = []
        for h in hosts:
            ip = str(h.get("ip_str") or "")
            org = h.get("org") or ""
            ports = h.get("ports") or []
            hostnames = h.get("hostnames") or []
            data = h.get("data") or []

            for port in ports:
                if port not in RISKY_PORTS:
                    continue
                label, sev = RISKY_PORTS[port]
                banner = ""
                for svc in data:
                    if svc.get("port") == port:
                        banner = str(svc.get("data") or "")[:160]
                        break
                banner_hint = f" Banner: {banner.strip()[:120]}." if banner.strip() else ""
                out.append(self._f(
                    "infra", "shodan_crypto_port",
                    f"{sev.upper()}: {label} on {ip}:{port} "
                    f"({'/'.join(hostnames) or 'no rDNS'}{', ' + org if org else ''}).{banner_hint}",
                    source="Shodan", source_url=f"https://www.shodan.io/host/{ip}",
                    confidence=85, passive=True,
                    evidence={
                        "severity": sev, "ip": ip, "port": port,
                        "label": label, "query": query,
                        "exploitability": "public_poc" if port in (8545, 8546, 8547, 8332) else "theoretical",
                        "remediation": (
                            f"Close port {port} on {ip} to the internet immediately. "
                            "Bind node RPC/database services to 127.0.0.1, require "
                            "authentication, and firewall management interfaces to "
                            "trusted IPs only. Re-scan on Shodan to verify the port "
                            "is no longer listed.")}))
        return out
