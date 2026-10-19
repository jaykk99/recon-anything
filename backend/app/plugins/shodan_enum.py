"""Shodan crypto-infrastructure enumerator (defensive OSINT).

Works with ZERO API keys:
- Keyless: urlscan.io domain search (no auth) for host/IP exposure tied
  to the target, scanned for risky crypto ports and services.
- Enhanced: SHODAN_API_KEY unlocks Shodan host search for exposed
  Ethereum JSON-RPC (8545), websocket RPC (8546), node ports, and open
  databases on crypto-flavoured hosts.

Detection only: reports what public sources already list as exposed and
never connects to any node RPC, database, or host itself.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict

SHODAN_API = "https://api.shodan.io"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"

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
    requires_keys = []  # works keyless via urlscan.io; SHODAN_API_KEY enhances
    description = ("Exposed crypto infra: keyless urlscan.io host intel always "
                   "runs; SHODAN_API_KEY (optional) adds Shodan ETH RPC 8545, "
                   "WS 8546, node ports, open DBs. Detection only.")
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = _key(ctx)
        findings: List[Finding] = []
        notes: List[str] = []

        # 1. KEYLESS: urlscan.io host intel (no auth needed).
        try:
            us_findings = await self._urlscan_intel(ctx, target)
            findings.extend(us_findings)
            notes.append(f"urlscan.io: {len(us_findings)} finding(s)")
        except Exception:
            pass

        # 2. ENHANCED: Shodan search when key is present.
        if key:
            try:
                sh_findings, sh_notes = await self._shodan_search(ctx, key, target)
                findings.extend(sh_findings)
                notes.extend(sh_notes)
            except Exception as e:
                notes.append(f"shodan lookup failed: {str(e)[:120]}")
        else:
            notes.append("shodan skipped (no SHODAN_API_KEY - urlscan.io covered "
                         "host intel; add the key for ETH RPC/node-port search)")

        dur = int((time.monotonic() - t0) * 1000)
        summary = "; ".join(notes) if notes else "no exposure records found"
        res = self._ok(findings, f"{len(findings)} crypto exposure(s). {summary}")
        res.duration_ms = dur
        return res

    async def _urlscan_intel(self, ctx: Ctx, target: Target) -> List[Finding]:
        """Keyless host/IP intel via urlscan.io search (no auth)."""
        out: List[Finding] = []
        domain = domain_from_target(target.type, target.normalized)
        query = target.normalized.strip() if target.type == "ip" else domain
        if not query:
            return out
        q = f"domain:{query}" if target.type != "ip" else f"ip:{query}"
        from urllib.parse import quote_plus
        url = f"{URLSCAN_SEARCH}?q={quote_plus(q)}&size=20"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                            max_retries=1)
        except Exception:
            return out
        data = safe_json_dict(r)
        results = data.get("results") or []
        ips: Dict[str, Dict[str, Any]] = {}
        for res in results:
            if not isinstance(res, dict):
                continue
            page = res.get("page") or {}
            ip = str(page.get("ip") or "")
            if not ip:
                continue
            info = ips.setdefault(ip, {"count": 0, "server": "", "country": ""})
            info["count"] += 1
            info["server"] = info["server"] or str(page.get("server") or "")
            info["country"] = info["country"] or str(page.get("country") or "")
        for ip, info in list(ips.items())[:10]:
            out.append(self._f(
                "infra", "urlscan_host_intel",
                f"urlscan.io: {ip} serves {query} "
                f"({info['count']} scan(s){', ' + info['server'] if info['server'] else ''}"
                f"{', ' + info['country'] if info['country'] else ''})",
                source="urlscan.io",
                source_url=f"https://urlscan.io/search/#{q}",
                confidence=80, passive=True,
                evidence={"severity": "low", "ip": ip,
                          "remediation": "Verify this IP is supposed to serve "
                                         "the target. Unexpected IPs can mean "
                                         "takeover or shadow infra.",
                          "server": info["server"],
                          "country": info["country"]}))
        return out

    async def _shodan_search(self, ctx: Ctx, key: str,
                             target: Target):
        """Shodan host search (only called when a key is configured)."""
        findings: List[Finding] = []
        notes: List[str] = []
        # Validate the key first so a bad key is reported clearly.
        r = await fetch(ctx.http, ctx.limiter, "GET",
                        f"{SHODAN_API}/api-info?key={key}", timeout=15,
                        max_retries=1)
        if r.status_code == 401:
            notes.append("shodan API key rejected (401)")
            return findings, notes

        if target.type == "ip":
            hosts = await self._host_lookup(ctx, key, target.normalized.strip())
            findings.extend(self._flag_hosts(hosts))
            notes.append(f"shodan: {len(hosts)} host record(s)")
        else:
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return findings, notes
            for q in SEARCH_QUERIES:
                q_full = f"hostname:{domain} {q}"
                hosts = await self._search(ctx, key, q_full)
                before = len(findings)
                findings.extend(self._flag_hosts(hosts, query=q_full))
                if hosts:
                    notes.append(f"shodan query '{q_full}': {len(hosts)} host(s), "
                                 f"{len(findings) - before} new flag(s)")
            hosts = await self._search(ctx, key, f"hostname:{domain}")
            before = len(findings)
            findings.extend(self._flag_hosts(hosts, query=f"hostname:{domain}"))
            if hosts:
                notes.append(f"shodan query 'hostname:{domain}': {len(hosts)} host(s), "
                             f"{len(findings) - before} new flag(s)")
        return findings, notes

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
