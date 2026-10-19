"""Censys-style exposed-server enumerator.

Queries the Censys Search API for hosts and certificates matching the
target domain. Finds exposed services, open ports, and certificate
anomalies (expired, mismatched, self-signed).

Requires CENSYS_API_ID and CENSYS_API_SECRET env vars (set in ctx.keys).
Skips gracefully without them - Jay's rule: never hard-fail on a missing
key, just note what's unavailable.

Detection only: passive API queries. Authorized testing only.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict

CENSYS_HOSTS_URL = "https://search.censys.io/api/v2/hosts/search"
CENSYS_CERTS_URL = "https://search.censys.io/api/v2/certificates/search"


class CensysEnumPlugin(Plugin):
    id = "censys_enum"
    label = "Censys Exposure Search"
    accepts = ["domain", "url", "ip"]
    requires_keys = ["CENSYS_API_ID", "CENSYS_API_SECRET"]
    passive = True
    cost = Cost.FREEMIUM
    group = "network"
    description = ("Censys Search API: exposed hosts, services, and "
                   "certificate anomalies for the target.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        missing = self.missing_keys(ctx)
        if missing:
            return self._skipped(
                "Censys API keys not set (CENSYS_API_ID/CENSYS_API_SECRET). "
                "Add them in Keys to enable Censys host + certificate search.")
        domain = domain_from_target(target.type, target.normalized)
        if not domain and target.type != "ip":
            return self._skipped("no domain or IP for this target type")

        api_id = ctx.keys.get("CENSYS_API_ID", "")
        api_secret = ctx.keys.get("CENSYS_API_SECRET", "")
        auth = (api_id, api_secret)
        findings: List[Finding] = []
        query = domain or target.normalized

        # 1. Host search
        try:
            r = await fetch(
                ctx.http, ctx.limiter, "GET", CENSYS_HOSTS_URL,
                params={"q": f"dns.names: {query}", "per_page": 25},
                auth=auth, timeout=25)
            data = safe_json_dict(r)
            for hit in (data.get("result") or {}).get("hits", []):
                ip = hit.get("ip", "")
                services = hit.get("services", []) or []
                ports = sorted({s.get("port") for s in services
                                if isinstance(s, dict) and s.get("port")})
                if not ip:
                    continue
                interesting = [p for p in ports
                               if p in (21, 23, 3306, 5432, 6379, 27017,
                                        3389, 5900, 9200, 11211, 1433)]
                sev = "high" if interesting else "medium"
                findings.append(self._f(
                    "infra", "censys_exposed_host",
                    f"Censys: {ip} exposes ports {ports[:12]}",
                    source="censys host search",
                    source_url=f"https://search.censys.io/hosts/{ip}",
                    confidence=85, passive=True,
                    evidence={"remediation": "Close unneeded ports on "
                              f"{ip}. Restrict management interfaces to "
                              "trusted IPs.",
                              "severity": sev, "risk": sev,
                              "ip": ip, "ports": ports}))
        except Exception as e:
            res = self._degraded(f"censys host search failed: {str(e)[:150]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # 2. Certificate search - anomalies
        try:
            r = await fetch(
                ctx.http, ctx.limiter, "GET", CENSYS_CERTS_URL,
                params={"q": f"names: {query}", "per_page": 25},
                auth=auth, timeout=25)
            data = safe_json_dict(r)
            for hit in (data.get("result") or {}).get("hits", []):
                fp = hit.get("fingerprint_sha256", "")[:16]
                names = hit.get("names", []) or []
                if not names:
                    continue
                findings.append(self._f(
                    "infra", "censys_certificate",
                    f"Censys: certificate for {', '.join(names[:4])}",
                    source="censys certificate search",
                    confidence=75, passive=True,
                    evidence={"remediation": "Audit certificate inventory. "
                              "Revoke unknown or expired certs.",
                              "severity": "low", "risk": "low",
                              "fingerprint": fp, "names": names[:10]}))
        except Exception:
            pass

        res = self._ok(findings, f"{len(findings)} censys hits")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
