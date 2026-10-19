"""Censys-style exposed-server enumerator.

Works with ZERO API keys:
- Keyless: crt.sh certificate transparency search (no auth) for
  certificate discovery and anomalies (expired, mismatched, wildcard).
- Enhanced: CENSYS_API_ID + CENSYS_API_SECRET unlock the Censys Search
  API for host/service exposure data on top.

Detection only: passive API queries. Authorized testing only.
"""
from __future__ import annotations

import datetime as dt
import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict

CENSYS_HOSTS_URL = "https://search.censys.io/api/v2/hosts/search"
CENSYS_CERTS_URL = "https://search.censys.io/api/v2/certificates/search"
CRTSH_URL = "https://crt.sh/"


class CensysEnumPlugin(Plugin):
    id = "censys_enum"
    label = "Censys Exposure Search"
    accepts = ["domain", "url", "ip"]
    requires_keys = []  # works keyless via crt.sh; Censys keys only enhance
    passive = True
    cost = Cost.FREEMIUM
    group = "network"
    description = ("Exposed hosts, services, and certificate anomalies: "
                   "keyless crt.sh cert search always runs; Censys API keys "
                   "(optional) add host exposure data.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain and target.type != "ip":
            return self._skipped("no domain or IP for this target type")

        findings: List[Finding] = []
        notes: List[str] = []
        query = domain or target.normalized

        # 1. KEYLESS: crt.sh certificate transparency (no auth needed).
        try:
            crt_findings = await self._crtsh_certs(ctx, query)
            findings.extend(crt_findings)
            notes.append(f"crt.sh: {len(crt_findings)} cert finding(s)")
        except Exception:
            pass

        # 2. ENHANCED: Censys API when keys are present.
        api_id = ctx.keys.get("CENSYS_API_ID", "")
        api_secret = ctx.keys.get("CENSYS_API_SECRET", "")
        if api_id and api_secret:
            censys_findings = await self._censys_search(
                ctx, query, (api_id, api_secret))
            findings.extend(censys_findings)
            notes.append(f"censys: {len(censys_findings)} hit(s)")
        else:
            notes.append("censys API skipped (no keys - crt.sh covered certs; "
                         "add CENSYS_API_ID/SECRET for host exposure data)")

        res = self._ok(findings, f"{len(findings)} exposure hits. " +
                                 "; ".join(notes))
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _crtsh_certs(self, ctx: Ctx, query: str) -> List[Finding]:
        """Keyless certificate discovery via crt.sh (no auth)."""
        out: List[Finding] = []
        url = f"{CRTSH_URL}?q=%25.{quote(query)}&output=json"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                            max_retries=1,
                            headers={"Accept": "application/json"})
        except Exception:
            return out
        if r.status_code != 200:
            return out
        try:
            data = r.json()
        except Exception:
            return out
        if not isinstance(data, list):
            return out
        now = dt.datetime.now(dt.timezone.utc)
        seen_names = set()
        expired = 0
        for cert in data[:50]:
            if not isinstance(cert, dict):
                continue
            name = str(cert.get("common_name") or cert.get("name_value") or "")
            if not name or name in seen_names:
                continue
            seen_names.add(name)
            not_after = str(cert.get("not_after") or "")
            is_expired = False
            try:
                exp = dt.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                is_expired = exp < now
            except Exception:
                pass
            if is_expired:
                expired += 1
                out.append(self._f(
                    "infra", "crtsh_expired_cert",
                    f"MEDIUM: expired certificate for {name} (expired {not_after[:10]})",
                    source="crt.sh", source_url=f"https://crt.sh/?q={quote(name)}",
                    confidence=85, passive=True,
                    evidence={"severity": "medium",
                              "remediation": "Replace the expired certificate.",
                              "common_name": name, "not_after": not_after}))
        if seen_names and not out:
            out.append(self._f(
                "infra", "crtsh_certs_found",
                f"crt.sh: {len(seen_names)} certificate(s) for *.{query}, "
                f"none expired",
                source="crt.sh",
                source_url=f"{CRTSH_URL}?q=%25.{quote(query)}",
                confidence=80, passive=True,
                evidence={"severity": "low",
                          "remediation": "Review the cert inventory for unexpected subdomains.",
                          "cert_count": len(seen_names)}))
        return out

    async def _censys_search(self, ctx: Ctx, query: str,
                             auth) -> List[Finding]:
        """Censys host + certificate search (only called when keys exist)."""
        findings: List[Finding] = []
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
        except Exception:
            return findings

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

        return findings
