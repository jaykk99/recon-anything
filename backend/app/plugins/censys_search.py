"""Censys host/service search (Tier-1 OSINT, keyed wrapper).

Thin native wrapper over the Censys Search API v2 (hosts search).
Censys is a paid SaaS: without CENSYS_API_ID + CENSYS_API_SECRET
(from the run's key vault or the process environment) this plugin
returns a clean SKIPPED result - "needs key" - and never fabricates
data. The full query path (search query build, pagination, service
parsing) sits behind that key check. For keyless certificate/host
coverage see the censys_enum plugin, which runs without keys.

Detection only: Censys is a passive index; nothing is probed.
"""
from __future__ import annotations

import os
import time
from typing import List, Optional, Tuple
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, \
    safe_json_dict

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"


def censys_keys(ctx: Ctx) -> Optional[Tuple[str, str]]:
    api_id = (ctx.keys.get("CENSYS_API_ID")
              or os.environ.get("CENSYS_API_ID") or "").strip()
    secret = (ctx.keys.get("CENSYS_API_SECRET")
              or os.environ.get("CENSYS_API_SECRET") or "").strip()
    if api_id and secret:
        return api_id, secret
    return None


def build_query(domain: Optional[str], ip: Optional[str]) -> str:
    if ip:
        return f"ip: {ip}"
    return f"services.tls.certificates.leaf.subject.common_name: {domain}"


def parse_hits(data: dict) -> List[dict]:
    """Censys v2 search payload -> flat hit dicts."""
    out: List[dict] = []
    result = data.get("result") or {}
    for hit in result.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        services = []
        for svc in hit.get("services") or []:
            if isinstance(svc, dict):
                services.append({
                    "port": svc.get("port"),
                    "service": svc.get("service_name") or "",
                    "transport": svc.get("transport_protocol") or "",
                })
        out.append({"ip": str(hit.get("ip") or ""), "services": services,
                    "location": (hit.get("location") or {}).get("country")
                    if isinstance(hit.get("location"), dict) else None})
    return out


class CensysSearchPlugin(Plugin):
    timeout_s = 60
    id = "censys_search"
    label = "Censys Host Search"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.PAID
    group = "infra"
    description = ("Censys Search API host/service lookup. Needs "
                   "CENSYS_API_ID + CENSYS_API_SECRET; skipped cleanly "
                   "when no key is configured.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        creds = censys_keys(ctx)
        if not creds:
            res = self._skipped(
                "needs key: set CENSYS_API_ID and CENSYS_API_SECRET "
                "to enable Censys host search")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        domain = domain_from_target(target.type, target.normalized)
        ip = target.normalized if target.type == "ip" else None
        if not domain and not ip:
            return self._skipped("no domain or IP for this target type")
        findings: List[Finding] = []
        query = build_query(domain, ip)
        try:
            resp = await fetch(
                ctx.http, ctx.limiter, "GET",
                f"{CENSYS_SEARCH_URL}?q={quote(query)}&per_page=25",
                timeout=25, max_retries=1,
                auth=(creds[0], creds[1]),
                headers={"Accept": "application/json"})
            if resp.status_code == 401:
                return self._skipped("needs key: Censys rejected the "
                                     "configured API credentials (401)")
            if resp.status_code != 200:
                return self._degraded(f"Censys search HTTP "
                                      f"{resp.status_code}")
            for hit in parse_hits(safe_json_dict(resp)):
                if not hit["ip"]:
                    continue
                ports = ", ".join(
                    f"{s['port']}/{s['service']}" for s in hit["services"]
                    if s["port"])
                findings.append(self._f(
                    "infra", "censys_host",
                    f"{hit['ip']}" + (f" [{ports}]" if ports else ""),
                    source="Censys Search API", source_url=CENSYS_SEARCH_URL,
                    confidence=85, passive=True,
                    evidence={"ip": hit["ip"], "services": hit["services"],
                              "country": hit["location"],
                              "severity": "low"}))
        except Exception as e:
            return self._degraded(f"Censys search failed: "
                                  f"{type(e).__name__}")
        res = self._ok(findings, f"{len(findings)} Censys host hits")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
