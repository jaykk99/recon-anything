"""WHOIS via keyless RDAP + WhoisXML keyed path (Tier-1 OSINT).

Native domain WHOIS through the public RDAP bootstrap (rdap.org,
which redirects to the authoritative registry RDAP; Verisign RDAP
as a direct fallback for com/net): registrar, creation / expiry /
updated events, status codes, nameservers, registrant org - all
keyless. When WHOISXML_API_KEY is configured (key vault or
environment) the plugin additionally queries the WhoisXML API for
its normalized WHOIS record; without a key that keyed path is
SKIPPED with a clean "needs key" note - never invented data.
"""
from __future__ import annotations

import os
import time
from typing import List, Optional
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, \
    safe_json_dict

WHOISXML_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"


def parse_rdap_domain(data: dict) -> dict:
    """RDAP domain document -> flat WHOIS facts."""
    out: dict = {}
    if not isinstance(data, dict):
        return out

    def event(action: str) -> Optional[str]:
        for ev in data.get("events", []) or []:
            if isinstance(ev, dict) and ev.get("eventAction") == action:
                return str(ev.get("eventDate") or "") or None
        return None

    out["created"] = event("registration")
    out["expires"] = event("expiration")
    out["updated"] = event("last changed")
    status = [str(s) for s in data.get("status", []) or []]
    if status:
        out["status"] = ", ".join(status)
    ns = [str(n.get("ldhName")) for n in data.get("nameservers", []) or []
          if isinstance(n, dict) and n.get("ldhName")]
    if ns:
        out["nameservers"] = ", ".join(ns)
    for ent in data.get("entities", []) or []:
        if not isinstance(ent, dict):
            continue
        v = ent.get("vcardArray") or []
        fn = None
        if len(v) > 1 and isinstance(v[1], list):
            for item in v[1]:
                if isinstance(item, list) and len(item) > 3 \
                        and item[0] == "fn" and item[3]:
                    fn = str(item[3])
                    break
        roles = ent.get("roles", []) or []
        if fn and "registrar" in roles:
            out.setdefault("registrar", fn)
        if fn and "registrant" in roles:
            out.setdefault("registrant_org", fn)
    return {k: v for k, v in out.items() if v}


class WhoisxmlLookupPlugin(Plugin):
    timeout_s = 60
    id = "whoisxml_lookup"
    label = "WHOIS (RDAP + WhoisXML)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "network"
    description = ("Domain WHOIS via keyless RDAP (rdap.org / Verisign) "
                   "natively; WhoisXML API enrichment runs only when "
                   "WHOISXML_API_KEY is set (skipped cleanly otherwise).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        facts = await self._rdap(ctx, domain)
        if facts:
            for key, value in facts.items():
                findings.append(self._f(
                    "identity", f"whois_{key}", str(value),
                    source="RDAP (rdap.org)",
                    source_url=f"https://rdap.org/domain/{domain}",
                    confidence=90, passive=True))
        key = (ctx.keys.get("WHOISXML_API_KEY")
               or os.environ.get("WHOISXML_API_KEY") or "").strip()
        if key:
            extra = await self._whoisxml(ctx, domain, key)
            findings.extend(extra)
            note = f"RDAP facts + WhoisXML enrichment for {domain}"
        else:
            note = (f"RDAP facts for {domain}; WhoisXML path skipped: "
                    f"needs key (WHOISXML_API_KEY not set)")
        if not findings:
            return self._degraded(f"no RDAP record found for {domain}")
        res = self._ok(findings, note)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _rdap(self, ctx: Ctx, domain: str) -> dict:
        urls = [f"https://rdap.org/domain/{quote(domain)}"]
        if domain.rsplit(".", 1)[-1] in ("com", "net"):
            urls.append(f"https://rdap.verisign.com/com/v1/domain/"
                        f"{quote(domain)}" if domain.endswith(".com")
                        else f"https://rdap.verisign.com/net/v1/domain/"
                             f"{quote(domain)}")
        urls.append(f"https://data.iana.org/rdap/domain/{quote(domain)}")
        for url in urls:
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                                   timeout=30, max_retries=1,
                                   follow_redirects=True)
                if resp.status_code == 200:
                    facts = parse_rdap_domain(safe_json_dict(resp))
                    if facts:
                        return facts
            except Exception:
                continue
        return {}

    async def _whoisxml(self, ctx: Ctx, domain: str,
                        key: str) -> List[Finding]:
        out: List[Finding] = []
        try:
            resp = await fetch(
                ctx.http, ctx.limiter, "GET",
                f"{WHOISXML_URL}?apiKey={quote(key)}&domainName="
                f"{quote(domain)}&outputFormat=JSON",
                timeout=20, max_retries=1)
            if resp.status_code != 200:
                return out
            record = (safe_json_dict(resp).get("WhoisRecord") or {})
            registry = record.get("registryData") or {}
            created = registry.get("createdDateNormalized") or \
                record.get("createdDateNormalized")
            if created:
                out.append(self._f(
                    "identity", "whoisxml_created", str(created),
                    source="WhoisXML API", confidence=85, passive=True))
            registrar = (record.get("registrarName")
                         or registry.get("registrarName"))
            if registrar:
                out.append(self._f(
                    "identity", "whoisxml_registrar", str(registrar),
                    source="WhoisXML API", confidence=85, passive=True))
        except Exception:
            pass
        return out
