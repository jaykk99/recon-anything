"""RDAP / WHOIS plugin (Milestone 2).

Uses RDAP (the modern WHOIS replacement, JSON over HTTPS, no key) via
the IANA bootstrap service. Falls back to whois.iana.org referral.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class RdapPlugin(Plugin):
    id = "rdap"
    label = "WHOIS / RDAP"
    accepts = ["domain", "url", "ip", "asn"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "Registrar, creation/expiry dates, registrant org via RDAP."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []

        if target.type == "asn":
            asn = target.normalized.upper().lstrip("AS")
            url = f"https://data.iana.org/rdap/asn{asn}"
            q = f"AS{asn}"
        elif target.type == "ip":
            url = f"https://data.iana.org/rdap/ip/{quote(target.normalized)}"
            q = target.normalized
        else:
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no domain/ip/asn for this target type")
            url = f"https://data.iana.org/rdap/domain/{quote(domain)}"
            q = domain

        async def do_rdap():
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
                if resp.status_code == 404:
                    return {"error": "not found in RDAP"}
                if resp.status_code != 200:
                    return {"error": f"HTTP {resp.status_code}"}
                return resp.json()
            except Exception as e:
                return {"error": str(e)[:200]}

        data, _ = await ctx.cache.cached("rdap", q, do_rdap)
        if isinstance(data, dict) and data.get("error"):
            res = self._degraded(f"RDAP: {data['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        def events_to(when: str):
            for ev in data.get("events", []):
                if ev.get("eventAction") == when:
                    return ev.get("eventDate")
            return None

        registrar = ""
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                v = ent.get("vcardArray", [])
                if len(v) > 1 and isinstance(v[1], list):
                    for item in v[1]:
                        if isinstance(item, list) and item[0] == "fn":
                            registrar = item[3]
                            break
            if registrar:
                break

        fields = {
            "registrar": registrar or "unknown",
            "created": events_to("registration") or "unknown",
            "expires": events_to("expiration") or "unknown",
            "last_changed": events_to("last changed") or "unknown",
            "status": ", ".join(data.get("status", [])) or "unknown",
        }
        # registrant org
        for ent in data.get("entities", []):
            if "registrant" in ent.get("roles", []):
                v = ent.get("vcardArray", [])
                if len(v) > 1 and isinstance(v[1], list):
                    for item in v[1]:
                        if isinstance(item, list) and item[0] == "fn":
                            fields["registrant_org"] = item[3]
                break
        # nameservers
        ns = [n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName")]
        if ns:
            fields["nameservers"] = ", ".join(ns)

        for k, v in fields.items():
            findings.append(self._f("infra", f"whois_{k}", str(v),
                                    source="RDAP (data.iana.org)",
                                    source_url=url, confidence=90, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"RDAP record for {q}")
        res.duration_ms = dur
        return res
