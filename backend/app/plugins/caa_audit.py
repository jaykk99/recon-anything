"""CAA (Certificate Authority Authorization) policy audit plugin.

dns.py reports raw CAA records; this plugin *grades the policy*:
- no CAA at all: any public CA can issue for the domain,
- CAA present but no issuewild: wildcard issuance unrestricted,
- CAA forbidding issuance ("issue ;"): reported as good hygiene,
- CAA on the registrable domain vs the FQDN (CAA walks up the tree -
  a policy on the parent covers the child, which is fine and noted).

Detection only: DNS CAA lookups via public resolvers.
"""
from __future__ import annotations

import time
from typing import List

import dns.asyncresolver

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target


async def _caa(res, name: str) -> List[str]:
    try:
        ans = await res.resolve(name, "CAA")
        return [str(rr) for rr in ans]
    except Exception:
        return []


class CaaAuditPlugin(Plugin):
    id = "caa_audit"
    label = "CAA Policy Audit"
    accepts = ["domain", "url", "email"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Grade the CAA issuance policy: missing policy, "
                   "issuewild gaps, issuance forbids.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        res = dns.asyncresolver.Resolver(configure=False)
        res.nameservers = ["8.8.8.8", "1.1.1.1"]
        res.timeout = 6
        res.lifetime = 10

        # CAA walks up: check the FQDN, then parent labels.
        labels = domain.split(".")
        records: List[str] = []
        found_at = ""
        for i in range(len(labels) - 1):
            name = ".".join(labels[i:])
            records = await _caa(res, name)
            if records:
                found_at = name
                break

        findings: List = []
        if not records:
            findings.append(self._f(
                "dns", "caa_missing",
                f"No CAA records for {domain} - any public CA can issue "
                "certificates for it",
                source="CAA audit", confidence=90, passive=True,
                evidence={"severity": "low",
                          "remediation": (
                              f"Publish a CAA record, e.g.: {domain}. "
                              "CAA 0 issue \"letsencrypt.org\" (and "
                              "issuewild if you use wildcard certs).")}))
            return PluginResult(
                plugin_id=self.id, status=PluginStatus.OK,
                findings=findings,
                elapsed_s=round(time.monotonic() - t0, 2),
                reason="no CAA policy found")

        tags = {}
        for r in records:
            parts = r.split()
            if len(parts) >= 3:
                tags.setdefault(parts[1].lower().strip('"'), []).append(
                    " ".join(parts[2:]))
        if found_at != domain:
            findings.append(self._f(
                "dns", "caa_inherited",
                f"CAA policy inherited from parent {found_at} "
                f"({len(records)} record(s))",
                source="CAA audit", confidence=85, passive=True,
                evidence={"severity": "low", "parent": found_at,
                          "records": records[:5],
                          "remediation": ("Informational: inheritance is "
                                          "valid per RFC 8659.")}))
        forbids = any('"' not in v and v.strip().strip('"').strip("'") == ";"
                      or v.strip() == '";"'
                      for vs in (tags.get("issue", []) +
                                 tags.get("issuewild", [])) for v in [vs])
        if forbids:
            findings.append(self._f(
                "dns", "caa_forbids_issuance",
                "CAA explicitly forbids certificate issuance (good hygiene "
                "for non-TLS domains)",
                source="CAA audit", confidence=90, passive=True,
                evidence={"severity": "low",
                          "remediation": "Informational: no action."}))
        else:
            if "issuewild" not in tags and "issue" in tags:
                findings.append(self._f(
                    "dns", "caa_no_issuewild",
                    "CAA restricts issue but not issuewild - wildcard "
                    "certificates can come from any CA",
                    source="CAA audit", confidence=80, passive=True,
                    evidence={"severity": "low", "records": records[:5],
                              "remediation": (
                                  "Add an issuewild tag mirroring your issue "
                                  "policy if you use (or want to block) "
                                  "wildcard certs.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"CAA policy at {found_at or domain}: "
                   f"{len(findings)} findings")
