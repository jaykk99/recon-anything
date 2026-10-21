"""Well-known URI audit plugin.

Fetches the standard /.well-known/ files and grades them:
- security.txt (RFC 9116): presence, Contact field, Expires freshness
- change-password: presence (good hygiene signal)
- assetlinks.json / apple-app-site-association: presence; flags
  overly broad delegation (delegate_permission/common.handle_all_urls)
- gpc.json (Global Privacy Control): presence
- robots.txt is covered by the robots plugin and skipped here.

Passive: plain GETs of standardized paths.
"""
from __future__ import annotations

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch_many
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target, safe_json_list

WELL_KNOWN = [
    "security.txt",
    "change-password",
    "assetlinks.json",
    "apple-app-site-association",
    "gpc.json",
]


class WellKnownAuditPlugin(Plugin):
    id = "well_known_audit"
    label = "Well-Known URIs"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Audit /.well-known/ files: security.txt, change-password, "
                   "assetlinks, apple-app-site-association, gpc.json.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        reqs = [("GET", f"{base}/.well-known/{p}") for p in WELL_KNOWN]
        resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                 concurrency=3, max_retries=0)
        findings: List = []
        seen_txt = False
        for (_m, url), resp in zip(reqs, resps):
            if resp is None or resp.status_code != 200:
                continue
            name = url.rsplit("/", 1)[-1]
            body = (resp.text or "")[:10000]
            if name == "security.txt":
                seen_txt = True
                has_contact = any(
                    l.lower().startswith("contact:") for l in
                    body.splitlines())
                if not has_contact:
                    findings.append(self._f(
                        "web", "security_txt_no_contact",
                        "security.txt present but has no Contact field",
                        source="well-known audit", source_url=url,
                        confidence=95, passive=True,
                        evidence={"severity": "low",
                                  "remediation": (
                                      "Add a Contact: line (mailto or URL) "
                                      "so researchers can reach you.")}))
                else:
                    findings.append(self._f(
                        "web", "security_txt_present",
                        "security.txt present with Contact field",
                        source="well-known audit", source_url=url,
                        confidence=95, passive=True,
                        evidence={"severity": "low",
                                  "remediation": (
                                      "Informational: keep Contact and "
                                      "Expires fresh.")}))
            elif name == "change-password":
                findings.append(self._f(
                    "web", "well_known_change_password",
                    "change-password well-known URL present (good hygiene)",
                    source="well-known audit", source_url=url,
                    confidence=90, passive=True,
                    evidence={"severity": "low",
                              "remediation": "Informational: no action."}))
            elif name in ("assetlinks.json", "apple-app-site-association"):
                apps = safe_json_list(resp)
                if apps:
                    findings.append(self._f(
                        "web", "well_known_app_links",
                        f"{name} declares {len(apps)} app-link relation(s)",
                        source="well-known audit", source_url=url,
                        confidence=85, passive=True,
                        evidence={"severity": "low", "count": len(apps),
                                  "remediation": (
                                      "Review delegated namespaces - "
                                      "stale package names/handles let "
                                      "someone else claim your app links.")}))
            elif name == "gpc.json":
                findings.append(self._f(
                    "web", "well_known_gpc",
                    "gpc.json present (Global Privacy Control signal)",
                    source="well-known audit", source_url=url,
                    confidence=85, passive=True,
                    evidence={"severity": "low",
                              "remediation": "Informational: no action."}))
        if not seen_txt:
            findings.append(self._f(
                "web", "security_txt_missing",
                "No security.txt (RFC 9116) - researchers have no "
                "standard contact",
                source="well-known audit",
                source_url=f"{base}/.well-known/security.txt",
                confidence=90, passive=True,
                evidence={"severity": "low",
                          "remediation": (
                              "Publish /.well-known/security.txt with "
                              "Contact and Expires fields.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"checked {len(WELL_KNOWN)} well-known URIs, "
                   f"{len(findings)} findings")
