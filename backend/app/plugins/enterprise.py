"""Enterprise software detector.

Detects SAP, Oracle, Salesforce, SharePoint, and other enterprise
products. Flags exposed admin panels and version disclosure.
Read-only. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

ENTERPRISE_SIGS = [
    (r"sap|/sap/bc/", "SAP", ["/sap/bc/gui/sap/its/webgui", "/sap/public/"]),
    (r"oracle|weblogic", "Oracle (WebLogic/Fusion)", ["/console/login/LoginForm.jsp"]),
    (r"salesforce|force\.com|lightning", "Salesforce", []),
    (r"sharepoint|/_layouts/", "Microsoft SharePoint", ["/_layouts/15/viewlsts.aspx"]),
    (r"servicenow", "ServiceNow", []),
    (r"workday", "Workday", []),
    (r"sap\.hybris|hybris", "SAP Hybris Commerce", []),
    (r"peoplesoft|psp/", "Oracle PeopleSoft", ["/psp/"]),
    (r"siteminder|smagent", "CA SiteMinder SSO", []),
    (r"okta", "Okta SSO", []),
    (r"jenkins", "Jenkins CI", ["/login"]),
    (r"jira|atlassian", "Atlassian Jira", ["/secure/Dashboard.jspa"]),
    (r"confluence", "Atlassian Confluence", ["/login.action"]),
]

REMEDIATION = ("Restrict enterprise admin panels to VPN, enforce MFA, "
               "patch promptly, and disable version disclosure.")


class EnterprisePlugin(Plugin):
    id = "enterprise"
    label = "Enterprise Software Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Detect SAP, Oracle, SharePoint, Jira and admin panels."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:400000]
            text = html + " " + str(page["headers"])
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        seen = set()
        for pat, name, admin_paths in ENTERPRISE_SIGS:
            if re.search(pat, text, re.I) and name not in seen:
                seen.add(name)
                findings.append(self._f(
                    "web", "enterprise_software",
                    f"Enterprise software detected: {name}. Verify admin "
                    f"panels are not exposed and versions are patched.",
                    source="Enterprise fingerprint", source_url=page_url,
                    confidence=70, passive=passive,
                    evidence={"severity": "medium", "product": name,
                              "remediation": REMEDIATION,
                              "scope_note": "Detection only. Authorized testing only."}))
                # probe admin paths
                for ap in admin_paths[:2]:
                    url = base + ap
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", url,
                                         timeout=12, follow_redirects=False)
                        if pr.status_code in (200, 401, 403):
                            findings.append(self._f(
                                "web", "enterprise_admin",
                                f"Enterprise admin surface: {name} panel at "
                                f"{url} (HTTP {pr.status_code}).",
                                source="Enterprise probe", source_url=url,
                                confidence=75, passive=passive,
                                evidence={"severity": "high",
                                          "remediation": REMEDIATION,
                                          "scope_note": "Read-only probe. Authorized testing only."}))
                    except Exception:
                        continue
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} enterprise findings")
        res.duration_ms = dur
        return res
