"""Enterprise software detector.

Detects SAP, Oracle, Salesforce, Microsoft (SharePoint, Dynamics 365,
Power BI, Exchange OWA/ECP), ServiceNow, Workday, Atlassian
(Jira/Confluence/Bitbucket/Bamboo), Tableau, Qlik, Splunk, Elastic
Kibana, SolarWinds, ManageEngine, and other enterprise products.
Flags exposed admin panels and version disclosure.
Read-only. Authorized testing only. Never attempts credentials.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (detection regex, product name, admin paths to probe)
ENTERPRISE_SIGS = [
    (r"sap|/sap/bc/|/sap/public/", "SAP",
     ["/sap/bc/gui/sap/its/webgui", "/sap/bc/ui5_ui5", "/irj/portal",
      "/sap/public/"]),
    (r"oracle|weblogic|/em/|/oam/", "Oracle (WebLogic/Fusion/EM/OAM)",
     ["/console/login/LoginForm.jsp", "/em/", "/oam/"]),
    (r"salesforce|force\.com|lightning", "Salesforce", ["/s/"]),
    (r"sharepoint|/_layouts/", "Microsoft SharePoint",
     ["/_layouts/15/viewlsts.aspx"]),
    (r"crm\.dynamics\.com|dynamics 365", "Microsoft Dynamics 365", []),
    (r"powerbi|powerbi\.com", "Microsoft Power BI", []),
    (r"/owa/|/ecp/|outlook web app", "Microsoft Exchange OWA/ECP",
     ["/owa/", "/ecp/"]),
    (r"servicenow", "ServiceNow", ["/navpage.do"]),
    (r"workday", "Workday", []),
    (r"sap\.hybris|hybris", "SAP Hybris Commerce", []),
    (r"peoplesoft|psp/", "Oracle PeopleSoft", ["/psp/"]),
    (r"siteminder|smagent", "CA SiteMinder SSO", []),
    (r"okta", "Okta SSO", []),
    (r"jenkins", "Jenkins CI", ["/login"]),
    (r"jira|atlassian", "Atlassian Jira", ["/secure/Dashboard.jspa"]),
    (r"confluence", "Atlassian Confluence", ["/login.action"]),
    (r"bitbucket", "Atlassian Bitbucket", ["/login"]),
    (r"bamboo", "Atlassian Bamboo", ["/login.action"]),
    (r"tableau|/views/", "Tableau Server", ["/views/"]),
    (r"qlik", "Qlik Sense", ["/hub/"]),
    (r"splunk", "Splunk", ["/en-US/account/login"]),
    (r"kibana|/app/kibana", "Elastic Kibana", ["/app/kibana", "/login"]),
    (r"solarwinds|orion", "SolarWinds Orion", ["/Orion/Login.aspx"]),
    (r"manageengine", "ManageEngine", ["/"]),
]

# Admin paths whose exposure is high severity on their own (mail flow,
# config panels). Everything else: exposed login panel = medium.
HIGH_ADMIN_PATHS = {"/ecp/"}

# Hints in a login panel body that default credentials are suggested.
DEFAULT_CRED_HINTS = re.compile(
    r"default\s+(user|password|credentials)|admin[/:]admin|"
    r"username:\s*admin", re.I)

REMEDIATION = ("Restrict enterprise admin panels to VPN, enforce MFA, "
               "patch promptly, and disable version disclosure.")


class EnterprisePlugin(Plugin):
    id = "enterprise"
    label = "Enterprise Software Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Detect SAP, Oracle, Salesforce, SharePoint, Exchange, "
                   "ServiceNow, Atlassian, Tableau, Splunk, Kibana and "
                   "admin panels. Read-only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
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
            page_url = page["url"]
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
                            body = pr.text[:8000]
                            sev = "medium"
                            note = (f"exposed {name} login/admin panel at "
                                    f"{url} (HTTP {pr.status_code})")
                            # high-value panels and default-cred hints
                            if ap in HIGH_ADMIN_PATHS:
                                sev = "high"
                                note += (" - high-value mail admin panel; "
                                         "restrict to VPN + MFA")
                            elif DEFAULT_CRED_HINTS.search(body):
                                sev = "high"
                                note += (" - page hints at default "
                                         "credentials; change them now")
                            findings.append(self._f(
                                "web", "enterprise_admin",
                                f"Enterprise admin surface ({sev}): {note}.",
                                source="Enterprise probe", source_url=url,
                                confidence=75, passive=passive,
                                evidence={"severity": sev,
                                          "remediation": REMEDIATION,
                                          "scope_note": "Read-only probe. "
                                          "Authorized testing only. No "
                                          "credential attempts made."}))
                    except Exception:
                        continue
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} enterprise findings")
        res.duration_ms = dur
        return res
