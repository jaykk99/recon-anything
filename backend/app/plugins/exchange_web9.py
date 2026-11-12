"""Exchange-web detectors, block 9: admin/internal surface
presence.

Ten detectors for references to admin and internal surfaces in a
site's own public text (robots files, sitemaps, JS route tables,
bundle config): admin panels, treasury/ops tooling, employee SSO,
internal hostnames. Presence detection only - no path is ever
requested by these detectors beyond the homepage the shared
plumbing already fetches (see _exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web9"

SPECS = [
    S("exch_admin_panel_route_ref", "Admin Panel Path in JS Routes or Page Text",
      "medium",
      "Shipped routes or page text reference an admin panel path, naming the staff console's location for every visitor.",
      "Serve the admin console as a separate app on a restricted network and strip its routes from the customer build.",
      patterns=[r"['\"]/(?:admin|administrator)/(?:login|dashboard|panel|users|orders)[^'\"]*['\"]",
                r"path\s*[:=]\s*['\"]/admin[^'\"]*['\"]"],
      category="web"),
    S("exch_treasury_ops_panel_ref", "Treasury/Ops Panel Reference in Client Code",
      "medium",
      "Client code references a treasury or operations panel surface, disclosing the internal tooling layout for the exchange's fund operations.",
      "Keep treasury/ops panels out of the customer build entirely; internal tooling gets its own deployment.",
      patterns=[r"['\"]/(?:ops|treasury-panel|treasury)/(?:dashboard|panel|console)[^'\"]*['\"]",
                r"(?:treasuryPanel|opsConsole|opsPanel)\s*[:=]\s*['\"][^'\"]+['\"]"],
      category="web"),
    S("exch_compliance_panel_ref", "Compliance Panel Reference in Client Code",
      "low",
      "Client code references a compliance panel/console surface, mapping the internal review tooling for KYC and transaction monitoring.",
      "Remove compliance tooling references from the customer build.",
      patterns=[r"['\"]/(?:compliance)/(?:panel|console|dashboard|review-queue)[^'\"]*['\"]",
                r"(?:compliancePanel|complianceConsole)\s*[:=]\s*['\"][^'\"]+['\"]"],
      category="web"),
    S("exch_employee_sso_endpoint_ref", "Employee SSO Endpoint Disclosed in Config",
      "medium",
      "Shipped config names an employee SSO endpoint (Okta/OneLogin/Azure AD tenant for staff), giving attackers the exact door for staff phishing and password spraying.",
      "Keep employee SSO endpoints out of customer-facing config; staff tooling should carry its own configuration.",
      patterns=[r"(?:sso|okta|onelogin)[A-Za-z_]*\s*[:=]\s*['\"]https?://[^'\"]*(?:okta\.com|onelogin\.com|microsoftonline\.com)[^'\"]*['\"]",
                r"['\"]https?://[^'\"]*(?:employee|staff)[^'\"]*(?:sso|okta|login)[^'\"]*['\"]"],
      category="identity"),
    S("exch_internal_hostname_bundle", "Internal Hostname in Bundle Text",
      "medium",
      "Bundle text contains an internal-only hostname (*.internal, *.corp, *.lan style), mapping the private network's naming scheme for outsiders.",
      "Strip internal hostnames from shipped artifacts and refer to internal services through the API tier only.",
      patterns=[r"[a-z0-9\-]+\.(?:internal|corp|lan|intranet)\b",
                r"['\"]https?://[a-z0-9\-]+\.(?:internal|corp|intranet)[^'\"]*['\"]"],
      category="infra"),
    S("exch_support_impersonation_route_ref", "Support Impersonation/Admin Route Referenced in JS",
      "high",
      "JS code references a support impersonation or login-as route - one of the highest-value staff functions - naming it for anyone who reads the bundle.",
      "Remove impersonation routes from customer code, gate them behind staff SSO plus step-up auth, and audit their use.",
      patterns=[r"['\"][^'\"]*(?:impersonate|login-as|loginAs|switch-user)[^'\"]*['\"]",
                r"(?:impersonation|impersonate)[A-Za-z]*\s*[:=]\s*['\"]/[^'\"]+['\"]"],
      category="web"),
    S("exch_internal_health_endpoint_ref", "Internal Health/Metrics Endpoint Referenced in Code",
      "low",
      "Code references an internal health or metrics endpoint (actuator, /internal/health, metrics), which typically answers without auth on the internal network and sometimes beyond it.",
      "Keep health/metrics endpoints off public route tables and bind them to internal interfaces only.",
      patterns=[r"['\"]/(?:actuator|internal/health|internal/metrics|metrics/internal)[^'\"]*['\"]",
                r"(?:healthEndpoint|metricsUrl)\s*[:=]\s*['\"]https?://[^'\"]*(?:actuator|internal)[^'\"]*['\"]"],
      category="infra"),
    S("exch_robots_admin_disallow", "Admin Paths Disclosed in robots.txt Disallow Lines",
      "low",
      "robots.txt names admin/internal paths in Disallow lines, publishing a map of the sensitive surfaces to every crawler and visitor.",
      "Do not list sensitive paths in robots.txt; protect them with authentication and network controls instead of obscurity.",
      patterns=[r"(?m)^\s*Disallow\s*:\s*/(?:admin|internal|ops|treasury|backoffice)\S*\s*$",
                r"(?m)^\s*Disallow\s*:\s*/\S*(?:admin-panel|staff|console)\S*\s*$"],
      category="web"),
    S("exch_sitemap_admin_url", "Admin/Internal URL Present in Sitemap",
      "low",
      "The sitemap lists an admin or internal URL, which both maps the surface and invites indexing of pages that should never be public.",
      "Remove admin/internal URLs from the sitemap and return 404/403 for them on the public host.",
      patterns=[r"<loc>[^<]*(?:/admin/|/internal/|/ops/|/backoffice/)[^<]*</loc>",
                r"<url>[\s\S]{0,200}?<loc>[^<]*(?:admin|internal)[^<]*</loc>"],
      category="web"),
    S("exch_ops_tooling_hostname_ref", "Ops Tooling Hostname Referenced in Bundle",
      "medium",
      "Bundle text references an ops tooling host (Grafana/Kibana/Jenkins-style), naming internal monitoring and CI surfaces for outsiders.",
      "Strip tooling hostnames from shipped artifacts; tooling lives behind VPN/SSO and its names are not public information.",
      patterns=[r"['\"]https?://(?:grafana|kibana|jenkins|argocd|vault)\.[^'\"]+['\"]",
                r"(?:grafana|kibana|jenkins)(?:Url|Host)\s*[:=]\s*['\"]https?://[^'\"]+['\"]"],
      category="infra"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web9(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
