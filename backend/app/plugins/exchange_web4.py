"""Exchange-web detectors, block 4: REST API configuration in
bundles.

Ten detectors for API-surface configuration an exchange frontend
ships to browsers: internal/admin base URLs, staging hosts in
production, admin-enabling flags, hidden treasury/compliance API
routes. Presence/config detection only (see _exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web4"

SPECS = [
    S("exch_internal_api_base_prod", "Internal API Base URL in Production Bundle",
      "medium",
      "The bundle names an internal API base URL (api-internal / internal host), mapping the private API tier for anyone who reads the code.",
      "Keep internal base URLs out of shipped code; the browser should know only the public API gateway.",
      patterns=[r"(?:apiBase|baseURL|apiUrl|API_BASE)\s*[:=]\s*['\"]https?://[^'\"]*internal[^'\"]*['\"]",
                r"['\"]https?://api-internal\.[^'\"]+['\"]"],
      category="api"),
    S("exch_admin_api_base_frontend", "Admin API Base URL in Frontend Config",
      "medium",
      "Frontend config carries a separate admin API base URL, disclosing the admin tier's location even though no customer browser should ever call it.",
      "Remove admin base URLs from customer builds; admin tooling should be a separate app on a restricted network.",
      patterns=[r"(?:adminApi|adminBase|ADMIN_API)[A-Za-z_]*\s*[:=]\s*['\"]https?://[^'\"]+['\"]",
                r"['\"]https?://admin-api\.[^'\"]+['\"]"],
      category="api"),
    S("exch_staging_api_host_prod", "Staging/Dev API Host Shipped to Production",
      "medium",
      "The production bundle references a staging or dev API host. Staging APIs usually have weaker auth and test data paths, and their presence proves environment config leaks across builds.",
      "Inject API hosts per environment at build time and fail production builds that reference staging/dev hosts.",
      patterns=[r"['\"]https?://(?:staging|stage|dev|qa)[.-][^'\"]*(?:api|exchange)[^'\"]*['\"]",
                r"(?:staging|dev)(?:Api|API)(?:Host|Url|Base)\s*[:=]\s*['\"]https?://[^'\"]+['\"]"],
      category="api"),
    S("exch_debug_flag_admin_enable", "Debug/Admin Feature Flag Enabled in Shipped Config",
      "high",
      "Shipped config enables a debug or admin-mode flag (enableAdmin / adminMode / debugMode true), which in many codebases unlocks privileged UI and API paths for any visitor who finds the toggle.",
      "Ship production config with admin/debug flags off, and enforce privilege server-side regardless of any client flag.",
      patterns=[r"(?:enableAdmin|adminMode|isAdmin|debugMode|enableDebug)\s*[:=]\s*true",
                r"['\"](?:enableAdmin|adminMode|debugMode)['\"]\s*:\s*true"],
      category="web"),
    S("exch_deprecated_api_version_ref", "Deprecated API Version Still Referenced in Routes",
      "low",
      "Client routes still reference a deprecated/legacy API version path. Deprecated versions often miss newer auth and rate-limit fixes and stay live long after the frontend moves on.",
      "Retire deprecated API versions or pin them behind the same auth controls as current versions, and remove stale references from shipped code.",
      patterns=[r"['\"]/(?:api|sapi|wapi)/v1/(?:account|trade|withdraw|order)[^'\"]*['\"][\s\S]{0,200}?deprecated",
                r"deprecated[\s\S]{0,200}?['\"]/(?:api|sapi|wapi)/v1/(?:account|trade|withdraw|order)[^'\"]*['\"]"],
      category="api"),
    S("exch_treasury_api_route_ref", "Treasury API Route Referenced in JS",
      "medium",
      "JS code references a treasury API route (moving exchange funds). Customer-facing code should never name treasury endpoints; the reference maps a high-value target.",
      "Remove treasury routes from customer builds and keep treasury tooling on a separate, network-restricted application.",
      patterns=[r"['\"]/(?:api/)?(?:v\d/)?treasury/(?:transfer|move|withdraw|sweep|balance)[^'\"]*['\"]",
                r"['\"]/api/(?:internal/)?treasury[^'\"]*['\"]"],
      category="api"),
    S("exch_compliance_api_route_ref", "Compliance/KYC-Admin API Route Referenced in JS",
      "medium",
      "JS code references a compliance or KYC-admin API route (review queues, document decisions), which belongs to internal tooling, not the customer app.",
      "Keep compliance-admin routes out of the customer build; serve them only in the internal console.",
      patterns=[r"['\"]/(?:api/)?(?:v\d/)?(?:compliance|kyc-admin|kyc_admin)/(?:review|queue|approve|documents)[^'\"]*['\"]",
                r"['\"]/api/(?:internal/)?compliance[^'\"]*['\"]"],
      category="api"),
    S("exch_localhost_api_prod_bundle", "Localhost API Base in Shipped Bundle",
      "low",
      "The shipped bundle points an API base at localhost/127.0.0.1, a build-hygiene failure showing environment config is not controlled - the same failure mode that ships staging hosts and test keys to production.",
      "Fail production builds that contain localhost endpoints and inject the API base per environment.",
      patterns=[r"(?:apiBase|baseURL|apiUrl|API_BASE|apiEndpoint)\s*[:=]\s*['\"]https?://(?:localhost|127\.0\.0\.1)(?::\d+)?[^'\"]*['\"]"],
      category="api"),
    S("exch_ops_feature_flag_ref", "Treasury/Ops Feature Flag Referenced in Client Config",
      "medium",
      "Client config names a feature flag for treasury/ops functions. Even disabled, the flag name and its gating logic show attackers exactly which privileged functions the client can unlock.",
      "Keep ops feature flags and their names server-side; the client should receive rendered UI for its role only.",
      patterns=[r"(?:featureFlags?|flags)\s*[:=]\s*\{[^}]{0,300}?(?:treasury|ops|admin)[A-Za-z_]*\s*[:=]",
                r"['\"](?:enableTreasury|enableOps|treasuryOps|opsPanel)['\"]\s*:\s*(?:true|false)"],
      category="web"),
    S("exch_internal_route_path_ref", "Internal API Path Referenced in JS Routes",
      "medium",
      "JS route tables reference /internal/ API paths, disclosing the internal route layout of the API tier to every visitor.",
      "Strip internal routes from customer builds and enforce that /internal/ paths are unreachable from public networks.",
      patterns=[r"['\"]/api/internal/[^'\"]+['\"]",
                r"['\"]/internal/(?:api|admin|ops)/[^'\"]+['\"]"],
      category="api"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web4(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
