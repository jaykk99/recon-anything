"""Finding-driven chaining: stored findings decide what runs next.

Hunter expansion pivots on ASSETS (a new subdomain gets generic
verification plugins). Chaining pivots on SIGNALS inside findings:
when a finding says a target runs WordPress, speaks GraphQL, exposes
a JWT, or serves an OpenAPI map, the specialized plugins for that
signal are queued on THAT target in the same run - if they have not
already run there.

This module is the pure planner: it reads stored Finding rows (the
same plugin/category/key/value/source shape the runs API serves) and
returns a per-target plugin plan plus the set of "hot" targets whose
findings are high-value. The engine does the enqueueing, so chained
jobs share the hunter task budget, the per-pass cap, and the
dispatcher's anti-starvation/budget gates. Detection only: every
plugin chained here is an existing detection plugin.

Cross-run reuse rides the known set: assets confirmed in earlier
scans are re-seeded by the engine, their plugins re-run, their tech
findings reappear, and chaining fires again on fresh evidence -
prior findings are never re-derived or ignored, they are re-earned
through the persisted known set.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

# Chained jobs per expansion pass, on top of the shared task budget.
MAX_CHAIN_JOBS_PER_PASS = 200

_VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")

# Tech/fingerprint keys whose VALUE names the software stack. A human
# reads the stack string and decides the next move from it (a CMS, a
# GraphQL hint, a login portal, a version worth a CVE lookup, a CDN in
# front that invites origin discovery). The real plugins emit these:
# webtech -> tech/server_header/x_powered_by/page_title; apidiscover ->
# server_header/backend_hint.
_TECH_KEYS = {"tech", "fingerprint_summary", "server_header",
              "x_powered_by", "page_title", "app_title", "app_version",
              "backend_hint", "generator", "powered_by"}

_CMS_TOKENS = ("wordpress", "wp-", "joomla", "drupal", "magento", "typo3",
               "ghost", "shopify", "prestashop", "opencart", "sitecore",
               "aem", "contentful", "craftcms", "umbraco", "sharepoint")

# CDN / WAF front: the real origin is elsewhere. A human pivots to
# origin discovery (reverse-IP / passive DNS / favicon-hash of the
# origin) when a CDN is fronting the site.
_CDN_TOKENS = ("cloudflare", "akamai", "fastly", "incapsula", "imperva",
               "sucuri", "stackpath", "cloudfront", "azure front door",
               "google frontend")

_CLOUD_TOKENS = ("s3.amazonaws.com", "storage.googleapis.com",
                 "blob.core.windows.net", "digitaloceanspaces.com",
                 "r2.cloudflarestorage.com", "s3.", ".s3-",
                 "amazonaws.com", "oss-", "cos.ap-")


# Finding keys that mean "an admin / login / privileged panel exists here".
# These surfaces are where broken-access-control, IDOR and auth-bypass
# findings (the high-$ bounty tiers) actually live, so a hit here should
# pull the whole access-control probe set onto this target.
_PANEL_KEYS = {"exposed_admin_panel", "panel_path", "login_forms",
               "admin_panel", "login_portal"}
_PANEL_VALUE_TOKENS = ("admin", "login", "signin", "sign in", "dashboard",
                       "wp-admin", "wp-login", "phpmyadmin", "adminer",
                       "console", "controlpanel", "control panel", "manage",
                       "auth", "sso", "account", "portal", "/api/admin")

# Finding keys that mean "a secret / credential was pointed at or exposed".
# One leaked pointer justifies a full secret sweep of the same target.
# (Keys verified against the emitting plugins: js_secrets -> js_secret,
# sourcemap -> sourcemap_secret/sourcemap_cred_comment, etc.)
_SECRET_KEYS = {"exposed_env", "laravel_env", "comment_secret",
                "exposed_generic_secret", "exposed_private_key",
                "hardcoded_password", "exposed_aws_key", "exposed_aws_secret",
                "exposed_github_token", "exposed_stripe_key", "js_secret",
                "sourcemap_secret", "sourcemap_cred_comment",
                "exposed_api_key", "exposed_slack_token", "exposed_gcp_key",
                "firebase_config", "basic_auth_creds"}

# Keys that mean "source maps / rich JS are present" -> deep JS mining,
# which routinely recovers internal endpoints and embedded secrets.
# Matched to real emitters: jsdeep -> js_endpoint/source_map, sourcemap
# -> sourcemap_exposed/sourcemap_internal_url/sourcemap_api_route,
# js_endpoints -> hidden_api_endpoint, webtech/apidiscover -> endpoint_js.
_SOURCEMAP_KEYS = {"sourcemap_exposed", "sourcemap_file", "sourcemap_sources",
                   "sourcemap_internal_url", "sourcemap_api_route",
                   "sourcemap_debug_flag", "source_map", "js_file",
                   "js_endpoint", "endpoint_js", "js_analysis",
                   "reconstructed_source_tree", "js_bundle_count"}

# Keys that mean "this subdomain may be a dangling takeover" -> confirm it.
_TAKEOVER_KEYS = {"takeover_candidate", "takeover_possible", "takeover_note",
                  "dangling", "subdomain_takeover", "cname"}

# API-surface keys: an endpoint map is the launch point for the
# object-level access-control + param probes that pay the best.
# (apidiscover -> openapi_paths/api_docs/api_map_entries/endpoint/
# graphql_endpoint; js_endpoints -> hidden_api_endpoint; hiddenpaths ->
# hidden_endpoint.)
_API_KEYS = {"openapi_paths", "api_docs", "api_map_entries", "api_call",
             "api_endpoint", "endpoint", "bank_api_surface",
             "hidden_api_endpoint", "hidden_endpoint", "options_allow",
             "swagger", "wsdl", "grpc_endpoint"}

# Parameter keys: a reflected or accepted parameter is where injection
# and object-level flaws live. accepted -> the whole param/injection
# probe set; reflected -> XSS first.
_PARAM_ACCEPTED_KEYS = {"param_accepted", "param_discovered", "param_hidden",
                        "fuzz_param_anomaly", "parameter"}
_PARAM_REFLECTED_KEYS = {"param_reflected", "reflected_param"}

# Open directory / path discovery -> sweep for backups, archives and
# more paths, then mine anything exposed for secrets.
_DIR_KEYS = {"open_directory", "opendir_archived", "dir_brute_hit",
             "hidden_endpoint", "discovered_path", "dirsearch_path",
             "directory_listing", "autoindex"}

# robots/sitemap "disallow" entries name paths the owner did not want
# crawled - exactly where a human looks next.
_PATHHINT_KEYS = {"robots_disallow", "sitemap_interesting", "robots_sitemap"}

# Form / input surface -> auth + parameter testing.
_FORM_KEYS = {"interesting_form", "form_inventory", "login_form",
              "upload_form", "search_form"}

# Email discovered -> breach cross-reference + mail-infra audit.
_EMAIL_KEYS = {"email_found", "email_pattern", "email", "email_address"}

# Open port / service banner -> service + version follow-up.
_PORT_KEYS = {"port_open", "tcp_banner", "http_banner", "service_detected"}

# Outdated-software banners -> straight to the CVE matchers.
_VERSIONED_KEYS = {"outdated_software", "cve_match", "nuclei_cve_match",
                   "version_disclosure"}

# Aggressive injection probes: a human only fires these in ACTIVE mode.
# In passive mode they are withheld so chaining stays passive-safe
# (the plugins also self-gate, but withholding keeps the queue clean).
_AGGRESSIVE = {"sqli", "xss", "cmdi", "rce", "ssti", "nosqli", "xpathi",
               "traversal", "ssrf", "smuggling", "cache_poisoning",
               "param_fuzzer", "deserialization_detect", "bola", "idor",
               "idorleak", "idor_comparator", "rate_limit_audit",
               "oauth_redirect_uri_validator"}


def _signal_plugins(key: str, value: str,
                    mode: str = "active") -> List[Tuple[str, str]]:
    """One finding -> [(signal, plugin_id)] it should chain to.

    Pure pattern matching over the stored finding's key/value; the
    engine intersects the plugin ids with the registry, each plugin's
    accepted target types, and the jobs already in the run. Every plugin
    named here is an existing DETECTION plugin - chaining only decides
    what already-built detection runs where, never what payload is sent.

    This is the "what would a human do next" map. It is deliberately
    broad: a real operator pivots off almost every signal (a tech
    banner, an open port, a discovered email, a reflected parameter, a
    directory listing, a CDN in front of the origin), not just the
    handful of highest-value ones. The keys are matched to what the
    emitting plugins actually produce, so a rule fires on real findings
    instead of names no plugin ever sets.

    `mode` gates the aggressive injection probes: in passive mode they
    are withheld, so a passive scan chains only passive-safe detection.
    """
    k = (key or "").strip().lower()
    v = (value or "").strip().lower()
    active = (mode or "active").strip().lower() != "passive"
    out: List[Tuple[str, str]] = []

    def add(signal: str, *pids: str):
        for pid in pids:
            if pid in _AGGRESSIVE and not active:
                continue
            out.append((signal, pid))

    # -- tech / fingerprint string: read the stack, pick the follow-up --
    if k in _TECH_KEYS:
        if any(tok in v for tok in _CMS_TOKENS):
            add("cms", "cms_probes", "cves", "backup")
            if "wordpress" in v or "wp-" in v:
                add("wordpress", "wpscan_scan")
        if "graphql" in v:
            add("graphql", "graphql", "graphql_probe", "apidiscover")
        if any(t in v for t in ("login", "sign in", "signin", "sso",
                                "keycloak", "okta", "auth0")):
            add("login_portal", "auth", "auth_surface", "endpointauth",
                "openid_discovery")
        if any(t in v for t in _CDN_TOKENS):
            # CDN/WAF fronting the site -> hunt the real origin.
            add("cdn_origin", "reverse_ip", "passive_dns", "favicon_hash")
        if _VERSION_RE.search(v):
            add("versioned_tech", "cves", "nuclei_cve_pack")

    # -- GraphQL anywhere -> the GraphQL + API probe set ----------------
    if k in ("graphql_endpoint", "graphql_introspection", "graphiql_ui",
             "graphql_types") or "graphql" in k:
        add("graphql", "graphql", "graphql_deep", "graphql_probe",
            "apidiscover")

    # -- JWT anywhere -> decode + weakness audit ------------------------
    if k.startswith("jwt"):
        add("jwt", "jwt", "jwt_audit")

    # -- API surface -> object-level access-control + parameter probes --
    if k in _API_KEYS:
        add("api_surface", "apidiscover", "param_discovery", "param_fuzzer",
            "bola", "idor", "idor_comparator")

    # -- admin / login / privileged panel -> access-control probe set ---
    if k in _PANEL_KEYS or (k in ("dir_brute_hit", "hidden_path",
                                  "hidden_endpoint", "discovered_path",
                                  "dirsearch_path", "open_directory")
                            and any(t in v for t in _PANEL_VALUE_TOKENS)):
        add("admin_panel", "auth", "auth_surface", "endpointauth",
            "idor", "bola", "param_fuzzer")

    # -- exposed secret / env pointer -> sweep the target for more ------
    if k in _SECRET_KEYS:
        add("exposed_secret", "secrets", "gitleaks_scan", "js_secrets",
            "keyleak")

    # -- source maps / rich JS present -> deep JS mining ---------------
    if k in _SOURCEMAP_KEYS:
        add("sourcemap", "sourcemap", "jsdeep", "js_secrets", "js_endpoints")

    # -- dangling / unclaimed record -> confirm the subdomain takeover --
    if k in _TAKEOVER_KEYS:
        add("takeover", "takeover")

    # -- open redirect -> SSRF chain (the classic escalation) ----------
    if k in ("open_redirect", "redirect_off_domain", "ssrf_open_redirect"):
        add("open_redirect", "ssrf")

    # -- permissive CORS -> credentialed cross-origin reads ------------
    if k in ("cors_misconfig", "cors_wildcard", "cors_reflect",
             "cors_methods"):
        add("cors", "cors", "jwt", "jwt_audit", "endpointauth")

    # -- exposed VCS -> recover the repo + its secrets -----------------
    if k in ("git_exposed", "svn_exposed", "hg_exposed"):
        add("git_exposed", "gitleaks_scan", "git")

    # -- parameters: injection + object-level follow-up ----------------
    if k in _PARAM_REFLECTED_KEYS:
        add("param_reflected", "xss", "param_fuzzer")
    if k in _PARAM_ACCEPTED_KEYS:
        add("param_accepted", "param_fuzzer", "sqli", "idor",
            "param_discovery")

    # -- directory listing / path discovery -> sweep + mine ------------
    if k in _DIR_KEYS:
        add("open_dir", "dirsearch", "backup", "secrets")
    if k in _PATHHINT_KEYS:
        # robots/sitemap disallow names paths the owner hid -> go look.
        add("path_hint", "hiddenpaths", "dirsearch", "backup")

    # -- a form is an input surface -> auth + parameter testing --------
    if k in _FORM_KEYS:
        add("form", "auth", "authscan", "param_fuzzer", "param_discovery")

    # -- a discovered email -> breach cross-ref + mail-infra audit -----
    if k in _EMAIL_KEYS:
        add("email", "email_breach", "breachwatch", "email_infra")

    # -- open port / banner -> service + version follow-up -------------
    if k in _PORT_KEYS:
        add("open_port", "banners", "port_scan")
        if any(t in v for t in ("http", "https", "80", "443", "8080",
                                "8443")):
            add("web_port", "headers", "webtech", "http_methods")
    if k in _VERSIONED_KEYS:
        add("versioned", "cves", "nuclei_cve_pack")

    # -- cloud storage reference anywhere in the value -----------------
    if k in ("cloud_bucket_ref", "s3_public_read", "s3_public_list",
             "bucket_public_list") or any(tok in v for tok in _CLOUD_TOKENS):
        add("cloud_storage", "cloud_buckets", "s3", "cloud_enum")

    # -- info-disclosure / debug surfaces -> error-mining + path hunt --
    if k in ("phpinfo_exposed", "debug_endpoint", "stacktrace",
             "error_response_disclosure", "exposed_debug"):
        add("info_disclosure", "exposed_debug", "error_pages",
            "infodisclosure")

    return out


def plan_chains(findings, targets,
                mode: str = "active") -> Tuple[Dict[str, List[str]],
                                               Set[str],
                                               Dict[str, List[str]]]:
    """Stored findings -> (plan, hot_target_ids, signals_by_target).

    plan maps target_id -> ordered unique plugin ids to queue on that
    target. hot_target_ids are targets carrying a critical/high-value
    finding: they get HIGH-priority chained jobs and first claim on
    the expansion frontier. A target with no signal findings plans
    nothing - a finding-less target queues nothing extra.

    `mode` is the run's mode ("passive"|"active"); it is forwarded to
    the signal map so a passive run never chains an aggressive probe.
    """
    target_ids = {t.id for t in targets}
    plan: Dict[str, List[str]] = {}
    signals: Dict[str, List[str]] = {}
    hot: Set[str] = set()
    for f in findings:
        tid = getattr(f, "target_id", "")
        if tid not in target_ids:
            continue
        ev = f.evidence if isinstance(getattr(f, "evidence", None), dict) \
            else {}
        sev = str(ev.get("severity", "")).lower()
        if (getattr(f, "bounty_value", "") or "") in ("critical", "high") \
                or sev in ("critical", "high"):
            hot.add(tid)
        for signal, pid in _signal_plugins(f.key or "", f.value or "", mode):
            lst = plan.setdefault(tid, [])
            if pid not in lst:
                lst.append(pid)
            sig = signals.setdefault(tid, [])
            if signal not in sig:
                sig.append(signal)
    return plan, hot, signals


def hot_values(findings, targets) -> Set[str]:
    """Values the frontier sort should treat as hot: the normalized
    values of hot targets plus the values of their high-value
    findings themselves, so a node already proven interesting expands
    before an unproven one."""
    _plan, hot, _sig = plan_chains(findings, targets)
    by_id = {t.id: t for t in targets}
    out: Set[str] = set()
    for tid in hot:
        t = by_id.get(tid)
        if t is not None and t.normalized:
            out.add(t.normalized)
    for f in findings:
        if getattr(f, "target_id", "") in hot and f.value:
            out.add(f.value)
    return out
