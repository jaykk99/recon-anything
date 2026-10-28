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

_TECH_KEYS = {"tech", "fingerprint_summary", "server_header",
              "x_powered_by", "page_title", "app_title"}

_CMS_TOKENS = ("wordpress", "joomla", "drupal", "magento", "typo3",
               "ghost", "shopify", "prestashop", "opencart")

_CLOUD_TOKENS = ("s3.amazonaws.com", "storage.googleapis.com",
                 "blob.core.windows.net", "digitaloceanspaces.com",
                 "r2.cloudflarestorage.com")


# Finding keys that mean "an admin / login / privileged panel exists here".
# These surfaces are where broken-access-control, IDOR and auth-bypass
# findings (the high-$ bounty tiers) actually live, so a hit here should
# pull the whole access-control probe set onto this target.
_PANEL_KEYS = {"exposed_admin_panel", "panel_path", "login_forms",
               "admin_panel", "login_portal"}
_PANEL_VALUE_TOKENS = ("admin", "login", "signin", "sign in", "dashboard",
                       "wp-admin", "phpmyadmin", "adminer", "console",
                       "controlpanel", "control panel", "manage")

# Finding keys that mean "a secret / credential was pointed at or exposed".
# One leaked pointer justifies a full secret sweep of the same target.
_SECRET_KEYS = {"exposed_env", "laravel_env", "comment_secret",
                "exposed_generic_secret", "exposed_private_key",
                "hardcoded_password", "exposed_aws_key", "exposed_aws_secret",
                "exposed_github_token", "exposed_stripe_key", "js_secret"}

# Keys that mean "source maps / rich JS are present" -> deep JS mining,
# which routinely recovers internal endpoints and embedded secrets.
_SOURCEMAP_KEYS = {"sourcemap_exposed", "sourcemap_file", "sourcemap_sources",
                   "sourcemap_internal_url", "sourcemap_api_route", "js_file",
                   "js_endpoint", "endpoint_js"}

# Keys that mean "this subdomain may be a dangling takeover" -> confirm it.
_TAKEOVER_KEYS = {"takeover_candidate", "takeover_possible", "takeover_note",
                  "dangling", "subdomain_takeover"}

# API-surface keys: an endpoint map is the launch point for the
# object-level access-control + param probes that pay the best.
_API_KEYS = {"openapi_paths", "api_docs", "api_map_entries", "api_call",
             "api_endpoint", "endpoint", "bank_api_surface"}


def _signal_plugins(key: str, value: str) -> List[Tuple[str, str]]:
    """One finding -> [(signal, plugin_id)] it should chain to.

    Pure pattern matching over the stored finding's key/value; the
    engine intersects the plugin ids with the registry, each plugin's
    accepted target types, and the jobs already in the run. Every plugin
    named here is an existing DETECTION plugin - chaining only decides
    what already-built detection runs where, never what payload is sent.

    The map is deliberately biased toward the signals that precede the
    high-value (high-$ bounty) finding classes: privileged panels ->
    access-control probes, API maps -> IDOR/BOLA/param probes, secret
    pointers -> full secret sweep, source maps -> deep JS mining,
    dangling records -> takeover confirmation, open redirects -> SSRF.
    """
    k = (key or "").strip().lower()
    v = (value or "").strip().lower()
    out: List[Tuple[str, str]] = []

    def add(signal: str, *pids: str):
        for pid in pids:
            out.append((signal, pid))

    if k in _TECH_KEYS:
        if any(tok in v for tok in _CMS_TOKENS):
            add("cms", "cms_probes", "cves", "backup")
        if "graphql" in v:
            add("graphql", "graphql", "graphql_probe", "apidiscover")
        if "login" in v or "sign in" in v:
            add("login_portal", "auth", "auth_surface", "endpointauth")
        if _VERSION_RE.search(v):
            add("versioned_tech", "cves")
    if k == "graphql_endpoint" or "graphql" in k:
        add("graphql", "graphql", "graphql_deep", "graphql_probe",
            "apidiscover")
    if k.startswith("jwt"):
        add("jwt", "jwt", "jwt_audit")
    # API surface -> the object-level access-control + parameter probes
    # that produce IDOR/BOLA (high) and behaviour-changing params.
    if k in _API_KEYS:
        add("api_surface", "apidiscover", "param_discovery", "param_fuzzer",
            "bola", "idor", "idor_comparator")
    # Admin / login / privileged panel -> full access-control probe set.
    if k in _PANEL_KEYS or (k in ("dir_brute_hit", "hidden_path")
                            and any(t in v for t in _PANEL_VALUE_TOKENS)):
        add("admin_panel", "auth", "auth_surface", "endpointauth",
            "idor", "bola", "param_fuzzer")
    # A single exposed secret / env pointer -> sweep the target for more.
    if k in _SECRET_KEYS:
        add("exposed_secret", "secrets", "gitleaks_scan", "js_secrets",
            "keyleak")
    # Source maps / rich JS present -> deep JS mining (endpoints+secrets).
    if k in _SOURCEMAP_KEYS:
        add("sourcemap", "sourcemap", "jsdeep", "js_secrets", "js_endpoints")
    # Dangling / unclaimed record -> confirm the subdomain takeover.
    if k in _TAKEOVER_KEYS:
        add("takeover", "takeover")
    # Open redirect -> SSRF chain (the classic "complex" escalation).
    if k == "open_redirect" or k == "redirect_off_domain":
        add("open_redirect", "ssrf")
    # Permissive CORS -> credentialed cross-origin reads: audit the token
    # and the authenticated surface it would expose.
    if k == "cors_misconfig":
        add("cors", "jwt", "jwt_audit", "endpointauth")
    if k == "git_exposed":
        add("git_exposed", "gitleaks_scan", "git")
    if any(tok in v for tok in _CLOUD_TOKENS):
        add("cloud_storage", "cloud_buckets", "s3", "cloud_enum")
    return out


def plan_chains(findings, targets) -> Tuple[Dict[str, List[str]],
                                            Set[str],
                                            Dict[str, List[str]]]:
    """Stored findings -> (plan, hot_target_ids, signals_by_target).

    plan maps target_id -> ordered unique plugin ids to queue on that
    target. hot_target_ids are targets carrying a critical/high-value
    finding: they get HIGH-priority chained jobs and first claim on
    the expansion frontier. A target with no signal findings plans
    nothing - a finding-less target queues nothing extra.
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
        for signal, pid in _signal_plugins(f.key or "", f.value or ""):
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
