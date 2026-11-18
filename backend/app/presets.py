"""One-click scan presets (anti-Amass).

Amass's weakness is configuration: unmatched depth, but you have to
already know the tool to get it. These presets make the common scan
shapes one click, with zero config:

- ``quick``    Quick Triage - passive only, the fast discovery set
               (DNS, subdomains, TLS, tech, WHOIS, published emails),
               no hunter expansion past the seed targets (depth 0).
               Answers "what is this
               target and what does it expose?" in minutes.
- ``standard`` Standard - the full default plugin set in active mode
               with hunter expansion to depth 1. The scan you run
               when you do not know what you are looking at yet.
- ``deep``     Deep - every applicable plugin including the deep
               crawlers and chain follow-ups, active mode, hunter
               expansion to the full depth cap. The Amass-depth scan,
               still one click.

A preset resolves to exactly the inputs POST /api/runs already
accepts - mode, an explicit plugin id list, and the per-run hunter
depth cap stored in queue_meta (app/hunters/engine.py honors it) -
so presets compose with everything downstream: plan gating still
filters the resolved list for customers, "selected means run" still
holds, and the run records which preset produced it.

Plugin ids are resolved against the LIVE registry at request time
(``resolve_preset``), never hard-coded snapshots: a plugin added or
removed later changes the preset's contents, not its meaning. The
quick set is defined by id because "fast + passive" is a property of
specific known plugins; unknown ids are dropped at resolve time.
"""
from __future__ import annotations

from typing import Dict, List, Optional

# The Quick Triage set: passive, fast, high-signal discovery only.
# Resolved against the live registry; ids that no longer exist are
# dropped silently (the preset degrades, never errors).
QUICK_PLUGIN_IDS = [
    "dns", "subdomains", "passive_subdomains", "tls", "rdap",
    "headers", "webtech", "tech_fingerprint", "emails", "wayback",
    "robots", "favicon_hash", "dns_infra", "email_infra", "caa_audit",
    "smtp_tls", "hsts",
]

# Plugins whose whole job is going deeper (crawl chains, deep JS,
# phase-2 follow-ups). Standard excludes them; Deep is defined as
# "everything applicable", so it needs no list.
DEEP_ONLY_PLUGIN_IDS = [
    "deepcrawl", "chain_followups", "jsdeep", "artifacts_deep",
    "graphql_deep", "stealth_crawler", "hakrawler", "katana",
    "feroxbuster", "gobuster", "dir_brute", "subdomain_brute",
]

# Task workflows: purpose-built scans for one kind of job, not a
# breadth tier. Each is a curated plugin set run in active mode with a
# sensible depth. They all share WORKFLOW_BASE - the discovery +
# expansion plugins the hunter engine dispatches on new assets - so that
# "selected means run" does not starve expansion/chaining: a workflow
# still turns a found subdomain/IP/endpoint into deeper work, it just
# keeps the follow-up focused on the task's own plugins.
WORKFLOW_BASE = [
    "dns", "dns_infra", "subdomains", "passive_subdomains", "subfinder",
    "rapiddns", "tls", "rdap", "headers", "webtech", "tech_fingerprint",
    "favicon_hash", "httpx_probe", "robots", "wayback", "ports", "banners",
    "reverse_ip", "passive_dns", "cdn_detect",
]

TAKEOVER_IDS = WORKFLOW_BASE + ["takeover", "cloudflare_detect"]

SECRETS_IDS = WORKFLOW_BASE + [
    "js_secrets", "jsdeep", "js_endpoints", "jsminer", "sourcemap",
    "secrets", "keyleak", "keyharvest", "gitleaks_scan", "git_exposed",
    "git", "s3", "cloud_buckets", "cloud_enum",
]

API_IDS = WORKFLOW_BASE + [
    "apidiscover", "graphql", "graphql_deep", "graphql_probe",
    "param_discovery", "param_fuzzer", "idor", "bola", "idor_comparator",
    "jwt", "jwt_audit", "cors", "openid_discovery",
    "oauth_redirect_uri_validator", "auth", "auth_surface", "endpointauth",
    "browser_render", "js_endpoints",
]

WEBAPP_IDS = WORKFLOW_BASE + [
    "crawler", "deepcrawl", "browser_render", "hiddenpaths", "dirsearch",
    "backup", "cves", "nuclei_cve_pack", "xss", "sqli", "ssrf", "cmdi",
    "ssti", "traversal", "cors", "csp_audit", "cookie_security",
    "clickjack", "http_methods", "forms", "redirect_chain", "smuggling",
    "js_endpoints", "js_secrets", "apidiscover",
]

PRESETS: Dict[str, Dict] = {
    "quick": {
        "id": "quick",
        "label": "Quick Triage",
        "description": "Passive only. Fast discovery: DNS, subdomains, "
                       "TLS, tech, WHOIS, published contacts. No hunter "
                       "expansion. Minutes, zero packets to the target "
                       "beyond public data sources.",
        "mode": "passive",
        "max_depth": 0,
        "plugin_ids": QUICK_PLUGIN_IDS,
    },
    "standard": {
        "id": "standard",
        "label": "Standard",
        "description": "The full default plugin set in active mode, "
                       "hunters expand one hop from each seed. The "
                       "right scan when you do not know what you are "
                       "looking at yet.",
        "mode": "active",
        "max_depth": 1,
        "plugin_ids": None,  # None = full default set minus deep-only
        "exclude_deep_only": True,
    },
    "deep": {
        "id": "deep",
        "label": "Deep",
        "description": "Every applicable plugin including deep "
                       "crawlers and chained follow-ups, active mode, "
                       "hunters expand to the full depth cap. Maximum "
                       "coverage, one click.",
        "mode": "active",
        "max_depth": None,  # None = engine default cap
        "plugin_ids": None,
        "exclude_deep_only": False,
    },
    # -- task workflows -------------------------------------------------
    "takeover": {
        "id": "takeover",
        "label": "Subdomain Takeover Hunt",
        "description": "Enumerate subdomains from every passive source, "
                       "resolve them, and confirm dangling / unclaimed "
                       "records that can be taken over. Expands two hops.",
        "mode": "active",
        "max_depth": 2,
        "plugin_ids": TAKEOVER_IDS,
    },
    "secrets": {
        "id": "secrets",
        "label": "Secret & Leak Sweep",
        "description": "Mine JS bundles, source maps, exposed VCS and "
                       "cloud storage for credentials and secrets, then "
                       "sweep anything a leak points at.",
        "mode": "active",
        "max_depth": 2,
        "plugin_ids": SECRETS_IDS,
    },
    "api": {
        "id": "api",
        "label": "API & Auth Security",
        "description": "Map the API surface (incl. live XHR/fetch via a "
                       "headless render), then test it for broken object-"
                       "level access control, parameter flaws, JWT and "
                       "CORS weaknesses.",
        "mode": "active",
        "max_depth": 1,
        "plugin_ids": API_IDS,
    },
    "webapp": {
        "id": "webapp",
        "label": "Web App Deep Dive",
        "description": "Full web-app assessment: crawl + headless render, "
                       "content/path discovery, CVEs, and the injection / "
                       "misconfig probe set. Active, one hop of expansion.",
        "mode": "active",
        "max_depth": 1,
        "plugin_ids": WEBAPP_IDS,
    },
    "contract": {
        "id": "contract",
        "label": "Smart Contract Audit",
        "description": "Full contract-analysis stack on a chain address: "
                       "source/bytecode recon, logic flaws, drain checks, "
                       "auditor tooling and the deep-audit detectors. "
                       "Applicable plugins only, maximum depth.",
        "mode": "active",
        "max_depth": None,
        "plugin_ids": None,   # full applicable set = the contract stack
        "exclude_deep_only": False,
    },
}


def list_presets() -> List[Dict]:
    """Preset metadata for the UI (no resolution - registry-free)."""
    return [{"id": p["id"], "label": p["label"],
             "description": p["description"], "mode": p["mode"],
             "max_depth": p["max_depth"]}
            for p in PRESETS.values()]


def resolve_preset(preset_id: str,
                   registry_ids: Optional[List[str]] = None) -> Dict:
    """Resolve a preset to concrete run inputs.

    Returns {preset, label, mode, plugins, max_depth} where
    ``plugins`` is an explicit id list, or None to mean "the full
    default set" (the runner's own selection semantics). Raises
    KeyError for an unknown preset id - the API turns that into a
    400, so a typo'd preset never silently becomes a full scan.
    """
    preset = PRESETS[preset_id]
    if registry_ids is None:
        from .plugins.registry import describe
        registry_ids = [p["id"] for p in describe()]
    known = set(registry_ids)
    if preset["plugin_ids"] is not None:
        plugins = [pid for pid in preset["plugin_ids"] if pid in known]
    elif preset.get("exclude_deep_only"):
        deep = set(DEEP_ONLY_PLUGIN_IDS)
        plugins = [pid for pid in registry_ids if pid not in deep]
    else:
        plugins = None
    return {"preset": preset["id"], "label": preset["label"],
            "mode": preset["mode"], "plugins": plugins,
            "max_depth": preset["max_depth"]}
