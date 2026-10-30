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
