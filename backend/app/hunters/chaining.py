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


def _signal_plugins(key: str, value: str) -> List[Tuple[str, str]]:
    """One finding -> [(signal, plugin_id)] it should chain to.

    Pure pattern matching over the stored finding's key/value; the
    engine intersects the plugin ids with the registry, each plugin's
    accepted target types, and the jobs already in the run.
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
            add("graphql", "graphql", "apidiscover")
        if "login" in v or "sign in" in v:
            add("login_portal", "auth", "auth_surface", "endpointauth")
        if _VERSION_RE.search(v):
            add("versioned_tech", "cves")
    if k == "graphql_endpoint" or "graphql" in k:
        add("graphql", "graphql", "apidiscover")
    if k.startswith("jwt"):
        add("jwt", "jwt")
    if k in ("openapi_paths", "api_docs", "api_map_entries", "api_call",
             "api_endpoint", "endpoint"):
        add("api_surface", "apidiscover", "param_discovery", "bola")
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
