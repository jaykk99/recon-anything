"""Known-set expansion engine: "use known to find more".

One pass (called by the runner when a run's jobs settle):

1. Read the run's findings and its original targets (the seeds).
2. Extract candidate assets (domains, subdomains, IPs, URLs,
   endpoints, JS files, emails, wallets, repos, certs, orgs).
3. Check hunt memory first (data service): assets already in the
   known set are skipped, dead ends are never re-walked.
4. New candidates are confirmed into the known set through the data
   service, attributed to their hunter, and audited.
5. Expansion rules per asset type generate follow-up jobs with the
   existing detection plugins on new target rows in the same run.
   Confirmed results of those jobs feed the next pass, so the known
   set grows frontier by frontier until the depth or task budget
   runs out (env: RECON_HUNTER_MAX_DEPTH default 2,
   RECON_HUNTER_MAX_TASKS default 300, RECON_HUNTERS_ENABLED=0 off).

Detection only: hunters generate leads and dispatch the existing
detection plugins. No exploitation, no credential attacks, no auth
bypass, no private-data access. Wallet pivots use read-only chain
data plugins only. Breach pivots move metadata only.

Knowledge use: expansion consults the data service for the bundled
packs (subdomain wordlist, secret patterns, tech fingerprints) and
for cached library resources (e.g. the SecLists subdomain list when
a fetch has populated the cache); the counts ride in the pass audit
record so the consultation is visible, not decorative.
"""
from __future__ import annotations

import os
import re
import uuid
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from ..agentdata import packs as _packs
from ..agentdata import resources as _resources
from ..agentdata import store
from ..classifier import domain_from_target
from ..models import Finding as FindingRow
from ..models import PluginJob, Run, Target as TargetRow
from .roles import EXPANSION, KEY_TO_ASSET

SYSTEM = store.DEFAULT_SYSTEM
MAX_DEPTH = int(os.environ.get("RECON_HUNTER_MAX_DEPTH", "2"))
MAX_TASKS = int(os.environ.get("RECON_HUNTER_MAX_TASKS", "300"))
MAX_PLUGINS_PER_ASSET = 6
ENABLED = os.environ.get("RECON_HUNTERS_ENABLED", "1") == "1"

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24}$")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_BTC_RE = re.compile(r"\b(bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-zA-HJ-NP-Z0-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_REPO_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def hunters_enabled() -> bool:
    return ENABLED


_SLD = {"co", "com", "org", "net", "ac", "gov", "edu"}


def _registrable(host: str) -> str:
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def root_key(target_type: str, normalized: str) -> str:
    """The memory/known-set key for a target: its registrable root
    domain when it has one, else the normalized value itself."""
    dom = domain_from_target(target_type, normalized or "")
    if dom:
        return _registrable(dom.lower())
    return (normalized or "").strip().lower()


# Asset type -> target type for verification jobs. Deterministic on
# purpose: the free-text classifier mislabels some hosts (its
# play_store heuristic fires on substrings), and a hunter asset's type
# is already known, so there is nothing to guess.
ASSET_TARGET_TYPE = {
    "domain": "domain", "subdomain": "domain", "cert": "domain",
    "ip": "ip", "url": "url", "endpoint": "url", "js_file": "url",
    "repo": "url", "email": "email", "wallet": "crypto_wallet",
    "org": "person_or_company",
}


def _clean_domain(value: str) -> str:
    v = (value or "").strip().lower().rstrip(".")
    v = v.split()[0] if v else ""
    v = v.strip("[]()<>\"'")
    if "://" in v:
        v = urlparse(v).netloc or v
    v = v.split(":")[0]
    return v


def extract_assets(findings, targets) -> List[Dict]:
    """Findings + seed targets -> candidate assets.

    Returns [{type, value, found_by, via}] deduped by (type, value).
    Pure function of its inputs: unit-tested without a database.
    """
    out: Dict[Tuple[str, str], Dict] = {}

    def add(asset_type, value, found_by, via):
        value = (value or "").strip()
        if not value or len(value) > 500:
            return
        key = (asset_type, value)
        if key not in out:
            out[key] = {"type": asset_type, "value": value,
                        "found_by": found_by, "via": via}

    for t in targets:
        norm = getattr(t, "normalized", "") or getattr(t, "raw", "")
        ttype = getattr(t, "type", "")
        if ttype == "domain":
            add("domain", _clean_domain(norm), "seed", "target")
        elif ttype == "url":
            add("url", norm, "seed", "target")
        elif ttype == "ip":
            add("ip", norm, "seed", "target")
        elif ttype == "email":
            add("email", norm.lower(), "seed", "target")
        elif ttype == "crypto_wallet":
            add("wallet", norm, "seed", "target")
        elif ttype == "github":
            add("repo", norm if norm.startswith("http")
                else f"https://github.com/{norm}", "seed", "target")

    for f in findings:
        key = (f.key or "")
        val = (f.value or "").strip()
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        mapped = KEY_TO_ASSET.get(key)
        if mapped:
            asset_type, hunter = mapped
            if asset_type in ("subdomain", "cert", "domain"):
                add(asset_type, _clean_domain(val), hunter, key)
            elif asset_type == "ip":
                tok = val.split()[0] if val else ""
                add("ip", tok, hunter, key)
            elif asset_type == "email":
                m = _EMAIL_RE.search(val)
                add("email", (m.group(0) if m else val).lower(), hunter, key)
            elif asset_type in ("url", "endpoint", "js_file"):
                add(asset_type, val, hunter, key)
            elif asset_type == "wallet":
                m = _BTC_RE.search(val) or _ETH_RE.search(val)
                add("wallet", m.group(0) if m else val, hunter, key)
            elif asset_type in ("repo", "org"):
                add(asset_type, val, hunter, key)
        # shape-based extraction from any finding value / source url
        for text in (val, f.source_url or ""):
            if not text:
                continue
            m = _REPO_RE.search(text)
            if m:
                add("repo", f"https://github.com/{m.group(1)}/{m.group(2)}",
                    "repo_hunter", "shape")
            if text.startswith(("http://", "https://")):
                path = urlparse(text).path.lower()
                if path.endswith(".js"):
                    add("js_file", text.split()[0], "js_miner", "shape")
            for m in _EMAIL_RE.finditer(text):
                add("email", m.group(0).lower(), "email_hunter", "shape")
            for m in _ETH_RE.finditer(text):
                add("wallet", m.group(0), "wallet_hunter", "shape")
    return [a for a in out.values()
            if a["type"] not in ("subdomain", "domain", "cert")
            or _DOMAIN_RE.match(a["value"] or "")]


def hunter_wordlist(session) -> List[str]:
    """The subdomain wordlist hunters consult, resolved through the
    data service: bundled pack first, then the cached SecLists
    resource when the library has been stocked."""
    words = list(_packs.pack_entries("subdomain_wordlist"))
    try:
        cached = _resources.cached_lines(session, "seclists-subdomains")
    except Exception:
        cached = []
    seen = set(words)
    for w in cached:
        if w not in seen:
            seen.add(w)
            words.append(w)
    return words


def knowledge_snapshot(session) -> Dict:
    """What the hunters consulted this pass (audit detail)."""
    snap = {"packs": {p["name"]: p["entries"]
                      for p in _packs.pack_inventory()}}
    try:
        snap["wordlist_total"] = len(hunter_wordlist(session))
    except Exception:
        snap["wordlist_total"] = 0
    return snap


def _primary_key(targets, accum: Dict) -> str:
    """The run's primary target key: the root of the first target that
    is not hunter-created (the seed the user actually scanned)."""
    hunter_ids = set(accum.get("hunter_targets", []))
    for t in targets:
        if t.id not in hunter_ids and t.normalized:
            return root_key(t.type, t.normalized)
    for t in targets:
        if t.normalized:
            return root_key(t.type, t.normalized)
    return ""


def new_accum() -> Dict:
    return {"depth": 0, "tasks_used": 0, "assets_new": 0, "jobs": 0,
            "expanded": [], "hunter_targets": [],
            "known_before": {}, "per_hunter": {}}


def _per_hunter(accum: Dict, hunter: str) -> Dict:
    return accum["per_hunter"].setdefault(hunter, {"assets": 0, "jobs": 0})


def hunter_expand(session, run: Run, accum: Dict,
                  advance_depth: bool = True) -> int:
    """Run one expansion pass. Mutates accum. Returns jobs enqueued.

    advance_depth=False is the incremental mid-run mode used by the
    runner's hunter sweep: jobs join the live queue as findings land,
    but the depth counter (asset generations) only advances on the
    settle/finalize passes, so early passes cannot burn the depth
    budget before late findings arrive. The expanded-marker set and
    the task budget bound incremental passes exactly like settle ones.
    """
    if not ENABLED:
        return 0
    findings = session.query(FindingRow).filter_by(run_id=run.id).all()
    targets = session.query(TargetRow).filter_by(run_id=run.id).all()
    target_keys = sorted({root_key(t.type, t.normalized) for t in targets
                          if t.normalized})
    if not target_keys:
        return 0
    primary_key = _primary_key(targets, accum)

    for tk in target_keys:
        if tk not in accum["known_before"]:
            accum["known_before"][tk] = store.known_total(session, SYSTEM, tk)

    assets = extract_assets(findings, targets)
    dead = set()
    for tk in target_keys:
        dead |= store.dead_end_values(session, SYSTEM, tk)
    already_known: Set[Tuple[str, str]] = set()
    for tk in target_keys:
        for a in store.get_known_set(session, SYSTEM, tk):
            already_known.add((a["type"], a["value"]))

    depth = accum["depth"]
    # Host-family dedupe: the same host must not re-enter the set as
    # "domain" after it was confirmed as "subdomain" (or the reverse)
    # when a later pass re-reads hunter-created targets as seeds.
    host_family = {"domain", "subdomain", "cert"}
    known_hosts = {v for (t, v) in already_known if t in host_family}
    new_assets: List[Dict] = []
    for a in assets:
        if a["value"] in dead:
            continue
        if a["type"] in host_family and a["value"] in known_hosts:
            continue
        tk = primary_key
        # assets belong to the target key whose root they sit under
        for cand in target_keys:
            if a["value"].endswith(cand) or cand in a["value"]:
                tk = cand
                break
        if (a["type"], a["value"]) in already_known:
            continue
        _row, created = store.add_known_asset(
            session, SYSTEM, tk, a["type"], a["value"],
            found_by=a["found_by"], run_id=run.id, depth=depth,
            meta={"via": a["via"]})
        if created:
            already_known.add((a["type"], a["value"]))
            if a["type"] in host_family:
                known_hosts.add(a["value"])
            new_assets.append(a)
            accum["assets_new"] += 1
            _per_hunter(accum, a["found_by"])["assets"] += 1
            store.record_action(session, SYSTEM, tk, a["found_by"],
                                "asset_found", run_id=run.id,
                                asset_type=a["type"], asset_value=a["value"],
                                detail={"via": a["via"], "depth": depth})

    # Expansion frontier: new assets this pass, plus seeds (depth 0)
    # that have not been expanded yet in this run.
    expanded = set(accum["expanded"])
    frontier = []
    for a in new_assets:
        frontier.append((a, depth))
    if depth == 0:
        for a in assets:
            if a["found_by"] == "seed":
                frontier.append((a, 0))

    from ..plugins.registry import discover
    from ..plugins.priority import priority_for
    from ..runner import (DEFAULT_PLUGIN_ESTIMATE_S,
                          PLUGIN_TIME_ESTIMATES)
    registry = discover()
    existing_targets = {t.normalized for t in targets}
    existing_jobs = {(j.target_id, j.plugin_id) for j in
                     session.query(PluginJob).filter_by(run_id=run.id).all()}
    target_by_norm = {t.normalized: t for t in targets}
    bounty = bool((run.summary or {}).get("bounty"))

    enqueued = 0
    for a, a_depth in frontier:
        if a_depth > MAX_DEPTH:
            continue
        marker = f"{a['type']}:{a['value']}"
        if marker in expanded:
            continue
        expanded.add(marker)
        accum["expanded"] = sorted(expanded)
        rules = EXPANSION.get(a["type"], [])
        if not rules:
            continue
        ttype = ASSET_TARGET_TYPE.get(a["type"])
        if ttype is None:
            continue
        norm = a["value"]
        trobj = target_by_norm.get(norm)
        if trobj is None:
            if norm in existing_targets:
                continue
            trobj = TargetRow(id=uuid.uuid4().hex[:12], run_id=run.id,
                              raw=a["value"], type=ttype,
                              normalized=norm)
            session.add(trobj)
            session.commit()
            existing_targets.add(norm)
            target_by_norm[norm] = trobj
            accum["hunter_targets"].append(trobj.id)
        used_for_asset = 0
        for hunter, plugin_ids in rules:
            for pid in plugin_ids:
                if accum["tasks_used"] >= MAX_TASKS:
                    break
                if used_for_asset >= MAX_PLUGINS_PER_ASSET:
                    break
                pcls = registry.get(pid)
                if pcls is None:
                    continue
                pinst = pcls()
                if pinst.accepts and ttype not in pinst.accepts:
                    continue
                if (trobj.id, pid) in existing_jobs:
                    continue
                session.add(PluginJob(
                    run_id=run.id, target_id=trobj.id, plugin_id=pid,
                    phase=getattr(pinst, "phase", 1),
                    priority=priority_for(pid, bounty=bounty),
                    estimate_s=PLUGIN_TIME_ESTIMATES.get(
                        pid, DEFAULT_PLUGIN_ESTIMATE_S),
                    status="queued"))
                existing_jobs.add((trobj.id, pid))
                accum["tasks_used"] += 1
                used_for_asset += 1
                enqueued += 1
                _per_hunter(accum, hunter)["jobs"] += 1
                store.record_action(
                    session, SYSTEM, primary_key, hunter, "job_enqueued",
                    run_id=run.id, asset_type=a["type"],
                    asset_value=a["value"],
                    detail={"plugin": pid, "target": norm,
                            "depth": a_depth})
            if accum["tasks_used"] >= MAX_TASKS:
                break
    session.commit()
    store.record_action(session, SYSTEM, primary_key, "hunter_engine",
                        "expand_pass", run_id=run.id,
                        detail={"depth": depth, "new_assets": len(new_assets),
                                "jobs_enqueued": enqueued,
                                "knowledge": knowledge_snapshot(session)})
    accum["jobs"] += enqueued
    if enqueued and advance_depth:
        accum["depth"] = depth + 1
    return enqueued


def finalize_hunt(session, run: Run, accum: Dict) -> Dict:
    """Close out the hunt for a finished run: dead ends for hunter
    targets that produced nothing, and the memory write hunters will
    read next time. Returns the public summary section."""
    findings = session.query(FindingRow).filter_by(run_id=run.id).all()
    targets = session.query(TargetRow).filter_by(run_id=run.id).all()
    target_keys = sorted({root_key(t.type, t.normalized) for t in targets
                          if t.normalized})
    by_target: Dict[str, int] = {}
    counts_by_cat: Dict[str, int] = {}
    for f in findings:
        by_target[f.target_id] = by_target.get(f.target_id, 0) + 1
        counts_by_cat[f.category] = counts_by_cat.get(f.category, 0) + 1
    target_by_id = {t.id: t for t in targets}
    for tid in accum.get("hunter_targets", []):
        t = target_by_id.get(tid)
        if t is None or by_target.get(tid, 0) > 0:
            continue
        tk = root_key(t.type, t.normalized)
        if store.add_dead_end(session, SYSTEM, tk, t.type, t.normalized,
                              run_id=run.id,
                              reason="hunter target produced no findings"):
            store.record_action(session, SYSTEM, tk, "hunter_engine",
                                "dead_end", run_id=run.id,
                                asset_type=t.type, asset_value=t.normalized)
    primary = _primary_key(targets, accum)
    per_key = {}
    for tk in target_keys:
        before = accum.get("known_before", {}).get(tk)
        after = store.known_total(session, SYSTEM, tk)
        if before is None:
            before = after
        # Memory is written for the primary target and for any key the
        # hunt actually stocked. Other target rows in the run (plugin
        # generated host spellings and the like) stay out of memory so
        # the growth report only tracks real known sets.
        if tk != primary and after == 0:
            continue
        per_key[tk] = {"known_before": before, "known_after": after}
        store.record_run_summary(session, SYSTEM, tk, run.id, before, after,
                                 counts_by_cat)
    return {
        "known_before": per_key.get(primary, {}).get("known_before", 0),
        "known_after": per_key.get(primary, {}).get("known_after", 0),
        "known_by_target": per_key,
        "extra_assets": accum.get("assets_new", 0),
        "extra_jobs": accum.get("jobs", 0),
        "depth_reached": accum.get("depth", 0),
        "per_hunter": accum.get("per_hunter", {}),
        "note": ("hunters expanded the known set and dispatched "
                 "verification plugins on the new frontier; "
                 "detection only, no chat"),
    }
