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
   runs out (env: RECON_HUNTER_MAX_DEPTH default 3,
   RECON_HUNTER_MAX_TASKS default 1500, RECON_HUNTERS_ENABLED=0 off).

Compounding: the first pass of a run also re-seeds the frontier from
the PERSISTED known set (assets confirmed by earlier scans of the
same target), so a rescan does not start over - known nodes get
fresh verification jobs (deduped against the run), their new
findings feed extraction again, and only dead ends (which expire
after a TTL) stay closed. Re-seeded expansion is budget-capped
(RECON_HUNTER_REEXPAND_FRACTION of the task budget) and new assets
always outrank re-seeded ones, so deltas are hunted first.

Chaining: stored findings also queue specialized plugins on the
target that produced them (see chaining.py): a WordPress tech
finding queues the CMS/CVE plugins on that target in the same run,
inside the same budget.

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

import ipaddress
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
from .roles import EXPANDABLE_TYPES, EXPANSION, KEY_TO_ASSET

SYSTEM = store.DEFAULT_SYSTEM
MAX_DEPTH = int(os.environ.get("RECON_HUNTER_MAX_DEPTH", "3"))
MAX_TASKS = int(os.environ.get("RECON_HUNTER_MAX_TASKS", "1500"))
MAX_PLUGINS_PER_ASSET = 12
# One pass may not flood the queue: the dispatcher interleaves by
# estimate, but a single 1500-job dump would still bury the seed
# plugins' findings under hunter work for the rest of the scan
# budget. Passes repeat as findings settle, so a per-pass cap costs
# nothing in total coverage.
MAX_TASKS_PER_PASS = int(
    os.environ.get("RECON_HUNTER_MAX_TASKS_PER_PASS", "500"))
# Share of the task budget that re-seeding the persisted known set
# (re-verifying nodes from earlier scans) may consume per run. New
# assets found in THIS run always get first claim on the rest.
REEXPAND_FRACTION = float(
    os.environ.get("RECON_HUNTER_REEXPAND_FRACTION", "0.4"))
# Cap on persisted assets re-seeded into one run's frontier.
KNOWN_SEED_LIMIT = int(
    os.environ.get("RECON_HUNTER_KNOWN_SEED_LIMIT", "250"))
ENABLED = os.environ.get("RECON_HUNTERS_ENABLED", "1") == "1"

# Frontier claim order: genuinely new attack surface first (a new
# registrable domain is worth more than another email), credentials
# and identity nodes last. Lower expands first when budget is tight.
ASSET_PRIORITY = {"domain": 0, "ip": 1, "subdomain": 2, "url": 3,
                  "endpoint": 3, "js_file": 4, "repo": 5, "email": 6,
                  "wallet": 6, "org": 7, "cert": 8}

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


def canon_ip(value: str) -> str:
    """Canonical IP form: compressed IPv6, normalized IPv4. The same
    address spelled two ways (2606:4700:0::6813:df11 vs
    2606:4700::6813:df11) must be ONE known-set asset, or expansion
    budget is burned re-hunting the same node."""
    v = (value or "").strip()
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v.lower()


def canon_url(value: str) -> str:
    """Canonical URL form for asset identity: lowercase scheme/host,
    default ports dropped, fragment dropped, root path unified
    (https://EXAMPLE.com:443/ == https://example.com). Path case and
    query are significant and preserved."""
    v = (value or "").strip()
    if "://" not in v:
        return v
    try:
        p = urlparse(v)
        port = p.port
    except ValueError:
        return v
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower()
    if not host:
        return v
    netloc = host
    if port and not ((scheme == "http" and port == 80)
                     or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = p.path or ""
    if path == "/":
        path = ""
    elif len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    q = f"?{p.query}" if p.query else ""
    return f"{scheme}://{netloc}{path}{q}"


def _canonical_value(asset_type: str, value: str) -> str:
    if asset_type in ("domain", "subdomain", "cert"):
        return _clean_domain(value)
    if asset_type == "ip":
        return canon_ip(value)
    if asset_type in ("url", "endpoint", "js_file"):
        return canon_url(value)
    if asset_type == "email":
        return value.lower()
    if asset_type == "wallet" and value.lower().startswith("0x"):
        # ETH addresses are case-insensitive identity (EIP-55 casing
        # is display-only); BTC/base58 strings are case-SENSITIVE and
        # are never folded.
        return value.lower()
    return value


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
        # Canonicalize BEFORE identity: the same node spelled two
        # ways (case, trailing dot, IPv6 compression, default port,
        # URL fragment) is one asset, or the known set fills with
        # duplicates and expansion budget is spent re-hunting them.
        value = _canonical_value(asset_type, value)
        if not value:
            return
        key = (asset_type, value)
        if key not in out:
            out[key] = {"type": asset_type, "value": value,
                        "found_by": found_by, "via": via}

    # Registrable roots of the run's own targets: a cert SAN (or any
    # host) OUTSIDE these roots is a related domain owned via the
    # same certificate, not a subdomain of the target - it is
    # promoted to a domain asset for the neighbor hunter.
    target_roots: Set[str] = set()
    for t in targets:
        d = domain_from_target(getattr(t, "type", ""),
                               getattr(t, "normalized", "")
                               or getattr(t, "raw", ""))
        if d:
            target_roots.add(_registrable(d.lower()))

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
            if key == "mx":
                # MX values are "10 mail.example.com." - the host is
                # the last token, not the priority number.
                toks = val.split()
                val = toks[-1] if toks else val
            if asset_type in ("subdomain", "cert", "domain"):
                host = _clean_domain(val)
                if (asset_type == "subdomain" and key == "tls_san"
                        and target_roots
                        and _registrable(host) not in target_roots):
                    add("domain", host, "neighbor_hunter", key)
                else:
                    add(asset_type, host, hunter, key)
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
    # A host extracted as both "domain" and "subdomain" is one node:
    # keep the domain entry (it carries the wider expansion rules).
    domain_vals = {a["value"] for a in out.values()
                   if a["type"] == "domain"}
    return [a for a in out.values()
            if not (a["type"] == "subdomain"
                    and a["value"] in domain_vals)
            and (a["type"] not in ("subdomain", "domain", "cert")
                 or _DOMAIN_RE.match(a["value"] or ""))]


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
            "known_before": {}, "per_hunter": {},
            "known_seeded": False, "tasks_reexpand": 0,
            "chained_jobs": 0}


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
    known_rows: Dict[Tuple[str, str], Dict] = {}
    for tk in target_keys:
        for a in store.get_known_set(session, SYSTEM, tk):
            already_known.add((a["type"], a["value"]))
            known_rows.setdefault((a["type"], a["value"]), a)

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
        # assets belong to the target key whose root they sit under:
        # registrable-root equality for hosts, suffix/substring for
        # the rest (URLs and emails contain their domain)
        if a["type"] in host_family:
            root = _registrable(a["value"])
            if root in target_keys:
                tk = root
        else:
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
    # that have not been expanded yet in this run, plus - once per
    # run - the PERSISTED known set from earlier scans of this
    # target, so a rescan compounds instead of starting over.
    # Entries are (asset, depth, is_known_reseed).
    expanded = set(accum["expanded"])
    frontier = []
    for a in new_assets:
        frontier.append((a, depth, False))
    if depth == 0:
        for a in assets:
            if a["found_by"] == "seed":
                frontier.append((a, 0, False))
    if not accum.get("known_seeded"):
        accum["known_seeded"] = True
        new_pairs = {(a["type"], a["value"]) for a in new_assets}
        seed_norms = {t.normalized for t in targets}
        seen_hosts: Set[str] = set()
        ordered_known = sorted(
            known_rows.items(),
            key=lambda kv: (ASSET_PRIORITY.get(kv[0][0], 9),
                            kv[1].get("depth") or 0))
        reseeds = 0
        for (ktype, kval), row in ordered_known:
            if reseeds >= KNOWN_SEED_LIMIT:
                break
            if ktype not in EXPANDABLE_TYPES:
                continue
            if (ktype, kval) in new_pairs or kval in dead:
                continue
            if ktype in host_family:
                if kval in seen_hosts or kval in seed_norms:
                    continue
                seen_hosts.add(kval)
            frontier.append((
                {"type": ktype, "value": kval,
                 "found_by": row.get("found_by") or "known_set",
                 "via": "known_set"},
                min(row.get("depth") or 0, MAX_DEPTH), True))
            reseeds += 1
    # Claim order: nodes behind high-value findings first, then new
    # surface before identity nodes, shallower before deeper, and
    # this run's discoveries before re-seeded known nodes.
    from .chaining import hot_values
    hot = hot_values(findings, targets)

    def _frontier_key(item):
        a, d, is_known = item
        return (0 if a["value"] in hot else 1,
                ASSET_PRIORITY.get(a["type"], 9), d,
                1 if is_known else 0)

    frontier.sort(key=_frontier_key)

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
    pass_enqueued = 0
    reexpand_cap = int(MAX_TASKS * REEXPAND_FRACTION)
    for a, a_depth, is_known in frontier:
        if pass_enqueued >= MAX_TASKS_PER_PASS:
            break
        if a_depth > MAX_DEPTH:
            continue
        if is_known and accum["tasks_reexpand"] >= reexpand_cap:
            # Re-seed budget spent; leave the marker unset so a
            # later run (fresh budget) can still re-verify this node.
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
                pass_enqueued += 1
                if is_known:
                    accum["tasks_reexpand"] += 1
                _per_hunter(accum, hunter)["jobs"] += 1
                store.record_action(
                    session, SYSTEM, primary_key, hunter, "job_enqueued",
                    run_id=run.id, asset_type=a["type"],
                    asset_value=a["value"],
                    detail={"plugin": pid, "target": norm,
                            "depth": a_depth})
            if accum["tasks_used"] >= MAX_TASKS:
                break

    # Finding-driven chaining: the run's stored findings queue
    # specialized plugins on the targets that produced them (a
    # WordPress tech finding queues the CMS/CVE plugins there).
    # Shares the task budget and the per-pass cap; hot targets
    # (critical/high-value findings) get HIGH-priority chained jobs.
    from .chaining import MAX_CHAIN_JOBS_PER_PASS, plan_chains
    chain_plan, hot_ids, chain_signals = plan_chains(findings, targets)
    target_by_id = {t.id: t for t in targets}
    chained_now = 0
    for tid, pids in chain_plan.items():
        if chained_now >= MAX_CHAIN_JOBS_PER_PASS:
            break
        if pass_enqueued >= MAX_TASKS_PER_PASS:
            break
        trobj = target_by_id.get(tid)
        if trobj is None:
            continue
        for pid in pids:
            if accum["tasks_used"] >= MAX_TASKS:
                break
            if chained_now >= MAX_CHAIN_JOBS_PER_PASS:
                break
            pcls = registry.get(pid)
            if pcls is None:
                continue
            pinst = pcls()
            if pinst.accepts and trobj.type not in pinst.accepts:
                continue
            if (trobj.id, pid) in existing_jobs:
                continue
            session.add(PluginJob(
                run_id=run.id, target_id=trobj.id, plugin_id=pid,
                phase=getattr(pinst, "phase", 1),
                priority=(1 if tid in hot_ids
                          else priority_for(pid, bounty=bounty)),
                estimate_s=PLUGIN_TIME_ESTIMATES.get(
                    pid, DEFAULT_PLUGIN_ESTIMATE_S),
                status="queued"))
            existing_jobs.add((trobj.id, pid))
            accum["tasks_used"] += 1
            accum["chained_jobs"] += 1
            chained_now += 1
            pass_enqueued += 1
            store.record_action(
                session, SYSTEM, primary_key, "chain_engine",
                "job_enqueued", run_id=run.id, asset_type=trobj.type,
                asset_value=trobj.normalized,
                detail={"plugin": pid, "target": trobj.normalized,
                        "signals": chain_signals.get(tid, []),
                        "via": "finding_chain"})
    enqueued += chained_now
    session.commit()
    store.record_action(session, SYSTEM, primary_key, "hunter_engine",
                        "expand_pass", run_id=run.id,
                        detail={"depth": depth, "new_assets": len(new_assets),
                                "jobs_enqueued": enqueued,
                                "chained_jobs": chained_now,
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
        "chained_jobs": accum.get("chained_jobs", 0),
        "reexpand_tasks": accum.get("tasks_reexpand", 0),
        "depth_reached": accum.get("depth", 0),
        "per_hunter": accum.get("per_hunter", {}),
        "note": ("hunters expanded the known set and dispatched "
                 "verification plugins on the new frontier; "
                 "detection only, no chat"),
    }
