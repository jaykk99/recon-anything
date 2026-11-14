"""Training data: real labeled rows from the continuous scanner.

Sources (both outside the repo, in ~/workspace/recon-continuous/results/):
- candidates.jsonl: one row per candidate the scanner promoted, with the
  auto-validator's verdict. This is the ONLY labeled data.
- batches.jsonl: the full finding rows those candidates came from, with
  the complete evidence dicts (confidence, source_origin, gate_analysis,
  contract_role, ...). Candidates alone carry no evidence, so each
  candidate is joined back to its batch finding on
  (chain, address, plugin, key) to enrich the features. Candidates
  with no batch match keep their candidate-row fields and absent
  evidence (never invented).

Labels (triage only):
- 1 = worth-validating: verdict UNVERIFIED (the candidate survived
  triage and still needs a live probe).
- 0 = likely-false-positive: verdict FALSE_POSITIVE or TRIGGER_ONLY.
- VERIFIED_REAL rows are EXCLUDED: both rows in this data are
  already-adjudicated simulation-path false positives, so the real
  verified count is 0 and there is nothing real to learn that class
  from. The model must never predict VERIFIED_REAL.

batches.jsonl has torn rows (the scanner died mid-write on some
batches); they are skipped and counted, never fatal.

External rows (load_external_rows) come from build_external_dataset.py:
judge/audit-confirmed public findings (ScaBench, xanoutas) mapped into
the same row shape. Their labels come from the source's own outcome
(confirmed High/Medium = worth-validating); Low/informational audit
findings are excluded, never relabeled, and there is no public
negative set at scale, so the likely-FP class stays Jay's own rows.
"""
from __future__ import annotations

import json
import random
import re
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Tuple

LABEL_WORTH_VALIDATING = 1
LABEL_LIKELY_FP = 0

# verdict -> label (None = exclude from training)
VERDICT_LABELS = {
    "UNVERIFIED": LABEL_WORTH_VALIDATING,
    "FALSE_POSITIVE": LABEL_LIKELY_FP,
    "TRIGGER_ONLY": LABEL_LIKELY_FP,
    "VERIFIED_REAL": None,
}


def load_jsonl(path: str) -> Iterator[Tuple[Dict, Optional[str]]]:
    """Yield (row, error). Torn lines yield (None, message) and are
    counted by the caller instead of aborting the load."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line), None
            except Exception as e:  # noqa: BLE001 - torn row, keep going
                yield None, f"{type(e).__name__}: {e}"


def _join_key(chain: str, address: str, plugin: str, key: str) -> Tuple:
    return ((chain or "").lower(), (address or "").lower(),
            (plugin or ""), (key or ""))


def _parse_ts(value) -> Optional[datetime]:
    """ISO timestamp -> aware datetime; None when absent/unparseable."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


_FUNCTIONS_RE = re.compile(r"functions\s*=\s*(\d+)")


def _finding_function_count(ev: Dict) -> Optional[float]:
    raw = ev.get("function_count")
    if raw is not None:
        try:
            return float(raw)
        except (TypeError, ValueError):
            pass
    m = _FUNCTIONS_RE.search(str(ev.get("detail") or ""))
    if m:
        return float(m.group(1))
    return None


def _load_deployer_map(path: Optional[str]):
    """fresh-deploys jsonl -> ({(chain, address): record},
    {creator: (n_contracts, n_chains)}). Empty maps when path is None
    or the file is missing."""
    by_addr: Dict[Tuple, Dict] = {}
    creator_contracts: Dict[str, set] = {}
    creator_chains: Dict[str, set] = {}
    if not path:
        return by_addr, creator_contracts, creator_chains
    try:
        fh = open(path, encoding="utf-8")
    except OSError:
        return by_addr, creator_contracts, creator_chains
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            addr = (rec.get("address") or "").lower()
            chain = (rec.get("chain") or "").lower()
            if not addr:
                continue
            by_addr[(chain, addr)] = rec
            creator = (rec.get("creator") or "").lower()
            if creator:
                creator_contracts.setdefault(creator, set()).add(addr)
                creator_chains.setdefault(creator, set()).add(chain)
    return by_addr, creator_contracts, creator_chains


def _load_transition_map(path: Optional[str]):
    """transition_events jsonl -> {(chain, address): [events sorted by
    detected_at]}. Empty map when path is None or the file is missing."""
    by_addr: Dict[Tuple, List[Dict]] = {}
    if not path:
        return by_addr
    try:
        fh = open(path, encoding="utf-8")
    except OSError:
        return by_addr
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            addr = (rec.get("address") or "").lower()
            chain = (rec.get("chain") or "").lower()
            if not addr:
                continue
            by_addr.setdefault((chain, addr), []).append(rec)
    for events in by_addr.values():
        events.sort(key=lambda e: str(e.get("detected_at") or ""))
    return by_addr


def build_dataset(candidates_path: str,
                  batches_path: Optional[str] = None,
                  limit: Optional[int] = None,
                  fresh_deploys_path: Optional[str] = None,
                  transitions_path: Optional[str] = None) -> Dict:
    """Build the labeled training set. Returns rows + build stats."""
    candidates: List[Dict] = []
    torn = 0
    for row, err in load_jsonl(candidates_path):
        if err is not None:
            torn += 1
            continue
        candidates.append(row)
        if limit and len(candidates) >= limit:
            break

    # Index batch findings by join key for evidence enrichment, and
    # count findings per (chain, address, plugin): the v2 spec gives
    # every plugin a count input (how many findings it produced on
    # this target). First occurrence wins for the finding itself.
    # The same pass accumulates the v3 per-contract context
    # (aggregates over every finding on the contract), so the extra
    # features cost one pass, not a second read of 248k findings.
    enriched: Dict[Tuple, Dict] = {}
    plugin_counts: Dict[Tuple, int] = {}
    contract_agg: Dict[Tuple, Dict] = {}
    batch_rows = 0
    batch_torn = 0
    batch_findings = 0
    if batches_path:
        for row, err in load_jsonl(batches_path):
            if err is not None:
                batch_torn += 1
                continue
            batch_rows += 1
            brow_chain = (row.get("chain", "") or "").lower()
            brow_addr = (row.get("address", "") or "").lower()
            akey = (brow_chain, brow_addr)
            agg = contract_agg.get(akey)
            if agg is None:
                agg = contract_agg[akey] = {
                    "n_findings": 0, "plugins": set(), "keys": set(),
                    "functions": set(), "conf_sum": 0.0, "conf_n": 0,
                    "max_conf": 0.0, "plugin_counts": {},
                    "has_source": False, "has_proxy": False,
                    "has_impl": False, "function_count": None,
                    "code_len": 0, "compiler": None, "stake_usd": None,
                    "n_batches": 0, "first_seen": None, "last_seen": None,
                    "callgraph_n": 0, "proxy_addrs": set(),
                    "impl_addrs": set(),
                }
            agg["n_batches"] += 1
            stake = row.get("stake_usd")
            if stake is not None:
                try:
                    stake = float(stake)
                    if agg["stake_usd"] is None or stake > agg["stake_usd"]:
                        agg["stake_usd"] = stake
                except (TypeError, ValueError):
                    pass
            seen = _parse_ts(row.get("scanned_at"))
            if seen is not None:
                if agg["first_seen"] is None or seen < agg["first_seen"]:
                    agg["first_seen"] = seen
                if agg["last_seen"] is None or seen > agg["last_seen"]:
                    agg["last_seen"] = seen
            for f in row.get("findings") or []:
                batch_findings += 1
                key = _join_key(row.get("chain", ""), row.get("address", ""),
                                f.get("plugin", ""), f.get("key", ""))
                # First occurrence wins: the finding as first scanned.
                enriched.setdefault(key, f)
                ckey = ((row.get("chain", "") or "").lower(),
                        (row.get("address", "") or "").lower(),
                        f.get("plugin", "") or "")
                plugin_counts[ckey] = plugin_counts.get(ckey, 0) + 1
                # v3 contract aggregates.
                ev = f.get("evidence") or {}
                if not isinstance(ev, dict):
                    ev = {}
                agg["n_findings"] += 1
                agg["plugins"].add(f.get("plugin") or "")
                agg["keys"].add(f.get("key") or "")
                fn = f.get("function") or ev.get("function") or ""
                if fn:
                    agg["functions"].add(str(fn))
                try:
                    conf = float(f.get("confidence") or 0)
                except (TypeError, ValueError):
                    conf = 0.0
                agg["conf_sum"] += conf
                agg["conf_n"] += 1
                if conf > agg["max_conf"]:
                    agg["max_conf"] = conf
                plug = f.get("plugin") or ""
                agg["plugin_counts"][plug] = \
                    agg["plugin_counts"].get(plug, 0) + 1
                if ev.get("source_origin"):
                    agg["has_source"] = True
                if ev.get("proxy_address"):
                    agg["has_proxy"] = True
                    agg["proxy_addrs"].add(str(ev["proxy_address"]))
                if ev.get("implementation_address"):
                    agg["has_impl"] = True
                    agg["impl_addrs"].add(str(ev["implementation_address"]))
                if agg["function_count"] is None:
                    agg["function_count"] = _finding_function_count(ev)
                code = ev.get("code")
                if code:
                    agg["code_len"] = max(agg["code_len"], len(str(code)))
                if agg["compiler"] is None and ev.get("compiler"):
                    agg["compiler"] = str(ev["compiler"])
                if plug == "cross_contract_call_graph":
                    agg["callgraph_n"] += 1

    deploy_by_addr, creator_contracts, creator_chains = \
        _load_deployer_map(fresh_deploys_path)
    transitions_by_addr = _load_transition_map(transitions_path)

    def _context_for(chain: str, address: str, plugin: str) -> Dict:
        """Assemble the v3 context dict for one (chain, address).
        Absent joins stay absent (None/False/0); nothing is guessed."""
        akey = ((chain or "").lower(), (address or "").lower())
        agg = contract_agg.get(akey)
        ctx: Dict = {}
        if agg is not None:
            ctx["n_findings"] = agg["n_findings"]
            ctx["n_plugins"] = len(agg["plugins"])
            ctx["n_keys"] = len(agg["keys"])
            ctx["n_functions"] = len(agg["functions"])
            ctx["max_conf"] = agg["max_conf"]
            ctx["mean_conf"] = (agg["conf_sum"] / agg["conf_n"]
                                if agg["conf_n"] else 0.0)
            total = max(1, agg["n_findings"])
            ctx["plugin_share"] = agg["plugin_counts"].get(plugin, 0) / total
            ctx["has_source"] = agg["has_source"]
            ctx["has_proxy"] = agg["has_proxy"]
            ctx["has_impl"] = agg["has_impl"]
            ctx["function_count"] = agg["function_count"]
            ctx["code_len"] = agg["code_len"]
            ctx["stake_usd"] = agg["stake_usd"]
            ctx["n_batches"] = agg["n_batches"]
            ctx["first_seen"] = (agg["first_seen"].isoformat()
                                 if agg["first_seen"] else None)
            if agg["first_seen"] and agg["last_seen"]:
                ctx["span_days"] = (
                    agg["last_seen"] - agg["first_seen"]).total_seconds() / 86400.0
            else:
                ctx["span_days"] = None
            ctx["callgraph_n"] = agg["callgraph_n"]
            ctx["n_proxy_addrs"] = len(agg["proxy_addrs"])
            ctx["n_impl_addrs"] = len(agg["impl_addrs"])
            last_seen = agg["last_seen"]
        else:
            ctx["first_seen"] = None
            ctx["span_days"] = None
            last_seen = None
        dep = deploy_by_addr.get(akey)
        if dep is not None:
            ctx["deployer_present"] = True
            creator = (dep.get("creator") or "").lower()
            ctx["deployer_contracts"] = len(
                creator_contracts.get(creator, set())) if creator else 1
            ctx["creator_chains"] = len(
                creator_chains.get(creator, set())) if creator else 1
            fresh = dep.get("fresh_7d")
            ctx["deployer_fresh_7d"] = bool(fresh) if fresh is not None else False
            verified = dep.get("code_verified")
            ctx["deployer_verified"] = (bool(verified)
                                        if verified is not None else False)
            first = _parse_ts(dep.get("first_seen_utc"))
            if first is not None and last_seen is not None:
                ctx["deployer_age_days"] = (
                    last_seen - first).total_seconds() / 86400.0
            else:
                ctx["deployer_age_days"] = None
        else:
            ctx["deployer_present"] = False
            ctx["deployer_contracts"] = 0
            ctx["creator_chains"] = 0
            ctx["deployer_fresh_7d"] = False
            ctx["deployer_verified"] = False
            ctx["deployer_age_days"] = None
        events = transitions_by_addr.get(akey) or []
        ctx["owner_events"] = len(events)
        ctx["owner_changed"] = any(
            "owner" in (e.get("changed") or []) for e in events)
        if events:
            after = events[-1].get("after") or {}
            ctx["owner_now_null"] = after.get("owner") is None
            ctx["owner_stake_usd"] = events[-1].get("stake_usd")
        else:
            ctx["owner_now_null"] = False
            ctx["owner_stake_usd"] = None
        return ctx

    rows: List[Dict] = []
    excluded = 0
    unenriched = 0
    for cand in candidates:
        verdict = (cand.get("validation") or {}).get("verdict")
        label = VERDICT_LABELS.get(verdict)
        if label is None:
            excluded += 1
            continue
        key = _join_key(cand.get("chain", ""), cand.get("address", ""),
                        cand.get("plugin", ""), cand.get("key", ""))
        finding = enriched.get(key)
        if finding is None:
            unenriched += 1
            # Candidate row alone: real fields, evidence absent.
            finding = {
                "plugin": cand.get("plugin"),
                "key": cand.get("key"),
                "severity": cand.get("severity"),
                "bounty_value": None,
                "confidence": None,
                "value": cand.get("value") or "",
                "recipient_class": cand.get("recipient_class"),
                "chain": cand.get("chain"),
                "function": cand.get("function"),
                "evidence": {},
                "plugin_finding_count": 1,
            }
        else:
            # Chain lives at batch-row level, not in the finding dict:
            # stamp it on so the feature extractor sees the real chain
            # (without this every training row read chain "other").
            finding = dict(finding)
            finding.setdefault("chain", cand.get("chain"))
            ckey = ((cand.get("chain", "") or "").lower(),
                    (cand.get("address", "") or "").lower(),
                    cand.get("plugin", "") or "")
            finding["plugin_finding_count"] = plugin_counts.get(ckey, 1)
        # v3 context: real on-disk joins only; unenriched candidates
        # still get the deployer/transition joins (they need no batch
        # match), everything else reads absent.
        finding["context"] = _context_for(
            cand.get("chain"), cand.get("address"), cand.get("plugin"))
        rows.append({
            "finding": finding,
            "label": label,
            "verdict": verdict,
            "chain": cand.get("chain"),
            "address": cand.get("address"),
            "plugin": cand.get("plugin"),
            "key": cand.get("key"),
            "function": cand.get("function"),
        })

    stats = {
        "candidates": len(candidates),
        "candidates_torn_lines": torn,
        "batch_rows": batch_rows,
        "batch_torn_lines": batch_torn,
        "batch_findings": batch_findings,
        "joined_with_evidence": len(rows) - unenriched,
        "without_batch_match": unenriched,
        "excluded_verified_real_rows": excluded,
        "train_rows": len(rows),
        "n_positive": sum(1 for r in rows if r["label"] == 1),
        "n_negative": sum(1 for r in rows if r["label"] == 0),
        "context_contracts": len(contract_agg),
        "deployer_joins": sum(
            1 for r in rows
            if (r["finding"].get("context") or {}).get("deployer_present")),
        "transition_joins": sum(
            1 for r in rows
            if (r["finding"].get("context") or {}).get("owner_events")),
    }
    return {"rows": rows, "stats": stats}


def load_external_rows(path: str) -> Tuple[List[Dict], Dict]:
    """Load external-findings rows (built by build_external_dataset.py).

    Rows are already in NN row shape (finding/label/verdict/... plus
    origin + source provenance). Labels come from the source's own
    outcome (judge/audit-confirmed High/Medium = worth-validating);
    nothing here re-labels or invents fields. Returns (rows, stats).
    """
    rows: List[Dict] = []
    bad = 0
    sources: Dict[str, int] = {}
    for row, err in load_jsonl(path):
        if err is not None or not isinstance(row, dict):
            bad += 1
            continue
        finding = row.get("finding")
        label = row.get("label")
        if not isinstance(finding, dict) or label not in (0, 1):
            bad += 1
            continue
        rows.append(row)
        src = ((row.get("source") or {}).get("dataset") or "unknown")
        sources[src] = sources.get(src, 0) + 1
    stats = {
        "external_rows": len(rows),
        "external_positive": sum(1 for r in rows if r["label"] == 1),
        "external_negative": sum(1 for r in rows if r["label"] == 0),
        "external_sources": sources,
        "external_bad_lines": bad,
    }
    return rows, stats


def stratified_split(rows: List[Dict], test_frac: float = 0.2,
                     seed: int = 42) -> Tuple[List[Dict], List[Dict]]:
    """Stratified train/test split (keeps the class ratio in both)."""
    rng = random.Random(seed)
    by_label: Dict[int, List[Dict]] = {}
    for r in rows:
        by_label.setdefault(r["label"], []).append(r)
    train: List[Dict] = []
    test: List[Dict] = []
    for label, items in by_label.items():
        items = list(items)
        rng.shuffle(items)
        n_test = max(1, round(len(items) * test_frac)) if len(items) > 1 else 0
        test.extend(items[:n_test])
        train.extend(items[n_test:])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test
