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

Call graphs (TDA): the same batch rows carry the target's
cross_contract_call_graph finding, whose evidence["depth"] record
says how the call graph was measured (callees, callee_layers). That
record is stamped on every row for the target as
finding["call_graph"], so the TDA features describe the target the
finding came from. It is target-level evidence from the same run,
available the same way at live-score time (score.py runs the
call-graph plugin in the same run), and it carries no verdict, so
nothing label-side leaks. Most targets measured 0 callees; the
record is still stamped (a measured-empty graph is not "no graph").

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
from typing import Dict, Iterator, List, Optional, Tuple

from .tda import parse_depth_record

LABEL_WORTH_VALIDATING = 1
LABEL_LIKELY_FP = 0

# verdict -> label (None = exclude from training)
VERDICT_LABELS = {
    "UNVERIFIED": LABEL_WORTH_VALIDATING,
    "FALSE_POSITIVE": LABEL_LIKELY_FP,
    "TRIGGER_ONLY": LABEL_LIKELY_FP,
    "VERIFIED_REAL": None,
}

# The plugin whose finding carries the target's call-graph record.
CALL_GRAPH_PLUGIN = "cross_contract_call_graph"


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


def _target_key(chain: str, address: str) -> Tuple:
    return ((chain or "").lower(), (address or "").lower())


def _call_graph_record(finding: Dict) -> Optional[Dict]:
    """The call-graph record for one cross_contract_call_graph
    finding: its depth record (callees / callee_layers), plus any
    multihop call_edges the finding carries. None when the finding
    carries no usable graph record."""
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    record: Dict = {}
    depth = parse_depth_record(ev.get("depth"))
    if depth is not None:
        record.update(depth)
    edges = ev.get("call_edges")
    if isinstance(edges, str):
        try:
            edges = json.loads(edges)
        except Exception:
            edges = None
    if isinstance(edges, list) and edges:
        record["call_edges"] = edges
    return record or None


def build_dataset(candidates_path: str,
                  batches_path: Optional[str] = None,
                  limit: Optional[int] = None) -> Dict:
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
    # Also index the target's call-graph record (see module docstring).
    enriched: Dict[Tuple, Dict] = {}
    plugin_counts: Dict[Tuple, int] = {}
    call_graphs: Dict[Tuple, Dict] = {}
    batch_rows = 0
    batch_torn = 0
    batch_findings = 0
    if batches_path:
        for row, err in load_jsonl(batches_path):
            if err is not None:
                batch_torn += 1
                continue
            batch_rows += 1
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
                if f.get("plugin") == CALL_GRAPH_PLUGIN:
                    tkey = _target_key(row.get("chain", ""),
                                       row.get("address", ""))
                    # Keep the most complete measurement of the
                    # target's graph: the record with the most callees
                    # (ties: first). A target is scanned many times
                    # and most scans record 0 callees; the richest
                    # record is the best measurement of the graph,
                    # and a record whose depth field has no usable
                    # callee count is skipped so a later parseable
                    # one can win. No verdict is involved.
                    rec = _call_graph_record(f)
                    if rec is not None:
                        prev = call_graphs.get(tkey)
                        if (prev is None or
                                (rec.get("callees") or 0) >
                                (prev.get("callees") or 0)):
                            call_graphs[tkey] = rec

    rows: List[Dict] = []
    excluded = 0
    unenriched = 0
    rows_with_call_graph = 0
    rows_with_nontrivial_graph = 0
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
        # Target call-graph record for the TDA features (same run,
        # no verdict in it). Absent when the target has no
        # call-graph finding in the batches.
        tkey = _target_key(cand.get("chain", ""), cand.get("address", ""))
        record = call_graphs.get(tkey)
        if record is not None:
            finding["call_graph"] = record
            rows_with_call_graph += 1
            if (record.get("callees") or 0) > 0 or record.get("call_edges"):
                rows_with_nontrivial_graph += 1
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
        "rows_with_call_graph": rows_with_call_graph,
        "rows_with_nontrivial_graph": rows_with_nontrivial_graph,
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
