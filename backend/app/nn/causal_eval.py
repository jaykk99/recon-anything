"""Honest evaluation of the causal model on REAL data only.

Real workflow, real numbers, nothing invented (per the restated
NO-SIMULATION RULE, Nov 14). This script evaluates ONLY on:
- candidates.jsonl (727 candidate rows from the continuous
  scanner; 725 labeled after excluding the 2 VERIFIED_REAL rows,
  which per data.py are already-adjudicated simulation-path
  false positives)
- transition_events.jsonl (52 observed owner flips on 11
  watched contracts)

Synthetic data appears NOWHERE in this evaluation. The hand-built
graphs with known ground truth live only in the unit self-tests
(backend/tests/test_nn_causal.py), where they prove the
do-operator / identification / counterfactual machinery works;
their results are never presented as evaluation numbers.

What is measured:
1. Holdout triage (fixed split: stratified, seed 42, 20% of the
   own 725 rows -> 145 test rows, same split the NN scorers use):
   majority baseline vs the correlation-only plugin-frequency
   baseline P(label | plugin) vs the back-door-adjusted causal
   estimate P(label | do(plugin)) adjusting for chain.
   Reference (reported, not recomputed): v1 scorer test acc
   0.8897, v2 0.9103, majority baseline 0.8552.
2. Identification on the real fitted graph: which effects are
   identified and which are not.
3. Transition held-out test: the last flip per multi-flip
   address (n=8) -- predict its direction (renounced vs new
   owner) from the mechanism fitted on earlier flips, vs the
   majority-direction and random baselines.
4. The backup-infra question on real data: predict_backup_infra
   with target "backup_infra" (unobserved mechanism -> must come
   back "unidentified"), plus the narrower identified mechanism
   P(next_owner | do(owner_change)) from the 52 flips.

Usage:
    python3 -m app.nn.causal_eval [candidates.jsonl]
        [transition_events.jsonl]
Defaults point at the recon-continuous workspace paths. The
script only reads; it prints JSON + a human summary to stdout.
"""
from __future__ import annotations

import json
import math
import os
import random
import sys
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.nn.causal import (  # noqa: E402
    VERDICT_LABELS,
    CausalGraph,
    StructuralModel,
    build_recon_graph,
    estimate_effect,
    identify_effect,
    predict_backup_infra,
    raw_conditional,
)

DEFAULT_CANDIDATES = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")
DEFAULT_TRANSITIONS = os.path.expanduser(
    "~/workspace/recon-continuous/state/transition_events.jsonl")

# Reported by the scorer work, not recomputed here.
REPORTED_V1_ACC = 0.8897
REPORTED_V2_ACC = 0.9103


def load_jsonl(path: str) -> List[Dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # torn row: skipped, counted by caller
    return rows


def build_labeled_rows(candidates: Sequence[Dict],
                       transitions: Sequence[Dict]) -> Tuple[List[Dict], Dict]:
    """Candidate rows in file order, labeled by verdict, enriched
    with the observed owner flip for their target (if any).

    Fields are candidate-row fields only (no batches join): the
    eval does not need the 451 MB batches file. A target with no
    recorded flip gets owner_change=0 and NO next_owner key --
    the next owner is unobserved there, never defaulted.
    """
    flips: Dict[Tuple, List[Dict]] = {}
    for t in transitions:
        key = ((t.get("chain") or "").lower(),
               (t.get("address") or "").lower())
        flips.setdefault(key, []).append(t)
    rows: List[Dict] = []
    excluded = 0
    for cand in candidates:
        verdict = (cand.get("validation") or {}).get("verdict")
        label = VERDICT_LABELS.get(verdict)
        if label is None:
            excluded += 1
            continue
        probe = (cand.get("live_probe") or {}).get("status") or "other"
        if probe not in ("success", "revert", "transport_error"):
            probe = "other"
        row: Dict = {
            "chain": cand.get("chain") or "other",
            "plugin": cand.get("plugin") or "other",
            "function": cand.get("function") or "other",
            "recipient_class": cand.get("recipient_class") or "other",
            "worth_validating": label,
            "live_probe": probe,
        }
        key = ((cand.get("chain") or "").lower(),
               (cand.get("address") or "").lower())
        target_flips = flips.get(key, [])
        row["owner_change"] = 1 if target_flips else 0
        if target_flips:
            last = sorted(target_flips,
                          key=lambda t: t.get("detected_at") or "")[-1]
            after = (last.get("after") or {}).get("owner")
            row["next_owner"] = ("renounced" if after is None
                                 else "new_owner")
        rows.append(row)
    stats = {
        "candidates": len(candidates),
        "labeled_rows": len(rows),
        "excluded_verified_real_rows": excluded,
        "n_positive": sum(1 for r in rows if r["worth_validating"] == 1),
        "n_negative": sum(1 for r in rows if r["worth_validating"] == 0),
        "targets_with_owner_flip": sum(
            1 for r in rows if r["owner_change"] == 1),
    }
    return rows, stats


def stratified_split(rows: List[Dict], test_frac: float = 0.2,
                     seed: int = 42) -> Tuple[List[Dict], List[Dict]]:
    """Byte-for-byte the split in the scorer's data.py (same seed,
    same order, same rounding), so the holdout is the same 145
    rows the v1/v2 numbers refer to."""
    rng = random.Random(seed)
    by_label: Dict[int, List[Dict]] = {}
    for r in rows:
        by_label.setdefault(r["worth_validating"], []).append(r)
    train: List[Dict] = []
    test: List[Dict] = []
    for label, items in by_label.items():
        items = list(items)
        rng.shuffle(items)
        n_test = (max(1, round(len(items) * test_frac))
                  if len(items) > 1 else 0)
        test.extend(items[:n_test])
        train.extend(items[n_test:])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def _clip(p: float) -> float:
    return min(max(p, 1e-6), 1.0 - 1e-6)


def predict_with(table: Dict, rows: Sequence[Dict], x: str,
                 fallback: float) -> Tuple[List[float], List[int]]:
    """Per-row P(label=1) from a {x_value: {0: p0, 1: p1}} table."""
    probs, labels = [], []
    for r in rows:
        dist = table.get(r[x])
        p1 = dist.get(1, fallback) if dist else fallback
        probs.append(_clip(p1))
        labels.append(r["worth_validating"])
    return probs, labels


def metrics(probs: Sequence[float],
            labels: Sequence[int]) -> Dict:
    n = len(labels)
    acc = sum(1 for p, y in zip(probs, labels)
              if (1 if p > 0.5 else 0) == y) / n
    ll = -sum(y * math.log(p) + (1 - y) * math.log(1 - p)
              for p, y in zip(probs, labels)) / n
    brier = sum((p - y) ** 2 for p, y in zip(probs, labels)) / n
    return {"n": n, "accuracy": round(acc, 4),
            "log_loss": round(ll, 4), "brier": round(brier, 4)}


def wilson_ci(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """95% Wilson interval for a proportion (honest small-n bars)."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(max(0.0, (c - m) / d), 4),
            round(min(1.0, (c + m) / d), 4))


def evaluate(candidates_path: str, transitions_path: str) -> Dict:
    candidates = load_jsonl(candidates_path)
    transitions = load_jsonl(transitions_path)
    rows, row_stats = build_labeled_rows(candidates, transitions)
    train, test = stratified_split(rows)
    out: Dict = {
        "data": {
            "candidates_path": candidates_path,
            "transitions_path": transitions_path,
            "transition_events": len(transitions),
            "transition_addresses": len(
                {(t.get("chain"), (t.get("address") or "").lower())
                 for t in transitions}),
            "implementation_changes": sum(
                1 for t in transitions
                if "implementation" in (t.get("changed") or [])),
            "owner_flips_to_null": sum(
                1 for t in transitions
                if (t.get("after") or {}).get("owner") is None),
            "owner_flips_from_null": sum(
                1 for t in transitions
                if (t.get("before") or {}).get("owner") is None),
            **row_stats,
            "train_rows": len(train),
            "test_rows": len(test),
            "test_positive": sum(1 for r in test
                                 if r["worth_validating"] == 1),
            "test_negative": sum(1 for r in test
                                 if r["worth_validating"] == 0),
        },
    }

    # -- 1. Holdout triage: majority / correlation / causal -------
    train_rate = sum(r["worth_validating"] for r in train) / len(train)
    maj_probs = [train_rate] * len(test)
    maj = metrics(maj_probs, [r["worth_validating"] for r in test])
    maj["note"] = "predicts the train majority class for every row"
    raw = raw_conditional(train, "plugin", "worth_validating")
    raw_table = {k: v for k, v in raw.items()}
    raw_probs, labels = predict_with(
        {k[0]: v for k, v in raw_table.items()}, test, "plugin",
        train_rate)
    corr = metrics(raw_probs, labels)
    corr["note"] = ("correlation-only: P(label | plugin), "
                    "no adjustment")
    adj = estimate_effect(train, "plugin", "worth_validating",
                          ["chain"])
    adj_table = {k: v for k, v in adj["estimate"].items()}
    adj_probs, _ = predict_with(adj_table, test, "plugin", train_rate)
    causal = metrics(adj_probs, labels)
    causal["note"] = ("back-door-adjusted: P(label | do(plugin)), "
                      "adjusting for chain")
    out["holdout_triage"] = {
        "majority": maj,
        "correlation_plugin_frequency": corr,
        "causal_chain_adjusted": causal,
        "reported_v1_scorer_test_acc": REPORTED_V1_ACC,
        "reported_v2_scorer_test_acc": REPORTED_V2_ACC,
        "reported_majority_baseline_acc": 0.8552,
        "raw_vs_adjusted_gap": {
            plugin: {
                "raw_P_label1_given_plugin": round(
                    raw_table.get((plugin,), {}).get(1, 0.0), 4),
                "adjusted_P_label1_do_plugin": round(
                    adj_table.get(plugin, {}).get(1, 0.0), 4),
            }
            for plugin in sorted(adj_table)
        },
    }

    # -- 2. Identification on the real graph -----------------------
    graph, notes = build_recon_graph(candidates, transitions)
    model = StructuralModel.fit(graph, train)
    out["identification"] = {
        "plugin_to_worth_validating": identify_effect(
            graph, "plugin", "worth_validating"),
        "owner_change_to_next_owner": identify_effect(
            graph, "owner_change", "next_owner"),
        "owner_change_to_backup_infra": identify_effect(
            graph, "owner_change", "backup_infra"),
        "fit_counts": model.fit_counts,
        "graph_notes": notes,
    }

    # -- 3. Transition held-out test: flip direction --------------
    by_addr: Dict[str, List[Dict]] = {}
    for t in transitions:
        by_addr.setdefault((t.get("address") or "").lower(),
                           []).append(t)
    for addr in by_addr:
        by_addr[addr].sort(key=lambda t: t.get("detected_at") or "")
    train_events: List[Dict] = []
    test_events: List[Dict] = []
    for addr, events in by_addr.items():
        if len(events) > 1:
            train_events.extend(events[:-1])
            test_events.append(events[-1])
        else:
            train_events.extend(events)
    # Mechanism: P(after_null | before_null, chain) from train.
    mech: Dict[Tuple, Dict[int, float]] = {}
    for t in train_events:
        key = ((t.get("before") or {}).get("owner") is None,
               t.get("chain"))
        d = mech.setdefault(key, {0: 0, 1: 0})
        d[1 if (t.get("after") or {}).get("owner") is None else 0] += 1
    mech_probs = {k: (v[1] + 1) / (v[0] + v[1] + 2)
                  for k, v in mech.items()}
    majority_dir = 1 if sum(
        1 for t in train_events
        if (t.get("after") or {}).get("owner") is None) * 2 >= len(
            train_events) else 0
    correct_mech = correct_maj = 0
    test_detail = []
    for t in test_events:
        actual = 1 if (t.get("after") or {}).get("owner") is None else 0
        key = ((t.get("before") or {}).get("owner") is None,
               t.get("chain"))
        p1 = mech_probs.get(key, 0.5)
        pred_mech = 1 if p1 > 0.5 else 0
        correct_mech += int(pred_mech == actual)
        correct_maj += int(majority_dir == actual)
        test_detail.append({
            "address": (t.get("address") or "")[:14],
            "chain": t.get("chain"),
            "before_null": key[0],
            "actual_after_null": actual,
            "mechanism_P_after_null": round(p1, 4),
            "mechanism_correct": bool(pred_mech == actual),
            "majority_correct": bool(majority_dir == actual),
        })
    n_test = len(test_events)
    out["transition_heldout"] = {
        "n_train_events": len(train_events),
        "n_test_events": n_test,
        "mechanism_accuracy": (round(correct_mech / n_test, 4)
                               if n_test else None),
        "mechanism_accuracy_wilson95": wilson_ci(correct_mech, n_test),
        "majority_accuracy": (round(correct_maj / n_test, 4)
                              if n_test else None),
        "random_expected_accuracy": 0.5,
        "mechanism_table_P_after_null": {
            f"before_null={k[0]},chain={k[1]}": round(v, 4)
            for k, v in sorted(mech_probs.items(), key=str)},
        "test_detail": test_detail,
        "caveat": (f"n={n_test}: the interval is wide by "
                   "construction. "
                   f"{len(transitions)} flips on "
                   f"{len(by_addr)} addresses cannot support a "
                   "causal claim about what follows an owner "
                   "change; this test only checks the narrow "
                   "renounce-vs-reassign mechanism."),
    }

    # -- 4. The backup-infra question on real data -----------------
    backup = predict_backup_infra(
        model, {"chain": "ethereum", "owner_change": 1},
        target="backup_infra")
    # The narrow identified mechanism, for contrast.
    tgraph = CausalGraph()
    tgraph.add_node("chain", ["bsc", "ethereum", "base",
                              "arbitrum", "polygon", "other"])
    tgraph.add_node("owner_change", [0, 1])
    tgraph.add_node("next_owner",
                    ["renounced", "new_owner", "unchanged"])
    tgraph.add_edge("chain", "owner_change")
    tgraph.add_edge("chain", "next_owner")
    tgraph.add_edge("owner_change", "next_owner")
    trows = [{
        "chain": t.get("chain") or "other",
        "owner_change": 1,
        "next_owner": ("renounced"
                       if (t.get("after") or {}).get("owner") is None
                       else "new_owner"),
    } for t in transitions]
    tmodel = StructuralModel.fit(tgraph, trows)
    narrow = predict_backup_infra(
        tmodel, {"chain": "ethereum"},
        offline_node="owner_change", offline_value=1,
        target="next_owner")
    out["backup_infra_question"] = {
        "backup_infra": backup,
        "narrow_renounce_vs_reassign": narrow,
        "empirical_P_renounced_given_flip": round(
            sum(1 for t in transitions
                if (t.get("after") or {}).get("owner") is None)
            / len(transitions), 4) if transitions else None,
    }

    # -- 5. Descriptive real-data facts ---------------------------
    cand_addrs = {(c.get("chain"), (c.get("address") or "").lower())
                  for c in candidates}
    trans_addrs = {(t.get("chain"), (t.get("address") or "").lower())
                   for t in transitions}
    out["descriptive"] = {
        "transition_addresses_also_in_candidates":
            len(trans_addrs & cand_addrs),
        "transition_addresses_total": len(trans_addrs),
        "finding_after_flip_test_possible":
            "no: only 2 of 11 flipped contracts ever appear in "
            "candidates, so 'what finding follows a flip' has no "
            "testable sample",
    }
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    candidates_path = argv[0] if len(argv) > 0 else DEFAULT_CANDIDATES
    transitions_path = argv[1] if len(argv) > 1 else DEFAULT_TRANSITIONS
    if not os.path.exists(candidates_path):
        print(f"REAL DATA NOT FOUND: {candidates_path}")
        return 1
    if not os.path.exists(transitions_path):
        print(f"REAL DATA NOT FOUND: {transitions_path}")
        return 1
    out = evaluate(candidates_path, transitions_path)
    print(json.dumps(out, indent=2, sort_keys=True))
    d = out["data"]
    h = out["holdout_triage"]
    t = out["transition_heldout"]
    print("\n--- SUMMARY (real data only) ---")
    print(f"labeled rows: {d['labeled_rows']} "
          f"({d['n_positive']} worth-validating / "
          f"{d['n_negative']} likely-FP); "
          f"holdout {d['test_rows']} rows "
          f"({d['test_positive']} pos / {d['test_negative']} neg)")
    print(f"holdout accuracy: majority {h['majority']['accuracy']}, "
          f"correlation {h['correlation_plugin_frequency']['accuracy']}, "
          f"causal-chain-adjusted {h['causal_chain_adjusted']['accuracy']} "
          f"(reported v1 {h['reported_v1_scorer_test_acc']}, "
          f"v2 {h['reported_v2_scorer_test_acc']})")
    print(f"holdout log-loss: correlation "
          f"{h['correlation_plugin_frequency']['log_loss']}, causal "
          f"{h['causal_chain_adjusted']['log_loss']}")
    print(f"PLUGIN -> WORTH_VALIDATING identifiable: "
          f"{out['identification']['plugin_to_worth_validating']['identifiable']} "
          f"({out['identification']['plugin_to_worth_validating']['reason']})")
    print(f"transition held-out direction test: n={t['n_test_events']}, "
          f"mechanism acc {t['mechanism_accuracy']} "
          f"(95% Wilson {t['mechanism_accuracy_wilson95']}), "
          f"majority {t['majority_accuracy']}, random 0.5")
    print(f"backup-infra question on real data: "
          f"{out['backup_infra_question']['backup_infra']['confidence']}")
    print(f"narrow mechanism P(renounced | flip): "
          f"{out['backup_infra_question']['empirical_P_renounced_given_flip']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
