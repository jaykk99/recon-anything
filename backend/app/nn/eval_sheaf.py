"""Honest evaluation of the sheaf consistency checker.

Runs on the REAL continuous-scanner data (candidates + transitions),
plus a hand-labelled injected-contradiction set (seed 42) and a
pairwise-graph baseline run on the same labelled set.

What is real and what is synthetic -- read this before quoting any
number below:
- REAL: every hyperedge count, every flag on real data, the 7
  owner null-flip oscillation contracts, the Token Hub ungrounded-
  severity exemplar. These come from the two jsonl files and nothing
  else.
- SYNTHETIC (labelled test fixtures, never scan data): the injected
  contradictions. A base hyperedge is copied, one fact is changed
  to contradict the hyperedge's own story, and the copy is labelled
  inconsistent. Controls are untouched copies labelled consistent.
  Precision/recall here measure "does the checker catch a
  contradiction that was deliberately planted", not "does it find
  real vulnerabilities".
- TOY: call_path hyperedges and symbol-cluster injections. No real
  multi-hop call paths exist on disk for these contracts, and no
  real symbol is shared by two contracts, so those two kinds are
  exercised on hand-built toy inputs. A perfect score there is a
  toy result, not a win, and it is reported as one.

The checker never predicts VERIFIED_REAL. Nothing here is a live
probe, a transaction, or an exploit. Detection only, triage only.

Usage:
    python -m app.nn.eval_sheaf [--candidates PATH] [--transitions PATH]
    (run from backend/, or python backend/app/nn/eval_sheaf.py)
Prints a JSON report to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from app.nn.hyperedges import (build_all, build_call_path_hyperedges,
                               build_symbol_cluster_hyperedges,
                               latest_owner_map, load_jsonl)
from app.nn.sheaf import (consistency, copy_hyperedge,
                          cover_obstructions, to_hypergraph_nn)

DEFAULT_CANDIDATES = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")
DEFAULT_TRANSITIONS = os.path.expanduser(
    "~/workspace/recon-continuous/state/transition_events.jsonl")

SEED = 42


# ---------------------------------------------------------------------------
# Injection (synthetic fixtures only)
# ---------------------------------------------------------------------------

def _set_fact(edge, entity, field_name, value):
    stalk = edge.stalk(entity)
    fact = stalk.fact(field_name)
    stalk.facts[field_name] = type(fact)(
        entity, field_name, value, fact.source + " [injected]")


def inject_noop_transition(edge):
    contract = next(e for e in edge.entities if e[0] == "contract")
    before = edge.stalk(contract).get("owner_before")
    _set_fact(edge, contract, "owner_after", before)
    return edge


def inject_target_mismatch(edge):
    finding = next(e for e in edge.entities if e[0] == "finding")
    _set_fact(edge, finding, "validation_address",
              "0x" + "99" * 20)
    return edge


def inject_function_unbind(edge):
    finding = next(e for e in edge.entities if e[0] == "finding"
                   and edge.stalk(e).get("function"))
    _set_fact(edge, finding, "validation_function", "")
    return edge


def inject_verdict_flip(edge):
    finding = next(e for e in edge.entities if e[0] == "finding"
                   and edge.stalk(e).get("live_status")
                   == "transport_error")
    _set_fact(edge, finding, "verdict", "VERIFIED_REAL")
    return edge


def inject_symbol_owner(edge):
    contracts = sorted(e for e in edge.entities if e[0] == "contract")
    _set_fact(edge, contracts[0], "owner", "0x" + "ab" * 20)
    return edge


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _prf(tp, fp, fn, tn):
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4), "f1": round(f1, 4)}


def _run_labelled(labelled, pairwise):
    tp = fp = fn = tn = 0
    for edge, label in labelled:
        score, _ = consistency(edge, pairwise=pairwise)
        flagged = score < 1.0
        if label == 1 and flagged:
            tp += 1
        elif label == 1:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    return _prf(tp, fp, fn, tn)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    ap.add_argument("--transitions", default=DEFAULT_TRANSITIONS)
    args = ap.parse_args()

    candidates, torn_c = load_jsonl(args.candidates)
    transitions, torn_t = load_jsonl(args.transitions)
    edges = build_all(candidates, transitions)
    all_edges = [e for kind in edges.values() for e in kind]
    owner_map = latest_owner_map(transitions)

    # --- real-data run: score everything, collect flags ----------
    by_kind = {}
    by_check = {}
    for kind, kind_edges in edges.items():
        flagged = 0
        for edge in kind_edges:
            score, results = consistency(edge)
            if score < 1.0:
                flagged += 1
                for r in results:
                    if not r.passed and r.weight > 0:
                        by_check[r.name] = by_check.get(r.name, 0) + 1
        by_kind[kind] = {"built": len(kind_edges), "flagged": flagged}
    obs = cover_obstructions(all_edges)
    oscillating = sorted(k for k, v in owner_map.items()
                         if v["oscillates"])
    # which oscillating contracts the cover check actually flags:
    # obstruction facts name the contract as
    # "contract:<chain>:<address>.<field> = <value> (<source>)"
    cover_contracts = set()
    for o in obs:
        for f in o["facts"]:
            cover_contracts.add(f.split(".")[0].split(":", 1)[1])
    real_cover_found = sorted(cover_contracts)

    # observations (weight 0): reported, never scored
    n_null_after = sum(1 for r in transitions
                       if (r.get("after") or {}).get("owner") is None)
    n_null_block = sum(1 for r in transitions
                       if r.get("block") is None)
    n_ungrounded = 0
    for edge in edges["finding_cluster"]:
        _s, results = consistency(edge)
        for r in results:
            if r.name == "ungrounded_severity_observed" \
                    and not r.passed:
                n_ungrounded += int(r.detail.split("/")[0])
    hub = [r for r in candidates if r.get("symbol") == "HUBBX"]

    # --- labelled injected set (seed 42) -------------------------
    rng = random.Random(SEED)
    trans_clean = [e for e in edges["owner_transition"]
                   if consistency(e)[0] >= 1.0]
    find_clean = [e for e in edges["finding_cluster"]
                  if consistency(e)[0] >= 1.0]
    # toy symbol cluster: two contracts, same symbol, same owner
    toy_cands = [
        {"chain": "bsc", "address": "0x" + "11" * 20,
         "symbol": "TOY"},
        {"chain": "bsc", "address": "0x" + "22" * 20,
         "symbol": "TOY"},
    ]
    toy_owner_map = {
        ("bsc", "0x" + "11" * 20): {"latest_known": "0x" + "aa" * 20},
        ("bsc", "0x" + "22" * 20): {"latest_known": "0x" + "aa" * 20},
    }
    toy_symbol = build_symbol_cluster_hyperedges(toy_cands,
                                                 toy_owner_map)
    # toy call paths: one clean, one with a paused hop graded candidate
    toy_paths = build_call_path_hyperedges([
        {"id": "toy-clean", "grade": "trigger-only",
         "finding_kinds": ["call_graph_gate_bypass_multihop"],
         "hops": [
             {"caller": "0x" + "11" * 20, "callee": "0x" + "22" * 20,
              "chain": "bsc", "function": "execute", "gated": True,
              "paused": False, "source_available": True},
             {"caller": "0x" + "22" * 20, "callee": "0x" + "33" * 20,
              "chain": "bsc", "function": "relay", "gated": False,
              "paused": False, "source_available": True},
         ]},
        {"id": "toy-paused", "grade": "candidate",
         "finding_kinds": ["call_graph_gate_bypass_multihop"],
         "hops": [
             {"caller": "0x" + "11" * 20, "callee": "0x" + "22" * 20,
              "chain": "bsc", "function": "execute", "gated": True,
              "paused": False, "source_available": True},
             {"caller": "0x" + "22" * 20, "callee": "0x" + "33" * 20,
              "chain": "bsc", "function": "relay", "gated": False,
              "paused": True, "source_available": True},
         ]},
    ])

    # positives: 5 injections x 6 types = 30
    positives = []
    pools = {
        "noop": [e for e in trans_clean],
        "target": [e for e in find_clean
                   if any(f for f in e.entities
                          if f[0] == "finding")],
        "function": [e for e in find_clean
                     if any(e.stalk(f).get("function")
                            for f in e.entities if f[0] == "finding")],
        "verdict": [e for e in find_clean
                    if any(e.stalk(f).get("live_status")
                           == "transport_error"
                           for f in e.entities if f[0] == "finding")],
        "symbol": toy_symbol,
        "paused": [toy_paths[1]],
    }
    injectors = {
        "noop": inject_noop_transition,
        "target": inject_target_mismatch,
        "function": inject_function_unbind,
        "verdict": inject_verdict_flip,
        "symbol": inject_symbol_owner,
        "paused": lambda e: e,  # already contradictory by construction
    }
    for kind in ["noop", "target", "function", "verdict", "symbol",
                 "paused"]:
        pool = pools[kind]
        for k in range(5):
            base = pool[(k * 7 + 3) % len(pool)] \
                if kind != "paused" else pool[0]
            edge = copy_hyperedge(base)
            edge.id = "%s#injected-%s-%d" % (base.id, kind, k)
            injectors[kind](edge)
            positives.append((edge, 1))

    # controls: 30 untouched copies, same kinds
    controls = []
    control_pools = {
        "owner_transition": trans_clean,
        "finding_cluster": find_clean,
        "symbol_cluster": toy_symbol,
        "call_path": [toy_paths[0]],
    }
    kinds_cycle = (["owner_transition"] * 5 + ["finding_cluster"] * 20
                   + ["symbol_cluster"] * 3 + ["call_path"] * 2)
    for k, kind in enumerate(kinds_cycle):
        pool = control_pools[kind]
        base = pool[(k * 11 + 5) % len(pool)]
        edge = copy_hyperedge(base)
        edge.id = "%s#control-%d" % (base.id, k)
        controls.append((edge, 0))
    labelled = positives + controls
    rng.shuffle(labelled)

    sheaf_metrics = _run_labelled(labelled, pairwise=False)
    pairwise_metrics = _run_labelled(labelled, pairwise=True)

    # toy call-path check on its own (reported separately, toy)
    toy_clean_score, _ = consistency(toy_paths[0])
    toy_paused_score, _ = consistency(toy_paths[1])

    report = {
        "data": {
            "candidates": len(candidates),
            "transitions": len(transitions),
            "torn_rows_skipped": {"candidates": torn_c,
                                  "transitions": torn_t},
            "distinct_contracts": len(
                set((r.get("chain"), r.get("address"))
                    for r in candidates)),
        },
        "hyperedges_built": {k: v["built"]
                             for k, v in by_kind.items()},
        "real_flags_by_kind": {k: v["flagged"]
                               for k, v in by_kind.items()},
        "real_flags_by_check": by_check,
        "real_cover_obstructions": len(obs),
        "real_oscillating_contracts": [
            "%s:%s" % (chain, addr) for chain, addr in oscillating],
        "real_cover_found_contracts": real_cover_found,
        "observations": {
            "null_owner_after_transitions": n_null_after,
            "null_block_transitions": n_null_block,
            "ungrounded_high_severity_findings": n_ungrounded,
            "token_hub_rows": len(hub),
            "note": ("observations are weight-0: reported, never "
                     "scored as contradictions"),
        },
        "labelled_injected": {
            "seed": SEED,
            "n_positive": len(positives),
            "n_control": len(controls),
            "injection_types": ["noop", "target", "function",
                                "verdict", "symbol", "paused"],
            "sheaf": sheaf_metrics,
            "pairwise_baseline": pairwise_metrics,
        },
        "toy_call_path": {
            "clean_trigger_only_score": round(toy_clean_score, 4),
            "paused_candidate_score": round(toy_paused_score, 4),
            "note": "toy inputs only; no real call paths on disk",
        },
        "hypergraph_nn_sample": to_hypergraph_nn(all_edges[0])
        if all_edges else None,
        "limits": [
            "symbol_cluster: 0 real hyperedges; no non-null symbol "
            "is shared by two contracts in this data",
            "call_path: 0 real hyperedges; no real PR #178 paths "
            "exist on disk for these contracts",
            "owner_cluster: built only from transition rows; "
            "candidates carry no owner field",
            "injected-set precision is measured against untouched "
            "controls from the same pool, not against live traffic",
            "a perfect score on the toy call_path / toy symbol "
            "sets is a toy result, not a win",
        ],
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
