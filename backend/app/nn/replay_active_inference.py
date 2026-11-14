"""Honest replay evaluation for the Active Inference triage loop.

REPLAY, NOT A LIVE RUN. No live probes are fired here.

NO-SIMULATION RULE (restated Nov 14): no simulated data anywhere.
This replay consumes ONLY real recorded outcomes. A lane query's
outcome is a real recorded fact: whether any plugin in that lane's
group fired on that contract in its historical batch
(batches.jsonl). A full probe's outcome is a real recorded verdict
(candidates.jsonl: UNVERIFIED = worth-validating). Nothing is
sampled, generated, or invented. The only counterfactual is the
ORDER in which real records are consumed: the loop chooses a
different probe order than history did. This is a reordering of
the real record, not a simulation of new observations.

What the replay cannot support: live performance. A live run would
read today's chain state; contracts change (state transitions,
proxy upgrades), so a live lane read today could differ from the
historical batch read. The replay numbers below are the loop's
performance on the historical record only. Synthetic distributions
appear ONLY in the unit self-tests of the entropy/EIG math
(tests/test_nn_active_inference.py) and are never presented as
evaluation numbers.

Protocol (anti-leakage):
- The pool is the 4,681 unique scanned addresses with known
  historical labels. Unscanned queue rows have no label and are
  excluded.
- Split-half by md5(chain:address) % 2. The module's priors and
  lane likelihoods were fit on the fit-half (== 0) only; the replay
  runs on the eval-half (== 1) only: 2,337 addresses, 287 worth.
- Baselines on the same eval-half at the same probe budgets:
  static = runner.py QUEUE_PRIORITY order, queue-file order within
  a queue, 1 probe-unit per contract; random = seed-42 shuffle.
- Budgets are probe-units: a full contract probe costs 1.0, one
  lane read costs 0.1. Static/random spend 1.0 per contract; the
  EIG loop spends 0.1 per lane and 1.0 per full probe.

Metrics per method and budget: worth-validating contracts found,
false promotes (EIG only: promoted but not truly worth), and total
decision-entropy reduction per probe-unit spent.

    python -m app.nn.replay_active_inference [--budgets 100 250 500 1000]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import sys
from collections import Counter
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.active_inference import (  # noqa: E402
    ActiveInferenceLoop,
    STATIC_QUEUE_ORDER,
    binary_entropy,
    contract_id,
    prior_for_contract,
)

LANE_PLUGINS = {
    "source_verification": {"contract_recon"},
    "recipient_probe": {"recipient_mint_to_caller", "recipient_unbacked_claim",
                        "recipient_overdraw_withdraw", "recipient_rescue_to_param",
                        "recipient_bridge_release_unproven",
                        "recipient_sig_value_to_self"},
    "gate_analysis": {"contract_logic"},
    "bytecode_deep": {"bytecode_deep_analysis"},
    "proxy_impl": {"cross_contract_call_graph", "storage_state_analysis"},
    "arithmetic_guards": {"unchecked_math_user_input",
                          "zeroday_contract_guards",
                          "state_change_without_event"},
}


def split_half(chain: str, address: str) -> int:
    return int(hashlib.md5(f"{chain}:{address}".encode()).hexdigest(), 16) % 2


def load_jsonl(path: str) -> List[Dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue  # torn row: skip, never fatal
    return rows


def load_pool(base: str):
    """(eval_contracts, worth, lane_fired, static_order).

    eval_contracts: contract dicts for the eval-half, in static
    order. worth: contract_id -> bool. lane_fired: contract_id ->
    {lane: bool} from the historical batch findings.
    """
    queues_dir = os.path.join(base, "state", "queues")
    results_dir = os.path.join(base, "results")
    cands = load_jsonl(os.path.join(results_dir, "candidates.jsonl"))
    worth = {}
    for c in cands:
        if (c.get("validation") or {}).get("verdict") == "UNVERIFIED":
            worth[contract_id(c)] = True
    batches = load_jsonl(os.path.join(results_dir, "batches.jsonl"))
    batch_by_id: Dict[str, Dict] = {}
    for b in batches:
        batch_by_id.setdefault(contract_id(b), b)
    lane_fired: Dict[str, Dict[str, bool]] = {}
    for cid, b in batch_by_id.items():
        plugins = {f.get("plugin") for f in b.get("findings") or []}
        lane_fired[cid] = {ln: bool(plugins & ps)
                           for ln, ps in LANE_PLUGINS.items()}
    # Queue rows in static order (queue priority, then file order).
    ordered: List[Dict] = []
    seen = set()
    for q in STATIC_QUEUE_ORDER:
        path = os.path.join(queues_dir, q + ".jsonl")
        if not os.path.exists(path):
            continue
        for row in load_jsonl(path):
            cid = contract_id(row)
            if cid in seen or cid not in batch_by_id:
                continue  # unscanned rows have no label: excluded
            seen.add(cid)
            ordered.append(row)
    eval_contracts = [c for c in ordered
                      if split_half(c.get("chain"), c.get("address")) == 1]
    return eval_contracts, worth, lane_fired


def run_static(contracts: List[Dict], worth: Dict[str, bool],
               budgets: List[int]) -> Dict[int, Dict]:
    out = {}
    for budget in budgets:
        probed = contracts[:budget]
        found = sum(1 for c in probed if worth.get(contract_id(c)))
        h = sum(binary_entropy(prior_for_contract(c)[0]) for c in probed)
        out[budget] = {"worth_found": found, "false_promotes": 0,
                       "contracts_probed": len(probed),
                       "queries_fired": len(probed),
                       "probe_units_spent": float(len(probed)),
                       "entropy_reduction_bits": round(h, 2),
                       "entropy_reduction_per_probe_unit":
                           round(h / len(probed), 4) if probed else 0.0}
    return out


def run_random(contracts: List[Dict], worth: Dict[str, bool],
               budgets: List[int], seed: int = 42) -> Dict[int, Dict]:
    shuffled = list(contracts)
    random.Random(seed).shuffle(shuffled)
    return run_static(shuffled, worth, budgets)


def run_eig(contracts: List[Dict], worth: Dict[str, bool],
            lane_fired: Dict[str, Dict[str, bool]],
            budgets: List[int], promote_q: float = 0.85,
            drop_q: float = 0.05) -> Dict[int, Dict]:
    out = {}
    for budget in budgets:
        loop = ActiveInferenceLoop(contracts, promote_q=promote_q,
                                   drop_q=drop_q)

        def observe(contract: Dict, query_name: str,
                    _worth=worth, _lanes=lane_fired) -> Optional[str]:
            cid = contract_id(contract)
            if query_name == "full_probe":
                return "positive" if _worth.get(cid) else "negative"
            fired = _lanes.get(cid, {}).get(query_name, False)
            return "positive" if fired else "negative"

        summary = loop.run(observe, budget=float(budget))
        promoted = summary["promoted_ids"]
        found = sum(1 for cid in promoted if worth.get(cid))
        by_query = Counter(t["query"] for t in loop.trace)
        out[budget] = {
            "worth_found": found,
            "false_promotes": len(promoted) - found,
            "contracts_probed": len({t["contract_id"] for t in loop.trace}),
            "queries_fired": len(loop.trace),
            "probe_units_spent": summary["probe_units_spent"],
            "entropy_reduction_bits": summary["entropy_reduction_bits"],
            "entropy_reduction_per_probe_unit":
                summary["entropy_reduction_per_probe_unit"],
            "queries_by_lane": dict(by_query),
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon-continuous",
                    default=os.path.expanduser(
                        "~/workspace/recon-continuous"))
    ap.add_argument("--budgets", type=int, nargs="+",
                    default=[100, 250, 500, 1000])
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--promote-q", type=float, default=0.85,
                    help="promote threshold for the EIG loop")
    ap.add_argument("--eig-variant-label", default="eig")
    args = ap.parse_args()
    contracts, worth, lane_fired = load_pool(args.recon_continuous)
    total_worth = sum(1 for c in contracts if worth.get(contract_id(c)))
    print(f"eval pool: {len(contracts)} contracts, "
          f"{total_worth} worth-validating")
    print("budgets are probe-units (full probe 1.0, lane 0.1)")
    print()
    print(f"{'method':<8} {'budget':>6} {'worth':>6} {'false+':>6} "
          f"{'probed':>6} {'queries':>7} {'spent':>7} "
          f"{'dH bits':>8} {'dH/unit':>7}")
    results = {}
    for name, fn in (("static", lambda b: run_static(contracts, worth, b)),
                     ("random", lambda b: run_random(contracts, worth, b,
                                                     seed=args.seed)),
                     (args.eig_variant_label,
                      lambda b: run_eig(contracts, worth, lane_fired, b,
                                        promote_q=args.promote_q))):
        res = fn(args.budgets)
        results[name] = res
        for budget in args.budgets:
            r = res[budget]
            print(f"{name:<8} {budget:>6} {r['worth_found']:>6} "
                  f"{r['false_promotes']:>6} {r['contracts_probed']:>6} "
                  f"{r['queries_fired']:>7} {r['probe_units_spent']:>7.1f} "
                  f"{r['entropy_reduction_bits']:>8.2f} "
                  f"{r['entropy_reduction_per_probe_unit']:>7.4f}")
        if name == args.eig_variant_label:
            for budget in args.budgets:
                print(f"  {name}@{budget} queries by lane: "
                      f"{results[name][budget]['queries_by_lane']}")
    print()
    print(json.dumps({"eval_pool": len(contracts),
                      "eval_worth_total": total_worth,
                      "budgets": args.budgets,
                      "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
