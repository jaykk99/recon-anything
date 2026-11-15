"""Point system for the ReconAnything neural triage scorer.

Jay's rule (2026-11-15): give the network a vulnerability example,
+1 point when it gets it right, -1 when it gets it wrong, over many
many tests, with a running total.

How it works
------------
* The eval set is REAL adjudicated findings only. The default set is
  the frozen 145-row own holdout (``eval/own-holdout-145.jsonl``,
  124 positive / 21 negative, seed 42) reconstructed byte-identically
  from ``candidates.jsonl.bak-20261114``. Labels are the adjudicated
  verdicts: label 1 = UNVERIFIED candidate, label 0 = FALSE_POSITIVE
  or TRIGGER_ONLY. No synthetic rows, ever.
* Each row is scored through the REAL runtime load path
  (``pipeline.load_model`` + ``features.extract`` + the multimodal
  embedder when the weights carry one + ``MLP.predict_proba``), the
  same functions ``score_finding_dicts`` uses in production.
* Threshold 0.5: score >= 0.5 predicts positive. Correct = +1 point,
  wrong = -1 point. No partial credit.
* A persistent JSON ledger records the running total, accuracy,
  per-plugin and per-chain points, the current correct streak, and a
  rounds history. Re-running appends a new round; history is never
  overwritten.

Models scored
-------------
* ``multimodal`` — 290-64-32-1 (255 finding features + 35 multimodal
  dense dims), the recommended shipped model. On the frozen holdout it
  scores tp122/fp2/fn2/tn19, accuracy 0.9724, +137 points.
* ``v2`` — 255-64-32-1 plain MLP, the fallback. On the frozen
  holdout it scores tp114/fp3/fn10/tn18, accuracy 0.9103, +119 points.

Those numbers are measured by running, not asserted from the docstring:
see ``backend/tests/test_nn_points.py`` (real-model smoke test).

Determinism note: the scorer is deterministic, so repeating the same
frozen set in later rounds earns the same points each round. New points
come from new eval sets (fresh adjudications), not from re-rolling the
same rows. The ledger keeps every round so that is visible.

Triage only: points rank the scorer, they never verify anything and
never predict VERIFIED_REAL.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from .features import extract
from .mlp import MLP  # noqa: F401  (re-exported for callers/tests)
from .multimodal import MultimodalEmbedder
from .pipeline import load_model

__all__ = [
    "THRESHOLD",
    "POINTS_CORRECT",
    "POINTS_WRONG",
    "MODEL_PATHS",
    "DEFAULT_EVAL",
    "DEFAULT_LEDGER",
    "flatten_finding",
    "load_eval_rows",
    "score_one",
    "score_rows",
    "run_round",
    "empty_ledger",
    "load_ledger",
    "save_ledger",
    "apply_round",
    "summarize",
    "main",
]

THRESHOLD = 0.5
POINTS_CORRECT = 1
POINTS_WRONG = -1

_HERE = Path(__file__).resolve().parent
MODEL_PATHS = {
    "multimodal": _HERE / "weights.json",
    "v2": _HERE / "weights_v2.json",
}
DEFAULT_EVAL = _HERE / "eval" / "own-holdout-145.jsonl"
DEFAULT_LEDGER = _HERE / "points_ledger.json"

# Verdicts that count as the positive class (a candidate worth
# validating) in the frozen holdout. The row's numeric `label` wins
# when present; this is the fallback mapping from `verdict`.
POSITIVE_VERDICTS = {"UNVERIFIED", "CANDIDATE", "VERIFIED_REAL"}


def flatten_finding(row: Dict) -> Dict:
    """One eval row -> the flat finding dict the scorer reads.

    The frozen holdout stores the finding nested under ``finding`` with
    row-level ``chain`` / ``function`` alongside. The scorer's feature
    extractor reads a flat dict, so merge the two, letting the nested
    finding win where both carry a field.
    """
    finding = row.get("finding")
    if not isinstance(finding, dict):
        finding = dict(row)
    flat = {"chain": row.get("chain"), "function": row.get("function")}
    flat.update({k: v for k, v in finding.items() if v is not None})
    if flat.get("chain") is None:
        flat["chain"] = row.get("chain") or "other"
    return flat


def row_label(row: Dict) -> int:
    """Adjudicated label for one eval row: 1 = candidate, 0 = not."""
    if "label" in row and row["label"] is not None:
        return 1 if int(row["label"]) == 1 else 0
    return 1 if str(row.get("verdict") or "").upper() in POSITIVE_VERDICTS else 0


def load_eval_rows(path: Optional[Path] = None) -> List[Dict]:
    """Load a JSONL eval set of real adjudicated rows."""
    p = Path(path) if path else DEFAULT_EVAL
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    if not rows:
        raise ValueError(f"no eval rows in {p}")
    return rows


def _embedder_for(meta: Optional[Dict]):
    if not meta or "multimodal" not in meta:
        return None
    try:
        return MultimodalEmbedder.from_dict(meta["multimodal"])
    except Exception:
        return None


def score_one(model, finding: Dict) -> Optional[float]:
    """Score one finding through the real runtime path. None if unscored."""
    net, spec, meta = model
    try:
        x = extract(finding, spec)
        emb = _embedder_for(meta)
        if emb is not None:
            block = emb.feature_block(finding)
            if block is not None:
                x = x + block
        return float(net.predict_proba(x))
    except Exception:
        return None


def score_rows(model, rows: Sequence[Dict], threshold: float = THRESHOLD,
               scorer: Optional[Callable[[Dict], Optional[float]]] = None
               ) -> List[Dict]:
    """Score every eval row. Returns one result dict per row, in order.

    ``scorer`` overrides the real model (unit tests inject a fake);
    when None the real runtime path scores each row. A row the scorer
    cannot score counts as WRONG (no free points for "unscored").
    """
    results = []
    for row in rows:
        finding = flatten_finding(row)
        p = scorer(finding) if scorer is not None else score_one(model, finding)
        label = row_label(row)
        pred = 1 if (p is not None and p >= threshold) else 0
        correct = pred == label
        results.append({
            "p": p,
            "pred": pred,
            "label": label,
            "correct": correct,
            "points": POINTS_CORRECT if correct else POINTS_WRONG,
            "plugin": str(row.get("plugin") or finding.get("plugin") or "unknown"),
            "chain": str(row.get("chain") or finding.get("chain") or "other"),
            "address": row.get("address"),
        })
    return results


def run_round(model_name: str, rows: Sequence[Dict],
              threshold: float = THRESHOLD,
              scorer: Optional[Callable[[Dict], Optional[float]]] = None
              ) -> Dict:
    """Score a whole eval set once. Returns the round summary."""
    if scorer is None:
        path = MODEL_PATHS.get(model_name)
        if path is None:
            raise ValueError(f"unknown model {model_name!r}; "
                             f"pick one of {sorted(MODEL_PATHS)}")
        model = load_model(str(path))
        if model is None:
            raise RuntimeError(f"could not load {model_name} weights from {path}")
    else:
        model = None
    results = score_rows(model, rows, threshold=threshold, scorer=scorer)
    tp = sum(1 for r in results if r["pred"] == 1 and r["label"] == 1)
    fp = sum(1 for r in results if r["pred"] == 1 and r["label"] == 0)
    fn = sum(1 for r in results if r["pred"] == 0 and r["label"] == 1)
    tn = sum(1 for r in results if r["pred"] == 0 and r["label"] == 0)
    n = len(results)
    correct = tp + tn
    points = sum(r["points"] for r in results)
    per_plugin: Dict[str, int] = {}
    per_chain: Dict[str, int] = {}
    for r in results:
        per_plugin[r["plugin"]] = per_plugin.get(r["plugin"], 0) + r["points"]
        per_chain[r["chain"]] = per_chain.get(r["chain"], 0) + r["points"]
    streak = 0
    best_streak = 0
    for r in results:
        streak = streak + 1 if r["correct"] else 0
        best_streak = max(best_streak, streak)
    return {
        "model": model_name,
        "n_tests": n,
        "points": points,
        "correct": correct,
        "wrong": n - correct,
        "accuracy": round(correct / n, 4) if n else 0.0,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "per_plugin": per_plugin,
        "per_chain": per_chain,
        "streak_end": streak,
        "best_streak": best_streak,
        "results": results,
        "threshold": threshold,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def empty_ledger() -> Dict:
    return {
        "total_points": 0,
        "n_tests": 0,
        "n_correct": 0,
        "n_wrong": 0,
        "accuracy": 0.0,
        "per_plugin": {},
        "per_chain": {},
        "current_streak": 0,
        "best_streak": 0,
        "rounds": [],
    }


def load_ledger(path: Optional[Path] = None) -> Dict:
    p = Path(path) if path else DEFAULT_LEDGER
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return empty_ledger()
    if not isinstance(data, dict) or "rounds" not in data:
        return empty_ledger()
    for key, default in empty_ledger().items():
        data.setdefault(key, default)
    return data


def save_ledger(ledger: Dict, path: Optional[Path] = None) -> Path:
    p = Path(path) if path else DEFAULT_LEDGER
    p.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n",
                 encoding="utf-8")
    return p


def apply_round(ledger: Dict, round_summary: Dict) -> Dict:
    """Fold one round into the ledger. The round is appended to history;
    totals, per-plugin / per-chain points and the running streak update.
    The streak carries across rounds in row order."""
    ledger["total_points"] += round_summary["points"]
    ledger["n_tests"] += round_summary["n_tests"]
    ledger["n_correct"] += round_summary["correct"]
    ledger["n_wrong"] += round_summary["wrong"]
    n = ledger["n_tests"]
    ledger["accuracy"] = round(ledger["n_correct"] / n, 4) if n else 0.0
    for plugin, pts in round_summary["per_plugin"].items():
        ledger["per_plugin"][plugin] = ledger["per_plugin"].get(plugin, 0) + pts
    for chain, pts in round_summary["per_chain"].items():
        ledger["per_chain"][chain] = ledger["per_chain"].get(chain, 0) + pts
    streak = ledger["current_streak"]
    for r in round_summary["results"]:
        streak = streak + 1 if r["correct"] else 0
        ledger["best_streak"] = max(ledger["best_streak"], streak)
    ledger["current_streak"] = streak
    stored = {k: v for k, v in round_summary.items() if k != "results"}
    stored["results"] = [
        {k: v for k, v in r.items() if k != "address"}
        for r in round_summary["results"]
    ]
    ledger["rounds"].append(stored)
    return ledger


def _ranked(mapping: Dict[str, int]):
    return sorted(mapping.items(), key=lambda kv: (-kv[1], kv[0]))


def summarize(ledger: Dict) -> str:
    lines = [
        f"total points: {ledger['total_points']} "
        f"over {ledger['n_tests']} tests "
        f"({ledger['n_correct']} right, {ledger['n_wrong']} wrong, "
        f"accuracy {ledger['accuracy']:.4f})",
        f"current streak: {ledger['current_streak']} correct in a row "
        f"(best {ledger['best_streak']})",
    ]
    plugins = _ranked(ledger["per_plugin"])
    if plugins:
        lines.append(f"top plugin: {plugins[0][0]} ({plugins[0][1]:+d} pts)")
        lines.append(f"bottom plugin: {plugins[-1][0]} ({plugins[-1][1]:+d} pts)")
    chains = _ranked(ledger["per_chain"])
    if chains:
        lines.append("per-chain: " + ", ".join(f"{c} {p:+d}" for c, p in chains))
    lines.append(f"rounds recorded: {len(ledger['rounds'])}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m app.nn.points",
        description="Point system for the ReconAnything neural triage "
                    "scorer: +1 per right call, -1 per wrong call, "
                    "over real adjudicated findings.")
    ap.add_argument("--model", choices=["multimodal", "v2", "both"],
                    default="both")
    ap.add_argument("--rounds", type=int, default=1,
                    help="repeat the eval set this many times "
                         "(each repeat appends a round to the ledger)")
    ap.add_argument("--eval", default=str(DEFAULT_EVAL),
                    help="JSONL of real adjudicated rows")
    ap.add_argument("--ledger", default=str(DEFAULT_LEDGER),
                    help="ledger JSON path (rounds accumulate here)")
    ap.add_argument("--threshold", type=float, default=THRESHOLD)
    args = ap.parse_args(argv)

    rows = load_eval_rows(args.eval)
    ledger = load_ledger(args.ledger)
    models = ["multimodal", "v2"] if args.model == "both" else [args.model]
    for model_name in models:
        for i in range(max(args.rounds, 1)):
            rnd = run_round(model_name, rows, threshold=args.threshold)
            apply_round(ledger, rnd)
            print(f"[{model_name}] round {i + 1}: "
                  f"{rnd['points']:+d} points over {rnd['n_tests']} tests "
                  f"(acc {rnd['accuracy']:.4f}, "
                  f"tp{rnd['confusion']['tp']}/fp{rnd['confusion']['fp']}/"
                  f"fn{rnd['confusion']['fn']}/tn{rnd['confusion']['tn']})")
    save_ledger(ledger, args.ledger)
    print(f"ledger: {args.ledger}")
    print(summarize(ledger))
    return 0


if __name__ == "__main__":  # python -m app.nn.points
    sys.exit(main())
