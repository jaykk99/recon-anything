"""Rescore the REVAL hypergraph weights on the fixed 145-row holdout.

Loads nn-reval-2026-11-14/results/hyper/weights.json (255-16-16-1,
200 epochs, trained on own-train 580 + external 1,922 = 2,502 rows,
seed 42), rebuilds the split from the Nov 12 backup candidates file
with the hypergraph branch's own data.py, builds the test hypergraph
from the TEST rows only (same protocol as train_hypergraph.py: no
train/test edge leakage), and dumps one JSON line per test row:
{key: [chain, address, plugin, key, label], label, score}.

Usage: run from the nn-reval-hyper worktree backend dir:
  python3 score_hyper.py <out.jsonl>
"""
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from app.nn.data import build_dataset, stratified_split  # noqa: E402
from app.nn.features import FeatureSpec, extract  # noqa: E402
from app.nn.hypergraph import HypergraphNN, build_hypergraph  # noqa: E402

CAND = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
BATCH = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
WEIGHTS = os.path.expanduser(os.environ.get(
    "ENSEMBLE_HYPER_WEIGHTS",
    "~/workspace/wt/nn-reval/nn-reval-2026-11-14/results/hyper/weights.json"))


def main() -> None:
    out = sys.argv[1]
    with open(WEIGHTS, encoding="utf-8") as fh:
        w = json.load(fh)
    net = HypergraphNN.from_dict(w["hypergraph"])
    spec = FeatureSpec.from_dict(w["features"])
    print(f"hypergraph layers={net.to_dict()['layers']} "
          f"n_features={spec.dim} trained_at={w.get('trained_at')}",
          flush=True)
    ds = build_dataset(CAND, BATCH)
    _tr, te = stratified_split(ds["rows"], 0.2, 42)
    print(f"own {len(ds['rows'])} test {len(te)} "
          f"pos {sum(1 for r in te if r['label'] == 1)} "
          f"neg {sum(1 for r in te if r['label'] == 0)}", flush=True)
    X = [extract(r["finding"], spec) for r in te]
    edges, stats = build_hypergraph(te)
    print(f"test hypergraph: {stats['n_edges']} edges, "
          f"{stats['nodes_covered']}/{stats['nodes_total']} covered",
          flush=True)
    probs = net.predict_proba_nodes(X, edges)
    with open(out, "w", encoding="utf-8") as fh:
        for r, p in zip(te, probs):
            fh.write(json.dumps({
                "key": [r["chain"], r["address"], r["plugin"],
                        r["key"], r["label"]],
                "label": r["label"], "score": p}) + "\n")
    print(f"wrote {out} n={len(te)}", flush=True)


if __name__ == "__main__":
    main()
