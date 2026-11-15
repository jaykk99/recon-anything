"""Rescore the REVAL multimodal weights on the fixed 145-row holdout.

Loads nn-reval-2026-11-14/results/multi/weights.json (290-64-32-1,
120 epochs, trained on own-train 580 + external 1,922 = 2,502 rows,
seed 42; embedder fit on TRAIN rows only), rebuilds the split from
the Nov 12 backup candidates file with the multimodal branch's own
data.py, and dumps one JSON line per test row:
{key: [chain, address, plugin, key, label], label, score}.

The MLP score only (not the 0.7 MLP + 0.3 kNN blend) is used: the
blend is a separate multimodal-internal result, and the ensemble
member here is the multimodal MLP itself.

Usage: run from the nn-reval-multi worktree backend dir:
  python3 score_multi.py <out.jsonl>
"""
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from app.nn.data import build_dataset, stratified_split  # noqa: E402
from app.nn.features import FeatureSpec, extract  # noqa: E402
from app.nn.mlp import MLP  # noqa: E402
from app.nn.multimodal import MultimodalEmbedder  # noqa: E402

CAND = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
BATCH = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
WEIGHTS = os.path.expanduser(os.environ.get(
    "ENSEMBLE_MULTI_WEIGHTS",
    "~/workspace/wt/nn-reval/nn-reval-2026-11-14/results/multi/weights.json"))


def main() -> None:
    out = sys.argv[1]
    with open(WEIGHTS, encoding="utf-8") as fh:
        w = json.load(fh)
    net = MLP.from_dict(w["mlp"])
    spec = FeatureSpec.from_dict(w["features"])
    emb = MultimodalEmbedder.from_dict(w["multimodal"])
    print(f"multimodal layers={net.layers} n_features={spec.dim} "
          f"trained_at={w.get('trained_at')}", flush=True)
    ds = build_dataset(CAND, BATCH)
    _tr, te = stratified_split(ds["rows"], 0.2, 42)
    print(f"own {len(ds['rows'])} test {len(te)} "
          f"pos {sum(1 for r in te if r['label'] == 1)} "
          f"neg {sum(1 for r in te if r['label'] == 0)}", flush=True)
    with open(out, "w", encoding="utf-8") as fh:
        for r in te:
            x = extract(r["finding"], spec) + emb.feature_block(r)
            assert len(x) == 290
            p = net.predict_proba(x)
            fh.write(json.dumps({
                "key": [r["chain"], r["address"], r["plugin"],
                        r["key"], r["label"]],
                "label": r["label"], "score": p}) + "\n")
    print(f"wrote {out} n={len(te)}", flush=True)


if __name__ == "__main__":
    main()
