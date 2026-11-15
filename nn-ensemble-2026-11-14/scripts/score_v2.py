"""Rescore the REVAL v2 weights on the fixed 145-row own holdout.

Loads the re-validation v2 checkpoint
(nn-reval-2026-11-14/results/v2/v2-ownholdout-ckpt.json, 120 epochs,
trained on own-train 580 + external 1,922 = 2,502 rows, seed 42),
rebuilds the split from the Nov 12 backup candidates file with the
v2 branch's own data.py, and dumps one JSON line per test row:
{key: [chain, address, plugin, key, label], label, score}.

Usage: run from the nn-reval-v2 worktree backend dir:
  python3 score_v2.py <out.jsonl>
"""
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from app.nn.data import build_dataset, stratified_split  # noqa: E402
from app.nn.mlp import load_checkpoint  # noqa: E402
from app.nn.verify_v2 import extract_v2  # noqa: E402

CAND = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
BATCH = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
CKPT = os.path.expanduser(os.environ.get(
    "ENSEMBLE_V2_CKPT",
    "~/workspace/wt/nn-reval/nn-reval-2026-11-14/results/v2/"
    "v2-ownholdout-ckpt.json"))
SPEC = os.path.join(os.getcwd(), "app", "nn", "weights.json")


def main() -> None:
    out = sys.argv[1]
    with open(SPEC, encoding="utf-8") as fh:
        spec = json.load(fh)["features"]
    net, epochs_done, _lt, _bc = load_checkpoint(CKPT)
    print(f"v2 checkpoint epochs_done={epochs_done} layers={net.layers}",
          flush=True)
    ds = build_dataset(CAND, BATCH)
    _tr, te = stratified_split(ds["rows"], 0.2, 42)
    print(f"own {len(ds['rows'])} test {len(te)} "
          f"pos {sum(1 for r in te if r['label'] == 1)} "
          f"neg {sum(1 for r in te if r['label'] == 0)}", flush=True)
    with open(out, "w", encoding="utf-8") as fh:
        for r in te:
            x = extract_v2(r["finding"], spec["plugins"], spec["keys"])
            assert len(x) == 255
            p = net.predict_proba(x)
            fh.write(json.dumps({
                "key": [r["chain"], r["address"], r["plugin"],
                        r["key"], r["label"]],
                "label": r["label"], "score": p}) + "\n")
    print(f"wrote {out} n={len(te)}", flush=True)


if __name__ == "__main__":
    main()
