"""Dump the fixed own-holdout split (seed 42) from one branch's data.py.

Usage: dump_split.py <worktree-backend-dir> <out.json>
Builds the dataset from the Nov 12 backup candidates file
(candidates.jsonl.bak-20261114, 727 rows -> 725 own rows after the 2
VERIFIED_REAL exclusions) + batches.jsonl, runs stratified_split(0.2, 42),
and writes own/train/test counts, label counts, dataset stats and the
sorted test-row keys. Run once per branch (v2 / hypergraph / multimodal)
and diff the test_keys: identical keys = the exact same 145-row holdout.
"""
import json
import os
import sys

sys.path.insert(0, sys.argv[1])
from app.nn.data import build_dataset, stratified_split  # noqa: E402

CAND = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
BATCH = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")


def main() -> None:
    ds = build_dataset(CAND, BATCH)
    rows = ds["rows"]
    tr, te = stratified_split(rows, 0.2, 42)
    keys = sorted([(r["chain"], r["address"], r["plugin"], r["key"],
                    r["label"]) for r in te])
    json.dump({"n_own": len(rows), "n_train": len(tr), "n_test": len(te),
               "test_pos": sum(1 for r in te if r["label"] == 1),
               "test_neg": sum(1 for r in te if r["label"] == 0),
               "stats": ds["stats"], "test_keys": keys},
              open(sys.argv[2], "w"), indent=1)
    print(sys.argv[2], "own", len(rows), "train", len(tr), "test", len(te),
          "pos", sum(1 for r in te if r["label"] == 1),
          "neg", sum(1 for r in te if r["label"] == 0), flush=True)
    print("batch stats:", ds["stats"]["batch_rows"],
          ds["stats"]["batch_torn_lines"], ds["stats"]["batch_findings"],
          "joined", ds["stats"]["joined_with_evidence"], flush=True)


if __name__ == "__main__":
    main()
