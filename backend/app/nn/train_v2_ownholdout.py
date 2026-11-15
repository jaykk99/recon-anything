"""Retrain the v2 spec (255-64-32-1) with the own-holdout procedure
and check the sweep record's honest baseline.

Procedure (from NN-V2-SWEEP-RECORD.md): split Jay's own 725 rows
first (seed 42 -> 580 train / 145 test), train on own-train + all
1,922 external rows, test ONLY on the 145 own holdout rows.
Claimed: acc 0.9103, ROC AUC 0.9697, tp114 fp3 fn10 tn18.

Uses the v2 extraction from verify_v2.py and the shipped v2 spec
(24 plugins / 24 keys) from weights.json. Trains with the current
MLP (sparse forward, ~1 ULP from the dense original).

Run detached: nohup python3 train_v2_ownholdout.py > train_v2_ownholdout.log 2>&1 &
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.data import (  # noqa: E402
    build_dataset, load_external_rows, stratified_split)
from app.nn.mlp import MLP, metrics_for  # noqa: E402
from app.nn.verify_v2 import extract_v2  # noqa: E402

NN_DIR = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")
BATCHES = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
EXTERNAL = os.path.join(NN_DIR, "external_findings.jsonl")
WEIGHTS = os.path.join(NN_DIR, "weights.json")
CKPT = os.path.join(os.path.dirname(NN_DIR), "..", "..",
                    "nn-logs", "v2-ownholdout-ckpt.json")


def main():
    with open(WEIGHTS, encoding="utf-8") as fh:
        spec = json.load(fh)["features"]
    plugins, keys = spec["plugins"], spec["keys"]
    dataset = build_dataset(CANDIDATES, BATCHES)
    own_rows = dataset["rows"]
    ext_rows, _ = load_external_rows(EXTERNAL)
    own_train, own_test = stratified_split(own_rows, 0.2, 42)
    train_rows = own_train + ext_rows
    print(f"own train {len(own_train)} test {len(own_test)} "
          f"+ external {len(ext_rows)} = train {len(train_rows)}",
          flush=True)
    X_train = [extract_v2(r["finding"], plugins, keys)
               for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract_v2(r["finding"], plugins, keys)
              for r in own_test]
    y_test = [r["label"] for r in own_test]
    assert len(X_train[0]) == 255
    net = MLP([255, 64, 32, 1], seed=42, lr=0.05)
    net.fit(X_train, y_train, epochs=120, batch_size=32,
            X_val=X_test, y_val=y_test, seed=42, history_every=20,
            checkpoint_path=CKPT, checkpoint_every=20)
    m = metrics_for(y_test, [net.predict_proba(x) for x in X_test])
    print(f"V2-OWNHOLDOUT-RETRAIN test n={m['n']} "
          f"acc={m['accuracy']:.4f} auc={m['roc_auc']:.4f} "
          f"cm={m['confusion']} baseline={m['majority_baseline_accuracy']:.4f}",
          flush=True)
    print(f"  claimed: n=145 acc=0.9103 auc=0.9697 "
          f"cm tp114 fp3 fn10 tn18", flush=True)
    print("OWNHOLDOUT-RETRAIN-DONE", flush=True)


if __name__ == "__main__":
    main()
