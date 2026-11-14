"""Evaluate a checkpoint file on the fixed own-holdout (145 rows, seed 42).

Usage: python3 eval_ckpt.py [ckpt_path]
Loads the checkpoint MLP, extracts v2 (255) features, and reports
train + own-holdout test metrics. Pure stdlib.
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "backend")))

from app.nn.data import build_dataset, load_external_rows, stratified_split  # noqa: E402
from app.nn.mlp import load_checkpoint, metrics_for  # noqa: E402
from app.nn.verify_v2 import extract_v2  # noqa: E402

NN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend", "app", "nn")
CANDIDATES = os.path.expanduser("~/workspace/recon-continuous/results/candidates.jsonl")
BATCHES = os.path.expanduser("~/workspace/recon-continuous/results/batches.jsonl")
EXTERNAL = os.path.join(NN_DIR, "external_findings.jsonl")
WEIGHTS = os.path.join(NN_DIR, "weights.json")


def main():
    ckpt_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "v2-ownholdout-ckpt.json")
    cand_path = (sys.argv[2] if len(sys.argv) > 2 else CANDIDATES)
    dump_path = sys.argv[3] if len(sys.argv) > 3 else None
    with open(WEIGHTS, encoding="utf-8") as fh:
        spec = json.load(fh)["features"]
    plugins, keys = spec["plugins"], spec["keys"]
    net, epochs_done, _, _ = load_checkpoint(ckpt_path)
    print(f"ckpt: {ckpt_path} epochs_done={epochs_done} layers={net.layers} "
          f"lr={net.lr} l2={net.l2} seed={net.seed}", flush=True)
    dataset = build_dataset(cand_path, BATCHES)
    own_rows = dataset["rows"]
    ext_rows, _ = load_external_rows(EXTERNAL)
    own_train, own_test = stratified_split(own_rows, 0.2, 42)
    print(f"own rows {len(own_rows)} train {len(own_train)} "
          f"test {len(own_test)} + external {len(ext_rows)}", flush=True)
    if dump_path:
        with open(dump_path, "w", encoding="utf-8") as fh:
            for r in own_test:
                fh.write(json.dumps(r, default=str) + "\n")
        print(f"holdout dumped to {dump_path} ({len(own_test)} rows)",
              flush=True)
    X_test = [extract_v2(r["finding"], plugins, keys) for r in own_test]
    y_test = [r["label"] for r in own_test]
    X_train = [extract_v2(r["finding"], plugins, keys)
               for r in own_train + ext_rows]
    y_train = [r["label"] for r in own_train + ext_rows]
    assert len(X_test[0]) == 255 and len(X_train[0]) == 255
    m_test = metrics_for(y_test, [net.predict_proba(x) for x in X_test])
    m_train = metrics_for(y_train, [net.predict_proba(x) for x in X_train])
    print(f"OWN-HOLDOUT test n={m_test['n']} acc={m_test['accuracy']:.4f} "
          f"auc={m_test['roc_auc']:.4f} cm={m_test['confusion']} "
          f"baseline={m_test['majority_baseline_accuracy']:.4f}", flush=True)
    print(f"  FP recall (likely-fp recall)={m_test['recall_likely_fp']:.4f} "
          f"precision_likely_fp={m_test['precision_likely_fp']:.4f} "
          f"recall_worth_validating={m_test['recall_worth_validating']:.4f}",
          flush=True)
    print(f"TRAIN n={m_train['n']} acc={m_train['accuracy']:.4f} "
          f"auc={m_train['roc_auc']:.4f} cm={m_train['confusion']}",
          flush=True)
    print("EVAL-CKPT-DONE", flush=True)


if __name__ == "__main__":
    main()
