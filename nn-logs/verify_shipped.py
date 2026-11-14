"""Verify the SHIPPED weights.json (runtime load path) on the frozen holdout.

Loads backend/app/nn/weights.json via pipeline.load_model (the exact
code the scorer uses at runtime), extracts v2 features, and reports
train + frozen own-holdout test metrics. Also reports the combined
split for reference (expected to drop vs the old combined weights:
the honest model never saw 20% of the own rows).
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "backend")))

from app.nn.data import build_dataset, load_external_rows, stratified_split  # noqa: E402
from app.nn.mlp import metrics_for  # noqa: E402
from app.nn.pipeline import load_model  # noqa: E402
from app.nn.verify_v2 import extract_v2  # noqa: E402

NN_DIR = os.path.normpath(os.path.join(_HERE, "..", "backend", "app", "nn"))
FROZEN = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
BATCHES = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
EXTERNAL = os.path.join(NN_DIR, "external_findings.jsonl")


def main():
    model = load_model()
    assert model is not None, "load_model() returned None for shipped weights"
    net, spec, meta = model
    print(f"loaded shipped weights: layers={net.layers} "
          f"format={meta.get('format')} eval_mode={meta.get('eval_mode')} "
          f"trained_at={meta.get('trained_at')}", flush=True)
    plugins, keys = spec.plugins, spec.keys
    dataset = build_dataset(FROZEN, BATCHES)
    own_rows = dataset["rows"]
    ext_rows, _ = load_external_rows(EXTERNAL)
    own_train, own_test = stratified_split(own_rows, 0.2, 42)
    X_test = [extract_v2(r["finding"], plugins, keys) for r in own_test]
    y_test = [r["label"] for r in own_test]
    X_train = [extract_v2(r["finding"], plugins, keys)
               for r in own_train + ext_rows]
    y_train = [r["label"] for r in own_train + ext_rows]
    m_test = metrics_for(y_test, [net.predict_proba(x) for x in X_test])
    m_train = metrics_for(y_train, [net.predict_proba(x) for x in X_train])
    print(f"SHIPPED-WEIGHTS OWN-HOLDOUT test n={m_test['n']} "
          f"acc={m_test['accuracy']:.4f} auc={m_test['roc_auc']:.4f} "
          f"cm={m_test['confusion']} baseline="
          f"{m_test['majority_baseline_accuracy']:.4f}", flush=True)
    print(f"  FP recall={m_test['recall_likely_fp']:.4f} "
          f"recall_worth_validating={m_test['recall_worth_validating']:.4f}",
          flush=True)
    print(f"SHIPPED-WEIGHTS TRAIN n={m_train['n']} "
          f"acc={m_train['accuracy']:.4f} auc={m_train['roc_auc']:.4f} "
          f"cm={m_train['confusion']}", flush=True)
    _, test_comb = stratified_split(own_rows + ext_rows, 0.2, 42)
    Xc = [extract_v2(r["finding"], plugins, keys) for r in test_comb]
    yc = [r["label"] for r in test_comb]
    mc = metrics_for(yc, [net.predict_proba(x) for x in Xc])
    print(f"SHIPPED-WEIGHTS COMBINED test n={mc['n']} "
          f"acc={mc['accuracy']:.4f} auc={mc['roc_auc']:.4f} "
          f"cm={mc['confusion']} (reference only; old combined weights "
          f"scored 0.9811 here with leakage)", flush=True)
    print("VERIFY-SHIPPED-DONE", flush=True)


if __name__ == "__main__":
    main()
