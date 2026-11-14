"""Repackage the v2 own-holdout checkpoint as the shipped weights.

Reads nn-logs/v2-ownholdout-ckpt.json (255-64-32-1, 120 epochs, the
honest own-holdout retrain), re-evaluates it on the FROZEN own
dataset (candidates.jsonl.bak-20261114: 725 rows, seed-42 split ->
580 train / 145 test) plus all 1,922 external rows, and writes the
result as backend/app/nn/weights.json + viewer-data.json, refreshing
the embedded block in viewer.html.

The frozen dataset is used deliberately: candidates.jsonl has been
edited since the retrain (Nov 14 audit: 2 VERIFIED_REAL -> FP, 2
Gravity UNVERIFIED -> FP, 4 rows removed). The 145-row holdout is
fixed by the task; the checkpoint only reproduces its claimed
0.9103 on the frozen set. One holdout row (Gravity base
contract_logic mint) was later re-adjudicated FP; the script reports
the same 145 rows scored under current labels as a secondary check.

Run: python3 nn-logs/repackage_v2.py
"""
import datetime as dt
import json
import os
import random
import sys
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "backend")))

from app.nn.data import build_dataset, load_external_rows, stratified_split  # noqa: E402
from app.nn.mlp import load_checkpoint, metrics_for, roc_auc  # noqa: E402
from app.nn.train import _refresh_viewer  # noqa: E402
from app.nn.verify_v2 import extract_v2  # noqa: E402

NN_DIR = os.path.normpath(os.path.join(_HERE, "..", "backend", "app", "nn"))
FROZEN_CANDIDATES = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114")
CURRENT_CANDIDATES = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")
BATCHES = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
EXTERNAL = os.path.join(NN_DIR, "external_findings.jsonl")
WEIGHTS = os.path.join(NN_DIR, "weights.json")
VIEWER_DATA = os.path.join(NN_DIR, "viewer-data.json")
VIEWER_HTML = os.path.join(NN_DIR, "viewer.html")
CKPT = os.path.join(_HERE, "v2-ownholdout-ckpt.json")

# v2-era importance groups (index spans over the 255 stored names).
GROUPS = [
    ("plugin", "plugin:"),
    ("key", "key:"),
    ("bounty_value", "bounty_value"),
    ("recipient_class", "recipient:"),
    ("chain", "chain:"),
    ("source_origin", "source:"),
    ("bytecode_signals", "bytecode_only_"),
    ("contract_role", "role:"),
    ("report_class", "report:"),
    ("proxy_impl", None),  # proxy_present..implementation_present
    ("function", None),    # function_present..function_len
    ("value_len", "value_len"),
    ("evidence_count", "evidence_count"),
]


def _group_spans(names):
    idx = {n: i for i, n in enumerate(names)}
    spans = {}
    for group, prefix in GROUPS:
        if prefix is not None:
            hits = [i for n, i in idx.items() if n.startswith(prefix)]
            if hits:
                spans[group] = (min(hits), max(hits) + 1)
        elif group == "proxy_impl":
            spans[group] = (idx["proxy_present"],
                            idx["implementation_present"] + 1)
        elif group == "function":
            spans[group] = (idx["function_present"],
                            idx["function_len"] + 1)
    return spans


def permutation_importance(net, names, X_test, y_test, seed=42):
    base_auc = roc_auc([net.predict_proba(x) for x in X_test], y_test)
    rng = random.Random(seed)
    out = []
    for group, (a, b) in sorted(_group_spans(names).items()):
        Xp = [list(x) for x in X_test]
        col_vals = [x[a:b] for x in Xp]
        rng.shuffle(col_vals)
        for row, vals in zip(Xp, col_vals):
            row[a:b] = vals
        auc = roc_auc([net.predict_proba(x) for x in Xp], y_test)
        out.append({"group": group, "auc_drop": round(base_auc - auc, 4)})
    out.sort(key=lambda d: d["auc_drop"], reverse=True)
    return out


def _current_labels():
    """(chain, address, plugin, key, function) -> current label."""
    from app.nn.data import VERDICT_LABELS, load_jsonl
    out = {}
    for row, err in load_jsonl(CURRENT_CANDIDATES):
        if err is not None:
            continue
        verdict = (row.get("validation") or {}).get("verdict")
        label = VERDICT_LABELS.get(verdict)
        if label is None:
            continue
        out[((row.get("chain") or "").lower(),
             (row.get("address") or "").lower(),
             row.get("plugin") or "", row.get("key") or "",
             row.get("function") or "")] = label
    return out


def main():
    with open(WEIGHTS, encoding="utf-8") as fh:
        old_weights = json.load(fh)
    with open(VIEWER_DATA, encoding="utf-8") as fh:
        old_viewer = json.load(fh)
    spec = old_weights["features"]
    plugins, keys = spec["plugins"], spec["keys"]
    net, epochs_done, _, _ = load_checkpoint(CKPT)
    print(f"ckpt epochs_done={epochs_done} layers={net.layers} "
          f"lr={net.lr} l2={net.l2} seed={net.seed}", flush=True)
    assert net.layers == [255, 64, 32, 1]

    dataset = build_dataset(FROZEN_CANDIDATES, BATCHES)
    own_rows = dataset["rows"]
    stats = dataset["stats"]
    ext_rows, ext_stats = load_external_rows(EXTERNAL)
    stats.update(ext_stats)
    own_train, own_test = stratified_split(own_rows, 0.2, 42)
    train_rows = own_train + ext_rows
    print(f"frozen own rows {len(own_rows)} train {len(own_train)} "
          f"test {len(own_test)} + external {len(ext_rows)} "
          f"= train {len(train_rows)}", flush=True)
    assert len(own_test) == 145 and len(own_train) == 580

    X_train = [extract_v2(r["finding"], plugins, keys) for r in train_rows]
    y_train = [r["label"] for r in train_rows]
    X_test = [extract_v2(r["finding"], plugins, keys) for r in own_test]
    y_test = [r["label"] for r in own_test]
    assert len(X_train[0]) == 255 and len(X_test[0]) == 255
    train_metrics = metrics_for(
        y_train, [net.predict_proba(x) for x in X_train])
    test_metrics = metrics_for(
        y_test, [net.predict_proba(x) for x in X_test])
    print(f"TRAIN n={train_metrics['n']} acc={train_metrics['accuracy']:.4f} "
          f"auc={train_metrics['roc_auc']:.4f} cm={train_metrics['confusion']}",
          flush=True)
    print(f"TEST n={test_metrics['n']} acc={test_metrics['accuracy']:.4f} "
          f"auc={test_metrics['roc_auc']:.4f} cm={test_metrics['confusion']} "
          f"baseline={test_metrics['majority_baseline_accuracy']:.4f}",
          flush=True)
    assert abs(test_metrics["accuracy"] - 0.9103) < 0.001, \
        "checkpoint does NOT reproduce claimed 0.9103"

    # Secondary check: same 145 rows under CURRENT labels (Nov 14
    # audit changed exactly one holdout row: Gravity base mint FP).
    cur = _current_labels()
    y_cur = []
    n_changed = 0
    for r in own_test:
        k = ((r["chain"] or "").lower(), (r["address"] or "").lower(),
             r["plugin"] or "", r["key"] or "", r["function"] or "")
        lab = cur.get(k, r["label"])
        if lab != r["label"]:
            n_changed += 1
            print(f"  holdout label changed since freeze: {k} "
                  f"{r['label']} -> {lab}", flush=True)
        y_cur.append(lab)
    m_cur = metrics_for(y_cur, [net.predict_proba(x) for x in X_test])
    print(f"TEST current-labels n={m_cur['n']} acc={m_cur['accuracy']:.4f} "
          f"auc={m_cur['roc_auc']:.4f} cm={m_cur['confusion']} "
          f"({n_changed} holdout row(s) relabelled since freeze)", flush=True)

    importance = permutation_importance(
        net, old_viewer["feature_names"], X_test, y_test)
    print(f"importance: {importance}", flush=True)

    n_pos = sum(y_train)
    n_neg = len(y_train) - n_pos
    pos_pct = 100.0 * n_pos / max(1, len(y_train))
    limits = list(old_weights["limits"])
    limits[2] = (
        f"Label skew: the own-holdout training set is {pos_pct:.0f}% "
        f"worth-validating / {100.0 - pos_pct:.0f}% likely-false-positive "
        f"({n_pos} positive / {n_neg} negative of {len(y_train)} rows: "
        f"580 own-train + 1,922 external). Accuracy near the majority "
        f"baseline means the model learned nothing; judge it by "
        f"minority-class recall and ROC AUC instead.")
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    stats["train_rows"] = len(train_rows)
    stats["n_positive"] = n_pos
    stats["n_negative"] = n_neg

    weights = {
        "format": "recon-nn-weights/1",
        "trained_at": now,
        "mlp": net.to_dict(),
        "features": spec,
        "metrics": {"train": train_metrics, "test": test_metrics},
        "dataset": stats,
        "limits": limits,
        "eval_mode": "own-holdout",
        "repackaged_from": "nn-logs/v2-ownholdout-ckpt.json",
        "repackaged_note": (
            "Shipped weights are the honest own-holdout v2 retrain "
            "(580 own-train + 1,922 external, tested on the fixed "
            "145-row own holdout, seed 42). The previous shipped "
            "weights were the combined-split v2 (test acc 0.9811 on "
            "a mixed own+external test set); they are preserved at "
            "nn-logs/v2-shipped-backup/weights.json. The 145-row "
            "holdout is frozen at nn-logs/own-holdout-145-bak.jsonl."),
    }
    with open(WEIGHTS, "w", encoding="utf-8") as fh:
        json.dump(weights, fh, indent=2)

    result = {
        "trained_at": now,
        "layers": [255, 64, 32, 1],
        "n_features": 255,
        "eval_mode": "own-holdout",
        "registry_plugins": len(plugins),
        "feature_names": old_viewer["feature_names"],
        "dataset": stats,
        "train_rows": len(train_rows),
        "test_rows": len(own_test),
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
        "history": {"loss": [], "train_acc": [], "val_acc": []},
        "feature_importance": importance,
        "limits": limits,
        "seed": 42,
        "epochs": epochs_done,
        "lr": net.lr,
        "external": len(ext_rows),
        "repackaged_from": "nn-logs/v2-ownholdout-ckpt.json",
        "test_current_labels": m_cur,
    }
    with open(VIEWER_DATA, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    _refresh_viewer(Path(VIEWER_HTML), result)
    print("REPACKAGE-DONE", flush=True)


if __name__ == "__main__":
    main()
