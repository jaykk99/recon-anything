"""Verify the shipped v2 artifacts reproduce their claimed numbers.

The v2 code was superseded in the working tree by the v3 spec, so
this script re-implements the v2 (255-feature) extraction faithfully
from the v2 spec recorded in the shipped weights.json, loads the
shipped v2 weights, and evaluates them on:
  1. the combined split (own + external, seed 42) -> the official
     train log claims acc 0.981, ROC AUC 0.998, tp444 fp4 fn6 tn76
     on 530 test rows.
  2. the own-holdout split (own rows only, seed 42) -> the sweep
     record claims acc 0.9103, ROC AUC 0.9697, tp114 fp3 fn10 tn18
     on 145 test rows.

Run detached: nohup python3 verify_v2.py > verify-v2.log 2>&1 &
"""
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.data import (  # noqa: E402
    build_dataset, load_external_rows, stratified_split)
from app.nn.mlp import MLP, metrics_for  # noqa: E402

NN_DIR = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")
BATCHES = os.path.expanduser(
    "~/workspace/recon-continuous/results/batches.jsonl")
EXTERNAL = os.path.join(NN_DIR, "external_findings.jsonl")
WEIGHTS = os.path.join(NN_DIR, "weights.json")

PLUGIN_BLOCK = ("fired", "confidence", "severity", "risk", "count",
                "gate_present", "gate_no_caller", "detector_present")
COUNT_CAP = 8.0
RECIPIENT_CLASSES = ("CALLER", "CALLER-SUPPLIED", "FIXED",
                     "HOLDER-SELF", "OTHER")
CHAINS = ("bsc", "ethereum", "base", "arbitrum", "polygon", "other")
SOURCE_ORIGINS = ("Sourcify v2", "Blockscout", "other")
CONTRACT_ROLES = ("implementation", "standalone", "proxy_shell", "other")
REPORT_CLASSES = ("candidate", "trigger_only", "other")
SEVERITY_ORDER = ("low", "medium", "high", "critical")
BOUNTY_ORDER = ("low", "medium", "high", "critical")


def _ordinal(value, order):
    v = (value or "").strip().lower()
    if v not in order:
        return 0.0
    return order.index(v) / max(1, len(order) - 1)


def _one_hot(value, choices):
    v = (value or "").strip()
    out = [0.0] * len(choices)
    if v in choices:
        out[choices.index(v)] = 1.0
    else:
        out[-1] = 1.0
    return out


def _top_one_hot(value, vocab):
    out = [0.0] * (len(vocab) + 1)
    v = (value or "").strip()
    if v in vocab:
        out[vocab.index(v)] = 1.0
    else:
        out[-1] = 1.0
    return out


def extract_v2(finding, plugins, keys):
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    vec = []
    n_blocks = len(plugins) + 1
    plugin = str(finding.get("plugin") or "")
    fired_idx = (plugins.index(plugin) if plugin in plugins
                 else n_blocks - 1)
    try:
        conf = float(finding.get("confidence") or 0)
    except (TypeError, ValueError):
        conf = 0.0
    conf = max(0.0, min(1.0, conf / 100.0))
    sev = _ordinal(str(finding.get("severity") or ev.get("severity") or ""),
                   SEVERITY_ORDER)
    risk = _ordinal(str(ev.get("risk") or ""), SEVERITY_ORDER)
    try:
        count = float(finding.get("plugin_finding_count") or 1)
    except (TypeError, ValueError):
        count = 1.0
    count = max(0.0, min(1.0, count / COUNT_CAP))
    gate = str(ev.get("gate_analysis") or "")
    gate_present = 1.0 if gate else 0.0
    gate_no_caller = 1.0 if "no caller gate" in gate.lower() else 0.0
    detector_present = 1.0 if ev.get("detector_outcome") not in (None, "") else 0.0
    block_vals = [1.0, conf, sev, risk, count, gate_present,
                  gate_no_caller, detector_present]
    for b in range(n_blocks):
        if b == fired_idx:
            vec += block_vals
        else:
            vec += [0.0] * len(PLUGIN_BLOCK)
    key = finding.get("key") or ev.get("check") or ""
    vec += _top_one_hot(str(key), keys)
    vec.append(_ordinal(str(finding.get("bounty_value") or ""), BOUNTY_ORDER))
    vec += _one_hot(str(finding.get("recipient_class") or "OTHER"),
                    RECIPIENT_CLASSES)
    chain = (finding.get("chain") or ev.get("chain") or "other")
    vec += _one_hot(str(chain).lower(), CHAINS)
    src = str(ev.get("source_origin") or "")
    vec += _one_hot(src if src in SOURCE_ORIGINS else "other",
                    SOURCE_ORIGINS)
    bonly = ev.get("bytecode_only")
    vec.append(1.0 if bonly is not None else 0.0)
    vec.append(1.0 if bonly is True
               or str(bonly).strip().lower() == "true" else 0.0)
    vec += _one_hot(str(ev.get("contract_role") or "other"),
                    CONTRACT_ROLES)
    vec += _one_hot(str(ev.get("report_class") or "other"),
                    REPORT_CLASSES)
    vec.append(1.0 if ev.get("proxy_address") else 0.0)
    vec.append(1.0 if ev.get("implementation_address") else 0.0)
    fn = str(finding.get("function") or ev.get("function") or "")
    vec.append(1.0 if fn else 0.0)
    vec.append(min(1.0, len(fn) / 64.0))
    value = str(finding.get("value") or "")
    vec.append(min(1.0, math.log10(1.0 + len(value)) / 4.0))
    vec.append(min(1.0, len(ev) / 20.0))
    return vec


def main():
    with open(WEIGHTS, encoding="utf-8") as fh:
        w = json.load(fh)
    spec = w["features"]
    plugins, keys = spec["plugins"], spec["keys"]
    print(f"shipped v2 spec: {len(plugins)} plugins, {len(keys)} keys, "
          f"version {spec.get('spec_version')}")
    print(f"shipped v2 metrics: {json.dumps(w['metrics']['test'])}")
    net = MLP.from_dict(w["mlp"])
    print(f"loaded net layers {net.layers}")

    dataset = build_dataset(CANDIDATES, BATCHES)
    own_rows = dataset["rows"]
    ext_rows, _ = load_external_rows(EXTERNAL)
    print(f"own rows {len(own_rows)}, external rows {len(ext_rows)}")

    # 1. combined split (the official train.py behaviour)
    _, test_comb = stratified_split(own_rows + ext_rows, 0.2, 42)
    X = [extract_v2(r["finding"], plugins, keys) for r in test_comb]
    y = [r["label"] for r in test_comb]
    assert len(X[0]) == 255, f"v2 dim {len(X[0])} != 255"
    m = metrics_for(y, [net.predict_proba(x) for x in X])
    print(f"COMBINED test n={m['n']} acc={m['accuracy']:.4f} "
          f"auc={m['roc_auc']:.4f} cm={m['confusion']} "
          f"baseline={m['majority_baseline_accuracy']:.4f}")
    print(f"  claimed: n=530 acc=0.9811 auc=0.9978 "
          f"cm tp444 fp4 fn6 tn76")

    # 2. own-holdout split (the sweep record's procedure)
    _, test_own = stratified_split(own_rows, 0.2, 42)
    Xo = [extract_v2(r["finding"], plugins, keys) for r in test_own]
    yo = [r["label"] for r in test_own]
    mo = metrics_for(yo, [net.predict_proba(x) for x in Xo])
    print(f"OWN-HOLDOUT test n={mo['n']} acc={mo['accuracy']:.4f} "
          f"auc={mo['roc_auc']:.4f} cm={mo['confusion']} "
          f"baseline={mo['majority_baseline_accuracy']:.4f}")
    print(f"  claimed: n=145 acc=0.9103 auc=0.9697 "
          f"cm tp114 fp3 fn10 tn18")
    print("VERIFY-DONE")


if __name__ == "__main__":
    main()
