"""Offline regression harness for the Track 4 labeled set.

Feeds every case in labeled_set.jsonl through the parts of the
pipeline that can run offline - the inline static gates
(app.plugins.inline_gates.gate_candidate) and validator v2's
static logic (app.plugins.auto_validator.validate_candidate with
no probe / balance / simulation evidence) - and scores the
VERIFIED_REAL decision against the labels.

Evaluation modes (recorded per case, never hidden):

- static_offline: addressed cases. Validator v2's full path
  needs live chain probes; offline it can only settle what the
  statics settle, so most addressed cases honestly land at
  UNVERIFIED here. A GATED_SELF_FUNDED gate result IS a settled
  FALSE_POSITIVE (the receipt is the caller's own input by
  construction). A GATED_CALLER_METERED shape is recorded in the
  row's gate field but does NOT mint a verdict offline: the
  fast-path row requires the stranger basis to be measured 0
  with a live read, which this harness does not fake.
- fixture_analyzer: repo fixture cases (no address). Scored by
  the deep analyzer's finding kinds: drain-kind detection on
  KNOWN_VULNERABLE cases, drain-kind silence on CLEAN_CONTROLs.

GATE RULE: any case with expected_real_finding=false that
receives a VERIFIED_REAL stamp is a FAIL (exit code 1). This
harness is offline measurement only; it writes nothing to any
production path and promotes nothing.

Usage: python run_benchmark.py [--out benchmark_results.json]
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, BACKEND)

from app.plugins.auto_validator import validate_candidate  # noqa: E402
from app.plugins.contract_chain import analyze_contract_source  # noqa: E402
from app.plugins.inline_gates import (  # noqa: E402
    GATE_CALLER_METERED,
    GATE_SELF_FUNDED,
    gate_candidate,
)

DRAIN_KINDS = {"selfdestruct", "full_balance_withdraw", "delegatecall",
               "tx_origin", "ownership_takeover_path"}


def load_cases(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def evaluate_fixture(case):
    kinds = {f.get("kind") for f in
             analyze_contract_source(case.get("source") or "", {})}
    row = {"evaluation_mode": "fixture_analyzer",
           "detected_kinds": sorted(k for k in kinds if k)}
    if case["verdict_class"] == "KNOWN_VULNERABLE":
        m = re.search(r"expect_any=([a-z_,]+)", case.get("notes") or "")
        expect = set(m.group(1).split(",")) if m else set()
        row["detection_hit"] = bool(kinds & expect)
    elif case["verdict_class"] == "CLEAN_CONTROL":
        row["detection_hit"] = not (kinds & DRAIN_KINDS)
        row["false_alarm_kinds"] = sorted(kinds & DRAIN_KINDS)
    # The analyzer never stamps VERIFIED_REAL; fixtures measure
    # detection, not the validator's stamp.
    row["predicted_verdict"] = "NOT_STAMPED"
    return row


def evaluate_addressed(case):
    candidate = {
        "address": case.get("address") or "",
        "chain": case.get("chain") or "",
        "function": case.get("function") or "",
        "kind": case.get("kind") or case.get("vulnerability_type") or "",
        "source": case.get("source"),
        "contract_name": case.get("contract_name") or "",
    }
    gate = gate_candidate(candidate)
    row = {"evaluation_mode": "static_offline",
           "gate": gate.get("gate"), "gate_reason": gate.get("reason")}
    if gate.get("gate") == GATE_SELF_FUNDED:
        row["predicted_verdict"] = "FALSE_POSITIVE"
        row["decided_by"] = "inline_gate"
        return row
    verdict = validate_candidate(candidate)
    row["predicted_verdict"] = verdict.get("verdict")
    row["validator_reason"] = (verdict.get("reason") or "")[:300]
    row["decided_by"] = ("inline_gate_shape+validator_v2_offline"
                         if gate.get("gate") == GATE_CALLER_METERED
                         else "validator_v2_offline")
    return row


def evaluate(case):
    row = {"contract_id": case["contract_id"],
           "chain": case["chain"], "address": case.get("address"),
           "verdict_class": case["verdict_class"],
           "expected_real_finding": case["expected_real_finding"]}
    try:
        if case["chain"] == "fixture":
            row.update(evaluate_fixture(case))
        else:
            row.update(evaluate_addressed(case))
    except Exception as exc:  # never drop a case silently
        row["evaluation_mode"] = "error"
        row["predicted_verdict"] = "ERROR"
        row["error"] = f"{type(exc).__name__}: {exc}"
    row["stamped_verified_real"] = \
        row.get("predicted_verdict") == "VERIFIED_REAL"
    row["gate_violation"] = bool(
        not case["expected_real_finding"] and row["stamped_verified_real"])
    return row


def summarize(rows):
    tp = sum(1 for r in rows if r["stamped_verified_real"]
             and r["expected_real_finding"])
    fp = sum(1 for r in rows if r["stamped_verified_real"]
             and not r["expected_real_finding"])
    fn = sum(1 for r in rows if not r["stamped_verified_real"]
             and r["expected_real_finding"])
    tn = sum(1 for r in rows if not r["stamped_verified_real"]
             and not r["expected_real_finding"])
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    fixtures = [r for r in rows if r["evaluation_mode"] == "fixture_analyzer"]
    vuln = [r for r in fixtures if r["verdict_class"] == "KNOWN_VULNERABLE"]
    clean = [r for r in fixtures if r["verdict_class"] == "CLEAN_CONTROL"]
    matrix = defaultdict(Counter)
    for r in rows:
        matrix[r["verdict_class"]][r.get("predicted_verdict")] += 1
    violations = [r["contract_id"] for r in rows if r["gate_violation"]]
    return {
        "cases": len(rows),
        "evaluation_modes": dict(Counter(r["evaluation_mode"]
                                         for r in rows)),
        "verified_real_decision": {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall,
            "false_positive_rate": fpr,
            "note": "VERIFIED_REAL can only be stamped with live "
                    "measured-receipt evidence, which this offline "
                    "harness never supplies; recall here measures "
                    "the offline stamp path only. Detection recall "
                    "on positive controls is measured separately "
                    "below.",
        },
        "fixture_detection": {
            "known_vulnerable": len(vuln),
            "known_vulnerable_detected":
                sum(1 for r in vuln if r.get("detection_hit")),
            "clean_controls": len(clean),
            "clean_controls_silent":
                sum(1 for r in clean if r.get("detection_hit")),
        },
        "gate_rule": {
            "rule": "expected_real_finding=false + VERIFIED_REAL "
                    "stamp = FAIL",
            "violations": violations,
            "pass": not violations,
        },
        "pass_fail_matrix": {k: dict(v) for k, v in
                             sorted(matrix.items())},
        "gate_shapes": dict(Counter(r.get("gate") for r in rows
                                    if r.get("gate"))),
        "errors": sum(1 for r in rows
                      if r["evaluation_mode"] == "error"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.join(
        HERE, "labeled_set.jsonl"))
    ap.add_argument("--out", default=os.path.join(
        HERE, "benchmark_results.json"))
    args = ap.parse_args()
    cases = load_cases(args.dataset)
    rows = [evaluate(c) for c in cases]
    summary = summarize(rows)
    with open(args.out, "w") as f:
        json.dump({"summary": summary, "rows": rows}, f, indent=1)
    print(json.dumps(summary, indent=1))
    print("wrote", args.out)
    return 0 if summary["gate_rule"]["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
