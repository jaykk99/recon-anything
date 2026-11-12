"""Track 4 labeled-set regression harness (pytest form).

Runs the full labeled set in benchmarks/labeled_set/ through the
inline gates + validator v2 offline logic (see
benchmarks/labeled_set/run_benchmark.py for modes and honesty
rules) and pins the invariants that must never regress:

- the dataset is present, deduplicated, and a few hundred cases;
- regression cases #1/#2 are MVK and aeWETH, and the gates catch
  their shapes (GATED_CALLER_METERED / GATED_SELF_FUNDED);
- GATE RULE: no case with expected_real_finding=false ever
  receives a VERIFIED_REAL stamp;
- the analyzer detects all canonical drain-pattern fixtures and
  stays silent (no drain kinds) on every clean control.
"""
import json
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)
sys.path.insert(0, os.path.join(BACKEND, "benchmarks", "labeled_set"))

import run_benchmark  # noqa: E402

DATASET = os.path.join(BACKEND, "benchmarks", "labeled_set",
                       "labeled_set.jsonl")
CASES = run_benchmark.load_cases(DATASET)
ROWS = [run_benchmark.evaluate(c) for c in CASES]
BY_ID = {r["contract_id"]: r for r in ROWS}

MVK = "bsc:0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0"
AEWETH = "arbitrum:0x8b194beae1d3e0788a1a35173978001acdfba668"


def test_dataset_shape_and_dedupe():
    assert len(CASES) >= 300, len(CASES)
    keys = [(c["chain"], (c.get("address") or c["contract_id"]).lower())
            for c in CASES]
    assert len(keys) == len(set(keys)), "duplicate chain+address cases"
    for c in CASES:
        assert isinstance(c["expected_real_finding"], bool)
        assert c["verdict_class"]
        assert c["contract_id"]


def test_regression_cases_1_and_2_are_mvk_and_aeweth():
    assert CASES[0]["contract_id"] == MVK
    assert CASES[1]["contract_id"] == AEWETH
    assert CASES[0]["expected_real_finding"] is False
    assert CASES[1]["expected_real_finding"] is False


def test_mvk_and_aeweth_shapes_are_gated():
    assert BY_ID[MVK]["gate"] == "GATED_CALLER_METERED"
    assert BY_ID[AEWETH]["gate"] == "GATED_SELF_FUNDED"
    assert BY_ID[AEWETH]["predicted_verdict"] == "FALSE_POSITIVE"


def test_gate_rule_no_false_case_stamped_verified_real():
    violations = [r["contract_id"] for r in ROWS if r["gate_violation"]]
    assert not violations, (
        "GATE RULE FAIL: expected_real_finding=false cases stamped "
        f"VERIFIED_REAL: {violations}")


def test_no_case_errors_out():
    errors = [r["contract_id"] for r in ROWS
              if r["evaluation_mode"] == "error"]
    assert not errors, f"cases that errored: {errors}"


def test_fixture_detection_bar():
    vuln = [r for r in ROWS if r["verdict_class"] == "KNOWN_VULNERABLE"]
    clean = [r for r in ROWS if r["verdict_class"] == "CLEAN_CONTROL"]
    assert len(vuln) == 6 and len(clean) == 12
    missed = [r["contract_id"] for r in vuln if not r["detection_hit"]]
    assert not missed, f"drain fixtures not detected: {missed}"
    noisy = [r["contract_id"] for r in clean if not r["detection_hit"]]
    assert not noisy, f"clean controls flagged with drain kinds: {noisy}"


def test_summary_metrics_are_honest():
    s = run_benchmark.summarize(ROWS)
    assert s["gate_rule"]["pass"] is True
    assert s["verified_real_decision"]["false_positive_rate"] == 0.0
    assert s["cases"] == len(CASES)
    json.dumps(s)  # summary must stay serializable for the report
