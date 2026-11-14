"""Tests for the symbolic rule layer.

Two levels: (1) rule mechanics — veto/boost/cite — tested with the
rule table itself, so they do not depend on validation coverage;
(2) rule validation — keep/drop decisions — tested on a synthetic
110-row set built to give each rule a known outcome. Fixture rows
are real-shaped (nn_fixtures.py).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.nn.symbolic import (  # noqa: E402
    _rule_table, apply_rules, combine, extract_facts, symbolic_score,
    validate_rules)
from nn_fixtures import ROWS  # noqa: E402


def _all_kept():
    """The full rule table as 'kept' (mechanics tests only)."""
    return [{"name": r["name"]} for r in _rule_table()]


def _rows():
    out = []
    for finding, label in ROWS:
        f = dict(finding)
        out.append({
            "finding": f, "label": label,
            "verdict": "UNVERIFIED" if label == 1 else "FALSE_POSITIVE",
            "chain": f.get("chain"),
            "address": "0x0000000000000000000000000000000000000001",
            "plugin": f.get("plugin"), "key": f.get("key"),
            "function": f.get("function"),
        })
    return out


def _facts(**overrides):
    base = {
        "plugin": "contract_logic", "key": "access_control_flaw",
        "severity": "high", "bounty_value": "high", "confidence": 85,
        "value": "x", "recipient_class": "CALLER-SUPPLIED",
        "chain": "bsc", "function": "mint",
        "evidence": {"risk": "high", "source_origin": "Sourcify v2",
                     "gate_analysis": "no caller gate on the function"},
        "plugin_finding_count": 1,
    }
    base.update(overrides)
    if "evidence" in overrides:
        base["evidence"] = overrides["evidence"]
    return extract_facts({"finding": base})


def _synthetic_row(**overrides):
    finding = {
        "plugin": "contract_logic", "key": "k", "severity": "medium",
        "bounty_value": "low", "confidence": 50, "value": "x",
        "recipient_class": "CALLER", "chain": "bsc", "function": "mint",
        "evidence": {"risk": "medium", "source_origin": "Sourcify v2",
                     "gate_analysis": "caller gate present"},
        "plugin_finding_count": 1,
    }
    finding.update({k: v for k, v in overrides.items()
                    if k not in ("evidence", "_label")})
    if "evidence" in overrides:
        finding["evidence"] = overrides["evidence"]
    label = overrides.get("_label", 1)
    return {"finding": finding, "label": label,
            "verdict": "UNVERIFIED" if label == 1 else "FALSE_POSITIVE",
            "chain": "bsc",
            "address": "0x0000000000000000000000000000000000000001",
            "plugin": "contract_logic", "key": "k", "function": "mint"}


def test_extract_facts_reads_real_fields():
    row = _rows()[2]  # unchecked_math proxy fixture
    facts = extract_facts(row)
    assert facts["has_proxy"] is True
    assert facts["has_implementation"] is True
    assert facts["gate_no_caller"] is True
    assert facts["recipient_is_caller"] is True
    assert facts["has_source"] is True


def test_veto_fixed_recipient_beats_high_neural_score():
    facts = _facts(recipient_class="FIXED")
    out = combine(0.99, facts, _all_kept())
    assert out["vetoed"] is True
    assert out["combined_p"] == 0.0
    assert out["label"] == "likely-false-positive"
    assert "VETO_FIXED_RECIPIENT" in out["fired_rules"]


def test_veto_holder_self_too():
    facts = _facts(recipient_class="HOLDER-SELF")
    out = combine(0.99, facts, _all_kept())
    assert out["vetoed"] is True
    assert out["combined_p"] == 0.0


def test_boost_fires_and_is_cited():
    facts = _facts()  # no caller gate + high severity
    out = combine(0.5, facts, _all_kept())
    assert "BOOST_NO_GATE_HIGH_SEV" in out["fired_rules"]
    assert out["combined_p"] > 0.5
    assert any(d["rule"] == "BOOST_NO_GATE_HIGH_SEV"
               for d in out["rule_details"])


def test_symbolic_score_is_bounded():
    for neural in (0.0, 0.5, 1.0):
        out = combine(neural, _facts(), _all_kept())
        assert 0.0 <= out["combined_p"] <= 1.0
    sym, _ = symbolic_score(_facts(), _all_kept())
    assert 0.0 <= sym <= 1.0


def test_validate_rules_keeps_supported_drops_unsupported():
    rows = []
    # 30 FIXED rows, all label 0 -> veto kept (precision 1.0).
    for _ in range(30):
        rows.append(_synthetic_row(
            recipient_class="FIXED", severity="high",
            evidence={"risk": "high", "source_origin": "Sourcify v2",
                      "gate_analysis": "caller gate present"},
            _label=0))
    # 30 caller high-confidence rows, all label 1 -> boost kept.
    for _ in range(30):
        rows.append(_synthetic_row(
            recipient_class="CALLER", confidence=90, severity="high",
            evidence={"risk": "high", "source_origin": "Sourcify v2",
                      "gate_analysis": "caller gate present"},
            _label=1))
    # 25 bytecode-only rows, all label 0 -> dampen kept.
    for _ in range(25):
        rows.append(_synthetic_row(
            evidence={"risk": "medium",
                      "gate_analysis": "caller gate present"},
            _label=0))
    # 25 proxy+impl rows, mostly label 0 -> boost dropped (precision
    # 0.16 below the base rate).
    for i in range(25):
        rows.append(_synthetic_row(
            evidence={"risk": "medium", "source_origin": "Sourcify v2",
                      "gate_analysis": "caller gate present",
                      "proxy_address": "0x01",
                      "implementation_address": "0x02"},
            _label=1 if i < 4 else 0))
    kept, dropped = validate_rules(rows)
    kept_names = {k["name"] for k in kept}
    dropped_names = {d["name"] for d in dropped}
    assert kept_names == {"VETO_FIXED_RECIPIENT",
                          "BOOST_CALLER_HIGH_CONF",
                          "DAMPEN_BYTECODE_ONLY"}
    assert "BOOST_PROXY_IMPL" in dropped_names
    assert "BOOST_NO_GATE_HIGH_SEV" in dropped_names  # zero coverage
    assert "BOOST_HIGH_BOUNTY" in dropped_names
    assert "BOOST_MULTI_FINDING" in dropped_names
    assert "DAMPEN_LOW_RISK_LOW_SEV" in dropped_names
    for k in kept:
        assert k["coverage"] >= 20
        assert k["status"] == "kept"


def test_combine_labels_are_triage_only():
    facts = _facts()
    for neural in (0.0, 0.25, 0.5, 0.75, 1.0):
        out = combine(neural, facts, _all_kept())
        assert out["label"] in ("worth-validating", "likely-false-positive")


def test_apply_rules_lists_every_fired_rule():
    facts = _facts(confidence=90, bounty_value="critical",
                   plugin_finding_count=7)
    res = apply_rules(facts, _all_kept())
    assert "BOOST_CALLER_HIGH_CONF" in res["fired"]
    assert "BOOST_HIGH_BOUNTY" in res["fired"]
    assert "BOOST_MULTI_FINDING" in res["fired"]
    assert res["vetoed"] is False
    assert res["adjustment"] > 0
