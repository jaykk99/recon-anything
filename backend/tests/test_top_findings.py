"""The report leads with confirmed findings, ranked, with proof."""
from app.reporting import (
    top_findings, verified_by_severity, executive_summary, _row_severity)


def _row(**kw):
    base = {"plugin": "p", "key": "k", "value": "v", "confidence": 80,
            "claim_status": "verified", "category": "web", "evidence": {}}
    base.update(kw)
    return base


def test_only_verified_rows_surface():
    rows = [
        _row(key="a", claim_status="verified", evidence={"severity": "high"}),
        _row(key="b", claim_status="candidate", evidence={"severity": "critical"}),
        _row(key="c", claim_status="suppressed", evidence={"severity": "high"}),
    ]
    out = top_findings(rows)
    assert [f["key"] for f in out] == ["a"]


def test_ranked_by_severity_then_confidence():
    rows = [
        _row(key="lo", confidence=90, evidence={"severity": "low"}),
        _row(key="crit", confidence=50, evidence={"severity": "critical"}),
        _row(key="hi1", confidence=70, evidence={"severity": "high"}),
        _row(key="hi2", confidence=95, evidence={"severity": "high"}),
    ]
    out = top_findings(rows)
    # critical first, then the two highs by confidence desc, then low
    assert [f["key"] for f in out] == ["crit", "hi2", "hi1", "lo"]


def test_proof_is_carried():
    rows = [_row(key="env", evidence={
        "severity": "critical",
        "proof": "env file with credential keys: DB_PASSWORD, AWS_SECRET"})]
    out = top_findings(rows)
    assert "DB_PASSWORD" in out[0]["proof"]


def test_proof_falls_back_to_precision_basis():
    rows = [_row(evidence={"severity": "high"},
                 precision={"basis": ["stranger call reverted", "gate holds"]})]
    out = top_findings(rows)
    assert "gate holds" in out[0]["proof"]


def test_verified_by_severity_counts():
    rows = [
        _row(evidence={"severity": "critical"}),
        _row(evidence={"severity": "high"}),
        _row(evidence={"severity": "high"}),
        _row(claim_status="candidate", evidence={"severity": "critical"}),
    ]
    c = verified_by_severity(rows)
    assert c["critical"] == 1 and c["high"] == 2


def test_severity_from_top_level_or_evidence():
    assert _row_severity({"evidence": {"severity": "HIGH"}}) == "high"
    assert _row_severity({"severity": "medium"}) == "medium"
    assert _row_severity({}) == "info"


def test_limit_respected():
    rows = [_row(key=str(i), evidence={"severity": "low"}) for i in range(40)]
    assert len(top_findings(rows, limit=25)) == 25


def test_executive_summary_leads_with_confirmed():
    rows = [
        _row(key="env", evidence={"severity": "critical", "proof": "env leaked"}),
        {"plugin": "x", "key": "tech", "value": "nginx", "category": "info",
         "claim_status": "candidate", "evidence": {}},
    ]
    s = executive_summary(rows)
    assert s["confirmed_count"] == 1
    assert s["confirmed_by_severity"]["critical"] == 1
    assert s["top_findings"][0]["key"] == "env"
    assert s["total_findings"] == 2


def test_empty_run_has_zero_confirmed():
    s = executive_summary([])
    assert s["confirmed_count"] == 0 and s["top_findings"] == []
