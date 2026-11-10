"""Audit report renders findings into a shareable markdown deliverable."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.audit_report import build_report, render_markdown  # noqa: E402


def test_report_renders_findings_and_probe_verdict():
    findings = [
        {"kind": "selfdestruct", "severity": "high", "function": "kill",
         "detail": "selfdestruct present", "code": "selfdestruct(msg.sender)"},
        {"kind": "reentrancy", "severity": "critical", "function": "claim",
         "detail": "external call before state write", "confidence": 88},
    ]
    probes = [{"finding": "reentrancy", "verdict": "UNVERIFIED",
               "transcript": "probe could not confirm live"}]
    md = render_markdown(build_report("0xabc", "ethereum", findings,
                                      probes=probes))
    assert "# Security Review" in md
    assert "Critical" in md and "High" in md
    assert "RA-001" in md
    assert "checks-effects-interactions" in md  # remediation present
    assert "UNVERIFIED" in md                   # probe verdict carried
    # critical sorts before high
    assert md.index("reentrancy") < md.index("selfdestruct")


def test_empty_findings_report():
    md = render_markdown(build_report("0xabc", "bsc", []))
    assert "No findings" in md
