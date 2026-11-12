"""Audit report renders findings into a shareable markdown deliverable."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.audit_report import (  # noqa: E402
    build_report, render_markdown, triage_corpus,
)


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


def test_token_market_remediation():
    """Report must render token/memecoin risk (pump.fun/SPL + any market)
    with the right remediation, not just Solidity findings."""
    findings = [
        {"kind": "rugcheck_mint_authority", "severity": "high",
         "detail": "mint authority active"},
        {"kind": "rugcheck_liquidity_unlocked", "severity": "critical",
         "detail": "LP not locked"},
        {"kind": "honeypot", "severity": "critical", "detail": "sells blocked"},
        {"kind": "creator_share", "severity": "medium",
         "detail": "creator holds 14%"},
    ]
    md = render_markdown(build_report("SoLmint...", "solana", findings))
    assert "Revoke mint authority" in md
    assert "locked or burned" in md
    assert "Honeypot" in md
    assert "dev dump" in md


def test_triage_corpus_writes_reports_and_ranked_index(tmp_path):
    """Batch triage: one report per contract above the severity floor,
    plus a risk-ranked INDEX.md. Below-floor contracts are skipped."""
    import json
    corpus = [
        {"address": "0xAAA", "chain": "ethereum", "findings": [
            {"check": "full_balance_withdraw", "severity": "critical",
             "function": "drain", "detail": "ungated full withdraw"}]},
        {"address": "0xBBB", "chain": "bsc", "findings": [
            {"kind": "tx_origin", "severity": "high", "detail": "tx.origin auth"}]},
        {"address": "SoL1", "chain": "solana", "findings": [
            {"kind": "rugcheck_mint_authority", "severity": "high",
             "detail": "mint authority active"}]},
        {"address": "0xCCC", "chain": "base", "findings": [
            {"check": "cosmetic", "severity": "info", "detail": "noise"}]},
    ]
    src = tmp_path / "findings.jsonl"
    src.write_text("\n".join(json.dumps(r) for r in corpus))
    out = tmp_path / "triage"

    summary = triage_corpus(str(src), str(out), min_severity="low")
    assert summary["reports_written"] == 3            # info-only skipped
    names = {p.name for p in out.iterdir()}
    assert "INDEX.md" in names
    assert "critical_0xAAA.md" in names               # worst-severity prefix
    assert not any("0xCCC" in n for n in names)       # below floor, no file

    index = (out / "INDEX.md").read_text()
    assert index.index("0xAAA") < index.index("0xBBB")  # critical ranked first

    # tightening the floor drops the high-severity contracts
    out2 = tmp_path / "triage_crit"
    s2 = triage_corpus(str(src), str(out2), min_severity="critical")
    assert s2["reports_written"] == 1


def test_dedupe_merges_corroborating_findings_capped_below_confirmed():
    """Several detectors flagging one issue collapse to a single finding
    that records corroboration and raises confidence - but corroboration
    alone can't reach the confirmed tier (75)."""
    findings = [
        {"kind": "reentrancy", "severity": "high", "function": "claim",
         "detail": "ext call before state", "confidence": 60,
         "plugin": "contract_audit"},
        {"kind": "reentrancy", "severity": "critical", "function": "claim",
         "detail": "external call before state write", "confidence": 66,
         "plugin": "contract_chain"},
        {"kind": "reentrancy", "severity": "high", "function": "claim",
         "detail": "reentrancy", "confidence": 55, "plugin": "deep_audit_7"},
        {"kind": "tx_origin", "severity": "high", "function": "auth",
         "detail": "tx.origin", "confidence": 70, "plugin": "contract_audit"},
    ]
    report = build_report("0xabc", "ethereum", findings)
    fs = report["findings"]
    assert len(fs) == 2                        # 3 reentrancy -> 1, + tx_origin
    re_f = next(f for f in fs if f["kind"] == "reentrancy")
    assert re_f["severity"] == "critical"      # worst severity wins
    assert re_f["corroboration"] == 3
    assert re_f["confidence"] == 74            # capped below confirmed(75)
    assert "corroborated by 3 detectors" in render_markdown(report)


def test_dedupe_preserves_confirmed_base_confidence():
    findings = [
        {"kind": "selfdestruct", "severity": "critical", "function": "kill",
         "confidence": 80, "plugin": "a"},
        {"kind": "selfdestruct", "severity": "critical", "function": "kill",
         "confidence": 78, "plugin": "b"},
    ]
    f = build_report("0x", "eth", findings)["findings"][0]
    assert f["confidence"] == 85               # already confirmed: not capped


def test_dedupe_keeps_distinct_findings_separate():
    findings = [
        {"kind": "reentrancy", "severity": "high", "function": "claim",
         "confidence": 60},
        {"kind": "reentrancy", "severity": "high", "function": "withdraw",
         "confidence": 60},   # different function = different finding
    ]
    assert len(build_report("0x", "eth", findings)["findings"]) == 2


def test_triage_skips_dust_keeps_real_and_unknown(tmp_path):
    """min_value_usd strips 'nominally 100k but dust' contracts, keeps the
    real ones and the ones we can't value, ranks by value within severity."""
    import json
    rows = [
        {"address": "0xREAL", "chain": "ethereum", "value_usd": 2_500_000,
         "findings": [{"check": "full_balance_withdraw", "severity": "critical",
                       "function": "drain", "detail": "ungated"}]},
        {"address": "0xDUST", "chain": "bsc", "value_usd": 120,
         "findings": [{"kind": "tx_origin", "severity": "high",
                       "detail": "tx.origin"}]},
        {"address": "0xNOMINAL", "chain": "base", "value_usd": 0,
         "findings": [{"check": "mint_authority_active", "severity": "high",
                       "detail": "infinite mint, no pool"}]},
        {"address": "0xUNKNOWN", "chain": "ethereum",
         "findings": [{"kind": "reentrancy", "severity": "high",
                       "function": "claim", "detail": "reentrant"}]},
    ]
    src = tmp_path / "f.jsonl"
    src.write_text("\n".join(json.dumps(r) for r in rows))
    out = tmp_path / "tri"
    s = triage_corpus(str(src), str(out), min_severity="low",
                      min_value_usd=100_000)
    assert s["reports_written"] == 2
    assert s["skipped_dust"] == 2
    assert s["index"] == ["0xREAL", "0xUNKNOWN"]   # real first, unknown kept
    index = (out / "INDEX.md").read_text()
    assert "$2,500,000" in index and "skipped as dust" in index
    assert "0xDUST" not in index and "0xNOMINAL" not in index


def test_triage_only_kinds_hunts_specific_vuln_including_zeroday(tmp_path):
    """only_kinds keeps just the contracts that have the hunted vuln class -
    e.g. the zero-day guard_convention_break - and reports the rest skipped."""
    import json
    rows = [
        {"address": "0xZERO", "chain": "ethereum", "value_usd": 2_000_000,
         "findings": [{"kind": "guard_convention_break", "severity": "high",
                       "function": "setAll", "detail": "breaks convention"}]},
        {"address": "0xREENT", "chain": "ethereum", "value_usd": 500_000,
         "findings": [{"kind": "reentrancy", "severity": "high",
                       "function": "claim", "detail": "reentrant"}]},
        {"address": "0xBORING", "chain": "bsc", "value_usd": 900_000,
         "findings": [{"kind": "shadowed_var", "severity": "low",
                       "detail": "cosmetic"}]},
    ]
    src = tmp_path / "f.jsonl"
    src.write_text("\n".join(json.dumps(r) for r in rows))

    s = triage_corpus(str(src), str(tmp_path / "a"), min_severity="low",
                      only_kinds={"guard_convention_break"})
    assert s["index"] == ["0xZERO"]
    assert s["skipped_kind"] == 2

    s2 = triage_corpus(str(src), str(tmp_path / "b"), min_severity="low",
                       only_kinds={"guard_convention_break", "reentrancy"})
    assert set(s2["index"]) == {"0xZERO", "0xREENT"}
    assert s2["skipped_kind"] == 1


def test_report_coverage_states_zero_drainable_paths_when_clean():
    """A clean report is a defensible artifact: it states 0 fund-loss paths
    were found and lists what was checked, not just an empty findings list."""
    r = build_report("0xCLEAN", "ethereum", [])
    assert r["drainable_paths"] == []
    md = render_markdown(r)
    assert "fund-loss / takeover paths found: 0" in md
    assert "Checks performed:" in md
    assert "Reentrancy on value-transferring paths" in md


def test_report_coverage_names_drainable_paths_when_present():
    r = build_report("0xVULN", "ethereum", [
        {"kind": "full_balance_withdraw", "severity": "critical",
         "function": "drain", "detail": "ungated withdraw"},
        {"kind": "reentrancy", "severity": "high", "function": "claim",
         "detail": "ext call before state"},
        {"kind": "shadowed_var", "severity": "low", "detail": "cosmetic"},
    ])
    # cosmetic finding is not a drainable path
    assert r["drainable_paths"] == ["full_balance_withdraw", "reentrancy"]
    md = render_markdown(r)
    assert "paths found: 2" in md
    assert "`full_balance_withdraw`" in md and "`reentrancy`" in md


def test_report_accepts_custom_checks_run():
    r = build_report("0xA", "ethereum", [], checks_run=["Only this check"])
    assert r["coverage"] == ["Only this check"]
    assert "Only this check" in render_markdown(r)
