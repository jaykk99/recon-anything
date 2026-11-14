"""Deep-audit batch-17 detector (AI dev, 2026-11-11).

The vulnerable fixture MUST fire with the plugin's own finding
kind + code evidence + gate analysis, classified candidate; the
FIXED-recipient variant MUST fire trigger-only at low severity
(never a candidate); every clean control MUST stay silent; every
other primitive leg (selfdestruct, upgrade, mint) MUST fire
candidate on its own vulnerable shape; the batch-11 fixtures MUST
stay silent under this detector (no cross-batch noise) and this
detector's vulnerable fixture MUST stay silent under all five
batch-11 detectors; the registry discovers exactly 1438 plugins
including this one.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit11_fixtures as fx11  # noqa: E402
import deep_audit17_fixtures as fx  # noqa: E402
from app.plugins.deep_audit11 import analyze_deep11_source, \
    SPECS as SPECS11  # noqa: E402
from app.plugins.deep_audit17 import SPECS, SPECS_BY_ID, \
    analyze_deep17_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

PID = "zeroday_exploit_chain"


def hits_for(src, pid=PID):
    return analyze_deep17_source(src, SPECS_BY_ID[pid])


def test_one_plugin_registered():
    assert len(SPECS) == 1
    reg = discover()
    assert PID in reg, f"{PID} missing from registry"


def test_registry_count_1438():
    reg = discover()
    assert len(reg) == 1438, \
        f"registry size {len(reg)}, expected 1438"


def test_vuln_fires_candidate_with_evidence():
    hits = hits_for(fx.VULN[PID])
    assert hits, f"{PID}: vulnerable fixture did not fire"
    assert all(h["kind"] == PID for h in hits)
    assert [h["function"] for h in hits] == ["execute"]
    assert hits[0]["leg"] == "delegatecall"
    assert hits[0]["value_basis"] == "fund_move"
    assert "target" in hits[0]["detail"]
    for h in hits:
        assert h["code"], f"{PID}: no code evidence"
        assert h["detail"], f"{PID}: no detail"
        assert h["function"], f"{PID}: no function"
        assert h["gate_analysis"], \
            f"{PID}: no gate analysis (validator-ready bar)"
        assert h["report_class"] == "candidate", (
            f"{PID}: vuln fixture must be a candidate, got "
            f"{h['report_class']} ({h.get('recipient')})")
        assert h["severity"] == "high"
        assert h["recipient"] == "CALLER-SUPPLIED"


def test_variant_fires_trigger_only_never_candidate():
    hits = hits_for(fx.VARIANT[PID])
    assert hits, f"{PID}: FIXED variant did not fire"
    for h in hits:
        assert h["report_class"] == "trigger_only", (
            f"{PID}: FIXED variant escalated to candidate")
        assert h["severity"] == "low"
        assert h["recipient"] == "FIXED"
        assert h["leg"] == "mint"


def test_clean_controls_silent():
    for clean_id, src in fx.CLEAN.items():
        hits = hits_for(src)
        assert hits == [], (
            f"{PID}: fired on the {clean_id} clean control: {hits}")
    for clean_id, src in fx.EXTRA_CLEAN.items():
        hits = hits_for(src)
        assert hits == [], (
            f"{PID}: fired on extra clean {clean_id}: {hits}")


def test_extra_vuln_legs_fire_candidate():
    for vuln_id, src in fx.EXTRA_VULN.items():
        hits = hits_for(src)
        assert hits, f"{PID}: {vuln_id} did not fire"
        assert all(h["report_class"] == "candidate" for h in hits), (
            f"{PID}: {vuln_id} must be a candidate: {hits}")
        assert all(h["severity"] == "high" for h in hits)
    legs = {h["leg"] for src in fx.EXTRA_VULN.values()
            for h in hits_for(src)}
    assert legs == {"selfdestruct", "upgrade", "mint"}, (
        f"{PID}: expected all three extra legs, got {legs}")


def test_batch11_fixtures_silent():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under this detector.
    for group in (fx11.VULN, fx11.CLEAN, fx11.VARIANT,
                  fx11.EXTRA_CLEAN):
        for fid, src in group.items():
            hits = hits_for(src)
            assert hits == [], (
                f"{PID}: fired on batch-11 fixture {fid}: {hits}")


def test_my_vuln_silent_under_batch11():
    # And the reverse: batch-11 detectors must not fire on this
    # detector's vulnerable fixture.
    for spec11 in SPECS11:
        hits = analyze_deep11_source(fx.VULN[PID], spec11)
        assert hits == [], (
            f"{spec11.id}: fired on the batch-17 fixture: {hits}")
    for vuln_id, src in fx.EXTRA_VULN.items():
        for spec11 in SPECS11:
            hits = analyze_deep11_source(src, spec11)
            assert hits == [], (
                f"{spec11.id}: fired on {vuln_id}: {hits}")
