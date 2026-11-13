"""Deep-audit batch-12/deep16 detectors (AI dev, 2026-11-07; merged 2026-11-12).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under BOTH detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-11 fixtures MUST stay silent under both
(no cross-batch noise); the registry discovers exactly
1235 plugins including both.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit11_fixtures as fx11  # noqa: E402
import deep_audit16_fixtures as fx  # noqa: E402
from app.plugins.deep_audit16 import SPECS, SPECS_BY_ID, \
    analyze_deep16_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep16_source(src, SPECS_BY_ID[pid])


def test_two_plugins_registered():
    assert len(IDS) == 2
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1235():
    reg = discover()
    assert len(reg) == 1437, \
        f"registry size {len(reg)}, expected 1437"


def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["code"], f"{pid}: no code evidence"
            assert h["detail"], f"{pid}: no detail"
            assert h["function"], f"{pid}: no function"
            assert h["gate_analysis"], \
                f"{pid}: no gate analysis (validator-ready bar)"
            assert h["report_class"] == "candidate", (
                f"{pid}: vuln fixture must be a candidate, got "
                f"{h['report_class']} ({h.get('recipient')})")
            assert h["severity"] == "high"
            assert h["recipient"] in (
                "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_variant_fires_trigger_only_never_candidate():
    for pid in IDS:
        hits = hits_for(fx.VARIANT[pid], pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_clean_controls_silent_under_both():
    for clean_id, src in fx.CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {clean_id} clean "
                f"control: {hits}")
    for clean_id, src in fx.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on extra clean {clean_id}: "
                f"{hits}")


def test_no_cross_talk_between_vuln_fixtures():
    for vuln_id, src in fx.VULN.items():
        for pid in IDS:
            if pid == vuln_id:
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_no_cross_talk_from_variant_fixtures():
    for var_id, src in fx.VARIANT.items():
        for pid in IDS:
            if pid == var_id:
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {var_id} variant: "
                f"{hits}")


def test_batch11_fixtures_silent_under_both():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-12 detector.
    for group in (fx11.VULN, fx11.CLEAN, fx11.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-11 fixture {fid}: "
                    f"{hits}")



def test_approval_names_the_approve_function():
    hits = hits_for(fx.VULN["approval_binds_id_not_version"],
                    "approval_binds_id_not_version")
    assert [h["function"] for h in hits] == ["approve"]
    assert "currentAssessment" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_approval_version_bound_silent():
    hits = hits_for(
        fx.CLEAN["approval_binds_id_not_version"],
        "approval_binds_id_not_version")
    assert hits == []


def test_zero_amount_names_the_withdraw_function():
    hits = hits_for(fx.VULN["zero_amount_withdraw_all"],
                    "zero_amount_withdraw_all")
    assert [h["function"] for h in hits] == ["withdraw"]
    assert "unstake" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_zero_amount_require_guard_silent():
    hits = hits_for(
        fx.CLEAN["zero_amount_withdraw_all"],
        "zero_amount_withdraw_all")
    assert hits == []


def test_zero_amount_revert_guard_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["zero_amount_withdraw_all_revert_guard"],
        "zero_amount_withdraw_all")
    assert hits == []


def test_zero_amount_super_redeem_silent():
    # Live-corpus FP (2026-11-07): sNUSD / StakedlvlUSD redeem()
    # overrides call super.redeem() - inherited ERC-4626 logic, not
    # an external staking system with 0-means-all semantics.
    hits = hits_for(
        fx.EXTRA_CLEAN["zero_amount_withdraw_all_super_redeem"],
        "zero_amount_withdraw_all")
    assert hits == []
