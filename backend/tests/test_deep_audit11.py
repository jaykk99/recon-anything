"""Deep-audit batch-11 detectors (AI dev, 2026-11-06).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-10 fixtures MUST stay silent under all
five (no cross-batch noise); the registry discovers exactly
1341 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit10_fixtures as fx10  # noqa: E402
import deep_audit11_fixtures as fx  # noqa: E402
from app.plugins.deep_audit11 import SPECS, SPECS_BY_ID, \
    analyze_deep11_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep11_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1226():
    reg = discover()
    assert len(reg) == 1341, \
        f"registry size {len(reg)}, expected 1341"


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


def test_clean_controls_silent_under_all_five():
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


def test_batch10_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-11 detector.
    for group in (fx10.VULN, fx10.CLEAN, fx10.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-10 fixture {fid}: "
                    f"{hits}")


def test_amm_names_the_swap_function():
    hits = hits_for(fx.VULN["amm_scale_rounding_wrong_direction"],
                    "amm_scale_rounding_wrong_direction")
    assert [h["function"] for h in hits] == ["swap"]
    assert "amountOut" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_amm_mulup_silent():
    hits = hits_for(
        fx.CLEAN["amm_scale_rounding_wrong_direction"],
        "amm_scale_rounding_wrong_direction")
    assert hits == []


def test_amm_ceil_div_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["amm_scale_rounding_wrong_direction_ceil_div"],
        "amm_scale_rounding_wrong_direction")
    assert hits == []


def test_amm_in_only_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["amm_scale_rounding_wrong_direction_in_only"],
        "amm_scale_rounding_wrong_direction")
    assert hits == []


def test_lending_names_the_deposit_function():
    hits = hits_for(fx.VULN["lending_accumulator_donation_inflation"],
                    "lending_accumulator_donation_inflation")
    assert [h["function"] for h in hits] == ["deposit"]
    assert "exchangeRate" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_lending_totalcash_silent():
    hits = hits_for(
        fx.CLEAN["lending_accumulator_donation_inflation"],
        "lending_accumulator_donation_inflation")
    assert hits == []


def test_lending_min_guard_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lending_accumulator_donation_inflation_min_guard"],
        "lending_accumulator_donation_inflation")
    assert hits == []


def test_batch_names_the_cook_function():
    hits = hits_for(fx.VULN["batch_deferred_check_flag_reset"],
                    "batch_deferred_check_flag_reset")
    assert [h["function"] for h in hits] == ["cook"]
    assert "solvencyCheckRequired" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_batch_unconditional_check_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["batch_deferred_check_flag_reset_unconditional"],
        "batch_deferred_check_flag_reset")
    assert hits == []


def test_liquidation_names_the_liquidate_function():
    hits = hits_for(fx.VULN["liquidation_residual_collateral_reborrow"],
                    "liquidation_residual_collateral_reborrow")
    assert [h["function"] for h in hits] == ["liquidate"]
    assert "userCollateral" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_liquidation_record_cleared_silent():
    hits = hits_for(
        fx.CLEAN["liquidation_residual_collateral_reborrow"],
        "liquidation_residual_collateral_reborrow")
    assert hits == []


def test_transient_names_the_callback_function():
    hits = hits_for(fx.VULN["transient_slot_reuse_auth_bypass"],
                    "transient_slot_reuse_auth_bypass")
    assert [h["function"] for h in hits] == \
        ["uniswapV3SwapCallback"]
    assert "tload" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_transient_separate_slots_silent():
    hits = hits_for(
        fx.CLEAN["transient_slot_reuse_auth_bypass"],
        "transient_slot_reuse_auth_bypass")
    assert hits == []


def test_transient_cleared_slot_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["transient_slot_reuse_auth_bypass_cleared"],
        "transient_slot_reuse_auth_bypass")
    assert hits == []
