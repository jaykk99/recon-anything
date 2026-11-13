"""Deep-audit batch-15 detectors (AI dev, 2026-11-11).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-11 and batch-10 fixtures MUST stay
silent under all five (no cross-batch noise); the registry
discovers exactly 1413 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit10_fixtures as fx10  # noqa: E402
import deep_audit11_fixtures as fx11  # noqa: E402
import deep_audit15_fixtures as fx  # noqa: E402
from app.plugins.deep_audit15 import SPECS, SPECS_BY_ID, \
    analyze_deep15_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep15_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1232():
    reg = discover()
    assert len(reg) == 1413, \
        f"registry size {len(reg)}, expected 1413"


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


def test_batch11_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-15 detector.
    for group in (fx11.VULN, fx11.CLEAN, fx11.VARIANT,
                  fx11.EXTRA_CLEAN):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-11 fixture {fid}: "
                    f"{hits}")


def test_batch10_fixtures_silent_under_all_five():
    for group in (fx10.VULN, fx10.CLEAN, fx10.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-10 fixture {fid}: "
                    f"{hits}")


def test_narrowing_names_the_borrow_function():
    hits = hits_for(fx.VULN["unsafe_narrowing_cast_collateral_zero"],
                    "unsafe_narrowing_cast_collateral_zero")
    assert [h["function"] for h in hits] == ["borrow"]
    assert "freeCollateral" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_narrowing_safecast_silent():
    hits = hits_for(
        fx.CLEAN["unsafe_narrowing_cast_collateral_zero"],
        "unsafe_narrowing_cast_collateral_zero")
    assert hits == []


def test_narrowing_max_check_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "unsafe_narrowing_cast_collateral_zero_max_check"],
        "unsafe_narrowing_cast_collateral_zero")
    assert hits == []


def test_narrowing_display_only_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "unsafe_narrowing_cast_collateral_zero_display_only"],
        "unsafe_narrowing_cast_collateral_zero")
    assert hits == []


def test_negative_fee_names_the_deposit_function():
    hits = hits_for(fx.VULN["negative_fee_mint_inflation"],
                    "negative_fee_mint_inflation")
    assert [h["function"] for h in hits] == ["deposit"]
    assert "setFee" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_negative_fee_uint256_silent():
    hits = hits_for(
        fx.CLEAN["negative_fee_mint_inflation"],
        "negative_fee_mint_inflation")
    assert hits == []


def test_negative_fee_setter_guard_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["negative_fee_mint_inflation_setter_guard"],
        "negative_fee_mint_inflation")
    assert hits == []


def test_negative_fee_clamped_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["negative_fee_mint_inflation_clamped"],
        "negative_fee_mint_inflation")
    assert hits == []


def test_scaled_allowance_names_the_transfer_from_function():
    hits = hits_for(fx.VULN["scaled_allowance_overapproval"],
                    "scaled_allowance_overapproval")
    assert [h["function"] for h in hits] == ["transferFrom"]
    assert "scaledAmount" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_scaled_allowance_same_unit_silent():
    hits = hits_for(
        fx.CLEAN["scaled_allowance_overapproval"],
        "scaled_allowance_overapproval")
    assert hits == []


def test_scaled_allowance_raw_check_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["scaled_allowance_overapproval_raw_check"],
        "scaled_allowance_overapproval")
    assert hits == []


def test_scaled_allowance_fixed_index_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "scaled_allowance_overapproval_fixed_index"],
        "scaled_allowance_overapproval")
    assert hits == []


def test_claim_callback_names_the_claim_function():
    hits = hits_for(fx.VULN["claim_callback_before_claimed_flag"],
                    "claim_callback_before_claimed_flag")
    assert [h["function"] for h in hits] == ["claim"]
    assert "groupLockup" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_claim_callback_flag_first_silent():
    hits = hits_for(
        fx.CLEAN["claim_callback_before_claimed_flag"],
        "claim_callback_before_claimed_flag")
    assert hits == []


def test_claim_callback_nonreentrant_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "claim_callback_before_claimed_flag_nonreentrant"],
        "claim_callback_before_claimed_flag")
    assert hits == []


def test_claim_callback_allowlist_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "claim_callback_before_claimed_flag_allowlist"],
        "claim_callback_before_claimed_flag")
    assert hits == []


def test_post_slash_names_the_deposit_function():
    hits = hits_for(fx.VULN["post_slash_erc4626_offset_inversion"],
                    "post_slash_erc4626_offset_inversion")
    assert [h["function"] for h in hits] == ["deposit"]
    assert "slash" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_post_slash_burn_shares_silent():
    hits = hits_for(
        fx.CLEAN["post_slash_erc4626_offset_inversion"],
        "post_slash_erc4626_offset_inversion")
    assert hits == []


def test_post_slash_deposit_guard_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "post_slash_erc4626_offset_inversion_deposit_guard"],
        "post_slash_erc4626_offset_inversion")
    assert hits == []


def test_post_slash_no_offset_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "post_slash_erc4626_offset_inversion_no_offset"],
        "post_slash_erc4626_offset_inversion")
    assert hits == []
