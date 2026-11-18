"""Deep-audit batch-22 detectors: claim guards, checkpoints, decimals.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-19 fixtures MUST stay silent under all
five (no cross-batch noise); the registry discovers exactly
1464 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit19_fixtures as fx19  # noqa: E402
import deep_audit22_fixtures as fx  # noqa: E402
from app.plugins.deep_audit22 import SPECS, SPECS_BY_ID, \
    analyze_deep22_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = [
    "claim_guard_wrong_key_replay",
    "checkpoint_overwrite_equal_key_rewrites_snapshot",
    "presale_hardcoded_decimals_dust_purchase",
    "collateral_value_assumes_18_decimals",
    "permissionless_collateral_listing_fake_token",
]


def hits_for(src, pid):
    return analyze_deep22_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1464():
    reg = discover()
    assert len(reg) == 1464, \
        f"registry size {len(reg)}, expected 1464"


def test_vuln_fires_candidate_with_evidence():
    for pid in RECIPIENT_IDS:
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
    for pid in fx.VARIANT:
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


def test_batch19_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-22 detector.
    for group in (fx19.VULN, fx19.CLEAN, fx19.VARIANT,
                  fx19.EXTRA_CLEAN):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-19 fixture {fid}: "
                    f"{hits}")


def test_claim_names_the_claim_function():
    hits = hits_for(fx.VULN["claim_guard_wrong_key_replay"],
                    "claim_guard_wrong_key_replay")
    assert [h["function"] for h in hits] == ["claim"]
    assert "_treasureHash" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_claim_same_key_silent():
    hits = hits_for(
        fx.CLEAN["claim_guard_wrong_key_replay"],
        "claim_guard_wrong_key_replay")
    assert hits == []


def test_claim_assigned_guard_var_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["claim_guard_assigned_in_constructor"],
        "claim_guard_wrong_key_replay")
    assert hits == []


def test_checkpoint_names_the_withdraw_function():
    hits = hits_for(
        fx.VULN["checkpoint_overwrite_equal_key_rewrites_snapshot"],
        "checkpoint_overwrite_equal_key_rewrites_snapshot")
    assert [h["function"] for h in hits] == ["withdraw"]
    assert "push" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_checkpoint_append_only_push_silent():
    # The #88287 shape (deep_audit21): withdraw pushes a
    # boundary checkpoint through an append-only push and the
    # payout reads it as a cap - no library overwrite, so
    # this detector must stay silent. This is the
    # adjudication pin between the two detectors.
    hits = hits_for(
        fx.CLEAN["checkpoint_overwrite_equal_key_rewrites_snapshot"],
        "checkpoint_overwrite_equal_key_rewrites_snapshot")
    assert hits == []


def test_presale_names_the_buy_function():
    hits = hits_for(
        fx.VULN["presale_hardcoded_decimals_dust_purchase"],
        "presale_hardcoded_decimals_dust_purchase")
    assert [h["function"] for h in hits] == ["buy"]
    assert "1e6" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_presale_decimals_read_silent():
    hits = hits_for(
        fx.CLEAN["presale_hardcoded_decimals_dust_purchase"],
        "presale_hardcoded_decimals_dust_purchase")
    assert hits == []


def test_presale_allowlisted_payment_token_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["presale_allowlisted_payment_token"],
        "presale_hardcoded_decimals_dust_purchase")
    assert hits == []


def test_collateral_names_the_valuation_function():
    hits = hits_for(
        fx.VULN["collateral_value_assumes_18_decimals"],
        "collateral_value_assumes_18_decimals")
    assert [h["function"] for h in hits] == ["getUsdValue"]
    assert "latestRoundData" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_collateral_decimals_read_silent():
    hits = hits_for(
        fx.CLEAN["collateral_value_assumes_18_decimals"],
        "collateral_value_assumes_18_decimals")
    assert hits == []


def test_collateral_per_token_config_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["collateral_per_token_decimals_config"],
        "collateral_value_assumes_18_decimals")
    assert hits == []


def test_collateral_1e18_spelling_fires():
    # The DSCEngine shape spelled with a 1e18 literal instead
    # of 1e10 must fire too.
    hits = hits_for(
        fx.EXTRA_VULN["collateral_value_assumes_18_decimals_1e18"],
        "collateral_value_assumes_18_decimals")
    assert hits, "1e18 spelling did not fire"
    assert all(h["kind"] == "collateral_value_assumes_18_decimals"
               for h in hits)
    assert hits[0]["report_class"] == "candidate"


def test_listing_names_the_listing_function():
    hits = hits_for(
        fx.VULN["permissionless_collateral_listing_fake_token"],
        "permissionless_collateral_listing_fake_token")
    assert [h["function"] for h in hits] == ["addCollateral"]
    assert "borrow" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_listing_gated_allowlisted_oracle_silent():
    hits = hits_for(
        fx.CLEAN["permissionless_collateral_listing_fake_token"],
        "permissionless_collateral_listing_fake_token")
    assert hits == []


def test_listing_gated_no_oracle_param_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["listing_gated_no_oracle_param"],
        "permissionless_collateral_listing_fake_token")
    assert hits == []
