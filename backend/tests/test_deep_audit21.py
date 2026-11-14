"""Deep-audit batch-21 detectors: oracle fallback, vault lockbooks,
period buckets, and redeem guards.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (the four recipient detectors); the FIXED-recipient
variant MUST fire trigger-only at low severity (never a
candidate); redeem_burns_shares_for_zero_assets fires
HOLDER-SELF / trigger-only at low severity by construction (the
caller themself is the victim); every clean control MUST stay
silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-19 fixtures MUST stay silent under all
five (no cross-batch noise); the registry discovers exactly
1438 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit19_fixtures as fx19  # noqa: E402
import deep_audit21_fixtures as fx  # noqa: E402
from app.plugins.deep_audit21 import SPECS, SPECS_BY_ID, \
    analyze_deep21_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["oracle_twap_fallback_to_spot",
                 "erc4626_lockbook_share_transfer_desync",
                 "rescue_marks_future_bucket_claimed",
                 "period_start_checkpoint_zeroes_payout_cap"]


def hits_for(src, pid):
    return analyze_deep21_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1438():
    reg = discover()
    assert len(reg) == 1438, \
        f"registry size {len(reg)}, expected 1438"


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


def test_redeem_fires_holder_self_trigger_only():
    pid = "redeem_burns_shares_for_zero_assets"
    hits = hits_for(fx.VULN[pid], pid)
    assert hits, f"{pid}: vulnerable fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    for h in hits:
        assert h["code"], f"{pid}: no code evidence"
        assert h["detail"], f"{pid}: no detail"
        assert h["function"] == "redeem"
        assert h["gate_analysis"], \
            f"{pid}: no gate analysis (validator-ready bar)"
        assert h["report_class"] == "trigger_only", (
            f"{pid}: redeem burns the caller's own shares, must "
            f"be trigger-only, got {h['report_class']}")
        assert h["severity"] == "low"
        assert h["recipient"] == "HOLDER-SELF"


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
    # not fire under any batch-21 detector.
    for group in (fx19.VULN, fx19.CLEAN, fx19.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-19 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx19.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-19 extra clean "
                f"{clean_id}: {hits}")


def test_oracle_names_the_redeem_function():
    hits = hits_for(fx.VULN["oracle_twap_fallback_to_spot"],
                    "oracle_twap_fallback_to_spot")
    assert [h["function"] for h in hits] == ["redeemPrincipal"]
    assert "spot" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "CALLER"


def test_oracle_twap_only_silent():
    hits = hits_for(
        fx.CLEAN["oracle_twap_fallback_to_spot"],
        "oracle_twap_fallback_to_spot")
    assert hits == []


def test_oracle_guarded_fallback_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["oracle_twap_fallback_guarded"],
        "oracle_twap_fallback_to_spot")
    assert hits == []


def test_lockbook_names_the_transfer_function():
    hits = hits_for(
        fx.VULN["erc4626_lockbook_share_transfer_desync"],
        "erc4626_lockbook_share_transfer_desync")
    assert [h["function"] for h in hits] == ["transfer"]
    assert "lock" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_lockbook_transfer_moves_entries_silent():
    hits = hits_for(
        fx.CLEAN["erc4626_lockbook_share_transfer_desync"],
        "erc4626_lockbook_share_transfer_desync")
    assert hits == []


def test_lockbook_non_transferable_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lockbook_non_transferable"],
        "erc4626_lockbook_share_transfer_desync")
    assert hits == []


def test_lockbook_plain_vault_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lockbook_plain_vault"],
        "erc4626_lockbook_share_transfer_desync")
    assert hits == []


def test_rescue_names_the_rescue_function():
    hits = hits_for(
        fx.VULN["rescue_marks_future_bucket_claimed"],
        "rescue_marks_future_bucket_claimed")
    assert [h["function"] for h in hits] == [
        "rescueWithdrawFromBlocklisted"]
    assert "claimed" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_rescue_elapsed_check_silent():
    hits = hits_for(
        fx.CLEAN["rescue_marks_future_bucket_claimed"],
        "rescue_marks_future_bucket_claimed")
    assert hits == []


def test_rescue_no_flag_write_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["rescue_no_flag_write"],
        "rescue_marks_future_bucket_claimed")
    assert hits == []


def test_checkpoint_names_the_payout_function():
    hits = hits_for(
        fx.VULN["period_start_checkpoint_zeroes_payout_cap"],
        "period_start_checkpoint_zeroes_payout_cap")
    assert [h["function"] for h in hits] == ["payout"]
    assert "checkpoint" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_checkpoint_snapshot_before_burn_silent():
    hits = hits_for(
        fx.CLEAN["period_start_checkpoint_zeroes_payout_cap"],
        "period_start_checkpoint_zeroes_payout_cap")
    assert hits == []


def test_checkpoint_exclusive_lookup_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["checkpoint_exclusive_lookup"],
        "period_start_checkpoint_zeroes_payout_cap")
    assert hits == []


def test_redeem_names_the_redeem_function():
    hits = hits_for(
        fx.VULN["redeem_burns_shares_for_zero_assets"],
        "redeem_burns_shares_for_zero_assets")
    assert [h["function"] for h in hits] == ["redeem"]
    assert "zero assets" in hits[0]["detail"].lower()


def test_redeem_assets_guard_silent():
    hits = hits_for(
        fx.CLEAN["redeem_burns_shares_for_zero_assets"],
        "redeem_burns_shares_for_zero_assets")
    assert hits == []


def test_redeem_no_asymmetry_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["redeem_no_asymmetry"],
        "redeem_burns_shares_for_zero_assets")
    assert hits == []
