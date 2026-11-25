"""Deep-audit batch-28 detectors: caller-writable snapshot
positions, share prices excluding sub-threshold collateral,
vouchers not bound to the redeemer, period exits writing the
new period's exposure snapshot, withdraws paying another
account's balance.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (the four recipient detectors); the period-exit
detector fires without a candidate classification (batch-20
auction precedent: the exit pays the caller's own balance -
the stranger-receivable value is the short-paid claim the
desync enables, not the exit). The FIXED-recipient variant
MUST fire trigger-only at low severity (never a candidate);
every clean control MUST stay silent under ALL five detectors;
every other plugin's vulnerable fixture MUST stay silent under
this one (no cross-talk); the batch-26 fixtures MUST stay
silent under all five (no cross-batch noise); the five new
VULN fixtures MUST stay silent under the relevant neighbours
(eip1271_magic_value_unchecked, ecrecover_zero_signer,
eip712_digest_unbound_to_payload, fee_on_transfer_overcredit,
recipient_unbacked_claim, access_control_arbitrary_call_injection,
and the five batch-26 detectors), EXCEPT the documented
co-fire: recipient_overdraw_withdraw fires on the
withdraw_pays_other_account_balance fixture by design - the
payout is not bounded by the CALLER's balance (it is bounded
by the VICTIM's), which is the hole from the boundedness
angle; the new detector adds the authorization dimension the
overdraw detector cannot express. That co-fire is asserted
explicitly, not pretended silent. The registry discovers
exactly 1494 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit26_fixtures as fx26  # noqa: E402
import deep_audit27_fixtures as fx27  # noqa: E402
import deep_audit28_fixtures as fx  # noqa: E402
from app.plugins.bsc_access import SPECS as ACCESS_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.deep_audit import SPECS_BY_ID as SPECS1, \
    analyze_deep_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit26 import SPECS_BY_ID as SPECS26, \
    analyze_deep26_source  # noqa: E402
from app.plugins.deep_audit27 import SPECS_BY_ID as SPECS27, \
    analyze_deep27_source  # noqa: E402
from app.plugins.deep_audit28 import SPECS, SPECS_BY_ID, \
    analyze_deep28_source  # noqa: E402
from app.plugins.deep_audit3 import SPECS_BY_ID as SPECS3, \
    analyze_deep3_source  # noqa: E402
from app.plugins.deep_audit5 import SPECS_BY_ID as SPECS5, \
    analyze_deep5_source  # noqa: E402
from app.plugins.recipient_first import \
    analyze_recipient_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["snapshot_position_sync_caller_writable",
                 "share_price_excludes_subthreshold_collateral",
                 "voucher_redeem_recipient_unbound",
                 "withdraw_pays_other_account_balance"]
ACCESS_BY_ID = {s.id: s for s in ACCESS_SPECS}


def hits_for(src, pid):
    return analyze_deep28_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1494():
    reg = discover()
    assert len(reg) == 1494, \
        f"registry size {len(reg)}, expected 1494"


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
            if pid == "share_price_excludes_subthreshold_collateral":
                # The payout leg meters the caller's own shares
                # (HOLDER-SELF in isolation), but it is priced
                # off the threshold-excluded valuation, so the
                # redeeming stranger receives assets beyond
                # their own deposit - the excess is
                # CALLER-received (the vault_share_inflation
                # precedent). Pinned explicitly here and in
                # test_share_price_names_the_valuation_function.
                assert h["recipient"] == "HOLDER-SELF"
            else:
                assert h["recipient"] in (
                    "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_period_exit_fires_without_candidate():
    pid = "period_exit_writes_new_period_exposure_snapshot"
    hits = hits_for(fx.VULN[pid], pid)
    assert hits, f"{pid}: vulnerable fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    for h in hits:
        assert h["code"], f"{pid}: no code evidence"
        assert h["detail"], f"{pid}: no detail"
        assert h["function"] == "exit"
        assert h["gate_analysis"], \
            f"{pid}: no gate analysis (validator-ready bar)"
        assert h["severity"] == "medium"
        assert h.get("report_class") is None, (
            f"{pid}: the exit pays the caller's own balance "
            f"- the value is the short-paid claim, so it "
            f"must not carry a candidate classification")


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


def test_batch26_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-28 detector.
    for group in (fx26.VULN, fx26.CLEAN, fx26.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-26 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx26.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-26 extra clean "
                f"{clean_id}: {hits}")


def test_batch27_fixtures_silent_under_all_five():
    # No cross-batch noise: the sibling quota batch-27 fixtures
    # (landed on master mid-run, 880e203e) must not fire under
    # any batch-28 detector either.
    for group in (fx27.VULN, fx27.CLEAN, fx27.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-27 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx27.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-27 extra clean "
                f"{clean_id}: {hits}")


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors: the EIP-1271 / ecrecover / EIP-712
    # signature detectors, the fee-on-transfer deposit
    # detector, the recipient-first claim detector, the BSC
    # arbitrary-call executor, the five batch-26 detectors,
    # and the five sibling batch-27 detectors (landed on
    # master mid-run). DOCUMENTED EXCEPTION: the overdraw
    # detector fires on the withdraw-other fixture by design
    # (bounded by the victim's balance, not the caller's) -
    # asserted in test_withdraw_other_overdraw_cofire below,
    # and excluded from the silence assertion here.
    neighbours = []
    neighbours.append(("eip1271_magic_value_unchecked",
                       lambda src, spec:
                       analyze_deep5_source(src, spec)))
    neighbours.append(("ecrecover_zero_signer",
                       lambda src, spec:
                       analyze_deep_source(src, spec)))
    neighbours.append(("eip712_digest_unbound_to_payload",
                       lambda src, spec:
                       analyze_deep3_source(src, spec)))
    neighbours.append(("fee_on_transfer_overcredit",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    neighbours.append(("recipient_unbacked_claim",
                       lambda src, spec_id:
                       analyze_recipient_source(src, spec_id)))
    neighbours.append(("access_control_arbitrary_call_injection",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    for pid in ("order_signature_validates_description_not_hash",
                "swap_output_trusted_report_no_receipt_check",
                "fee_claim_exceeds_accrued_fees",
                "settlement_swap_executes_caller_target_spends_approvals",
                "recorded_supply_caps_pool_reserves"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep26_source(src, spec)))
    for pid in ("lp_mint_no_minimum_liquidity_lock",
                "merkle_claim_replayable_across_chains",
                "vesting_claim_overrelease_past_duration",
                "permit_deadline_param_never_enforced",
                "bonding_curve_price_from_raw_balance_no_virtual_reserve"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep27_source(src, spec)))
    specs = {}
    specs.update(SPECS1)
    specs.update(SPECS2)
    specs.update(SPECS3)
    specs.update(SPECS5)
    specs.update(SPECS26)
    specs.update(SPECS27)
    specs.update(ACCESS_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            if pid not in specs and pid not in (
                    "recipient_unbacked_claim",):
                continue
            spec = specs.get(pid, pid)
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_withdraw_other_overdraw_cofire():
    # DOCUMENTED CO-FIRE (see the fixtures module docstring):
    # recipient_overdraw_withdraw fires on the withdraw-other
    # fixture because the payout is not bounded by the CALLER's
    # balance - it is bounded by the VICTIM's. That is the same
    # hole from the boundedness angle; the new detector adds
    # the authorization dimension. It must NOT fire on the
    # other four vuln fixtures.
    src = fx.VULN["withdraw_pays_other_account_balance"]
    hits = analyze_recipient_source(
        src, "recipient_overdraw_withdraw")
    assert hits, "overdraw must co-fire on the withdraw-other " \
        "fixture (payout bounded by the victim, not the caller)"
    assert all(h["kind"] == "recipient_overdraw_withdraw"
               for h in hits)
    for vuln_id, src2 in fx.VULN.items():
        if vuln_id == "withdraw_pays_other_account_balance":
            continue
        hits = analyze_recipient_source(
            src2, "recipient_overdraw_withdraw")
        assert hits == [], (
            f"recipient_overdraw_withdraw fired on the "
            f"{vuln_id} fixture: {hits}")


def test_snapshot_sync_names_the_sync_function():
    hits = hits_for(
        fx.VULN["snapshot_position_sync_caller_writable"],
        "snapshot_position_sync_caller_writable")
    assert [h["function"] for h in hits] == ["syncInvestor"]
    assert "positions" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_snapshot_sync_recompute_silent():
    hits = hits_for(
        fx.CLEAN["snapshot_position_sync_caller_writable"],
        "snapshot_position_sync_caller_writable")
    assert hits == []


def test_snapshot_sync_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["sync_gated"],
        "snapshot_position_sync_caller_writable")
    assert hits == []


def test_snapshot_sync_internal_recompute_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["sync_recompute_internal"],
        "snapshot_position_sync_caller_writable")
    assert hits == []


def test_snapshot_sync_no_payout_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["sync_no_payout"],
        "snapshot_position_sync_caller_writable")
    assert hits == []


def test_share_price_names_the_valuation_function():
    hits = hits_for(
        fx.VULN["share_price_excludes_subthreshold_collateral"],
        "share_price_excludes_subthreshold_collateral")
    assert [h["function"] for h in hits] == ["totalAssets"]
    assert "MIN_WETH" in hits[0]["detail"]
    assert hits[0]["recipient"] == "HOLDER-SELF"


def test_share_price_unconditional_silent():
    hits = hits_for(
        fx.CLEAN["share_price_excludes_subthreshold_collateral"],
        "share_price_excludes_subthreshold_collateral")
    assert hits == []


def test_share_price_zero_guard_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["share_zero_guard"],
        "share_price_excludes_subthreshold_collateral")
    assert hits == []


def test_share_price_gated_legs_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["share_gated_legs"],
        "share_price_excludes_subthreshold_collateral")
    assert hits == []


def test_share_price_ternary_fires():
    hits = hits_for(
        fx.VULN_TERNARY,
        "share_price_excludes_subthreshold_collateral")
    assert hits, "ternary threshold exclusion must still fire"
    assert all(h["kind"] ==
               "share_price_excludes_subthreshold_collateral"
               for h in hits)
    assert [h["function"] for h in hits] == ["totalAssets"]
    assert hits[0]["report_class"] == "candidate"


def test_voucher_names_the_redeem_function():
    hits = hits_for(
        fx.VULN["voucher_redeem_recipient_unbound"],
        "voucher_redeem_recipient_unbound")
    assert [h["function"] for h in hits] == \
        ["withdrawLevelReward"]
    assert "redeemer" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_voucher_recipient_bound_silent():
    hits = hits_for(
        fx.CLEAN["voucher_redeem_recipient_unbound"],
        "voucher_redeem_recipient_unbound")
    assert hits == []


def test_voucher_no_nonce_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["voucher_no_nonce"],
        "voucher_redeem_recipient_unbound")
    assert hits == []


def test_voucher_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["voucher_gated"],
        "voucher_redeem_recipient_unbound")
    assert hits == []


def test_voucher_no_sig_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["voucher_no_sig"],
        "voucher_redeem_recipient_unbound")
    assert hits == []


def test_period_exit_names_the_exit_function():
    hits = hits_for(
        fx.VULN["period_exit_writes_new_period_exposure_snapshot"],
        "period_exit_writes_new_period_exposure_snapshot")
    assert [h["function"] for h in hits] == ["exit"]
    assert "periodExposure" in hits[0]["detail"]


def test_period_exit_deposit_only_write_silent():
    hits = hits_for(
        fx.CLEAN["period_exit_writes_new_period_exposure_snapshot"],
        "period_exit_writes_new_period_exposure_snapshot")
    assert hits == []


def test_period_exit_reads_only_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["period_reads_only"],
        "period_exit_writes_new_period_exposure_snapshot")
    assert hits == []


def test_period_exit_no_claim_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["period_no_claim"],
        "period_exit_writes_new_period_exposure_snapshot")
    assert hits == []


def test_period_exit_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["period_gated"],
        "period_exit_writes_new_period_exposure_snapshot")
    assert hits == []


def test_withdraw_other_names_the_withdraw_function():
    hits = hits_for(
        fx.VULN["withdraw_pays_other_account_balance"],
        "withdraw_pays_other_account_balance")
    assert [h["function"] for h in hits] == ["withdraw"]
    assert "account" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_withdraw_other_identity_checked_silent():
    hits = hits_for(
        fx.CLEAN["withdraw_pays_other_account_balance"],
        "withdraw_pays_other_account_balance")
    assert hits == []


def test_withdraw_other_allowance_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["withdraw_allowance"],
        "withdraw_pays_other_account_balance")
    assert hits == []


def test_withdraw_other_own_only_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["withdraw_own_only"],
        "withdraw_pays_other_account_balance")
    assert hits == []


def test_withdraw_other_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["withdraw_gated"],
        "withdraw_pays_other_account_balance")
    assert hits == []
