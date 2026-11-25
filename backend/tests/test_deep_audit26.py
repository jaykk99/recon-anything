"""Deep-audit batch-26 detectors: order-signature description
validation, swap-output trusted reports, fee claims above
accrued fees, settlement swaps spending approvals, recorded
supply capping pool reserves.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (the four recipient detectors); the recorded-supply
detector fires without a candidate classification (batch-20
auction precedent: the withdraw itself pays the caller's own
balance - the stranger-receivable value is the mispriced pool
trade the desync enables, not the withdrawal). The
FIXED-recipient variant MUST fire trigger-only at low severity
(never a candidate); every clean control MUST stay silent
under ALL five detectors; every other plugin's vulnerable
fixture MUST stay silent under this one (no cross-talk); the
batch-25 fixtures MUST stay silent under all five (no
cross-batch noise); the five new VULN fixtures MUST stay
silent under the relevant neighbours
(eip1271_magic_value_unchecked, ecrecover_zero_signer,
eip712_digest_unbound_to_payload, fee_on_transfer_overcredit,
recipient_overdraw_withdraw, recipient_unbacked_claim,
access_control_arbitrary_call_injection, and the five batch-25
detectors); the registry discovers exactly 1500 plugins
including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit25_fixtures as fx25  # noqa: E402
import deep_audit26_fixtures as fx  # noqa: E402
from app.plugins.bsc_access import SPECS as ACCESS_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.deep_audit import SPECS_BY_ID as SPECS1, \
    analyze_deep_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit25 import SPECS_BY_ID as SPECS25, \
    analyze_deep25_source  # noqa: E402
from app.plugins.deep_audit26 import SPECS, SPECS_BY_ID, \
    analyze_deep26_source  # noqa: E402
from app.plugins.deep_audit3 import SPECS_BY_ID as SPECS3, \
    analyze_deep3_source  # noqa: E402
from app.plugins.deep_audit5 import SPECS_BY_ID as SPECS5, \
    analyze_deep5_source  # noqa: E402
from app.plugins.recipient_first import \
    analyze_recipient_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["order_signature_validates_description_not_hash",
                 "swap_output_trusted_report_no_receipt_check",
                 "fee_claim_exceeds_accrued_fees",
                 "settlement_swap_executes_caller_target_spends_approvals"]
ACCESS_BY_ID = {s.id: s for s in ACCESS_SPECS}


def hits_for(src, pid):
    return analyze_deep26_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1480():
    reg = discover()
    assert len(reg) == 1500, \
        f"registry size {len(reg)}, expected 1500"


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


def test_recorded_supply_fires_without_candidate():
    pid = "recorded_supply_caps_pool_reserves"
    hits = hits_for(fx.VULN[pid], pid)
    assert hits, f"{pid}: vulnerable fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    for h in hits:
        assert h["code"], f"{pid}: no code evidence"
        assert h["detail"], f"{pid}: no detail"
        assert h["function"] == "withdraw"
        assert h["gate_analysis"], \
            f"{pid}: no gate analysis (validator-ready bar)"
        assert h["severity"] == "medium"
        assert h.get("report_class") is None, (
            f"{pid}: the withdraw pays the caller's own balance "
            f"- the value is the mispriced pool trade, so it "
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


def test_batch25_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-26 detector.
    for group in (fx25.VULN, fx25.CLEAN, fx25.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-25 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx25.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-25 extra clean "
                f"{clean_id}: {hits}")


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors: the EIP-1271 / ecrecover / EIP-712
    # signature detectors, the fee-on-transfer deposit
    # detector, the recipient-first withdraw / claim
    # detectors, the BSC arbitrary-call executor, and the
    # five batch-25 detectors.
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
    for pid in ("recipient_overdraw_withdraw",
                "recipient_unbacked_claim"):
        neighbours.append((pid, lambda src, spec_id:
                           analyze_recipient_source(src, spec_id)))
    neighbours.append(("access_control_arbitrary_call_injection",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    for pid in ("nft_batch_mint_underpayment",
                "multicall_arbitrary_delegatecall",
                "auction_bid_after_deadline",
                "bridge_deposit_value_unbound_to_msgvalue",
                "merkle_proof_amount_unbound"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep25_source(src, spec)))
    specs = {}
    specs.update(SPECS1)
    specs.update(SPECS2)
    specs.update(SPECS3)
    specs.update(SPECS5)
    specs.update(SPECS25)
    specs.update(ACCESS_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            if pid not in specs and pid not in (
                    "recipient_overdraw_withdraw",
                    "recipient_unbacked_claim"):
                continue
            spec = specs.get(pid, pid)
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_order_sig_names_the_validator_function():
    hits = hits_for(
        fx.VULN["order_signature_validates_description_not_hash"],
        "order_signature_validates_description_not_hash")
    assert [h["function"] for h in hits] == ["isValidSignature"]
    assert "description" in hits[0]["detail"]
    assert "orderHash" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_order_sig_hash_bound_silent():
    hits = hits_for(
        fx.CLEAN["order_signature_validates_description_not_hash"],
        "order_signature_validates_description_not_hash")
    assert hits == []


def test_order_sig_no_value_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["order_no_value"],
        "order_signature_validates_description_not_hash")
    assert hits == []


def test_order_sig_hash_compared_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["order_hash_compared"],
        "order_signature_validates_description_not_hash")
    assert hits == []


def test_order_sig_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["order_gated"],
        "order_signature_validates_description_not_hash")
    assert hits == []


def test_swap_output_names_the_swap_function():
    hits = hits_for(
        fx.VULN["swap_output_trusted_report_no_receipt_check"],
        "swap_output_trusted_report_no_receipt_check")
    assert [h["function"] for h in hits] == ["swapAndCredit"]
    assert "reported" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_swap_output_receipt_checked_silent():
    hits = hits_for(
        fx.CLEAN["swap_output_trusted_report_no_receipt_check"],
        "swap_output_trusted_report_no_receipt_check")
    assert hits == []


def test_swap_output_credit_delta_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["swap_credit_delta"],
        "swap_output_trusted_report_no_receipt_check")
    assert hits == []


def test_swap_output_no_payout_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["swap_no_payout"],
        "swap_output_trusted_report_no_receipt_check")
    assert hits == []


def test_swap_output_no_credit_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["swap_no_credit"],
        "swap_output_trusted_report_no_receipt_check")
    assert hits == []


def test_fee_claim_names_the_claim_function():
    hits = hits_for(
        fx.VULN["fee_claim_exceeds_accrued_fees"],
        "fee_claim_exceeds_accrued_fees")
    assert [h["function"] for h in hits] == ["claimFees"]
    assert "fees" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_fee_claim_capped_silent():
    hits = hits_for(
        fx.CLEAN["fee_claim_exceeds_accrued_fees"],
        "fee_claim_exceeds_accrued_fees")
    assert hits == []


def test_fee_claim_from_stored_state_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["fee_from_stored_state"],
        "fee_claim_exceeds_accrued_fees")
    assert hits == []


def test_fee_claim_min_capped_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["fee_min_capped"],
        "fee_claim_exceeds_accrued_fees")
    assert hits == []


def test_fee_claim_caller_amount_capped_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["fee_caller_amount_capped"],
        "fee_claim_exceeds_accrued_fees")
    assert hits == []


def test_settlement_names_the_execute_function():
    hits = hits_for(
        fx.VULN["settlement_swap_executes_caller_target_spends_approvals"],
        "settlement_swap_executes_caller_target_spends_approvals")
    assert [h["function"] for h in hits] == ["executeSwap"]
    assert "target" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_settlement_allowlist_silent():
    hits = hits_for(
        fx.CLEAN["settlement_swap_executes_caller_target_spends_approvals"],
        "settlement_swap_executes_caller_target_spends_approvals")
    assert hits == []


def test_settlement_router_bound_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["settle_router_bound"],
        "settlement_swap_executes_caller_target_spends_approvals")
    assert hits == []


def test_settlement_owner_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["settle_owner_gated"],
        "settlement_swap_executes_caller_target_spends_approvals")
    assert hits == []


def test_settlement_no_approval_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["settle_no_approval"],
        "settlement_swap_executes_caller_target_spends_approvals")
    assert hits == []


def test_settlement_delegatecall_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["settle_delegatecall"],
        "settlement_swap_executes_caller_target_spends_approvals")
    assert hits == []


def test_settlement_stored_target_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["settle_stored_target"],
        "settlement_swap_executes_caller_target_spends_approvals")
    assert hits == []


def test_recorded_supply_names_the_withdraw_function():
    hits = hits_for(
        fx.VULN["recorded_supply_caps_pool_reserves"],
        "recorded_supply_caps_pool_reserves")
    assert [h["function"] for h in hits] == ["withdraw"]
    assert "recordedSupply" in hits[0]["detail"]


def test_recorded_supply_guarded_decrement_silent():
    hits = hits_for(
        fx.CLEAN["recorded_supply_caps_pool_reserves"],
        "recorded_supply_caps_pool_reserves")
    assert hits == []


def test_recorded_supply_raw_balance_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["supply_raw_balance"],
        "recorded_supply_caps_pool_reserves")
    assert hits == []


def test_recorded_supply_no_decrement_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["supply_no_decrement"],
        "recorded_supply_caps_pool_reserves")
    assert hits == []


def test_recorded_supply_try_catch_swallowing_fires():
    hits = hits_for(
        fx.VULN_TRY_CATCH,
        "recorded_supply_caps_pool_reserves")
    assert hits, "try/catch swallowing the transfer failure " \
        "must still fire"
    assert all(h["kind"] == "recorded_supply_caps_pool_reserves"
               for h in hits)
    assert [h["function"] for h in hits] == ["withdraw"]
    assert hits[0]["severity"] == "medium"
    assert hits[0].get("report_class") is None
