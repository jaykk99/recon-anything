"""Deep-audit batch-30 detectors: an OFT credit accumulator
that underflows on first credit, Uniswap v4 hook fees charged
on the requested amount instead of the realised delta, hook
fees computed on the wrong leg for exact-output swaps, a vault
swap that never verifies the sold token left, and a vault swap
that leaves a router approval unrevoked.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis. The two
vault-swap detectors fire as candidates (high severity); the
OFT detector fires without a candidate classification (medium,
fund-locking class - the batch-28 period-exit precedent); the
two hook-fee detectors fire trigger-only at low severity with
recipient FIXED (the fee lands at the hook itself - the
batch-21 redeem_burns_shares_for_zero_assets precedent).
The FIXED-recipient variants of the vault swaps MUST fire
trigger-only at low severity (never a candidate); every clean
control MUST stay silent under ALL five detectors; every other
plugin's vulnerable fixture MUST stay silent under this one
(no cross-talk); the batch-26/27/28 fixtures MUST stay silent
under all five (no cross-batch noise); the five new VULN
fixtures MUST stay silent under the relevant neighbours
(eip1271_magic_value_unchecked, ecrecover_zero_signer,
eip712_digest_unbound_to_payload, fee_on_transfer_overcredit,
hook_cei_reentrancy, v4_hook_shared_delta_take_pair,
bridge_replay_unbound_digest, bridge_wrapped_token_mint_
unbacked, lzreceive_no_origin_validation, vault_share_
inflation, recipient_unbacked_claim, recipient_overdraw_
withdraw, access_control_arbitrary_call_injection, the five
batch-26 detectors, the five batch-27 detectors, and the
five batch-28 detectors). The registry discovers exactly
1495 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit26_fixtures as fx26  # noqa: E402
import deep_audit27_fixtures as fx27  # noqa: E402
import deep_audit28_fixtures as fx28  # noqa: E402
import deep_audit30_fixtures as fx  # noqa: E402
from app.plugins.bsc_access import SPECS as ACCESS_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_mev_bridge import SPECS as MEVB_SPECS  # noqa: E402
from app.plugins.deep_audit import SPECS_BY_ID as SPECS1, \
    analyze_deep_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit20 import SPECS_BY_ID as SPECS20, \
    analyze_deep20_source  # noqa: E402
from app.plugins.deep_audit26 import SPECS_BY_ID as SPECS26, \
    analyze_deep26_source  # noqa: E402
from app.plugins.deep_audit27 import SPECS_BY_ID as SPECS27, \
    analyze_deep27_source  # noqa: E402
from app.plugins.deep_audit28 import SPECS_BY_ID as SPECS28, \
    analyze_deep28_source  # noqa: E402
from app.plugins.deep_audit30 import SPECS, SPECS_BY_ID, \
    analyze_deep30_source  # noqa: E402
from app.plugins.deep_audit3 import SPECS_BY_ID as SPECS3, \
    analyze_deep3_source  # noqa: E402
from app.plugins.deep_audit5 import SPECS_BY_ID as SPECS5, \
    analyze_deep5_source  # noqa: E402
from app.plugins.recipient_first import \
    analyze_recipient_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["swap_fake_order_no_sold_token_check",
                 "swap_approval_leftover_unrevoked"]
TRIGGER_ONLY_IDS = ["hook_fee_on_requested_not_realized",
                    "hook_fee_exact_output_wrong_leg"]
ACCESS_BY_ID = {s.id: s for s in ACCESS_SPECS}
MEVB_BY_ID = {s.id: s for s in MEVB_SPECS}


def hits_for(src, pid):
    return analyze_deep30_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1495():
    reg = discover()
    assert len(reg) == 1495, \
        f"registry size {len(reg)}, expected 1495"


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
            if pid == "swap_fake_order_no_sold_token_check":
                # The payout leg meters the caller's own shares
                # (HOLDER-SELF in isolation), but it is priced
                # off the donation-inflated valuation, so the
                # redeeming stranger receives assets beyond
                # their own deposit - the excess is
                # CALLER-received (the batch-28 share-price
                # precedent). Pinned explicitly here and in
                # test_swap_fake_order_names_the_swap_function.
                assert h["recipient"] == "HOLDER-SELF"
            else:
                assert h["recipient"] in (
                    "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_oft_fires_without_candidate():
    pid = "oft_credit_accumulator_underflow"
    hits = hits_for(fx.VULN[pid], pid)
    assert hits, f"{pid}: vulnerable fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    for h in hits:
        assert h["code"], f"{pid}: no code evidence"
        assert h["detail"], f"{pid}: no detail"
        assert h["function"] == "_credit"
        assert h["gate_analysis"], \
            f"{pid}: no gate analysis (validator-ready bar)"
        assert h["severity"] == "medium"
        assert h.get("report_class") is None, (
            f"{pid}: the credit path locks funds - the value "
            f"is the failed bridge, so it must not carry a "
            f"candidate classification")


def test_hook_fee_fires_trigger_only():
    for pid in TRIGGER_ONLY_IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["code"], f"{pid}: no code evidence"
            assert h["detail"], f"{pid}: no detail"
            assert h["function"], f"{pid}: no function"
            assert h["gate_analysis"], \
                f"{pid}: no gate analysis (validator-ready bar)"
            assert h["report_class"] == "trigger_only", (
                f"{pid}: hook-fee vuln must be trigger-only, "
                f"got {h['report_class']}")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


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


def test_batch28_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-30 detector.
    for group in (fx28.VULN, fx28.CLEAN, fx28.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-28 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx28.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-28 extra clean "
                f"{clean_id}: {hits}")


def test_batch26_fixtures_silent_under_all_five():
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
    # detector, the v4 hook detectors, the bridge detectors,
    # the vault share-inflation detector, the recipient-first
    # claim / overdraw detectors, the BSC arbitrary-call
    # executor, and the batch-26/27/28 detectors.
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
    neighbours.append(("hook_cei_reentrancy",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    neighbours.append(("v4_hook_shared_delta_take_pair",
                       lambda src, spec:
                       analyze_deep3_source(src, spec)))
    neighbours.append(("bridge_replay_unbound_digest",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    neighbours.append(("bridge_wrapped_token_mint_unbacked",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("lzreceive_no_origin_validation",
                       lambda src, spec:
                       analyze_deep20_source(src, spec)))
    neighbours.append(("vault_share_inflation",
                       lambda src, spec:
                       analyze_deep_source(src, spec)))
    neighbours.append(("recipient_unbacked_claim",
                       lambda src, spec_id:
                       analyze_recipient_source(src, spec_id)))
    neighbours.append(("recipient_overdraw_withdraw",
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
    for pid in ("snapshot_position_sync_caller_writable",
                "share_price_excludes_subthreshold_collateral",
                "voucher_redeem_recipient_unbound",
                "period_exit_writes_new_period_exposure_snapshot",
                "withdraw_pays_other_account_balance"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep28_source(src, spec)))
    specs = {}
    specs.update(SPECS1)
    specs.update(SPECS2)
    specs.update(SPECS3)
    specs.update(SPECS5)
    specs.update(SPECS20)
    specs.update(SPECS26)
    specs.update(SPECS27)
    specs.update(SPECS28)
    specs.update(ACCESS_BY_ID)
    specs.update(MEVB_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            if pid not in specs and pid not in (
                    "recipient_unbacked_claim",
                    "recipient_overdraw_withdraw"):
                continue
            spec = specs.get(pid, pid)
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_oft_names_the_credit_function():
    hits = hits_for(
        fx.VULN["oft_credit_accumulator_underflow"],
        "oft_credit_accumulator_underflow")
    assert [h["function"] for h in hits] == ["_credit"]
    assert "totalBridgedOut" in hits[0]["detail"]


def test_oft_guarded_silent():
    hits = hits_for(
        fx.CLEAN["oft_credit_accumulator_underflow"],
        "oft_credit_accumulator_underflow")
    assert hits == []


def test_oft_initialized_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["oft_initialized"],
        "oft_credit_accumulator_underflow")
    assert hits == []


def test_oft_no_marker_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["oft_no_marker"],
        "oft_credit_accumulator_underflow")
    assert hits == []


def test_hook_fee_requested_names_the_hook_function():
    hits = hits_for(
        fx.VULN["hook_fee_on_requested_not_realized"],
        "hook_fee_on_requested_not_realized")
    assert [h["function"] for h in hits] == ["beforeSwap"]
    assert "amountSpecified" in hits[0]["detail"]
    assert hits[0]["recipient"] == "FIXED"


def test_hook_fee_requested_realised_check_silent():
    hits = hits_for(
        fx.CLEAN["hook_fee_on_requested_not_realized"],
        "hook_fee_on_requested_not_realized")
    assert hits == []


def test_hook_fee_requested_no_afterswap_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["hook2_no_afterswap"],
        "hook_fee_on_requested_not_realized")
    assert hits == []


def test_hook_fee_wrong_leg_names_the_hook_function():
    hits = hits_for(
        fx.VULN["hook_fee_exact_output_wrong_leg"],
        "hook_fee_exact_output_wrong_leg")
    assert [h["function"] for h in hits] == ["afterSwap"]
    assert "feeAmount" in hits[0]["detail"]
    assert hits[0]["recipient"] == "FIXED"


def test_hook_fee_wrong_leg_exact_input_branch_silent():
    hits = hits_for(
        fx.CLEAN["hook_fee_exact_output_wrong_leg"],
        "hook_fee_exact_output_wrong_leg")
    assert hits == []


def test_hook_fee_wrong_leg_no_leg_math_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["hook3_no_leg_math"],
        "hook_fee_exact_output_wrong_leg")
    assert hits == []


def test_swap_fake_order_names_the_swap_function():
    hits = hits_for(
        fx.VULN["swap_fake_order_no_sold_token_check"],
        "swap_fake_order_no_sold_token_check")
    assert [h["function"] for h in hits] == ["swap"]
    assert "sold" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "HOLDER-SELF"


def test_swap_fake_order_balance_check_silent():
    hits = hits_for(
        fx.CLEAN["swap_fake_order_no_sold_token_check"],
        "swap_fake_order_no_sold_token_check")
    assert hits == []


def test_swap_approval_names_the_swap_function():
    hits = hits_for(
        fx.VULN["swap_approval_leftover_unrevoked"],
        "swap_approval_leftover_unrevoked")
    assert [h["function"] for h in hits] == ["swap"]
    assert "router" in hits[0]["detail"]
    assert hits[0]["recipient"] == "UNRESOLVED"


def test_swap_approval_reset_silent():
    hits = hits_for(
        fx.CLEAN["swap_approval_leftover_unrevoked"],
        "swap_approval_leftover_unrevoked")
    assert hits == []
