"""Deep-audit batch-32 detectors: a bridge redeem honouring a
fixed 1:1 rate with no peg read and no circuit breaker, a
4337/7579 validator whose owner branch skips the execution
policy the session-key branch enforces, an exact-output swap
with an unbounded maximum input, a period/duration config
setter with a lower bound only and no escape, and a v4 hook
that credits a per-swap rebate to the router (the hook's
`sender`) with a direct claim path.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis. The two
recipient detectors (#1 bridge redeem, #2 validator) fire
classified candidate; #3 (swap), #4 (period) and #5 (hook)
fire WITHOUT a candidate classification (batch-28 period-exit
precedent: #3 the caller is the victim of their own unbounded
swap, #4 a privileged freeze landing on users, #5 the credited
recipient is the FIXED router). The FIXED-recipient variant
(#1 only) MUST fire trigger-only at low severity (never a
candidate); every clean control MUST stay silent under ALL
five detectors; every other plugin's vulnerable fixture MUST
stay silent under this one (no cross-talk); the batch-26/27/28
fixtures MUST stay silent under all five (no cross-batch
noise); the five new VULN fixtures MUST stay silent under the
relevant neighbours (chainlink_price_unbounded,
bridge_wrapped_token_mint_unbacked and the rest of the bridge
family, aa_validation_ungated, ecrecover_zero_signer,
eip1271_magic_value_unchecked, eip712_digest_unbound_to_
payload, fee_on_transfer_overcredit, hook_cei_reentrancy,
v4_hook_shared_delta_take_pair, the period checkpoint /
capacity / rescue detectors, recipient_overdraw_withdraw,
recipient_unbacked_claim, recipient_rescue_to_param,
access_control_arbitrary_call_injection, cp_proto_unbounded_
slippage, and the five batch-26/27/28 detectors). The batch-30
hook-fee pair (hook_fee_on_requested_not_realized,
hook_fee_exact_output_wrong_leg) lives in unmerged PR #208,
so it cannot be imported here; it was verified silent on all
five VULN fixtures from the Nov 22 worktree in a scratch run.
The registry discovers exactly 1495 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit26_fixtures as fx26  # noqa: E402
import deep_audit27_fixtures as fx27  # noqa: E402
import deep_audit28_fixtures as fx28  # noqa: E402
import deep_audit32_fixtures as fx  # noqa: E402
from app.plugins.bsc_access import SPECS as ACCESS_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_mev_bridge import SPECS as MEVB_SPECS  # noqa: E402
from app.plugins.cryptopack_protocol import \
    audit_protocol_source  # noqa: E402
from app.plugins.deep_audit import SPECS_BY_ID as SPECS1, \
    analyze_deep_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit20b import SPECS_BY_ID as SPECS20B, \
    analyze_deep20_source  # noqa: E402
from app.plugins.deep_audit21 import SPECS_BY_ID as SPECS21, \
    analyze_deep21_source  # noqa: E402
from app.plugins.deep_audit23 import SPECS_BY_ID as SPECS23, \
    analyze_deep23_source  # noqa: E402
from app.plugins.deep_audit26 import SPECS_BY_ID as SPECS26, \
    analyze_deep26_source  # noqa: E402
from app.plugins.deep_audit27 import SPECS_BY_ID as SPECS27, \
    analyze_deep27_source  # noqa: E402
from app.plugins.deep_audit28 import SPECS_BY_ID as SPECS28, \
    analyze_deep28_source  # noqa: E402
from app.plugins.deep_audit3 import SPECS_BY_ID as SPECS3, \
    analyze_deep3_source  # noqa: E402
from app.plugins.deep_audit32 import SPECS, SPECS_BY_ID, \
    analyze_deep32_source  # noqa: E402
from app.plugins.deep_audit5 import SPECS_BY_ID as SPECS5, \
    analyze_deep5_source  # noqa: E402
from app.plugins.deep_audit6 import SPECS_BY_ID as SPECS6, \
    analyze_deep6_source  # noqa: E402
from app.plugins.recipient_first import \
    analyze_recipient_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["bridge_redeem_no_peg_circuit_breaker",
                 "aa_validator_owner_branch_no_execution_policy"]
NO_CLASS_IDS = ["swap_exact_output_unbounded_max_input",
                "period_config_no_upper_bound_no_escape",
                "hook_sender_is_router_rebate_credit"]
ACCESS_BY_ID = {s.id: s for s in ACCESS_SPECS}
MEVB_BY_ID = {s.id: s for s in MEVB_SPECS}


def hits_for(src, pid):
    return analyze_deep32_source(src, SPECS_BY_ID[pid])


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
            if pid == "bridge_redeem_no_peg_circuit_breaker":
                # The payout leg meters the caller's own
                # wrapped balance (HOLDER-SELF in isolation),
                # but it is priced off the unpegged 1:1 rate,
                # so the redeeming stranger receives reserve
                # assets beyond the market value of what they
                # burned - the excess is CALLER-received (the
                # batch-28 share-price precedent). Pinned
                # explicitly here and in
                # test_bridge_redeem_names_the_redeem_function.
                assert h["recipient"] == "HOLDER-SELF"
            else:
                assert h["recipient"] == "CALLER-SUPPLIED"


def test_no_candidate_detectors_fire_without_classification():
    expected = {"swap_exact_output_unbounded_max_input": "medium",
                "period_config_no_upper_bound_no_escape": "high",
                "hook_sender_is_router_rebate_credit": "medium"}
    for pid, sev in expected.items():
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["code"], f"{pid}: no code evidence"
            assert h["detail"], f"{pid}: no detail"
            assert h["function"], f"{pid}: no function"
            assert h["gate_analysis"], \
                f"{pid}: no gate analysis (validator-ready bar)"
            assert h["severity"] == sev, (
                f"{pid}: expected severity {sev}, got "
                f"{h['severity']}")
            assert h.get("report_class") is None, (
                f"{pid}: must not carry a candidate "
                f"classification (got {h.get('report_class')})")


def test_variant_fires_trigger_only_never_candidate():
    for pid in fx.VARIANT:
        hits = hits_for(fx.VARIANT[pid], pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_extra_vuln_no_bound_fires():
    pid = "swap_exact_output_unbounded_max_input"
    hits = hits_for(fx.EXTRA_VULN["swap_no_bound"], pid)
    assert hits, "no-bound exactOutput call must still fire"
    assert all(h["kind"] == pid for h in hits)
    assert [h["function"] for h in hits] == ["swapExactOutput"]
    assert hits[0].get("report_class") is None


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


def test_no_cross_talk_from_extra_vuln():
    for name, src in fx.EXTRA_VULN.items():
        for pid in IDS:
            if pid == "swap_exact_output_unbounded_max_input":
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on extra vuln {name}: {hits}")


def _prior_batch_silent(fxmod):
    for group in (fxmod.VULN, fxmod.CLEAN,
                  getattr(fxmod, "VARIANT", {})):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on prior-batch fixture "
                    f"{fid}: {hits}")
    for clean_id, src in fxmod.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on prior-batch extra clean "
                f"{clean_id}: {hits}")


def test_batch26_fixtures_silent_under_all_five():
    _prior_batch_silent(fx26)


def test_batch27_fixtures_silent_under_all_five():
    _prior_batch_silent(fx27)


def test_batch28_fixtures_silent_under_all_five():
    _prior_batch_silent(fx28)


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors: the Chainlink price detector, the
    # whole bridge family, the 4337 validation / ecrecover
    # detectors, the EIP-1271 / EIP-712 signature detectors,
    # the fee-on-transfer deposit detector, the v4 hook CEI /
    # shared-delta detectors, the period checkpoint / capacity
    # / rescue detectors, the recipient-first claim / overdraw
    # / rescue detectors, the BSC arbitrary-call executor, the
    # five batch-26 detectors, the five batch-27 detectors and
    # the five batch-28 detectors.
    neighbours = []
    neighbours.append(("chainlink_price_unbounded",
                       lambda src, spec:
                       analyze_deep6_source(src, spec)))
    neighbours.append(("aa_validation_ungated",
                       lambda src, spec:
                       analyze_deep_source(src, spec)))
    neighbours.append(("ecrecover_zero_signer",
                       lambda src, spec:
                       analyze_deep_source(src, spec)))
    neighbours.append(("eip1271_magic_value_unchecked",
                       lambda src, spec:
                       analyze_deep5_source(src, spec)))
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
    neighbours.append(("period_start_checkpoint_zeroes_payout_cap",
                       lambda src, spec:
                       analyze_deep21_source(src, spec)))
    neighbours.append(("rescue_marks_future_bucket_claimed",
                       lambda src, spec:
                       analyze_deep21_source(src, spec)))
    neighbours.append(("cover_capacity_counts_unpaid_prior_period",
                       lambda src, spec:
                       analyze_deep20_source(src, spec)))
    neighbours.append(("stale_capacity_snapshot_after_payout",
                       lambda src, spec:
                       analyze_deep23_source(src, spec)))
    neighbours.append(("recipient_overdraw_withdraw",
                       lambda src, spec_id:
                       analyze_recipient_source(src, spec_id)))
    neighbours.append(("recipient_unbacked_claim",
                       lambda src, spec_id:
                       analyze_recipient_source(src, spec_id)))
    neighbours.append(("recipient_rescue_to_param",
                       lambda src, spec_id:
                       analyze_recipient_source(src, spec_id)))
    neighbours.append(("access_control_arbitrary_call_injection",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    for spec in MEVB_SPECS:
        neighbours.append((spec.id, lambda src, spec:
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
    specs.update(SPECS6)
    specs.update(SPECS20B)
    specs.update(SPECS21)
    specs.update(SPECS23)
    specs.update(SPECS26)
    specs.update(SPECS27)
    specs.update(SPECS28)
    specs.update(ACCESS_BY_ID)
    specs.update(MEVB_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            if pid not in specs and pid not in (
                    "recipient_overdraw_withdraw",
                    "recipient_unbacked_claim",
                    "recipient_rescue_to_param"):
                continue
            spec = specs.get(pid, pid)
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")
        # cp_proto_unbounded_slippage: no amountOutMin == 0
        # and no deadline == type(uint).max anywhere in the
        # fixture (the swap fixture's whole point is the
        # input-side mirror, not the min-out side).
        checks = [f["check"] for f in audit_protocol_source(src)]
        assert "unbounded_slippage" not in checks, (
            f"cp_proto_unbounded_slippage fired on the "
            f"{vuln_id} fixture: {checks}")


def test_bridge_redeem_names_the_redeem_function():
    hits = hits_for(
        fx.VULN["bridge_redeem_no_peg_circuit_breaker"],
        "bridge_redeem_no_peg_circuit_breaker")
    assert [h["function"] for h in hits] == ["redeem"]
    assert "1:1" in hits[0]["detail"]
    assert hits[0]["recipient"] == "HOLDER-SELF"


def test_bridge_redeem_peg_check_silent():
    hits = hits_for(
        fx.CLEAN["bridge_redeem_no_peg_circuit_breaker"],
        "bridge_redeem_no_peg_circuit_breaker")
    assert hits == []


def test_bridge_redeem_pause_flag_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["bridge_pause"],
        "bridge_redeem_no_peg_circuit_breaker")
    assert hits == []


def test_bridge_redeem_computed_rate_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["bridge_computed_rate"],
        "bridge_redeem_no_peg_circuit_breaker")
    assert hits == []


def test_validator_names_the_validate_function():
    hits = hits_for(
        fx.VULN["aa_validator_owner_branch_no_execution_policy"],
        "aa_validator_owner_branch_no_execution_policy")
    assert [h["function"] for h in hits] == ["validateUserOp"]
    assert "owner branch" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_validator_owner_policy_checked_silent():
    hits = hits_for(
        fx.CLEAN["aa_validator_owner_branch_no_execution_policy"],
        "aa_validator_owner_branch_no_execution_policy")
    assert hits == []


def test_validator_single_branch_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["validator_single_branch"],
        "aa_validator_owner_branch_no_execution_policy")
    assert hits == []


def test_validator_no_policy_anywhere_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["validator_no_policy_anywhere"],
        "aa_validator_owner_branch_no_execution_policy")
    assert hits == []


def test_swap_names_the_swap_function():
    hits = hits_for(
        fx.VULN["swap_exact_output_unbounded_max_input"],
        "swap_exact_output_unbounded_max_input")
    assert [h["function"] for h in hits] == ["swapExactOutput"]
    assert "type(uint256).max" in hits[0]["detail"]


def test_swap_bounded_max_silent():
    hits = hits_for(
        fx.CLEAN["swap_exact_output_unbounded_max_input"],
        "swap_exact_output_unbounded_max_input")
    assert hits == []


def test_swap_computed_cap_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["swap_computed_cap"],
        "swap_exact_output_unbounded_max_input")
    assert hits == []


def test_swap_passthrough_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["swap_passthrough"],
        "swap_exact_output_unbounded_max_input")
    assert hits == []


def test_period_names_the_setter_function():
    hits = hits_for(
        fx.VULN["period_config_no_upper_bound_no_escape"],
        "period_config_no_upper_bound_no_escape")
    assert [h["function"] for h in hits] == \
        ["addPeriodConfiguration"]
    assert "periodConfigs" in hits[0]["detail"]


def test_period_upper_bound_silent():
    hits = hits_for(
        fx.CLEAN["period_config_no_upper_bound_no_escape"],
        "period_config_no_upper_bound_no_escape")
    assert hits == []


def test_period_cancel_path_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["period_cancel_path"],
        "period_config_no_upper_bound_no_escape")
    assert hits == []


def test_period_replace_path_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["period_replace_path"],
        "period_config_no_upper_bound_no_escape")
    assert hits == []


def test_hook_names_the_hook_function():
    hits = hits_for(
        fx.VULN["hook_sender_is_router_rebate_credit"],
        "hook_sender_is_router_rebate_credit")
    assert [h["function"] for h in hits] == ["afterSwap"]
    assert "sender" in hits[0]["detail"]
    assert "router" in hits[0]["detail"]


def test_hook_trader_credit_silent():
    hits = hits_for(
        fx.CLEAN["hook_sender_is_router_rebate_credit"],
        "hook_sender_is_router_rebate_credit")
    assert hits == []


def test_hook_no_claim_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["hook_no_claim"],
        "hook_sender_is_router_rebate_credit")
    assert hits == []


def test_hook_claim_to_treasury_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["hook_claim_treasury"],
        "hook_sender_is_router_rebate_credit")
    assert hits == []
