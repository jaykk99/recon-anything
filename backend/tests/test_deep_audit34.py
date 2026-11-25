"""Deep-audit batch-34 detectors: a burn that skips the
liquidity decrement when both withdrawal amounts round to
zero, a mint / claim that burns tokens from a caller-supplied
address, a liquidation that burns the debt token in the
wrong units, an OFT _credit that subtracts from an
uninitialized unclamped accumulator, and a reward
distribution that overwrites duplicate array entries
instead of accumulating them.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-33 fixtures MUST stay silent under all
five (no cross-batch noise); the five new VULN fixtures MUST
stay silent under the relevant neighbours
(withdraw_rounding_drain,
zero_amount_withdrawal_full_balance,
token_sell_hook_burns_pair_reserves_sync,
bridge_wrapped_token_mint_unbacked, fee_on_transfer_overcredit,
bep20_burn_from_overflow, gamefi_asset_duplication_on_burn,
pancake_lp_token_burn_logic,
redeem_burns_shares_for_zero_assets), with NO documented
co-fire this batch. NOTE: liquidation_clears_collateral_
keeps_debt (batch 29, PR #206) and
evm_caller_token_transferfrom are NOT on master - the first is
an open unmerged PR, the second is not in the registry at all
despite the research log calling it built - so neighbour
silence for them cannot be asserted here; the fixtures are
checked against them in the live run only if those branches
are present. The registry
discovers exactly 1500 plugins including all five. The
FP-regression rows (deep_audit13 + deep_audit14) stay silent
under all five. The OFT finding is FUND-LOCKING, not a
stranger drain - the detail says so honestly and the test
pins the wording.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit13_fixtures as fx13  # noqa: E402
import deep_audit14_fixtures as fx14  # noqa: E402
import deep_audit33_fixtures as fx33  # noqa: E402
import deep_audit34_fixtures as fx  # noqa: E402
from app.plugins.bsc_bep20 import SPECS as BEP20_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_gamefi import SPECS as GAMEFI_SPECS  # noqa: E402
from app.plugins.bsc_mev_bridge import SPECS as BRIDGE_SPECS  # noqa: E402
from app.plugins.bsc_pancake import SPECS as PANCAKE_SPECS  # noqa: E402
from app.plugins.deep_audit10 import SPECS_BY_ID as SPECS10, \
    analyze_deep10_source  # noqa: E402
from app.plugins.deep_audit12 import SPECS_BY_ID as SPECS12, \
    analyze_deep12_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit21 import SPECS_BY_ID as SPECS21, \
    analyze_deep21_source  # noqa: E402
from app.plugins.deep_audit24 import SPECS_BY_ID as SPECS24, \
    analyze_deep24_source  # noqa: E402
from app.plugins.deep_audit34 import SPECS, SPECS_BY_ID, \
    analyze_deep34_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep34_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1500():
    reg = discover()
    assert len(reg) == 1500, \
        f"registry size {len(reg)}, expected 1500"


def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert len(hits) == 1, (
            f"{pid}: vulnerable fixture must fire exactly once, "
            f"got {len(hits)}")
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


def test_batch33_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-34 detector.
    for group in (fx33.VULN, fx33.CLEAN, fx33.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-33 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx33.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-33 extra clean "
                f"{clean_id}: {hits}")


def test_fp_regression_rows_silent_under_all_five():
    # The hand-read false-positive fixture shapes stay silent
    # under every batch-34 detector. (The 93-row fp_regression
    # in the task brief is backend/scripts/fp_regression.py,
    # which scores contract_logic rows - run separately, 93
    # PASS / 0 FAIL; the FP_REGRESSION fixture dicts here total
    # 8 rows: 5 in deep_audit13 + 3 in deep_audit14.)
    rows = dict(fx13.FP_REGRESSION)
    rows.update(fx14.FP_REGRESSION)
    assert len(rows) == 8
    for fid, src in rows.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on FP-regression {fid}: {hits}")


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors: the caller-transferFrom detector, the
    # rounding / zero-amount withdrawal detectors, the
    # sell-hook burn detector, the bridge wrapped-mint
    # detector, the fee-on-transfer deposit detector, and the
    # burn-family detectors (BEP20 burnFrom overflow, gamefi
    # duplication-on-burn, pancake LP burn logic, redeem
    # burns-shares-for-zero-assets). No co-fire is documented
    # this batch: none of the five fixtures prices from its
    # own balance, burns a victim in a transfer, or mints
    # from a bridge message. DOCUMENTED EXCEPTION: the pancake
    # LP burn detector fires on the burn-debit and liquidation
    # fixtures by design (both expose a `.burn(` through an
    # ungated function mentioning msg.sender - its whole broad
    # pattern) - asserted in
    # test_burn_debit_and_liquidation_pancake_cofire below, and
    # excluded from the silence assertion here for those two
    # fixtures only. (evm_caller_token_transferfrom and
    # liquidation_clears_collateral_keeps_debt are NOT on
    # master - see the module docstring - so they are not in
    # this list.)
    neighbours = []
    neighbours.append(("withdraw_rounding_drain",
                       lambda src, spec:
                       analyze_deep10_source(src, spec)))
    neighbours.append(("zero_amount_withdrawal_full_balance",
                       lambda src, spec:
                       analyze_deep12_source(src, spec)))
    neighbours.append(("token_sell_hook_burns_pair_reserves_sync",
                       lambda src, spec:
                       analyze_deep24_source(src, spec)))
    neighbours.append(("bridge_wrapped_token_mint_unbacked",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("fee_on_transfer_overcredit",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    neighbours.append(("bep20_burn_from_overflow",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("gamefi_asset_duplication_on_burn",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("pancake_lp_token_burn_logic",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("redeem_burns_shares_for_zero_assets",
                       lambda src, spec:
                       analyze_deep21_source(src, spec)))
    specs = {}
    specs.update(SPECS21)
    specs.update(SPECS10)
    specs.update(SPECS12)
    specs.update(SPECS24)
    specs.update(SPECS2)
    for s in (BEP20_SPECS, GAMEFI_SPECS, PANCAKE_SPECS,
              BRIDGE_SPECS):
        specs.update({x.id: x for x in s})
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            # DOCUMENTED CO-FIRE (see the module docstring):
            # the pancake LP burn detector fires on the
            # burn-debit and liquidation fixtures by design.
            if pid == "pancake_lp_token_burn_logic" and \
                    vuln_id in (
                        "burn_debits_caller_supplied_address",
                        "liquidation_burns_wrong_units_debt"):
                continue
            spec = specs.get(pid)
            assert spec is not None, f"no spec for {pid}"
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_burn_debit_and_liquidation_pancake_cofire():
    # DOCUMENTED CO-FIRE (see the fixtures module docstring):
    # pancake_lp_token_burn_logic fires on the burn-debit and
    # liquidation VULN fixtures because both expose a `.burn(`
    # through an ungated function mentioning msg.sender. That
    # is the same hole from the LP-burn angle; the new
    # detectors add the dimensions it cannot express (the
    # wrong-address debit, the wrong-units debt burn). It must
    # NOT fire on the other three vuln fixtures.
    spec = {s.id: s for s in PANCAKE_SPECS}[
        "pancake_lp_token_burn_logic"]
    for vuln_id in ("burn_debits_caller_supplied_address",
                    "liquidation_burns_wrong_units_debt"):
        hits = analyze_bsc_source(fx.VULN[vuln_id], spec)
        assert hits, "pancake_lp_token_burn_logic must " \
            f"co-fire on the {vuln_id} fixture"
        assert all(h["kind"] == "pancake_lp_token_burn_logic"
                   for h in hits)
    for vuln_id, src in fx.VULN.items():
        if vuln_id in ("burn_debits_caller_supplied_address",
                       "liquidation_burns_wrong_units_debt"):
            continue
        hits = analyze_bsc_source(src, spec)
        assert hits == [], (
            f"pancake_lp_token_burn_logic fired on the "
            f"{vuln_id} fixture: {hits}")


def test_burn_zero_names_the_burn_function():
    hits = hits_for(
        fx.VULN["burn_zero_amount_skips_liquidity_decrement"],
        "burn_zero_amount_skips_liquidity_decrement")
    assert [h["function"] for h in hits] == ["burn"]
    assert "amount0" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_burn_zero_early_return_fires():
    hits = hits_for(
        fx.VULN_BURN_EARLY_RETURN,
        "burn_zero_amount_skips_liquidity_decrement")
    assert hits, "both-zero early return after the burn must " \
        "still fire"
    assert all(h["kind"] ==
               "burn_zero_amount_skips_liquidity_decrement"
               for h in hits)
    assert [h["function"] for h in hits] == ["burn"]
    assert hits[0]["report_class"] == "candidate"


def test_burn_zero_unconditional_silent():
    hits = hits_for(
        fx.CLEAN["burn_zero_amount_skips_liquidity_decrement"],
        "burn_zero_amount_skips_liquidity_decrement")
    assert hits == []


def test_burn_zero_early_return_before_burn_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["burn_early_return_before_burn"],
        "burn_zero_amount_skips_liquidity_decrement")
    assert hits == []


def test_burn_zero_single_amount_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["burn_single_amount"],
        "burn_zero_amount_skips_liquidity_decrement")
    assert hits == []


def test_burn_debit_names_the_buy_function():
    hits = hits_for(
        fx.VULN["burn_debits_caller_supplied_address"],
        "burn_debits_caller_supplied_address")
    assert [h["function"] for h in hits] == ["buyPresent"]
    assert "presentReceiver" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_burn_debit_burns_sender_silent():
    hits = hits_for(
        fx.CLEAN["burn_debits_caller_supplied_address"],
        "burn_debits_caller_supplied_address")
    assert hits == []


def test_burn_debit_allowance_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["buy_allowance"],
        "burn_debits_caller_supplied_address")
    assert hits == []


def test_burn_debit_param_is_sender_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["buy_param_is_sender"],
        "burn_debits_caller_supplied_address")
    assert hits == []


def test_burn_debit_no_mint_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["buy_no_mint"],
        "burn_debits_caller_supplied_address")
    assert hits == []


def test_liquidation_names_the_finalize_function():
    hits = hits_for(
        fx.VULN["liquidation_burns_wrong_units_debt"],
        "liquidation_burns_wrong_units_debt")
    assert [h["function"] for h in hits] == ["finalizeLiquidation"]
    assert "userDebt" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_liquidation_raydiv_fires():
    hits = hits_for(
        fx.VULN_LIQ_RAYDIV,
        "liquidation_burns_wrong_units_debt")
    assert hits, "rayDiv-normalized debt must still fire"
    assert all(h["kind"] ==
               "liquidation_burns_wrong_units_debt"
               for h in hits)
    assert [h["function"] for h in hits] == ["finalizeLiquidation"]
    assert hits[0]["report_class"] == "candidate"


def test_liquidation_raw_balance_silent():
    hits = hits_for(
        fx.CLEAN["liquidation_burns_wrong_units_debt"],
        "liquidation_burns_wrong_units_debt")
    assert hits == []


def test_liquidation_rescaled_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["liq_rescaled"],
        "liquidation_burns_wrong_units_debt")
    assert hits == []


def test_liquidation_no_seizure_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["liq_no_seizure"],
        "liquidation_burns_wrong_units_debt")
    assert hits == []


def test_liquidation_raydiv_rescaled_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["liq_raydiv_rescaled"],
        "liquidation_burns_wrong_units_debt")
    assert hits == []


def test_oft_credit_names_the_credit_function():
    hits = hits_for(
        fx.VULN["oft_credit_unclamped_accumulator_underflow"],
        "oft_credit_unclamped_accumulator_underflow")
    assert [h["function"] for h in hits] == ["_credit"]
    assert "totalBridgedOut" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"
    # Fund-locking, not a drain: the finding must say so.
    assert "FUND-LOCKING" in hits[0]["detail"]
    assert "not a stranger-receivable" in hits[0]["detail"]


def test_oft_credit_guarded_silent():
    hits = hits_for(
        fx.CLEAN["oft_credit_unclamped_accumulator_underflow"],
        "oft_credit_unclamped_accumulator_underflow")
    assert hits == []


def test_oft_credit_clamp_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["oft_clamp"],
        "oft_credit_unclamped_accumulator_underflow")
    assert hits == []


def test_oft_credit_init_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["oft_init"],
        "oft_credit_unclamped_accumulator_underflow")
    assert hits == []


def test_oft_credit_no_marker_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["oft_no_marker"],
        "oft_credit_unclamped_accumulator_underflow")
    assert hits == []


def test_duplicate_rewards_names_the_constructor():
    hits = hits_for(
        fx.VULN["duplicate_array_entries_overwrite_rewards"],
        "duplicate_array_entries_overwrite_rewards")
    assert [h["function"] for h in hits] == ["constructor"]
    assert "playersToRewards" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_duplicate_rewards_accumulate_silent():
    hits = hits_for(
        fx.CLEAN["duplicate_array_entries_overwrite_rewards"],
        "duplicate_array_entries_overwrite_rewards")
    assert hits == []


def test_duplicate_rewards_seen_check_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["pot_seen_check"],
        "duplicate_array_entries_overwrite_rewards")
    assert hits == []


def test_duplicate_rewards_no_loop_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["pot_no_loop"],
        "duplicate_array_entries_overwrite_rewards")
    assert hits == []


def test_duplicate_rewards_non_reward_mapping_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["pot_non_reward_mapping"],
        "duplicate_array_entries_overwrite_rewards")
    assert hits == []
