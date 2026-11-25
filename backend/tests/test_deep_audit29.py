"""Deep-audit batch 29 - four new incident-anchored detectors.

- liquidation_clears_collateral_keeps_debt (MORE Markets, Nov 16 2026,
  ~$308-348k on Flow EVM): liquidate zeroes the collateral but never
  clears the matching debt, so the debt can be withdrawn from the
  reserve. Mirror image of built liquidation_residual_collateral_
  reborrow (zeroes debt, leaves collateral -> reborrow).
- bridge_withdraw_no_consumed_receipt_check (Ankr, Nov 9 2026, ~$304k):
  five validly-signed withdrawals all citing one already-redeemed
  0.0044 ankrETH Optimism deposit, with changed recipients/tokens/
  amounts. The digest binds chain + message id and the signature is
  valid, so it is NOT bridge_replay_unbound_digest (digest under-binds
  identity) and NOT bridge_release_value_unbound_to_proof (value is
  bound to the signed receipt): the missing piece is a consumed-receipt
  check.
- restake_reward_baseline_desync_on_transfer (Chain Games, Nov 15 2026,
  ~$20k realised / 36M CHAIN): restake mints rewards as (rewardPerShare
  - initialRewardPerShare[account]) x balance; ERC20 transfers never
  set the recipient's baseline, so a fresh recipient (baseline 0)
  claims historical rewards.
- subaccount_transfer_unchecked_underflow (Arcus Perps, Nov 9-10 2026,
  $2.23M USDG): internal transfers between a fresh account's own
  subaccounts inflated its recorded balance (integer underflow);
  withdrew against it. The debit EXISTS but is unchecked/unguarded,
  so it is NOT internal_transfer_credit_without_debit (no debit at
  all) and NOT unchecked_math_user_input (tracks locals, not state
  mapping debits).

Only four shipped: the November incident well is exhausted for novel,
fixtureable, stranger-receivable contract shapes - every other fresh
incident adjudicated to an already-built class (see research-log.md
2026-11-20). The charter allows fewer than 5 with a stated reason.

Neighbour fixes shipped alongside (pre-existing detectors, exposed by
this batch's fixtures):
- bridge_withdrawer_identity_spoof: its forbid list did not recognise
  `messageId` as a binding, so it fired on a withdraw whose recipient
  IS bound into the signed digest over the message id (the Ankr
  shape). `messageId` added to the forbid list; its own bsc100 VULN
  fixture (no message id) still fires.
- staking_total_shares_mismatch: fn_re `deposit|stake` matched the
  `restake` function name, so it fired on a restake that credits
  shares from a COMPUTED reward, not a requested deposit amount.
  fn_re anchored to `^(?:deposit|stake)`; its own bsc100 VULN fixture
  (function `stake`) still fires.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bsc100_fixtures as bsc_fx  # noqa: E402
import deep_audit27_fixtures as fx27  # noqa: E402
import deep_audit28_fixtures as fx28  # noqa: E402
import deep_audit29_fixtures as fx  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_access import SPECS as ACC_SPECS  # noqa: E402
from app.plugins.bsc_mev_bridge import SPECS as MEV_SPECS  # noqa: E402
from app.plugins.bsc_staking import SPECS as STK_SPECS  # noqa: E402
from app.plugins.business_logic import (  # noqa: E402
    SPECS_BY_ID as SPECS_BL, analyze_business_logic_source)
from app.plugins.deep_audit import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA, analyze_deep_source)
from app.plugins.deep_audit2 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA2, analyze_deep2_source)
from app.plugins.deep_audit3 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA3, analyze_deep3_source)
from app.plugins.deep_audit4 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA4, analyze_deep4_source)
from app.plugins.deep_audit5 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA5, analyze_deep5_source)
from app.plugins.deep_audit6 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA6, analyze_deep6_source)
from app.plugins.deep_audit10 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA10, analyze_deep10_source)
from app.plugins.deep_audit11 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA11, analyze_deep11_source)
from app.plugins.deep_audit20 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA20, analyze_deep20_source)
from app.plugins.deep_audit23 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA23, analyze_deep23_source)
from app.plugins.deep_audit24 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA24, analyze_deep24_source)
from app.plugins.deep_audit27 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA27, analyze_deep27_source)
from app.plugins.deep_audit28 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA28, analyze_deep28_source)
from app.plugins.deep_audit29 import (  # noqa: E402
    SPECS_BY_ID as SPECS_DA29, analyze_deep29_source)
from app.plugins.recipient_first import (  # noqa: E402
    analyze_recipient_source)
from app.plugins.registry import discover  # noqa: E402

IDS = [
    "liquidation_clears_collateral_keeps_debt",
    "bridge_withdraw_no_consumed_receipt_check",
    "restake_reward_baseline_desync_on_transfer",
    "subaccount_transfer_unchecked_underflow",
]
RECIPIENTS = {
    "liquidation_clears_collateral_keeps_debt": "CALLER",
    "bridge_withdraw_no_consumed_receipt_check": "CALLER-SUPPLIED",
    "restake_reward_baseline_desync_on_transfer": "CALLER",
    # Excess precedent (share-price family): the payout leg meters
    # the caller's own position, but the desync creates value beyond
    # the deposit, so the excess is caller-received -> candidate.
    "subaccount_transfer_unchecked_underflow": "HOLDER-SELF",
}
FUNCTIONS = {
    "liquidation_clears_collateral_keeps_debt": "liquidate",
    "bridge_withdraw_no_consumed_receipt_check": "withdraw",
    "restake_reward_baseline_desync_on_transfer": "restake",
    "subaccount_transfer_unchecked_underflow": "transferBetween",
}


def _hits(pid, src):
    return analyze_deep29_source(src, SPECS_DA29[pid])


def _kinds(pid, src):
    return [h["kind"] for h in _hits(pid, src)]


# ----------------------------------------------------------------
# registration + registry count
# ----------------------------------------------------------------

def test_four_plugins_registered():
    reg = discover()
    for pid in IDS:
        assert pid in reg, pid
    assert SPECS_DA29["liquidation_clears_collateral_keeps_debt"].family == "deep29"


def test_registry_count_1494():
    assert len(discover()) == 1494


# ----------------------------------------------------------------
# vulnerable fixtures fire as candidates with evidence
# ----------------------------------------------------------------

def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
        hits = _hits(pid, fx.VULN[pid])
        assert len(hits) == 1, (pid, hits)
        h = hits[0]
        assert h["kind"] == pid
        assert h["function"] == FUNCTIONS[pid]
        assert h["report_class"] == "candidate"
        assert h["recipient"] == RECIPIENTS[pid], (pid, h)
        assert h["severity"] == "high"
        assert h.get("gate_analysis")
        assert h.get("detail")


def test_vuln_gate_analysis_names_detector():
    # restake: the classifier must name the recipient CALLER even
    # though the payout leg is a ledger credit, not a transfer.
    hits = _hits("restake_reward_baseline_desync_on_transfer",
                 fx.VULN["restake_reward_baseline_desync_on_transfer"])
    assert hits[0]["recipient"] == "CALLER"
    # gate_analysis is a prose string, not a dict.
    assert "caller" in hits[0]["gate_analysis"].lower()


def test_subaccount_vuln_recipient_holder_self_candidate():
    hits = _hits("subaccount_transfer_unchecked_underflow",
                 fx.VULN["subaccount_transfer_unchecked_underflow"])
    assert hits[0]["report_class"] == "candidate"
    assert hits[0]["recipient"] == "HOLDER-SELF"


# ----------------------------------------------------------------
# FIXED variants fire trigger-only, never candidate
# ----------------------------------------------------------------

def test_variant_fires_trigger_only_never_candidate():
    for pid in IDS:
        hits = _hits(pid, fx.VARIANT[pid])
        assert len(hits) == 1, (pid, hits)
        h = hits[0]
        assert h["kind"] == pid
        assert h["report_class"] == "trigger_only"
        assert h["recipient"] == "FIXED"
        assert h["severity"] == "low"


# ----------------------------------------------------------------
# clean controls stay silent
# ----------------------------------------------------------------

def test_clean_controls_silent_under_all_four():
    for pid in IDS:
        assert _hits(pid, fx.CLEAN[pid]) == [], pid
        for src in fx.EXTRA_CLEAN.values():
            assert _kinds(pid, src) == [], (pid, src[:60])


def test_no_cross_talk_between_vuln_fixtures():
    for pid in IDS:
        for other in IDS:
            if other == pid:
                continue
            assert _kinds(pid, fx.VULN[other]) == [], (pid, other)


def test_no_cross_talk_from_variant_fixtures():
    for pid in IDS:
        for other in IDS:
            if other == pid:
                continue
            assert _kinds(pid, fx.VARIANT[other]) == [], (pid, other)


# ----------------------------------------------------------------
# batch-28 and batch-27 fixtures stay silent under all four
# ----------------------------------------------------------------

def test_batch28_fixtures_silent_under_all_four():
    for pid in IDS:
        for name, coll in (
                ("VULN", fx28.VULN), ("VARIANT", fx28.VARIANT),
                ("CLEAN", fx28.CLEAN), ("EXTRA_CLEAN", fx28.EXTRA_CLEAN)):
            for src in coll.values():
                assert _kinds(pid, src) == [], (pid, name)
        # VULN_TERNARY is a single source string, not a dict.
        assert _kinds(pid, fx28.VULN_TERNARY) == [], (pid, "VULN_TERNARY")


def test_batch27_fixtures_silent_under_all_four():
    for pid in IDS:
        for name, coll in (
                ("VULN", fx27.VULN), ("VARIANT", fx27.VARIANT),
                ("CLEAN", fx27.CLEAN), ("EXTRA_CLEAN", fx27.EXTRA_CLEAN)):
            for src in coll.values():
                assert _kinds(pid, src) == [], (pid, name)


# ----------------------------------------------------------------
# new vuln fixtures stay silent under the neighbours
# ----------------------------------------------------------------

_NEIGHBOURS = []


def _n(pid, fn):
    _NEIGHBOURS.append((pid, fn))


_n("eip1271_magic_value_unchecked",
   lambda src, spec: analyze_deep5_source(src, spec))
_n("ecrecover_zero_signer",
   lambda src, spec: analyze_deep_source(src, spec))
_n("eip712_digest_unbound_to_payload",
   lambda src, spec: analyze_deep3_source(src, spec))
_n("fee_on_transfer_overcredit",
   lambda src, spec: analyze_deep2_source(src, spec))
_n("bridge_replay_unbound_digest",
   lambda src, spec: analyze_deep2_source(src, spec))
_n("signature_nonce_unconsumed",
   lambda src, spec: analyze_deep5_source(src, spec))
_n("unchecked_math_user_input",
   lambda src, spec: analyze_deep6_source(src, spec))
_n("liquidation_bonus_to_borrower",
   lambda src, spec: analyze_deep10_source(src, spec))
_n("liquidation_residual_collateral_reborrow",
   lambda src, spec: analyze_deep11_source(src, spec))
_n("liquidation_caller_supplied_price",
   lambda src, spec: analyze_deep20_source(src, spec))
_n("internal_transfer_credit_without_debit",
   lambda src, spec: analyze_deep23_source(src, spec))
_n("bridge_release_value_unbound_to_proof",
   lambda src, spec: analyze_deep24_source(src, spec))
_n("share_transfer_cancel_desync",
   lambda src, spec: analyze_deep3_source(src, spec))
_n("reward_distribution_manipulation",
   lambda src, spec: analyze_business_logic_source(src, spec))
_n("staking_total_shares_mismatch",
   lambda src, spec: analyze_bsc_source(src, spec))
_n("staking_zero_deposit_harvest",
   lambda src, spec: analyze_bsc_source(src, spec))
_n("bridge_withdrawer_identity_spoof",
   lambda src, spec: analyze_bsc_source(src, spec))
_n("bridge_wrapped_token_mint_unbacked",
   lambda src, spec: analyze_bsc_source(src, spec))
_n("bridge_deposit_event_spoofing",
   lambda src, spec: analyze_bsc_source(src, spec))
_n("access_control_arbitrary_call_injection",
   lambda src, spec: analyze_bsc_source(src, spec))
_n("recipient_unbacked_claim",
   lambda src, spec_id: analyze_recipient_source(src, spec_id))
_n("recipient_overdraw_withdraw",
   lambda src, spec_id: analyze_recipient_source(src, spec_id))
for _pid in ("snapshot_position_sync_caller_writable",
             "share_price_excludes_subthreshold_collateral",
             "voucher_redeem_recipient_unbound",
             "period_exit_writes_new_period_exposure_snapshot",
             "withdraw_pays_other_account_balance"):
    _n(_pid, lambda src, spec: analyze_deep28_source(src, spec))
for _pid in ("lp_mint_no_minimum_liquidity_lock",
             "merkle_claim_replayable_across_chains",
             "vesting_claim_overrelease_past_duration",
             "permit_deadline_param_never_enforced",
             "bonding_curve_price_from_raw_balance_no_virtual_reserve"):
    _n(_pid, lambda src, spec: analyze_deep27_source(src, spec))

_ALL_SPECS = {}
for _s in (SPECS_DA, SPECS_DA2, SPECS_DA3, SPECS_DA4, SPECS_DA5, SPECS_DA6,
           SPECS_DA10, SPECS_DA11, SPECS_DA20, SPECS_DA23, SPECS_DA24,
           SPECS_DA27, SPECS_DA28, SPECS_BL):
    _ALL_SPECS.update(_s)
_ALL_SPECS.update({s.id: s for s in ACC_SPECS})
_ALL_SPECS.update({s.id: s for s in MEV_SPECS})
_ALL_SPECS.update({s.id: s for s in STK_SPECS})


def test_new_vuln_fixtures_silent_under_neighbours():
    for vuln_id, src in fx.VULN.items():
        for pid, fn in _NEIGHBOURS:
            spec = _ALL_SPECS.get(pid, pid)
            hits = fn(src, spec)
            assert hits == [], (pid, vuln_id, hits)


# ----------------------------------------------------------------
# neighbour-detector fixes shipped with this batch
# ----------------------------------------------------------------

def test_spoof_suppressed_by_message_id_but_still_fires():
    spec = {s.id: s for s in MEV_SPECS}["bridge_withdrawer_identity_spoof"]
    # The Ankr-shaped withdraw binds the recipient into the signed
    # digest over the message id, so the spoof detector must not fire.
    assert analyze_bsc_source(
        fx.VULN["bridge_withdraw_no_consumed_receipt_check"],
        spec) == []
    # Its own bsc100 VULN fixture (no message id) still fires.
    assert analyze_bsc_source(
        bsc_fx.VULN["bridge_withdrawer_identity_spoof"], spec) != []


def test_total_shares_mismatch_restake_silent_but_still_fires():
    spec = {s.id: s for s in STK_SPECS}["staking_total_shares_mismatch"]
    # restake credits shares from a COMPUTED reward, not a requested
    # deposit amount, so the mismatch detector must not fire.
    assert analyze_bsc_source(
        fx.VULN["restake_reward_baseline_desync_on_transfer"],
        spec) == []
    # Its own bsc100 VULN fixture (function `stake`) still fires.
    assert analyze_bsc_source(
        bsc_fx.VULN["staking_total_shares_mismatch"], spec) != []


# ----------------------------------------------------------------
# per-detector detail
# ----------------------------------------------------------------

def test_liquidation_detail_names_collateral_and_debt():
    hits = _hits("liquidation_clears_collateral_keeps_debt",
                 fx.VULN["liquidation_clears_collateral_keeps_debt"])
    assert "collateral" in hits[0]["detail"].lower()
    assert "debt" in hits[0]["detail"].lower()


def test_bridge_detail_names_receipt():
    hits = _hits("bridge_withdraw_no_consumed_receipt_check",
                 fx.VULN["bridge_withdraw_no_consumed_receipt_check"])
    assert "receipt" in hits[0]["detail"].lower()


def test_restake_detail_names_baseline():
    hits = _hits("restake_reward_baseline_desync_on_transfer",
                 fx.VULN["restake_reward_baseline_desync_on_transfer"])
    assert "initialRewardPerShare" in hits[0]["detail"]


def test_subaccount_detail_names_unchecked():
    hits = _hits("subaccount_transfer_unchecked_underflow",
                 fx.VULN["subaccount_transfer_unchecked_underflow"])
    assert "unchecked" in hits[0]["detail"].lower()
