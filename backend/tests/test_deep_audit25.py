"""Deep-audit batch-25 detectors: batch-mint underpayment,
multicall delegatecall, auction deadline, bridge deposit
value, merkle amount binding.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (the four recipient detectors); the auction detector
fires without a candidate classification (batch-20 auction
precedent: stale-price / locked funds are not a stranger
drain). The FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-24 fixtures MUST stay silent under all
five (no cross-batch noise); the five new VULN fixtures MUST
stay silent under the relevant neighbours
(erc721_mint_without_receiver_check, bep721_mint_index_overflow,
bep721_reentrancy_on_safe_mint, recipient_mint_to_caller,
multicall_value_reuse, multicall_2771_sender_spoof,
eip7702_unverified_delegate, auction_bid_no_prior_refund,
marketplace_expired_order_execution,
bridge_deposit_event_spoofing, masterchef_deposit_fee_skimming,
staking_total_shares_mismatch, merkle_claim_no_claimed_marker,
claim_guard_wrong_key_replay, claim_callback_before_claimed_flag,
merkle_proof_unbounded_leaf_index, merkle_leaf_single_hash,
recipient_unbacked_claim, gamefi_state_desync_reward_claim,
staking_reward_compounding_reentrancy);
the registry discovers exactly 1495 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit24_fixtures as fx24  # noqa: E402
import deep_audit25_fixtures as fx  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_gamefi import SPECS as GAMEFI_SPECS  # noqa: E402
from app.plugins.bsc_mev_bridge import SPECS as MEVB_SPECS  # noqa: E402
from app.plugins.bsc_staking import SPECS as STAKING_SPECS  # noqa: E402
from app.plugins.deep_audit10 import SPECS_BY_ID as SPECS10, \
    analyze_deep10_source  # noqa: E402
from app.plugins.deep_audit15 import SPECS_BY_ID as SPECS15, \
    analyze_deep15_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit20 import SPECS_BY_ID as SPECS20, \
    analyze_deep20_source  # noqa: E402
from app.plugins.deep_audit22 import SPECS_BY_ID as SPECS22, \
    analyze_deep22_source  # noqa: E402
from app.plugins.deep_audit24 import SPECS_BY_ID as SPECS24, \
    analyze_deep24_source  # noqa: E402
from app.plugins.deep_audit25 import SPECS, SPECS_BY_ID, \
    analyze_deep25_source  # noqa: E402
from app.plugins.deep_audit5 import SPECS_BY_ID as SPECS5, \
    analyze_deep5_source  # noqa: E402
from app.plugins.deep_audit8 import SPECS_BY_ID as SPECS8, \
    analyze_deep8_source  # noqa: E402
from app.plugins.recipient_first import \
    analyze_recipient_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["nft_batch_mint_underpayment",
                 "multicall_arbitrary_delegatecall",
                 "bridge_deposit_value_unbound_to_msgvalue",
                 "merkle_proof_amount_unbound"]
MEVB_BY_ID = {s.id: s for s in MEVB_SPECS}
GAMEFI_BY_ID = {s.id: s for s in GAMEFI_SPECS}
STAKING_BY_ID = {s.id: s for s in STAKING_SPECS}


def hits_for(src, pid):
    return analyze_deep25_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1480():
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
            assert h["recipient"] in (
                "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_auction_fires_without_candidate():
    pid = "auction_bid_after_deadline"
    hits = hits_for(fx.VULN[pid], pid)
    assert hits, f"{pid}: vulnerable fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    for h in hits:
        assert h["code"], f"{pid}: no code evidence"
        assert h["detail"], f"{pid}: no detail"
        assert h["function"] == "bid"
        assert h["gate_analysis"], \
            f"{pid}: no gate analysis (validator-ready bar)"
        assert h["severity"] == "medium"
        assert h.get("report_class") is None, (
            f"{pid}: stale-price / locked funds are not a "
            f"stranger drain, must not carry a candidate "
            f"classification")


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


def test_batch24_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-25 detector.
    for group in (fx24.VULN, fx24.CLEAN, fx24.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-24 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx24.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-24 extra clean "
                f"{clean_id}: {hits}")


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors: the ERC721 / BEP721 mint detectors,
    # the recipient-first mint / claim detectors, the
    # multicall / 7702 detectors, the auction refund /
    # marketplace expiry detectors, the bridge deposit /
    # staking deposit detectors, and the Merkle claim
    # detectors.
    neighbours = []
    neighbours.append(("erc721_mint_without_receiver_check",
                       lambda src, spec:
                       analyze_deep5_source(src, spec)))
    for pid in ("bep721_mint_index_overflow",
                "bep721_reentrancy_on_safe_mint",
                "gamefi_state_desync_reward_claim",
                "marketplace_expired_order_execution"):
        neighbours.append((pid, lambda src, spec:
                           analyze_bsc_source(src, spec)))
    for pid in ("recipient_mint_to_caller",
                "recipient_unbacked_claim"):
        neighbours.append((pid, lambda src, spec_id:
                           analyze_recipient_source(src, spec_id)))
    for pid in ("multicall_value_reuse",
                "merkle_leaf_single_hash"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep8_source(src, spec)))
    neighbours.append(("multicall_2771_sender_spoof",
                       lambda src, spec:
                       analyze_deep10_source(src, spec)))
    neighbours.append(("eip7702_unverified_delegate",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    for pid in ("auction_bid_no_prior_refund",
                "merkle_claim_no_claimed_marker"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep20_source(src, spec)))
    for pid in ("bridge_deposit_event_spoofing",):
        neighbours.append((pid, lambda src, spec:
                           analyze_bsc_source(src, spec)))
    for pid in ("masterchef_deposit_fee_skimming",
                "staking_total_shares_mismatch",
                "staking_reward_compounding_reentrancy"):
        neighbours.append((pid, lambda src, spec:
                           analyze_bsc_source(src, spec)))
    neighbours.append(("claim_guard_wrong_key_replay",
                       lambda src, spec:
                       analyze_deep22_source(src, spec)))
    neighbours.append(("claim_callback_before_claimed_flag",
                       lambda src, spec:
                       analyze_deep15_source(src, spec)))
    neighbours.append(("merkle_proof_unbounded_leaf_index",
                       lambda src, spec:
                       analyze_deep24_source(src, spec)))
    specs = {}
    specs.update(SPECS5)
    specs.update(SPECS8)
    specs.update(SPECS10)
    specs.update(SPECS2)
    specs.update(SPECS20)
    specs.update(SPECS22)
    specs.update(SPECS15)
    specs.update(SPECS24)
    specs.update(MEVB_BY_ID)
    specs.update(GAMEFI_BY_ID)
    specs.update(STAKING_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            if pid not in specs and pid not in (
                    "recipient_mint_to_caller",
                    "recipient_unbacked_claim"):
                continue
            spec = specs.get(pid, pid)
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_nft_mint_names_the_buy_function():
    hits = hits_for(
        fx.VULN["nft_batch_mint_underpayment"],
        "nft_batch_mint_underpayment")
    assert [h["function"] for h in hits] == ["buy"]
    assert "quantity" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_nft_mint_priced_per_unit_silent():
    hits = hits_for(
        fx.CLEAN["nft_batch_mint_underpayment"],
        "nft_batch_mint_underpayment")
    assert hits == []


def test_nft_mint_single_unit_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["nft_single_mint"],
        "nft_batch_mint_underpayment")
    assert hits == []


def test_nft_mint_reversed_pricing_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["nft_reversed_pricing"],
        "nft_batch_mint_underpayment")
    assert hits == []


def test_multicall_names_the_multicall_function():
    hits = hits_for(
        fx.VULN["multicall_arbitrary_delegatecall"],
        "multicall_arbitrary_delegatecall")
    assert [h["function"] for h in hits] == ["multicall"]
    assert "targets" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_multicall_stored_implementation_silent():
    hits = hits_for(
        fx.CLEAN["multicall_arbitrary_delegatecall"],
        "multicall_arbitrary_delegatecall")
    assert hits == []


def test_multicall_allowlist_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["multicall_allowlist"],
        "multicall_arbitrary_delegatecall")
    assert hits == []


def test_multicall_plain_call_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["multicall_plain_call"],
        "multicall_arbitrary_delegatecall")
    assert hits == []


def test_auction_names_the_bid_function():
    hits = hits_for(
        fx.VULN["auction_bid_after_deadline"],
        "auction_bid_after_deadline")
    assert [h["function"] for h in hits] == ["bid"]
    assert "auctionEnd" in hits[0]["detail"] or \
        "deadline" in hits[0]["detail"].lower()


def test_auction_deadline_enforced_silent():
    hits = hits_for(
        fx.CLEAN["auction_bid_after_deadline"],
        "auction_bid_after_deadline")
    assert hits == []


def test_auction_modifier_deadline_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["auction_modifier_deadline"],
        "auction_bid_after_deadline")
    assert hits == []


def test_auction_helper_deadline_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["auction_helper_deadline"],
        "auction_bid_after_deadline")
    assert hits == []


def test_auction_no_deadline_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["auction_no_deadline"],
        "auction_bid_after_deadline")
    assert hits == []


def test_bridge_deposit_names_the_deposit_function():
    hits = hits_for(
        fx.VULN["bridge_deposit_value_unbound_to_msgvalue"],
        "bridge_deposit_value_unbound_to_msgvalue")
    assert [h["function"] for h in hits] == ["deposit"]
    assert "amount" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_bridge_deposit_value_bound_silent():
    hits = hits_for(
        fx.CLEAN["bridge_deposit_value_unbound_to_msgvalue"],
        "bridge_deposit_value_unbound_to_msgvalue")
    assert hits == []


def test_bridge_deposit_credits_msgvalue_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["bridge_credits_msgvalue"],
        "bridge_deposit_value_unbound_to_msgvalue")
    assert hits == []


def test_bridge_deposit_erc20_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["bridge_erc20_deposit"],
        "bridge_deposit_value_unbound_to_msgvalue")
    assert hits == []


def test_merkle_amount_names_the_claim_function():
    hits = hits_for(
        fx.VULN["merkle_proof_amount_unbound"],
        "merkle_proof_amount_unbound")
    assert [h["function"] for h in hits] == ["claim"]
    assert "amount" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_merkle_amount_bound_leaf_silent():
    hits = hits_for(
        fx.CLEAN["merkle_proof_amount_unbound"],
        "merkle_proof_amount_unbound")
    assert hits == []


def test_merkle_amount_leaf_param_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["merkle_leaf_param"],
        "merkle_proof_amount_unbound")
    assert hits == []


def test_merkle_amount_stored_entitlement_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["merkle_stored_entitlement"],
        "merkle_proof_amount_unbound")
    assert hits == []
