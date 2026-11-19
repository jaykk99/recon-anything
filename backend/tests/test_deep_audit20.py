"""Deep-audit batch-20 detectors: claims, bridges, auctions, lending.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (the four recipient detectors); the FIXED-recipient
variant MUST fire trigger-only at low severity (never a
candidate); every clean control MUST stay silent under ALL five
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk); the batch-19 fixtures
MUST stay silent under all five (no cross-batch noise); the
registry discovers exactly 1490 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit19_fixtures as fx19  # noqa: E402
import deep_audit20_fixtures as fx  # noqa: E402
from app.plugins.deep_audit20 import SPECS, SPECS_BY_ID, \
    analyze_deep20_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["merkle_claim_no_claimed_marker",
                 "lzreceive_no_origin_validation",
                 "borrow_no_collateral_check",
                 "liquidation_caller_supplied_price"]


def hits_for(src, pid):
    return analyze_deep20_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1480():
    reg = discover()
    assert len(reg) == 1490, \
        f"registry size {len(reg)}, expected 1490"


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
    pid = "auction_bid_no_prior_refund"
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
            f"{pid}: locked funds are not a stranger drain, "
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


def test_batch19_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-20 detector.
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


def test_merkle_names_the_claim_function():
    hits = hits_for(fx.VULN["merkle_claim_no_claimed_marker"],
                    "merkle_claim_no_claimed_marker")
    assert [h["function"] for h in hits] == ["claim"]
    assert "Merkle" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_merkle_claimed_marker_silent():
    hits = hits_for(
        fx.CLEAN["merkle_claim_no_claimed_marker"],
        "merkle_claim_no_claimed_marker")
    assert hits == []


def test_merkle_helper_mark_silent():
    # Marker written in an internal helper the entry point calls.
    hits = hits_for(
        fx.EXTRA_CLEAN["merkle_helper_mark"],
        "merkle_claim_no_claimed_marker")
    assert hits == []


def test_merkle_no_payout_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["merkle_no_payout"],
        "merkle_claim_no_claimed_marker")
    assert hits == []


def test_lzreceive_names_the_receive_function():
    hits = hits_for(fx.VULN["lzreceive_no_origin_validation"],
                    "lzreceive_no_origin_validation")
    assert [h["function"] for h in hits] == ["lzReceive"]
    assert "origin" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] in (
        "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_lzreceive_endpoint_gate_silent():
    hits = hits_for(
        fx.CLEAN["lzreceive_no_origin_validation"],
        "lzreceive_no_origin_validation")
    assert hits == []


def test_lzreceive_inline_check_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lz_inline_check"],
        "lzreceive_no_origin_validation")
    assert hits == []


def test_auction_names_the_bid_function():
    hits = hits_for(fx.VULN["auction_bid_no_prior_refund"],
                    "auction_bid_no_prior_refund")
    assert [h["function"] for h in hits] == ["bid"]
    assert "highestBid" in hits[0]["detail"]


def test_auction_pending_returns_silent():
    hits = hits_for(
        fx.CLEAN["auction_bid_no_prior_refund"],
        "auction_bid_no_prior_refund")
    assert hits == []


def test_auction_helper_refund_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["auction_helper_refund"],
        "auction_bid_no_prior_refund")
    assert hits == []


def test_auction_direct_refund_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["auction_direct_refund"],
        "auction_bid_no_prior_refund")
    assert hits == []


def test_borrow_names_the_borrow_function():
    hits = hits_for(fx.VULN["borrow_no_collateral_check"],
                    "borrow_no_collateral_check")
    assert [h["function"] for h in hits] == ["borrow"]
    assert "collateral" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "CALLER"


def test_borrow_collateral_require_silent():
    hits = hits_for(
        fx.CLEAN["borrow_no_collateral_check"],
        "borrow_no_collateral_check")
    assert hits == []


def test_borrow_comptroller_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["borrow_comptroller"],
        "borrow_no_collateral_check")
    assert hits == []


def test_liquidation_names_the_liquidate_function():
    hits = hits_for(fx.VULN["liquidation_caller_supplied_price"],
                    "liquidation_caller_supplied_price")
    assert [h["function"] for h in hits] == ["liquidate"]
    assert "price" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "CALLER"


def test_liquidation_oracle_price_silent():
    hits = hits_for(
        fx.CLEAN["liquidation_caller_supplied_price"],
        "liquidation_caller_supplied_price")
    assert hits == []


def test_liquidation_oracle_enforced_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["liquidation_oracle_enforced"],
        "liquidation_caller_supplied_price")
    assert hits == []
