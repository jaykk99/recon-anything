"""Deep-audit batch-12 detectors (AI dev, 2026-11-08).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-10 and batch-11 fixtures MUST stay
silent under all five (no cross-batch noise); the registry
discovers exactly 1232 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit10_fixtures as fx10  # noqa: E402
import deep_audit11_fixtures as fx11  # noqa: E402
import deep_audit12_fixtures as fx  # noqa: E402
from app.plugins.deep_audit12 import SPECS, SPECS_BY_ID, \
    analyze_deep12_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep12_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1232():
    reg = discover()
    assert len(reg) == 1235, \
        f"registry size {len(reg)}, expected 1235"


def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
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
    for pid in IDS:
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


def test_batch11_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-12 detector.
    for group in (fx11.VULN, fx11.CLEAN, fx11.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-11 fixture {fid}: "
                    f"{hits}")


def test_batch10_fixtures_silent_under_all_five():
    # Same for batch 10 (withdraw / forwarder / eip7702
    # shapes sit close to the batch-12 lanes).
    for group in (fx10.VULN, fx10.CLEAN, fx10.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-10 fixture {fid}: "
                    f"{hits}")


def test_zero_amount_names_the_withdraw_function():
    hits = hits_for(fx.VULN["zero_amount_withdrawal_full_balance"],
                    "zero_amount_withdrawal_full_balance")
    assert [h["function"] for h in hits] == ["withdraw"]
    assert "amount == 0" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_zero_amount_positive_guard_silent():
    hits = hits_for(
        fx.CLEAN["zero_amount_withdrawal_full_balance"],
        "zero_amount_withdrawal_full_balance")
    assert hits == []


def test_zero_amount_strict_amount_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["zero_amount_withdrawal_full_balance"],
        "zero_amount_withdrawal_full_balance")
    assert hits == []


def test_settlement_names_the_settle_function():
    hits = hits_for(fx.VULN["scheduled_settlement_books_unpaid"],
                    "scheduled_settlement_books_unpaid")
    assert [h["function"] for h in hits] == ["settleDay"]
    assert "outstandingDebt" in hits[0]["detail"]
    assert hits[0]["recipient"] == "UNRESOLVED"


def test_settlement_arrival_verified_silent():
    hits = hits_for(
        fx.CLEAN["scheduled_settlement_books_unpaid"],
        "scheduled_settlement_books_unpaid")
    assert hits == []


def test_settlement_no_booking_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["scheduled_settlement_books_unpaid"],
        "scheduled_settlement_books_unpaid")
    assert hits == []


def test_vesting_names_the_cancel_function():
    hits = hits_for(fx.VULN["vesting_release_cancel_double_debit"],
                    "vesting_release_cancel_double_debit")
    assert [h["function"] for h in hits] == ["cancel"]
    assert "position.shares" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_vesting_both_counters_silent():
    hits = hits_for(
        fx.CLEAN["vesting_release_cancel_double_debit"],
        "vesting_release_cancel_double_debit")
    assert hits == []


def test_vesting_no_total_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["vesting_release_cancel_double_debit"],
        "vesting_release_cancel_double_debit")
    assert hits == []


def test_ghost_names_the_refund_function():
    hits = hits_for(
        fx.VULN["intent_deposit_ghost_credit_no_rollback"],
        "intent_deposit_ghost_credit_no_rollback")
    assert [h["function"] for h in hits] == \
        ["refundFailedDeposit"]
    assert "balances" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_ghost_credit_after_call_silent():
    hits = hits_for(
        fx.CLEAN["intent_deposit_ghost_credit_no_rollback"],
        "intent_deposit_ghost_credit_no_rollback")
    assert hits == []


def test_ghost_refund_clears_credit_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["intent_deposit_ghost_credit_no_rollback"],
        "intent_deposit_ghost_credit_no_rollback")
    assert hits == []


def test_aa_names_the_execute_functions():
    hits = hits_for(fx.VULN["aa_execute_ungated"],
                    "aa_execute_ungated")
    assert [h["function"] for h in hits] == \
        ["execute", "executeBatch"]
    assert "target" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_aa_only_owner_silent():
    hits = hits_for(
        fx.CLEAN["aa_execute_ungated"], "aa_execute_ungated")
    assert hits == []


def test_aa_entrypoint_gate_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["aa_execute_ungated"],
        "aa_execute_ungated")
    assert hits == []
