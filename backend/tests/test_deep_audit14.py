"""Deep-audit batch-14 detectors (AI dev, 2026-11-10).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-10, batch-11 and batch-13 fixtures MUST
stay silent under all five (no cross-batch noise); the registry
discovers exactly 1351 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit10_fixtures as fx10  # noqa: E402
import deep_audit11_fixtures as fx11  # noqa: E402
try:
    import deep_audit12_fixtures as fx12  # noqa: E402
except ImportError:
    # Batch-12 fixtures live on unmerged PR #153, not on master
    # yet: the batch-12 silence test skips until they land.
    fx12 = None  # noqa: E402
try:
    import deep_audit13_fixtures as fx13  # noqa: E402
except ImportError:
    # Batch-13 fixtures live on unmerged PR #158, not on master
    # yet: the batch-13 silence test skips until they land.
    fx13 = None  # noqa: E402
import deep_audit14_fixtures as fx  # noqa: E402
from app.plugins.deep_audit14 import SPECS, SPECS_BY_ID, \
    analyze_deep14_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep14_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1232():
    reg = discover()
    assert len(reg) == 1351, \
        f"registry size {len(reg)}, expected 1351"


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


def test_batch13_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-14 detector. Skipped while
    # batch-13 fixtures are still on unmerged PR #158.
    if fx13 is None:
        import pytest
        pytest.skip("deep_audit13_fixtures not on master yet "
                    "(PR #158 unmerged)")
    for group in (fx13.VULN, fx13.CLEAN, fx13.VARIANT,
                  fx13.EXTRA_CLEAN):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-13 fixture {fid}: "
                    f"{hits}")


def test_batch12_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-14 detector, with ONE known
    # dual-shape exception (merged 2026-11-12): the batch-12
    # intent_deposit_ghost_credit_no_rollback fixture ALSO
    # performs its token transfer before the accounting write,
    # so callback_token_cei_violation legitimately fires on it
    # as trigger_only / low / FIXED - never a candidate. The
    # overlap is in the fixture shape, not a detector bug.
    if fx12 is None:
        import pytest
        pytest.skip("deep_audit12_fixtures not on master yet "
                    "(PR #153 unmerged)")
    for group in (fx12.VULN, fx12.CLEAN, fx12.VARIANT,
                  fx12.EXTRA_CLEAN):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                if (pid == "callback_token_cei_violation" and
                        fid == "intent_deposit_ghost_credit_no_rollback"):
                    assert all(
                        h["report_class"] == "trigger_only" and
                        h["severity"] == "low" for h in hits), (
                        f"{pid}: dual-shape overlap on {fid} must "
                        f"stay trigger_only/low, got {hits}")
                    continue
                assert hits == [], (
                    f"{pid}: fired on batch-12 fixture {fid}: "
                    f"{hits}")


def test_batch11_fixtures_silent_under_all_five():
    for group in (fx11.VULN, fx11.CLEAN, fx11.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-11 fixture {fid}: "
                    f"{hits}")


def test_batch10_fixtures_silent_under_all_five():
    for group in (fx10.VULN, fx10.CLEAN, fx10.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-10 fixture {fid}: "
                    f"{hits}")


def test_provider_names_the_borrow_function():
    hits = hits_for(
        fx.VULN["lending_collateral_price_provider_unvalidated"],
        "lending_collateral_price_provider_unvalidated")
    assert [h["function"] for h in hits] == ["borrow"]
    assert "priceProviders" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_provider_owner_gated_setter_silent():
    hits = hits_for(
        fx.CLEAN["lending_collateral_price_provider_unvalidated"],
        "lending_collateral_price_provider_unvalidated")
    assert hits == []


def test_provider_allowlisted_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "lending_collateral_price_provider_unvalidated"],
        "lending_collateral_price_provider_unvalidated")
    assert hits == []


def test_cei_names_the_flow_functions():
    hits = hits_for(fx.VULN["callback_token_cei_violation"],
                    "callback_token_cei_violation")
    assert [h["function"] for h in hits] == [
        "withdraw", "mintShares"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"
    assert hits[1]["recipient"] == "CALLER-SUPPLIED"


def test_cei_update_first_silent():
    hits = hits_for(fx.CLEAN["callback_token_cei_violation"],
                    "callback_token_cei_violation")
    assert hits == []


def test_cei_nonreentrant_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["callback_token_cei_violation"],
        "callback_token_cei_violation")
    assert hits == []


def test_forwarder_names_the_execute_function():
    hits = hits_for(
        fx.VULN["forwarder_library_msgdata_tail_confusion"],
        "forwarder_library_msgdata_tail_confusion")
    assert [h["function"] for h in hits] == [
        "executeViaLibrary"]
    assert "_msgSender" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_forwarder_no_forwarder_silent():
    hits = hits_for(
        fx.CLEAN["forwarder_library_msgdata_tail_confusion"],
        "forwarder_library_msgdata_tail_confusion")
    assert hits == []


def test_forwarder_fixed_calldata_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "forwarder_library_msgdata_tail_confusion"],
        "forwarder_library_msgdata_tail_confusion")
    assert hits == []


def test_governance_names_the_vote_function():
    hits = hits_for(
        fx.VULN["governance_no_snapshot_immediate_seat"],
        "governance_no_snapshot_immediate_seat")
    assert [h["function"] for h in hits] == ["vote"]
    assert "electLeader" in hits[0]["detail"]
    assert hits[0]["recipient"] == "UNRESOLVED"


def test_governance_snapshot_silent():
    hits = hits_for(
        fx.CLEAN["governance_no_snapshot_immediate_seat"],
        "governance_no_snapshot_immediate_seat")
    assert hits == []


def test_governance_timelocked_seat_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["governance_no_snapshot_immediate_seat"],
        "governance_no_snapshot_immediate_seat")
    assert hits == []


def test_pool_names_the_invest_function():
    hits = hits_for(
        fx.VULN["vault_underwrites_attacker_created_pool"],
        "vault_underwrites_attacker_created_pool")
    assert [h["function"] for h in hits] == ["invest"]
    assert "pool" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_pool_allowlisted_silent():
    hits = hits_for(
        fx.CLEAN["vault_underwrites_attacker_created_pool"],
        "vault_underwrites_attacker_created_pool")
    assert hits == []


def test_pool_min_liquidity_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["vault_underwrites_attacker_created_pool"],
        "vault_underwrites_attacker_created_pool")
    assert hits == []


def test_fp_regression_shapes_silent_under_all_five():
    # Shapes hand-read as false positives on the first live
    # corpus pass (2026-11-10): super.mint() passthroughs,
    # MORPHO.supply() on the fixed Morpho protocol, and
    # router.addLiquidity() on a fixed DEX router - the
    # pool-method receiver was a fixed protocol / parent
    # contract, not a caller-derived pool. All must stay
    # silent under every batch-14 detector.
    for fid, src in fx.FP_REGRESSION.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on FP-regression {fid}: {hits}")
