"""Deep-audit batch-20 detectors: cover capacity, user selectors,
settlement sweeps, wrapper creation, supply-cap bypass.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-16 and batch-19 fixtures MUST stay
silent under all five (no cross-batch noise); the registry
discovers exactly 1438 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit16_fixtures as fx16  # noqa: E402
import deep_audit19_fixtures as fx19  # noqa: E402
import deep_audit20_fixtures as fx  # noqa: E402
from app.plugins.deep_audit20 import SPECS, SPECS_BY_ID, \
    analyze_deep20_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = list(IDS)
SEVERITY = {
    "cover_capacity_counts_unpaid_prior_period": "high",
    "user_bytes_as_call_selector": "high",
    "permissionless_sweep_breaks_settlement_finality": "high",
    "wrapper_create_no_code_check": "medium",
    "supply_cap_bypass_direct_transfer": "high",
}
FUNCTION = {
    "cover_capacity_counts_unpaid_prior_period": "claim",
    "user_bytes_as_call_selector": "verifyProof",
    "permissionless_sweep_breaks_settlement_finality":
        "sweepUnclaimedBonus",
    "wrapper_create_no_code_check": "createERC223Wrapper",
    "supply_cap_bypass_direct_transfer": "borrow",
}


def hits_for(src, pid):
    return analyze_deep20_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1438():
    reg = discover()
    assert len(reg) == 1438, \
        f"registry size {len(reg)}, expected 1438"


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
            assert h["severity"] == SEVERITY[pid], (
                f"{pid}: severity {h['severity']}, expected "
                f"{SEVERITY[pid]}")
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


def test_batch16_fixtures_silent_under_all_five():
    # No cross-batch noise: the batch-16 fixtures must not fire
    # under any batch-20 detector.
    for group in (fx16.VULN, fx16.CLEAN, fx16.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-16 fixture {fid}: "
                    f"{hits}")


def test_batch19_fixtures_silent_under_all_five():
    # No cross-batch noise: the batch-19 fixtures must not fire
    # under any batch-20 detector. Batch-19's
    # weak_onchain_randomness has no recipient, but its VULN
    # fixture must still stay silent under all five.
    for group in (fx19.VULN, fx19.CLEAN, fx19.VARIANT,
                  fx19.EXTRA_CLEAN):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-19 fixture {fid}: "
                    f"{hits}")


def test_cover_names_the_claim_function():
    pid = "cover_capacity_counts_unpaid_prior_period"
    hits = hits_for(fx.VULN[pid], pid)
    assert [h["function"] for h in hits] == ["claim"]
    assert "unpaidPriorPeriod" in hits[0]["detail"]
    assert "availableCover" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_cover_subtracted_unpaid_silent():
    pid = "cover_capacity_counts_unpaid_prior_period"
    hits = hits_for(fx.CLEAN[pid], pid)
    assert hits == []


def test_cover_sub_spelling_silent():
    pid = "cover_capacity_counts_unpaid_prior_period"
    hits = hits_for(fx.EXTRA_CLEAN["cover_capacity_sub_spelling"],
                    pid)
    assert hits == []


def test_selector_names_the_verify_function():
    pid = "user_bytes_as_call_selector"
    hits = hits_for(fx.VULN[pid], pid)
    assert [h["function"] for h in hits] == ["verifyProof"]
    assert "bytes4(proof)" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_selector_constant_selector_silent():
    pid = "user_bytes_as_call_selector"
    hits = hits_for(fx.CLEAN[pid], pid)
    assert hits == []


def test_selector_interface_selector_silent():
    pid = "user_bytes_as_call_selector"
    hits = hits_for(
        fx.EXTRA_CLEAN["selector_interface_selector"], pid)
    assert hits == []


def test_selector_keccak_constant_silent():
    pid = "user_bytes_as_call_selector"
    hits = hits_for(
        fx.EXTRA_CLEAN["selector_keccak_constant"], pid)
    assert hits == []


def test_sweep_names_the_sweep_function():
    pid = "permissionless_sweep_breaks_settlement_finality"
    hits = hits_for(fx.VULN[pid], pid)
    assert [h["function"] for h in hits] == ["sweepUnclaimedBonus"]
    assert "claimsStarted" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_sweep_latch_read_silent():
    pid = "permissionless_sweep_breaks_settlement_finality"
    hits = hits_for(fx.CLEAN[pid], pid)
    assert hits == []


def test_sweep_only_owner_silent():
    pid = "permissionless_sweep_breaks_settlement_finality"
    hits = hits_for(fx.EXTRA_CLEAN["sweep_only_owner"], pid)
    assert hits == []


def test_wrapper_names_the_create_function():
    pid = "wrapper_create_no_code_check"
    hits = hits_for(fx.VULN[pid], pid)
    assert [h["function"] for h in hits] == ["createERC223Wrapper"]
    assert "isContract" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_wrapper_is_contract_silent():
    pid = "wrapper_create_no_code_check"
    hits = hits_for(fx.CLEAN[pid], pid)
    assert hits == []


def test_wrapper_code_length_silent():
    pid = "wrapper_create_no_code_check"
    hits = hits_for(
        fx.EXTRA_CLEAN["wrapper_code_length_check"], pid)
    assert hits == []


def test_cap_names_the_borrow_function():
    pid = "supply_cap_bypass_direct_transfer"
    hits = hits_for(fx.VULN[pid], pid)
    assert [h["function"] for h in hits] == ["borrow"]
    assert "supplyCap" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_cap_internal_ledger_silent():
    pid = "supply_cap_bypass_direct_transfer"
    hits = hits_for(fx.CLEAN[pid], pid)
    assert hits == []


def test_cap_checked_in_borrow_silent():
    pid = "supply_cap_bypass_direct_transfer"
    hits = hits_for(fx.EXTRA_CLEAN["cap_checked_in_borrow"], pid)
    assert hits == []
