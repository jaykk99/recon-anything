"""Deep-audit batch-13 detectors (AI dev, 2026-11-09).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL four detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-10, batch-11 and batch-12 fixtures MUST
stay silent under all four (no cross-batch noise); the registry
discovers exactly 1424 plugins including all four.
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
import deep_audit13_fixtures as fx  # noqa: E402
from app.plugins.deep_audit13 import SPECS, SPECS_BY_ID, \
    analyze_deep13_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep13_source(src, SPECS_BY_ID[pid])


def test_four_plugins_registered():
    assert len(IDS) == 4
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1339():
    reg = discover()
    assert len(reg) == 1424, \
        f"registry size {len(reg)}, expected 1424"


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


def test_clean_controls_silent_under_all_four():
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


def test_batch12_fixtures_silent_under_all_four():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-13 detector. Skipped while
    # batch-12 fixtures are still on unmerged PR #153.
    if fx12 is None:
        import pytest
        pytest.skip("deep_audit12_fixtures not on master yet "
                    "(PR #153 unmerged)")
    for group in (fx12.VULN, fx12.CLEAN, fx12.VARIANT,
                  fx12.EXTRA_CLEAN):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-12 fixture {fid}: "
                    f"{hits}")


def test_batch11_fixtures_silent_under_all_four():
    for group in (fx11.VULN, fx11.CLEAN, fx11.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-11 fixture {fid}: "
                    f"{hits}")


def test_batch10_fixtures_silent_under_all_four():
    for group in (fx10.VULN, fx10.CLEAN, fx10.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-10 fixture {fid}: "
                    f"{hits}")


def test_sweep_names_the_refund_functions():
    hits = hits_for(fx.VULN["residual_balance_sweep_ungated"],
                    "residual_balance_sweep_ungated")
    assert [h["function"] for h in hits] == [
        "refundETH", "unwrapWETH9"]
    assert "address(this).balance" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"
    assert hits[1]["recipient"] == "CALLER-SUPPLIED"


def test_sweep_gated_and_bounded_silent():
    hits = hits_for(
        fx.CLEAN["residual_balance_sweep_ungated"],
        "residual_balance_sweep_ungated")
    assert hits == []


def test_sweep_bounded_amount_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["residual_balance_sweep_ungated"],
        "residual_balance_sweep_ungated")
    assert hits == []


def test_pyth_names_the_consumer_function():
    hits = hits_for(fx.VULN["pyth_price_unsafe_unchecked"],
                    "pyth_price_unsafe_unchecked")
    assert [h["function"] for h in hits] == ["getCollateralValue"]
    assert "getPriceUnsafe" in hits[0]["detail"]
    assert hits[0]["recipient"] == "UNRESOLVED"


def test_pyth_safe_api_silent():
    hits = hits_for(
        fx.CLEAN["pyth_price_unsafe_unchecked"],
        "pyth_price_unsafe_unchecked")
    assert hits == []


def test_pyth_publish_time_check_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["pyth_price_unsafe_unchecked"],
        "pyth_price_unsafe_unchecked")
    assert hits == []


def test_paymaster_names_the_validator():
    hits = hits_for(fx.VULN["paymaster_sponsorship_unbounded"],
                    "paymaster_sponsorship_unbounded")
    assert [h["function"] for h in hits] == [
        "validatePaymasterUserOp"]
    assert "validationData 0" in hits[0]["detail"]
    assert hits[0]["recipient"] == "UNRESOLVED"


def test_paymaster_signed_silent():
    hits = hits_for(
        fx.CLEAN["paymaster_sponsorship_unbounded"],
        "paymaster_sponsorship_unbounded")
    assert hits == []


def test_paymaster_capped_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["paymaster_sponsorship_unbounded"],
        "paymaster_sponsorship_unbounded")
    assert hits == []



def test_stale_names_the_setter_function():
    hits = hits_for(
        fx.VULN["stale_permission_after_replacement"],
        "stale_permission_after_replacement")
    assert [h["function"] for h in hits] == ["setRebalancer"]
    assert "rebalancer" in hits[0]["detail"]
    assert hits[0]["recipient"] == "UNRESOLVED"


def test_stale_revoke_first_silent():
    hits = hits_for(
        fx.CLEAN["stale_permission_after_replacement"],
        "stale_permission_after_replacement")
    assert hits == []


def test_stale_never_granted_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["stale_permission_after_replacement"],
        "stale_permission_after_replacement")
    assert hits == []


def test_fp_regression_shapes_silent_under_all_five():
    # Shapes hand-read as false positives on the first live
    # corpus pass (2026-11-09): _msgSender() gates,
    # mapping-allowlist gates, modifier-override gates,
    # hasAdminRole gates, and one-time setters. All must stay
    # silent under every batch-13 detector.
    for fid, src in fx.FP_REGRESSION.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on FP-regression {fid}: {hits}")
