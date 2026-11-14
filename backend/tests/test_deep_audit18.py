"""Deep-audit batch-18 detector: multi-token deposit length mismatch.

The vulnerable fixture MUST fire with the plugin's own finding
kind + code evidence + gate analysis, classified candidate; the
FIXED-recipient variant MUST fire trigger-only at low severity
(never a candidate); the caller-supplied and split-input extra
vuln shapes MUST fire candidate; every clean control MUST stay
silent; every other batch's fixtures (12-17) MUST stay silent
under this detector (no cross-batch noise); the registry
discovers exactly 1437 plugins including this one.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit12_fixtures as fx12  # noqa: E402
import deep_audit13_fixtures as fx13  # noqa: E402
import deep_audit14_fixtures as fx14  # noqa: E402
import deep_audit15_fixtures as fx15  # noqa: E402
import deep_audit16_fixtures as fx16  # noqa: E402
import deep_audit17_fixtures as fx17  # noqa: E402
import deep_audit18_fixtures as fx  # noqa: E402
from app.plugins.deep_audit18 import SPECS, SPECS_BY_ID, \
    analyze_deep18_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

PID = "multitoken_deposit_length_mismatch"
IDS = [s.id for s in SPECS]


def hits_for(src, pid=PID):
    return analyze_deep18_source(src, SPECS_BY_ID[pid])


def test_one_plugin_registered():
    assert len(IDS) == 1
    reg = discover()
    assert PID in reg, f"{PID} missing from registry"


def test_registry_count_1437():
    reg = discover()
    assert len(reg) == 1437, \
        f"registry size {len(reg)}, expected 1437"


def test_vuln_fires_candidate_with_evidence():
    hits = hits_for(fx.VULN[PID])
    assert hits, f"{PID}: vulnerable fixture did not fire"
    assert all(h["kind"] == PID for h in hits)
    for h in hits:
        assert h["code"], f"{PID}: no code evidence"
        assert h["detail"], f"{PID}: no detail"
        assert h["function"], f"{PID}: no function"
        assert h["gate_analysis"], \
            f"{PID}: no gate analysis (validator-ready bar)"
        assert h["report_class"] == "candidate", (
            f"{PID}: vuln fixture must be a candidate, got "
            f"{h['report_class']} ({h.get('recipient')})")
        assert h["severity"] == "high"
        assert h["recipient"] in (
            "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_variant_fires_trigger_only_never_candidate():
    hits = hits_for(fx.VARIANT[PID])
    assert hits, f"{PID}: FIXED variant did not fire"
    for h in hits:
        assert h["report_class"] == "trigger_only", (
            f"{PID}: FIXED variant escalated to candidate")
        assert h["severity"] == "low"
        assert h["recipient"] == "FIXED"


def test_caller_supplied_variant_fires_candidate():
    hits = hits_for(fx.EXTRA_VULN["caller_supplied_recipient"])
    assert hits, f"{PID}: caller-supplied fixture did not fire"
    assert all(h["kind"] == PID for h in hits)
    for h in hits:
        assert h["report_class"] == "candidate"
        assert h["recipient"] == "CALLER-SUPPLIED"


def test_split_inputs_variant_fires_candidate():
    hits = hits_for(fx.EXTRA_VULN["amounts0_amounts1_style"])
    assert hits, f"{PID}: split-input fixture did not fire"
    assert all(h["kind"] == PID for h in hits)
    for h in hits:
        assert h["report_class"] == "candidate"
        assert h["recipient"] == "CALLER"


def test_clean_controls_silent():
    for clean_id, src in fx.CLEAN.items():
        hits = hits_for(src)
        assert hits == [], (
            f"{PID}: fired on the {clean_id} clean "
            f"control: {hits}")
    for clean_id, src in fx.EXTRA_CLEAN.items():
        hits = hits_for(src)
        assert hits == [], (
            f"{PID}: fired on extra clean {clean_id}: "
            f"{hits}")


def test_batch17_fixtures_silent():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under this detector.
    for group in (fx17.VULN, fx17.CLEAN, fx17.VARIANT,
                  fx17.EXTRA_CLEAN):
        for fid, src in group.items():
            hits = hits_for(src)
            assert hits == [], (
                f"{PID}: fired on batch-17 fixture {fid}: "
                f"{hits}")


def test_batches12_to_16_fixtures_silent():
    # No cross-batch noise from any earlier deep-audit batch.
    for fxm in (fx12, fx13, fx14, fx15, fx16):
        for group in (fxm.VULN, fxm.CLEAN, fxm.VARIANT,
                      fxm.EXTRA_CLEAN):
            for fid, src in group.items():
                hits = hits_for(src)
                assert hits == [], (
                    f"{PID}: fired on fixture {fid}: {hits}")


def test_vuln_names_the_deposit_function():
    hits = hits_for(fx.VULN[PID])
    assert [h["function"] for h in hits] == ["depositMulti"]
    assert "amounts.length" in hits[0]["detail"]
    assert "token0" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_length_check_silent():
    hits = hits_for(fx.CLEAN[PID])
    assert hits == []


def test_single_token_vault_silent():
    hits = hits_for(fx.CLEAN["single_token_vault"])
    assert hits == []


def test_full_valuation_without_length_check_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["full_valuation_no_length_check"])
    assert hits == []


def test_token0_only_withdraw_silent():
    hits = hits_for(fx.EXTRA_CLEAN["token0_only_withdraw"])
    assert hits == []


def test_length_check_literal_2_silent():
    hits = hits_for(fx.EXTRA_CLEAN["length_check_literal_2"])
    assert hits == []
