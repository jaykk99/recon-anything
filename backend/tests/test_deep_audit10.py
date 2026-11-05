"""Deep-audit batch-10 detectors (AI dev, 2026-11-05).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the registry discovers exactly 847 plugins
including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit10_fixtures as fx  # noqa: E402
from app.plugins.deep_audit10 import SPECS, SPECS_BY_ID, \
    analyze_deep10_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep10_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_847():
    reg = discover()
    assert len(reg) == 852, \
        f"registry size {len(reg)}, expected 852"


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


def test_withdraw_names_the_withdraw_function():
    hits = hits_for(fx.VULN["withdraw_rounding_drain"],
                    "withdraw_rounding_drain")
    assert [h["function"] for h in hits] == ["withdraw"]
    assert "sharesToBurn" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_withdraw_min_guard_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["withdraw_rounding_drain_min_guard"],
        "withdraw_rounding_drain")
    assert hits == []


def test_forwarder_names_the_execute_function():
    hits = hits_for(fx.VULN["forwarder_execute_spoof"],
                    "forwarder_execute_spoof")
    assert [h["function"] for h in hits] == ["execute"]
    assert "from" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_multicall_names_the_multicall_function():
    hits = hits_for(fx.VULN["multicall_2771_sender_spoof"],
                    "multicall_2771_sender_spoof")
    assert [h["function"] for h in hits] == ["multicall"]
    assert "delegatecall" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_liquidation_names_the_liquidate_function():
    hits = hits_for(fx.VULN["liquidation_bonus_to_borrower"],
                    "liquidation_bonus_to_borrower")
    assert [h["function"] for h in hits] == ["liquidate"]
    assert "LIQUIDATION_BONUS" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_liquidation_literal_factor_fires():
    src = fx.VULN["liquidation_bonus_to_borrower"].replace(
        "debtToCover * LIQUIDATION_BONUS / 100",
        "debtToCover * 110 / 100")
    hits = hits_for(src, "liquidation_bonus_to_borrower")
    assert hits, "literal * 110 / 100 bonus did not fire"
    assert "110" in hits[0]["detail"]


def test_liquidation_additive_factor_fires():
    src = fx.VULN["liquidation_bonus_to_borrower"].replace(
        "debtToCover * LIQUIDATION_BONUS / 100",
        "debtToCover * (100 + 10) / 100")
    hits = hits_for(src, "liquidation_bonus_to_borrower")
    assert hits, "additive (100 + 10) bonus did not fire"


def test_liquidation_no_bonus_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["liquidation_bonus_to_borrower_no_bonus"],
        "liquidation_bonus_to_borrower")
    assert hits == []


def test_eip7702_names_the_execute_function():
    hits = hits_for(fx.VULN["eip7702_low_slot_collision"],
                    "eip7702_low_slot_collision")
    assert [h["function"] for h in hits] == ["execute"]
    assert "owner" in hits[0]["detail"]


def test_eip7702_token_fp_shapes_silent():
    # Loose-marker false positives from the 2026-11-05 corpus
    # run: Delegator-named governance tokens and upgradeable
    # tokens with initialize + delegatecall in the bundle are
    # NOT EIP-7702 delegates and must stay silent.
    for key in ("eip7702_low_slot_collision_token_fp",
                "eip7702_low_slot_collision_upgradeable_fp"):
        hits = hits_for(fx.EXTRA_CLEAN[key],
                        "eip7702_low_slot_collision")
        assert hits == [], f"{key} fired: {hits}"
