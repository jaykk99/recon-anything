"""Deep-audit batch-7 detectors (bridge + proxy slices,
2026-11-04).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate at the spec severity; the FIXED-recipient variant
(value-moving detectors only) MUST fire trigger-only at low
severity, never a candidate; every clean control MUST stay
silent under ALL twelve detectors; every other plugin's
vulnerable / variant fixture MUST stay silent under this one
(no cross-talk); the registry discovers exactly 1434 plugins
including all twelve.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit7_fixtures as fx  # noqa: E402
from app.plugins.deep_audit7 import SPECS, SPECS_BY_ID, \
    analyze_deep7_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]

EXPECTED_SEVERITY = {
    "bridge_digest_no_destination_chain": "high",
    "bridge_bytes_proof_length_unvalidated": "high",
    "bridge_static_gas_limit": "low",
    "bridge_receiver_sender_unchecked": "high",
    "bridge_mint_burn_gate_asymmetry": "medium",
    "bridge_nonce_order_unenforced": "medium",
    "bridge_proof_nullifier_missing": "high",
    "bridge_payload_slice_unbounded": "medium",
    "uups_authorize_upgrade_missing": "high",
    "initializer_flag_after_call": "medium",
    "diamond_selector_collision": "medium",
    "beacon_implementation_zero_accepted": "medium",
}


def hits_for(src, pid):
    return analyze_deep7_source(src, SPECS_BY_ID[pid])


def test_twelve_plugins_registered():
    assert len(IDS) == 12
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1237():
    reg = discover()
    assert len(reg) == 1434, \
        f"registry size {len(reg)}, expected 1434"


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
            assert h["severity"] == EXPECTED_SEVERITY[pid], (
                f"{pid}: severity {h['severity']}, expected "
                f"{EXPECTED_SEVERITY[pid]}")
            assert h["recipient"] in (
                "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_extra_vuln_shapes_fire():
    hits = hits_for(fx.EXTRA_VULN[
        "bridge_static_gas_limit_struct"],
        "bridge_static_gas_limit")
    assert hits, "literal struct-field gas limit did not fire"
    hits = hits_for(fx.EXTRA_VULN[
        "uups_authorize_upgrade_missing_absent"],
        "uups_authorize_upgrade_missing")
    assert hits, "missing _authorizeUpgrade did not fire"
    assert "Flattened-source caveat" in hits[0]["detail"]


def test_variant_fires_trigger_only_never_candidate():
    for pid, src in fx.VARIANT.items():
        hits = hits_for(src, pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_clean_controls_silent_under_all_twelve():
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


def test_no_cross_talk_between_detectors():
    for pid in IDS:
        for other in IDS:
            if other == pid:
                continue
            hits = hits_for(fx.VULN[pid], other)
            assert hits == [], (
                f"{other}: fired on {pid}'s vulnerable "
                f"fixture: {hits}")
    for var_id, src in fx.VARIANT.items():
        for other in IDS:
            if other == var_id:
                continue
            hits = hits_for(src, other)
            assert hits == [], (
                f"{other}: fired on {var_id}'s variant "
                f"fixture: {hits}")


def test_mint_burn_fires_on_ungated_side_only():
    hits = hits_for(fx.VULN["bridge_mint_burn_gate_asymmetry"],
                    "bridge_mint_burn_gate_asymmetry")
    assert [h["function"] for h in hits] == ["burn"]


def test_diamond_names_colliding_contracts():
    hits = hits_for(fx.VULN["diamond_selector_collision"],
                    "diamond_selector_collision")
    assert hits and "FacetAlpha" in hits[0]["detail"]
    assert "FacetBeta" in hits[0]["detail"]
    assert "transfer(address,uint256)" in hits[0]["detail"]


# --- UUPS _authorizeUpgrade modifier-gate awareness (USDG false positive) ---
# Labeled case: USDG impl 0xfacd...a65f gates upgrades with
# `_authorizeUpgrade(...) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}` -
# empty body, gated by a modifier. The standard OZ pattern must NOT flag.
_PID_UUPS = "uups_authorize_upgrade_missing"


def test_uups_empty_body_but_modifier_gated_not_flagged():
    gated = [
        ("onlyRole(DEFAULT_ADMIN_ROLE)",
         "contract USDG is UUPSUpgradeable {"
         " function _authorizeUpgrade(address n) internal override"
         " onlyRole(DEFAULT_ADMIN_ROLE) {} }"),
        ("onlyOwner",
         "contract T is UUPSUpgradeable {"
         " function _authorizeUpgrade(address a) internal override"
         " onlyOwner {} }"),
        ("custom onlyUpgrader modifier",
         "contract T is UUPSUpgradeable {"
         " function _authorizeUpgrade(address a) internal override"
         " onlyUpgrader {} }"),
    ]
    for label, src in gated:
        assert hits_for(src, _PID_UUPS) == [], \
            f"false positive on modifier-gated UUPS: {label}"


def test_uups_genuinely_ungated_still_flags():
    src = ("contract Bad is UUPSUpgradeable {"
           " function _authorizeUpgrade(address a) internal override {} }")
    assert hits_for(src, _PID_UUPS), \
        "genuinely ungated _authorizeUpgrade must still flag"
