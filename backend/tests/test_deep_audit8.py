"""Deep-audit batch-8 detectors (reentrancy + crypto/signature).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate at the spec severity; the FIXED-recipient variant
MUST fire trigger-only at low severity (never a candidate);
every clean control MUST stay silent under ALL fourteen
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk); the registry discovers
exactly 1361 plugins including all fourteen.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit8_fixtures as fx  # noqa: E402
from app.plugins.deep_audit8 import SPECS, SPECS_BY_ID, \
    analyze_deep8_source, KECCAK_OK  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]

EXPECTED_SEVERITY = {
    "cross_function_guard_sibling": "high",
    "reentrancy_guard_uninitialized": "medium",
    "eth_send_stipend_brick": "low",
    "fallback_state_write_extended": "low",
    "token_callback_caller_unverified": "high",
    "multicall_value_reuse": "high",
    "push_payment_revert_dos": "medium",
    "ecdsa_recover_zero_unchecked": "high",
    "raw_ecrecover_s_unbounded": "medium",
    "merkle_leaf_single_hash": "medium",
    "hardcoded_hash_constant_mismatch": "high",
    "weak_randomness_value_outcome": "high",
    "empty_signature_accepted": "high",
    "packed_encoding_collision": "medium",
}


def hits_for(src, pid):
    return analyze_deep8_source(src, SPECS_BY_ID[pid])


def test_fourteen_plugins_registered():
    assert KECCAK_OK, "keccak self-test failed: CRY-005 dropped"
    assert len(IDS) == 14
    assert set(EXPECTED_SEVERITY) == set(IDS)
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_800():
    reg = discover()
    assert len(reg) == 1361, \
        f"registry size {len(reg)}, expected 1361"


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
    for pid, src in fx.EXTRA_VULN.items():
        hits = hits_for(src, pid)
        assert hits, f"{pid}: extra vulnerable shape did not fire"
        assert all(h["report_class"] == "candidate" for h in hits)


def test_variant_fires_trigger_only_never_candidate():
    for pid, src in fx.VARIANT.items():
        hits = hits_for(src, pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_clean_controls_silent_under_all_fourteen():
    for clean_id, src in fx.CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {clean_id} clean "
                f"control: {hits}")


def test_no_cross_talk_between_detectors():
    for pid in IDS:
        for other in IDS:
            if other == pid:
                continue
            hits = hits_for(fx.VULN[pid], other)
            assert hits == [], (
                f"{other}: fired on {pid}'s vulnerable "
                f"fixture: {hits}")
            if pid in fx.VARIANT:
                hits = hits_for(fx.VARIANT[pid], other)
                assert hits == [], (
                    f"{other}: fired on {pid}'s variant "
                    f"fixture: {hits}")
            if pid in fx.EXTRA_VULN:
                hits = hits_for(fx.EXTRA_VULN[pid], other)
                assert hits == [], (
                    f"{other}: fired on {pid}'s extra "
                    f"fixture: {hits}")
