"""Deep-audit batch-4 detectors (scaffold port, 2026-11-04).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate at the spec severity; the FIXED-recipient variant
MUST fire trigger-only at low severity (never a candidate);
every clean control MUST stay silent under ALL three
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk); the registry discovers
exactly 853 plugins including all three.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit4_fixtures as fx  # noqa: E402
from app.plugins.deep_audit4 import SPECS, SPECS_BY_ID, \
    analyze_deep4_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]

EXPECTED_SEVERITY = {
    "bridge_proof_length_unvalidated": "high",
    "bridge_root_zero_assertion": "medium",
    "spot_price_own_balance": "high",
}


def hits_for(src, pid):
    return analyze_deep4_source(src, SPECS_BY_ID[pid])


def test_three_plugins_registered():
    assert len(IDS) == 3
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_794():
    reg = discover()
    assert len(reg) == 860, \
        f"registry size {len(reg)}, expected 860"


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


def test_variant_fires_trigger_only_never_candidate():
    for pid in IDS:
        hits = hits_for(fx.VARIANT[pid], pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_clean_controls_silent_under_all_three():
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
            hits = hits_for(fx.VARIANT[pid], other)
            assert hits == [], (
                f"{other}: fired on {pid}'s variant "
                f"fixture: {hits}")
