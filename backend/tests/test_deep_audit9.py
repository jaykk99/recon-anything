"""Deep-audit batch-9 detectors (system architecture slices,
2026-11-04).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, at the spec
severity, classified honestly for these config/quality
classes - report_class "trigger_only" with recipient "NONE"
(no stranger value destination exists in any of the eight
classes; candidate would be dishonest); every clean control
MUST stay silent under ALL eight detectors; every other
plugin's vulnerable fixture MUST stay silent under this one
(no cross-talk); the registry discovers exactly 1351 plugins
including all eight.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit9_fixtures as fx  # noqa: E402
from app.plugins.deep_audit9 import SPECS, SPECS_BY_ID, \
    analyze_deep9_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]

EXPECTED_SEVERITY = {
    "growable_array_loop_no_pagination": "low",
    "block_number_as_time": "low",
    "hardcoded_zero_role_address": "low",
    "state_change_without_event": "low",
    "private_sensitive_state_var": "medium",
    "assembly_fmp_literal_corruption": "medium",
    "assembly_returndatacopy_unbounded": "medium",
    "coinbase_decision_input": "low",
}


def hits_for(src, pid):
    return analyze_deep9_source(src, SPECS_BY_ID[pid])


def test_eight_plugins_registered():
    assert len(IDS) == 8
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_794():
    reg = discover()
    assert len(reg) == 1351, \
        f"registry size {len(reg)}, expected 1351"


def test_vuln_fires_trigger_only_with_evidence():
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
            assert h["report_class"] == "trigger_only", (
                f"{pid}: these classes have no stranger value "
                f"destination, got {h['report_class']}")
            assert h["recipient"] in (
                "NONE", "FIXED", "HOLDER-SELF"), h["recipient"]
            assert h["severity"] == EXPECTED_SEVERITY[pid], (
                f"{pid}: severity {h['severity']}, expected "
                f"{EXPECTED_SEVERITY[pid]}")


def test_no_event_cap_three_per_contract():
    hits = hits_for(fx.VULN["state_change_without_event"],
                    "state_change_without_event")
    assert len(hits) == 3, \
        f"cap 3 per contract, got {len(hits)}"


def test_clean_controls_silent_under_all_eight():
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
