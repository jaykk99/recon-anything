"""Deep L2 / DA detectors (feat/deep-lowlevel-50).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; every clean control MUST stay silent under ALL three
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_l2_fixtures as fx  # noqa: E402
from app.plugins.deep_l2 import SPECS, SPECS_BY_ID, \
    analyze_deep_l2_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep_l2_source(src, SPECS_BY_ID[pid])


def test_three_plugins_registered():
    assert len(IDS) == 3
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1434():
    reg = discover()
    assert len(reg) == 1434, \
        f"registry size {len(reg)}, expected 1434"


def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["detail"], f"{pid}: no detail"
            assert h["gate_analysis"], \
                f"{pid}: no gate analysis (validator-ready bar)"
            assert h["severity"] in ("low", "medium", "high"), \
                f"{pid}: bad severity {h['severity']}"
            assert h["report_class"] == "candidate", (
                f"{pid}: vuln fixture must be a candidate, got "
                f"{h['report_class']}")


def test_clean_controls_silent_under_all_three():
    for clean_id, src in fx.CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid} fired on clean control {clean_id}: {hits}")


def test_no_cross_talk_between_plugins():
    for vuln_id, src in fx.VULN.items():
        for pid in IDS:
            if pid == vuln_id:
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid} fired on {vuln_id}'s fixture: {hits}")
