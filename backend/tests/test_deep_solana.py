"""Deep Solana detectors (feat/deep-lowlevel-50).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; every clean control MUST stay silent under ALL six
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_solana_fixtures as fx  # noqa: E402
from app.plugins.deep_solana import SPECS, SPECS_BY_ID, \
    analyze_deep_solana_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def to_src(fixture_id, fixture):
    """Serialize a fixture dict into the data string the analyzer
    takes. Serialization follows the FIXTURE's own shape, not the
    analyzer under test (cross-talk runs feed one fixture to every
    analyzer)."""
    if fixture_id == "solana_bpf_elf_syscalls_disassembler":
        return json.dumps({"elf_base64": fixture["solana_elf"]})
    if fixture_id == "token2022_transfer_hook_program_resolver":
        return json.dumps(
            {"account_data_base64": fixture["solana_account"]})
    if fixture_id == "alt_address_lookup_table_resolver":
        return json.dumps(
            {"table_data_base64": fixture["solana_account"]})
    if fixture_id == "jito_bundle_tip_auction_correlator":
        return fixture["solana_bundle"]
    return fixture["solana_source"]


def hits_for(fixture_id, fixture, pid):
    return analyze_deep_solana_source(to_src(fixture_id, fixture),
                                      SPECS_BY_ID[pid])


def test_six_plugins_registered():
    assert len(IDS) == 6
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1424():
    reg = discover()
    assert len(reg) == 1424, \
        f"registry size {len(reg)}, expected 1424"


def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
        hits = hits_for(pid, fx.VULN[pid], pid)
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


def test_clean_controls_silent_under_all_six():
    for clean_id, fixture in fx.CLEAN.items():
        for pid in IDS:
            hits = hits_for(clean_id, fixture, pid)
            assert hits == [], (
                f"{pid} fired on clean control {clean_id}: {hits}")


def test_no_cross_talk_between_plugins():
    for vuln_id, fixture in fx.VULN.items():
        for pid in IDS:
            if pid == vuln_id:
                continue
            hits = hits_for(vuln_id, fixture, pid)
            assert hits == [], (
                f"{pid} fired on {vuln_id}'s fixture: {hits}")
