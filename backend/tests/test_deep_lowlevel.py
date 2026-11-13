"""Deep low-level EVM detectors (feat/deep-lowlevel-50).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (except the ERC-4337 paymaster simulator, which is
simulation-only and MUST fire unverified with proof
simulation_only); every clean control MUST stay silent under ALL
twelve detectors; every other plugin's vulnerable fixture MUST
stay silent under this one (no cross-talk), with ONE documented
exception: the Safe fallback-handler write is also an ungated
param-driven state write, so the Z3 tracer correctly fires on
the Safe vuln fixture too.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_lowlevel_fixtures as fx  # noqa: E402
from app.plugins.deep_lowlevel import SPECS, SPECS_BY_ID, \
    analyze_deep_lowlevel_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]

# (vuln fixture id, other detector id) pairs where a second
# finding is correct, not noise:
# - the Safe vuln writes fallbackHandler from an ungated caller
#   parameter, which the Z3 storage-taint tracer proves is
#   arbitrary-value control;
# - the Z3 vuln's ungated owner write is also a privilege-changing
#   state write in an unguarded block, which the CFG reconstructor
#   correctly flags.
ALLOWED_OVERLAP = {
    ("gnosis_safe_fallback_handler_mutator_check",
     "symbolic_z3_storage_taint_tracer"),
    ("symbolic_z3_storage_taint_tracer",
     "evm_cfg_basic_block_reconstructor"),
}


def hits_for(src, pid):
    return analyze_deep_lowlevel_source(src, SPECS_BY_ID[pid])


def test_twelve_plugins_registered():
    assert len(IDS) == 12
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1433():
    reg = discover()
    assert len(reg) == 1433, \
        f"registry size {len(reg)}, expected 1433"


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
            if pid == "erc4337_entrypoint_paymaster_simulator":
                assert h["report_class"] == "unverified", (
                    f"{pid}: paymaster simulation must be unverified, "
                    f"got {h['report_class']}")
                assert h.get("proof") == "simulation_only", (
                    f"{pid}: paymaster finding must be simulation_only")
            else:
                assert h["report_class"] == "candidate", (
                    f"{pid}: vuln fixture must be a candidate, got "
                    f"{h['report_class']}")


def test_variant_else_branch_fires_candidate():
    hits = hits_for(fx.VARIANT["evm_cfg_basic_block_reconstructor"],
                    "evm_cfg_basic_block_reconstructor")
    assert hits, "CFG else-branch variant did not fire"
    assert all(h["kind"] == "evm_cfg_basic_block_reconstructor"
               for h in hits)
    assert all(h["report_class"] == "candidate" for h in hits)


def test_clean_controls_silent_under_all_twelve():
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
            if (vuln_id, pid) in ALLOWED_OVERLAP:
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid} fired on {vuln_id}'s fixture: {hits}")
