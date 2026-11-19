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


def test_registry_count_1480():
    reg = discover()
    assert len(reg) == 1485, \
        f"registry size {len(reg)}, expected 1485"


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


def test_eof_legacy_bytecode_is_silent():
    # FP elimination (2026-11-18): legacy deployed bytecode is not
    # an EOF container at all - the verifier's "not an EOF container
    # (bad magic/version)" sentinel is nothing to verify, not a
    # failure. Fired on 12/12 BNB + 2/2 crypto.com targets before
    # the fix (every mainnet contract is legacy bytecode).
    hits = hits_for(fx._EOF_LEGACY,
                    "eof_container_code_section_verifier")
    assert hits == [], f"EOF verifier fired on legacy bytecode: {hits}"


def test_z3_construction_only_writes_are_silent():
    # FP elimination (2026-11-18): storage written only in the
    # constructor or a one-time initializer is set at deploy, not
    # attacker-controllable post-deploy. Fired 3x BNB + 8x
    # crypto.com before the fix (poolDeployer / _tokenDescriptor /
    # feeToSetter / initialize writes).
    for src in (fx._Z3_CONSTRUCTOR_ONLY, fx._Z3_INITIALIZER_ONLY):
        hits = hits_for(src, "symbolic_z3_storage_taint_tracer")
        assert hits == [], (
            f"z3 tracer fired on construction-only write: {hits}")


def test_cfg_negated_early_return_guard_is_silent():
    # FP elimination (2026-11-18): a negated guard clause
    # (`if (msg.sender != pendingAdmin || ...) return 1;`) guards
    # everything after it. Venus Unitroller _acceptAdmin shape.
    hits = hits_for(fx._CFG_NEGATED_GUARD,
                    "evm_cfg_basic_block_reconstructor")
    assert hits == [], (
        f"CFG fired behind a negated early-return guard: {hits}")


def test_cfg_signature_gated_entrypoint_is_silent():
    # FP elimination (2026-11-18): a signature-authorized
    # entrypoint (ecrecover over a nonce-bound digest) is gated by
    # the signature, not msg.sender. PancakeSwap V3 NFPM permit
    # shape.
    hits = hits_for(fx._CFG_SIGNATURE_GATE,
                    "evm_cfg_basic_block_reconstructor")
    assert hits == [], (
        f"CFG fired on a signature-gated entrypoint: {hits}")
