"""Deep-audit batch-5 detectors (ERC + access slices, 2026-11-04).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate at the spec severity; the FIXED-recipient variants
MUST fire trigger-only at low severity (never a candidate);
every clean control MUST stay silent under ALL twelve
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk); the registry discovers
exactly 1051 plugins including all twelve.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit5_fixtures as fx  # noqa: E402
from app.plugins.deep_audit5 import SPECS, SPECS_BY_ID, \
    analyze_deep5_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]

EXPECTED_SEVERITY = {
    "erc20_missing_return_guard": "medium",
    "erc721_mint_without_receiver_check": "medium",
    "erc1155_batch_receiver_missing": "medium",
    "eip712_separator_unbound": "high",
    "erc2771_msg_sender_unbound": "high",
    "eip1271_magic_value_unchecked": "medium",
    "two_step_ownership_missing": "low",
    "default_admin_grant_exposed": "medium",
    "renounce_role_last_admin": "low",
    "pause_coverage_missing": "medium",
    "signature_nonce_unconsumed": "high",
    "multisig_threshold_setter_unsafe": "medium",
}


def hits_for(src, pid):
    return analyze_deep5_source(src, SPECS_BY_ID[pid])


def test_twelve_plugins_registered():
    assert len(IDS) == 12
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_798():
    reg = discover()
    assert len(reg) == 1051, \
        f"registry size {len(reg)}, expected 1051"


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


def test_vuln_extra_shapes_fire_candidate():
    for pid, src in fx.VULN_EXTRA.items():
        hits = hits_for(src, pid)
        assert hits, f"{pid}: extra vulnerable shape did not fire"
        for h in hits:
            assert h["report_class"] == "candidate"
            assert h["severity"] == EXPECTED_SEVERITY[pid]


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


def test_no_cross_talk_between_detectors():
    for pid in IDS:
        for other in IDS:
            if other == pid:
                continue
            hits = hits_for(fx.VULN[pid], other)
            assert hits == [], (
                f"{other}: fired on {pid}'s vulnerable "
                f"fixture: {hits}")
    for pid, src in fx.VARIANT.items():
        for other in IDS:
            if other == pid:
                continue
            hits = hits_for(src, other)
            assert hits == [], (
                f"{other}: fired on {pid}'s variant "
                f"fixture: {hits}")
    for pid, src in fx.VULN_EXTRA.items():
        for other in IDS:
            if other == pid:
                continue
            hits = hits_for(src, other)
            assert hits == [], (
                f"{other}: fired on {pid}'s extra vulnerable "
                f"fixture: {hits}")


def test_separator_deploy_bound_is_trigger_only():
    # FP elimination (2026-11-05): a separator whose
    # construction carries a chain term is bound to the
    # deployment chain (Dai / Uni / UniswapV2Pair shape) -
    # it must fire, but never as a candidate.
    for pid, src in fx.DEPLOY_BOUND.items():
        hits = hits_for(src, pid)
        assert hits, f"{pid}: deploy-bound shape went silent"
        for h in hits:
            assert h["report_class"] == "trigger_only"
            assert h["severity"] == "low"


def test_nonce_helper_consumption_stays_silent():
    # OZ ERC20Permit shape: the verify function reads the
    # nonce through _useNonce(); the state write lives in
    # the helper. Must not fire signature_nonce_unconsumed.
    src = """
contract OzPermitShape {
    mapping(address => uint256) private _nonces;
    function _useNonce(address owner) internal returns (uint256) {
        return _nonces[owner]++;
    }
    function nonces(address owner) public view returns (uint256) {
        return _nonces[owner];
    }
    function permit(address owner, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 digest = keccak256(abi.encodePacked(owner, _useNonce(owner)));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad signature");
    }
}
"""
    assert hits_for(src, "signature_nonce_unconsumed") == []
