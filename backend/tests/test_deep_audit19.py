"""Deep-audit batch-19 detectors: signatures and randomness.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (the three recipient detectors); the FIXED-recipient
variant MUST fire trigger-only at low severity (never a
candidate); every clean control MUST stay silent under ALL four
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk); the batch-12/deep16
fixtures MUST stay silent under all four (no cross-batch
noise); the registry discovers exactly 1434 plugins including
all four.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit16_fixtures as fx16  # noqa: E402
import deep_audit19_fixtures as fx  # noqa: E402
from app.plugins.deep_audit19 import SPECS, SPECS_BY_ID, \
    analyze_deep19_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["ecrecover_no_malleability_guard",
                 "signature_replay_no_nonce",
                 "permit_no_domain_separator"]


def hits_for(src, pid):
    return analyze_deep19_source(src, SPECS_BY_ID[pid])


def test_four_plugins_registered():
    assert len(IDS) == 4
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1434():
    reg = discover()
    assert len(reg) == 1434, \
        f"registry size {len(reg)}, expected 1434"


def test_vuln_fires_candidate_with_evidence():
    for pid in RECIPIENT_IDS:
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


def test_randomness_fires_without_candidate():
    pid = "weak_onchain_randomness"
    hits = hits_for(fx.VULN[pid], pid)
    assert hits, f"{pid}: vulnerable fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    for h in hits:
        assert h["code"], f"{pid}: no code evidence"
        assert h["detail"], f"{pid}: no detail"
        assert h["function"] == "drawWinner"
        assert h["gate_analysis"], \
            f"{pid}: no gate analysis (validator-ready bar)"
        assert h["severity"] == "medium"
        assert h.get("report_class") is None, (
            f"{pid}: randomness is not a value move, must not "
            f"carry a candidate classification")


def test_variant_fires_trigger_only_never_candidate():
    for pid in fx.VARIANT:
        hits = hits_for(fx.VARIANT[pid], pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_clean_controls_silent_under_all_four():
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


def test_batch16_fixtures_silent_under_all_four():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-19 detector.
    for group in (fx16.VULN, fx16.CLEAN, fx16.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-16 fixture {fid}: "
                    f"{hits}")


def test_malleability_names_the_claim_function():
    hits = hits_for(fx.VULN["ecrecover_no_malleability_guard"],
                    "ecrecover_no_malleability_guard")
    assert [h["function"] for h in hits] == ["claim"]
    assert "ecrecover" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_malleability_s_guard_silent():
    hits = hits_for(
        fx.CLEAN["ecrecover_no_malleability_guard"],
        "ecrecover_no_malleability_guard")
    assert hits == []


def test_replay_names_the_claim_function():
    hits = hits_for(fx.VULN["signature_replay_no_nonce"],
                    "signature_replay_no_nonce")
    assert [h["function"] for h in hits] == ["claim"]
    assert "nonce" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_replay_nonce_consumed_silent():
    hits = hits_for(
        fx.CLEAN["signature_replay_no_nonce"],
        "signature_replay_no_nonce")
    assert hits == []


def test_permit_names_the_permit_function():
    hits = hits_for(fx.VULN["permit_no_domain_separator"],
                    "permit_no_domain_separator")
    assert [h["function"] for h in hits] == ["permit"]
    assert "DOMAIN_SEPARATOR" in hits[0]["detail"]


def test_permit_domain_separator_silent():
    hits = hits_for(
        fx.CLEAN["permit_no_domain_separator"],
        "permit_no_domain_separator")
    assert hits == []


def test_randomness_names_the_draw_function():
    hits = hits_for(fx.VULN["weak_onchain_randomness"],
                    "weak_onchain_randomness")
    assert [h["function"] for h in hits] == ["drawWinner"]
    assert "block.timestamp" in hits[0]["detail"]


def test_randomness_vrf_silent():
    hits = hits_for(
        fx.CLEAN["weak_onchain_randomness"],
        "weak_onchain_randomness")
    assert hits == []


def test_randomness_deadline_only_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["timestamp_deadline_only"],
        "weak_onchain_randomness")
    assert hits == []


# Live-run FP pins (2026-11-12 corpus, 1,396 sources): each shape
# fired on a real contract and was hand-read as a false positive.
def test_malleability_cast_wrapped_s_guard_silent():
    # Axelar permit: `if (uint256(s) > HALF) revert InvalidS();`
    hits = hits_for(
        fx.EXTRA_CLEAN["cast_wrapped_s_guard"],
        "ecrecover_no_malleability_guard")
    assert hits == []


def test_malleability_ecdsa_recover_call_silent():
    # BoldToken permit: ECDSA.recover with no import line and no
    # s bound in the function — the OZ call enforces the bound.
    hits = hits_for(
        fx.EXTRA_CLEAN["ecdsa_recover_no_import"],
        "ecrecover_no_malleability_guard")
    assert hits == []


def test_replay_nonce_writeback_silent():
    # dYdX permit: `_nonces[owner] = currentValidNonce.add(1)`.
    hits = hits_for(
        fx.EXTRA_CLEAN["nonce_writeback_add"],
        "signature_replay_no_nonce")
    assert hits == []


def test_replay_underscore_nonces_silent():
    # WrappedLYX mint: `_nonces[bridgeNonce] = true` mark.
    hits = hits_for(
        fx.EXTRA_CLEAN["underscore_nonces_mark"],
        "signature_replay_no_nonce")
    assert hits == []


def test_permit_eip712_domain_separator_silent():
    # Dollar permit: hashEIP712Message(EIP712_DOMAIN_SEPARATOR).
    hits = hits_for(
        fx.EXTRA_CLEAN["eip712_domain_separator_const"],
        "permit_no_domain_separator")
    assert hits == []


def test_malleability_cast_wrapped_s_guard_underscore_silent():
    # VerseToken permit: `if (uint256(_s) > HALF) revert ...`.
    hits = hits_for(
        fx.EXTRA_CLEAN["cast_wrapped_s_guard_underscore"],
        "ecrecover_no_malleability_guard")
    assert hits == []
