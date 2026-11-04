"""Deep-audit batch-3 detectors (AI dev, 2026-11-04).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the registry discovers exactly 800 plugins
including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit3_fixtures as fx  # noqa: E402
from app.plugins.deep_audit3 import SPECS, SPECS_BY_ID, \
    analyze_deep3_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep3_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_786():
    reg = discover()
    assert len(reg) == 800, \
        f"registry size {len(reg)}, expected 800"


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
            assert h["severity"] == "high"
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


def test_clean_controls_silent_under_all_five():
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


def test_transient_names_the_deliver_function():
    hits = hits_for(fx.VULN["transient_latch_unconsumed"],
                    "transient_latch_unconsumed")
    assert [h["function"] for h in hits] == ["deliver"]
    assert "tload" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_transient_hash_bound_latch_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["transient_latch_unconsumed_hash_bound"],
        "transient_latch_unconsumed")
    assert hits == []


def test_v4_names_the_after_swap_hook():
    hits = hits_for(fx.VULN["v4_hook_shared_delta_take_pair"],
                    "v4_hook_shared_delta_take_pair")
    assert [h["function"] for h in hits] == ["afterSwap"]
    assert "take" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_v4_delta_isolation_clean_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["v4_hook_shared_delta_take_pair_delta"],
        "v4_hook_shared_delta_take_pair")
    assert hits == []


def test_inverted_names_the_borrow_function():
    hits = hits_for(fx.VULN["inverted_division_zero_collapse"],
                    "inverted_division_zero_collapse")
    assert [h["function"] for h in hits] == ["borrow"]
    assert "rate" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_share_names_the_cancel_function():
    hits = hits_for(fx.VULN["share_transfer_cancel_desync"],
                    "share_transfer_cancel_desync")
    assert [h["function"] for h in hits] == ["cancel"]
    assert "entitlements" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_eip712_names_the_claim_batch_function():
    hits = hits_for(fx.VULN["eip712_digest_unbound_to_payload"],
                    "eip712_digest_unbound_to_payload")
    assert [h["function"] for h in hits] == ["claimBatch"]
    assert "FeeApproval" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"
