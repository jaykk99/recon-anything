"""Business-logic invariant detectors (manual bug-hunter
methodology, 2026-11-11).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the deep-audit batch-10 and batch-11 fixtures
MUST stay silent under all five (no cross-batch noise); the
registry discovers exactly 1437 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit10_fixtures as fx10  # noqa: E402
import deep_audit11_fixtures as fx11  # noqa: E402
from business_logic_fixtures import FIXTURES  # noqa: E402
from app.plugins.business_logic import SPECS, SPECS_BY_ID, \
    analyze_business_logic_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]

VULN = {pid: FIXTURES[pid]["vuln"] for pid in IDS}
VARIANT = {pid: FIXTURES[pid]["variant"] for pid in IDS}
CLEAN = {pid: FIXTURES[pid]["clean"] for pid in IDS}


def hits_for(src, pid):
    return analyze_business_logic_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1437():
    reg = discover()
    assert len(reg) == 1437, \
        f"registry size {len(reg)}, expected 1437"


def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
        hits = hits_for(VULN[pid], pid)
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


def test_reward_shape_a_fires_candidate():
    hits = hits_for(FIXTURES["reward_distribution_manipulation"]
                    ["vuln_a"],
                    "reward_distribution_manipulation")
    assert hits, "reward shape (a): balance-derived accumulator " \
        "did not fire"
    assert [h["function"] for h in hits] == ["stake"]
    assert hits[0]["report_class"] == "candidate"
    assert hits[0]["recipient"] == "CALLER"


def test_variant_fires_trigger_only_never_candidate():
    for pid in IDS:
        hits = hits_for(VARIANT[pid], pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_clean_controls_silent_under_all_five():
    for clean_id, src in CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {clean_id} clean "
                f"control: {hits}")


def test_no_cross_talk_between_vuln_fixtures():
    for vuln_id, src in VULN.items():
        for pid in IDS:
            if pid == vuln_id:
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_no_cross_talk_from_variant_fixtures():
    for var_id, src in VARIANT.items():
        for pid in IDS:
            if pid == var_id:
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {var_id} variant: "
                f"{hits}")


def test_prior_batches_silent_under_all_five():
    # No cross-batch noise: the deep-audit batch-10 and
    # batch-11 fixtures must not fire under any business-logic
    # detector.
    for mod in (fx10, fx11):
        for group in (mod.VULN, mod.CLEAN, mod.VARIANT):
            for fid, src in group.items():
                for pid in IDS:
                    hits = hits_for(src, pid)
                    assert hits == [], (
                        f"{pid}: fired on prior-batch fixture "
                        f"{fid}: {hits}")
        for fid, src in getattr(mod, "EXTRA_CLEAN", {}).items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on prior-batch extra clean "
                    f"{fid}: {hits}")


def test_rounding_names_the_deposit_function():
    hits = hits_for(VULN["rounding_iterated_drain"],
                    "rounding_iterated_drain")
    assert [h["function"] for h in hits] == ["deposit"]
    assert "totalSupply" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_reward_names_the_stake_function():
    hits = hits_for(VULN["reward_distribution_manipulation"],
                    "reward_distribution_manipulation")
    assert [h["function"] for h in hits] == ["stake"]
    assert "reward" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "CALLER"


def test_flash_names_the_callback_function():
    hits = hits_for(
        VULN["flashloan_same_block_state_inconsistency"],
        "flashloan_same_block_state_inconsistency")
    assert [h["function"] for h in hits] == ["onFlashLoan"]
    assert "exchange rate" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_order_names_the_borrow_function():
    hits = hits_for(VULN["multistep_state_order_violation"],
                    "multistep_state_order_violation")
    assert [h["function"] for h in hits] == ["borrow"]
    assert "borrows" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_oracle_names_the_borrow_function():
    hits = hits_for(VULN["oracle_trust_assumption_break"],
                    "oracle_trust_assumption_break")
    assert [h["function"] for h in hits] == ["borrow"]
    assert "latestRoundData" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"
