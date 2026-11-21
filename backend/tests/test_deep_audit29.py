"""Deep-audit batch-29 detectors: a relayer executing arbitrary
calls with its trusted identity, a Uniswap v4 hook callback
paying out with no pool-manager check, a swap helper routing
through a caller-supplied pool key with no allowlist, a
governance execute with a zero quorum, and a batch reward
assignment that overwrites duplicates while the total counts
them all.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (the four recipient detectors); the duplicate-reward
detector fires trigger-only at medium severity with recipient
HOLDER-SELF (user-harm / insolvency class, NOT
stranger-receivable - the duplicated player loses their
earlier reward). The FIXED-recipient variant (owner-gated
relay / hook / helper / execute) MUST fire trigger-only at
low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-27 and batch-28 fixtures MUST stay
silent under all five (no cross-batch noise); the five new
VULN fixtures MUST stay silent under the relevant neighbours
(settlement_swap_executes_caller_target_spends_approvals,
multicall_arbitrary_delegatecall,
access_control_arbitrary_call_injection,
bridge_replay_unbound_digest, hook_cei_reentrancy,
v4_hook_shared_delta_take_pair,
token_sell_hook_burns_pair_reserves_sync,
governance_quorum_calculation_flaw,
governance_early_execution_race, timelock_delay_bypass,
gamefi_state_desync_reward_claim, recipient_unbacked_claim,
share_transfer_cancel_desync), EXCEPT the documented
co-fire: recipient_unbacked_claim fires on the
relay_arbitrary_call_trusted_identity fixture by design - a
claim-named function moving value through a generic call
with no entitlement backing it is the same hole from the
claim angle; the new detector adds the trusted-identity
dimension the claim detector cannot express (the call
executes as the relayer). That co-fire is asserted
explicitly, not pretended silent. The registry discovers
exactly 1495 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit27_fixtures as fx27  # noqa: E402
import deep_audit28_fixtures as fx28  # noqa: E402
import deep_audit29_fixtures as fx  # noqa: E402
from app.plugins.bsc_access import SPECS as ACCESS_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_gamefi import SPECS as GAME_SPECS  # noqa: E402
from app.plugins.bsc_governance import SPECS as GOV_SPECS  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit24 import SPECS_BY_ID as SPECS24, \
    analyze_deep24_source  # noqa: E402
from app.plugins.deep_audit25 import SPECS_BY_ID as SPECS25, \
    analyze_deep25_source  # noqa: E402
from app.plugins.deep_audit26 import SPECS_BY_ID as SPECS26, \
    analyze_deep26_source  # noqa: E402
from app.plugins.deep_audit29 import SPECS, SPECS_BY_ID, \
    analyze_deep29_source  # noqa: E402
from app.plugins.deep_audit3 import SPECS_BY_ID as SPECS3, \
    analyze_deep3_source  # noqa: E402
from app.plugins.recipient_first import \
    analyze_recipient_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["relay_arbitrary_call_trusted_identity",
                 "v4_hook_callback_no_poolmanager_check",
                 "swap_helper_caller_supplied_pool_hook_no_allowlist",
                 "governance_zero_quorum_executes"]
ACCESS_BY_ID = {s.id: s for s in ACCESS_SPECS}
GOV_BY_ID = {s.id: s for s in GOV_SPECS}
GAME_BY_ID = {s.id: s for s in GAME_SPECS}


def hits_for(src, pid):
    return analyze_deep29_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1495():
    reg = discover()
    assert len(reg) == 1495, \
        f"registry size {len(reg)}, expected 1495"


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
            if pid == "v4_hook_callback_no_poolmanager_check":
                assert h["recipient"] == "CALLER-SUPPLIED"
            else:
                assert h["recipient"] == "CALLER", (
                    f"{pid}: expected CALLER, got "
                    f"{h['recipient']}")


def test_duplicate_reward_fires_trigger_only_medium():
    pid = "duplicate_reward_overwrite_desync"
    hits = hits_for(fx.VULN[pid], pid)
    assert hits, f"{pid}: vulnerable fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    for h in hits:
        assert h["code"], f"{pid}: no code evidence"
        assert h["detail"], f"{pid}: no detail"
        assert h["function"] == "constructor"
        assert h["gate_analysis"], \
            f"{pid}: no gate analysis (validator-ready bar)"
        assert h["severity"] == "medium"
        assert h["recipient"] == "HOLDER-SELF", (
            f"{pid}: the duplicated player loses their own "
            f"earlier reward - recipient must be HOLDER-SELF, "
            f"got {h['recipient']}")
        assert h.get("report_class") == "trigger_only", (
            f"{pid}: user-harm / insolvency class, NOT "
            f"stranger-receivable - must be trigger-only, got "
            f"{h.get('report_class')}")
        assert "NOT stranger-receivable" in h["detail"] or \
            "not a stranger-receivable" in h["detail"], (
            f"{pid}: the finding must label itself honestly "
            f"as not stranger-receivable")


def test_variant_fires_trigger_only_never_candidate():
    for pid in fx.VARIANT:
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


def test_batch27_fixtures_silent_under_all_five():
    # No cross-batch noise: the sibling quota batch-27 fixtures
    # (landed on master mid-run for batch 28) must not fire
    # under any batch-29 detector either.
    for group in (fx27.VULN, fx27.CLEAN, fx27.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-27 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx27.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-27 extra clean "
                f"{clean_id}: {hits}")


def test_batch28_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-29 detector.
    for group in (fx28.VULN, fx28.CLEAN, fx28.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-28 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx28.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-28 extra clean "
                f"{clean_id}: {hits}")
    for pid in IDS:
        hits = hits_for(fx28.VULN_TERNARY, pid)
        assert hits == [], (
            f"{pid}: fired on batch-28 ternary fixture: {hits}")


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors. DOCUMENTED EXCEPTION:
    # recipient_unbacked_claim fires on the relay fixture by
    # design (a claim-named function moving value through a
    # generic call with no entitlement backing it - the same
    # hole from the claim angle; the new detector adds the
    # trusted-identity dimension) - asserted in
    # test_relay_unbacked_claim_cofire below, and excluded
    # from the silence assertion here.
    neighbours = {
        "relay_arbitrary_call_trusted_identity": [
            ("settlement_swap_executes_caller_target_spends_approvals",
             lambda src, spec: analyze_deep26_source(src, spec)),
            ("multicall_arbitrary_delegatecall",
             lambda src, spec: analyze_deep25_source(src, spec)),
            ("access_control_arbitrary_call_injection",
             lambda src, spec: analyze_bsc_source(src, spec)),
            ("bridge_replay_unbound_digest",
             lambda src, spec: analyze_deep2_source(src, spec)),
        ],
        "v4_hook_callback_no_poolmanager_check": [
            ("hook_cei_reentrancy",
             lambda src, spec: analyze_deep2_source(src, spec)),
            ("v4_hook_shared_delta_take_pair",
             lambda src, spec: analyze_deep3_source(src, spec)),
            ("token_sell_hook_burns_pair_reserves_sync",
             lambda src, spec: analyze_deep24_source(src, spec)),
        ],
        "swap_helper_caller_supplied_pool_hook_no_allowlist": [
            ("settlement_swap_executes_caller_target_spends_approvals",
             lambda src, spec: analyze_deep26_source(src, spec)),
            ("v4_hook_shared_delta_take_pair",
             lambda src, spec: analyze_deep3_source(src, spec)),
        ],
        "governance_zero_quorum_executes": [
            ("governance_quorum_calculation_flaw",
             lambda src, spec: analyze_bsc_source(src, spec)),
            ("governance_early_execution_race",
             lambda src, spec: analyze_bsc_source(src, spec)),
            ("timelock_delay_bypass",
             lambda src, spec: analyze_bsc_source(src, spec)),
        ],
        "duplicate_reward_overwrite_desync": [
            ("gamefi_state_desync_reward_claim",
             lambda src, spec: analyze_bsc_source(src, spec)),
            ("recipient_unbacked_claim",
             lambda src, spec_id:
             analyze_recipient_source(src, spec_id)),
            ("share_transfer_cancel_desync",
             lambda src, spec: analyze_deep3_source(src, spec)),
        ],
    }
    specs = {}
    specs.update(SPECS2)
    specs.update(SPECS3)
    specs.update(SPECS24)
    specs.update(SPECS25)
    specs.update(SPECS26)
    specs.update(ACCESS_BY_ID)
    specs.update(GOV_BY_ID)
    specs.update(GAME_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours[vuln_id]:
            spec = specs.get(pid, pid)
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_relay_unbacked_claim_cofire():
    # DOCUMENTED CO-FIRE (see the fixtures module docstring):
    # recipient_unbacked_claim fires on the relay fixture
    # because claimMessage moves value through a generic call
    # with no entitlement backing it - the same hole from the
    # claim angle. The new detector adds the trusted-identity
    # dimension the claim detector cannot express (the call
    # executes as the relayer). It must NOT fire on the other
    # four vuln fixtures.
    src = fx.VULN["relay_arbitrary_call_trusted_identity"]
    hits = analyze_recipient_source(
        src, "recipient_unbacked_claim")
    assert hits, "unbacked claim must co-fire on the relay " \
        "fixture (generic call with no entitlement backing it)"
    assert all(h["kind"] == "recipient_unbacked_claim"
               for h in hits)
    for vuln_id, src2 in fx.VULN.items():
        if vuln_id == "relay_arbitrary_call_trusted_identity":
            continue
        hits = analyze_recipient_source(
            src2, "recipient_unbacked_claim")
        assert hits == [], (
            f"recipient_unbacked_claim fired on the "
            f"{vuln_id} fixture: {hits}")


def test_relay_names_the_relay_function():
    hits = hits_for(
        fx.VULN["relay_arbitrary_call_trusted_identity"],
        "relay_arbitrary_call_trusted_identity")
    assert [h["function"] for h in hits] == ["claimMessage"]
    assert "target" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_relay_allowlist_silent():
    hits = hits_for(
        fx.CLEAN["relay_arbitrary_call_trusted_identity"],
        "relay_arbitrary_call_trusted_identity")
    assert hits == []


def test_relay_digest_verified_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["relay_digest_verified"],
        "relay_arbitrary_call_trusted_identity")
    assert hits == []


def test_relay_fixed_target_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["relay_fixed_target"],
        "relay_arbitrary_call_trusted_identity")
    assert hits == []


def test_hook_names_the_callback():
    hits = hits_for(
        fx.VULN["v4_hook_callback_no_poolmanager_check"],
        "v4_hook_callback_no_poolmanager_check")
    assert [h["function"] for h in hits] == ["afterSwap"]
    assert "poolManager" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_hook_manager_check_silent():
    hits = hits_for(
        fx.CLEAN["v4_hook_callback_no_poolmanager_check"],
        "v4_hook_callback_no_poolmanager_check")
    assert hits == []


def test_hook_only_pool_manager_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["hook_only_pool_manager"],
        "v4_hook_callback_no_poolmanager_check")
    assert hits == []


def test_swap_helper_names_the_helper():
    hits = hits_for(
        fx.VULN["swap_helper_caller_supplied_pool_hook_no_allowlist"],
        "swap_helper_caller_supplied_pool_hook_no_allowlist")
    assert [h["function"] for h in hits] == ["executeSwap"]
    assert "key" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_swap_helper_allowlist_silent():
    hits = hits_for(
        fx.CLEAN["swap_helper_caller_supplied_pool_hook_no_allowlist"],
        "swap_helper_caller_supplied_pool_hook_no_allowlist")
    assert hits == []


def test_swap_helper_stored_key_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["swap_stored_key"],
        "swap_helper_caller_supplied_pool_hook_no_allowlist")
    assert hits == []


def test_governance_names_the_execute_function():
    hits = hits_for(
        fx.VULN["governance_zero_quorum_executes"],
        "governance_zero_quorum_executes")
    assert [h["function"] for h in hits] == ["execute"]
    assert "quorum" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_governance_quorum_enforced_silent():
    hits = hits_for(
        fx.CLEAN["governance_zero_quorum_executes"],
        "governance_zero_quorum_executes")
    assert hits == []


def test_governance_quorum_helper_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["gov_quorum_helper"],
        "governance_zero_quorum_executes")
    assert hits == []


def test_governance_no_call_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["gov_execute_no_call"],
        "governance_zero_quorum_executes")
    assert hits == []


def test_duplicate_reward_names_the_constructor():
    hits = hits_for(
        fx.VULN["duplicate_reward_overwrite_desync"],
        "duplicate_reward_overwrite_desync")
    assert [h["function"] for h in hits] == ["constructor"]
    assert "playersToRewards" in hits[0]["detail"]
    assert "remainingRewards" in hits[0]["detail"]
    assert hits[0]["recipient"] == "HOLDER-SELF"


def test_duplicate_reward_accumulate_silent():
    hits = hits_for(
        fx.CLEAN["duplicate_reward_overwrite_desync"],
        "duplicate_reward_overwrite_desync")
    assert hits == []


def test_duplicate_reward_require_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["pot_duplicate_require"],
        "duplicate_reward_overwrite_desync")
    assert hits == []
