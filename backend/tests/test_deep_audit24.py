"""Deep-audit batch-24 detectors: sell-hook reserve sync, escape-hatch
inputs, LP mint trust, bridge value binding, merkle leaf index.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-20 fixtures MUST stay silent under all
five (no cross-batch noise); the five new VULN fixtures MUST
stay silent under the relevant neighbours
(merkle_claim_no_claimed_marker, lzreceive_no_origin_validation,
bridge_replay_unbound_digest, bridge_wrapped_token_mint_unbacked,
bridge_withdrawer_identity_spoof, callback_token_cei_violation);
the registry discovers exactly 1459 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit20_fixtures as fx20  # noqa: E402
import deep_audit24_fixtures as fx  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_mev_bridge import SPECS as MEVB_SPECS  # noqa: E402
from app.plugins.deep_audit14 import SPECS_BY_ID as SPECS14, \
    analyze_deep14_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit20 import SPECS_BY_ID as SPECS20, \
    analyze_deep20_source  # noqa: E402
from app.plugins.deep_audit24 import SPECS, SPECS_BY_ID, \
    analyze_deep24_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = IDS
MEVB_BY_ID = {s.id: s for s in MEVB_SPECS}


def hits_for(src, pid):
    return analyze_deep24_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1459():
    reg = discover()
    assert len(reg) == 1459, \
        f"registry size {len(reg)}, expected 1459"


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


def test_batch20_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-24 detector.
    for group in (fx20.VULN, fx20.CLEAN, fx20.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-20 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx20.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-20 extra clean "
                f"{clean_id}: {hits}")


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors: the batch-20 claim / lzReceive
    # detectors, the bridge replay / mint / withdrawer
    # detectors, and the token-callback CEI detector.
    neighbours = []
    for pid in ("merkle_claim_no_claimed_marker",
                "lzreceive_no_origin_validation"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep20_source(src, spec)))
    neighbours.append(("bridge_replay_unbound_digest",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    for pid in ("bridge_wrapped_token_mint_unbacked",
                "bridge_withdrawer_identity_spoof"):
        neighbours.append((pid, lambda src, spec:
                           analyze_bsc_source(src, spec)))
    neighbours.append(("callback_token_cei_violation",
                       lambda src, spec:
                       analyze_deep14_source(src, spec)))
    specs = {}
    specs.update(SPECS20)
    specs.update(SPECS2)
    specs.update(MEVB_BY_ID)
    specs.update(SPECS14)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            hits = fn(src, specs[pid])
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_sell_hook_names_the_transfer_function():
    hits = hits_for(
        fx.VULN["token_sell_hook_burns_pair_reserves_sync"],
        "token_sell_hook_burns_pair_reserves_sync")
    assert [h["function"] for h in hits] == ["_transfer"]
    assert "pair" in hits[0]["detail"].lower()
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_sell_hook_settle_first_silent():
    hits = hits_for(
        fx.CLEAN["token_sell_hook_burns_pair_reserves_sync"],
        "token_sell_hook_burns_pair_reserves_sync")
    assert hits == []


def test_sell_hook_plain_transfer_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["sell_plain_transfer"],
        "token_sell_hook_burns_pair_reserves_sync")
    assert hits == []


def test_sell_hook_helper_after_settle_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["sell_helper_after_settle"],
        "token_sell_hook_burns_pair_reserves_sync")
    assert hits == []


def test_escape_hatch_names_the_hatch_function():
    hits = hits_for(
        fx.VULN["escape_hatch_unbound_public_inputs"],
        "escape_hatch_unbound_public_inputs")
    assert [h["function"] for h in hits] == ["escapeHatch"]
    assert "publicOutput" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_escape_hatch_verified_proof_silent():
    hits = hits_for(
        fx.CLEAN["escape_hatch_unbound_public_inputs"],
        "escape_hatch_unbound_public_inputs")
    assert hits == []


def test_escape_hatch_fixed_amount_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["escape_fixed_amount"],
        "escape_hatch_unbound_public_inputs")
    assert hits == []


def test_lp_mint_names_the_remove_function():
    hits = hits_for(
        fx.VULN["lp_mint_unverified_caller_supplied"],
        "lp_mint_unverified_caller_supplied")
    assert [h["function"] for h in hits] == ["removeLiquidity"]
    assert "lpToken" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_lp_mint_stored_token_silent():
    hits = hits_for(
        fx.CLEAN["lp_mint_unverified_caller_supplied"],
        "lp_mint_unverified_caller_supplied")
    assert hits == []


def test_lp_mint_storage_read_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lp_storage_read"],
        "lp_mint_unverified_caller_supplied")
    assert hits == []


def test_bridge_value_names_the_release_function():
    hits = hits_for(
        fx.VULN["bridge_release_value_unbound_to_proof"],
        "bridge_release_value_unbound_to_proof")
    assert [h["function"] for h in hits] == ["release"]
    assert "amount" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_bridge_value_record_bound_silent():
    hits = hits_for(
        fx.CLEAN["bridge_release_value_unbound_to_proof"],
        "bridge_release_value_unbound_to_proof")
    assert hits == []


def test_bridge_value_no_verification_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["bridge_no_verification"],
        "bridge_release_value_unbound_to_proof")
    assert hits == []


def test_bridge_value_paid_allowlist_mint_silent():
    # FP pinned 2026-11-17: ERC20Plus mintManyERC20AL verifies an
    # allowlist proof and mints a caller amount, but the caller
    # pays per token under caps - a paid mint, not a bridge
    # release (not bridge-shaped: no release name, no transfer /
    # message identifier, no bridge contract).
    hits = hits_for(
        fx.EXTRA_CLEAN["bridge_mint_allowlist_paid"],
        "bridge_release_value_unbound_to_proof")
    assert hits == []


def test_merkle_index_names_the_verify_function():
    hits = hits_for(
        fx.VULN["merkle_proof_unbounded_leaf_index"],
        "merkle_proof_unbounded_leaf_index")
    assert [h["function"] for h in hits] == ["verifyLeaf"]
    assert "index" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_merkle_index_bound_silent():
    hits = hits_for(
        fx.CLEAN["merkle_proof_unbounded_leaf_index"],
        "merkle_proof_unbounded_leaf_index")
    assert hits == []


def test_merkle_index_no_index_param_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["leaf_no_index"],
        "merkle_proof_unbounded_leaf_index")
    assert hits == []
