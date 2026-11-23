"""Deep-audit batch-27 detectors: LP mint with no minimum
liquidity lock, merkle claims replayable across chains,
vesting claims that over-release past the duration, permit
deadlines never enforced, bonding-curve prices from raw
balances.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-26 fixtures MUST stay silent under all
five (no cross-batch noise); the five new VULN fixtures MUST
stay silent under the relevant neighbours
(vault_share_inflation, lending_accumulator_donation_inflation,
lp_mint_unverified_caller_supplied,
merkle_claim_no_claimed_marker, merkle_proof_amount_unbound,
permit_no_domain_separator, signature_replay_no_nonce,
ecrecover_no_malleability_guard, weak_onchain_randomness,
ecdsa_signature_replay_cross_chain,
vesting_release_cancel_double_debit, push_payment_revert_dos,
fee_on_transfer_overcredit, recipient_overdraw_withdraw,
recipient_unbacked_claim,
access_control_arbitrary_call_injection, and the five batch-26
detectors); the registry discovers exactly 1495 plugins
including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit26_fixtures as fx26  # noqa: E402
import deep_audit27_fixtures as fx  # noqa: E402
from app.plugins.bsc_access import SPECS as ACCESS_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.deep_audit import SPECS_BY_ID as SPECS1, \
    analyze_deep_source  # noqa: E402
from app.plugins.deep_audit11 import SPECS_BY_ID as SPECS11, \
    analyze_deep11_source  # noqa: E402
from app.plugins.deep_audit12 import SPECS_BY_ID as SPECS12, \
    analyze_deep12_source  # noqa: E402
from app.plugins.deep_audit19 import SPECS_BY_ID as SPECS19, \
    analyze_deep19_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit20 import SPECS_BY_ID as SPECS20, \
    analyze_deep20_source  # noqa: E402
from app.plugins.deep_audit24 import SPECS_BY_ID as SPECS24, \
    analyze_deep24_source  # noqa: E402
from app.plugins.deep_audit25 import SPECS_BY_ID as SPECS25, \
    analyze_deep25_source  # noqa: E402
from app.plugins.deep_audit26 import SPECS_BY_ID as SPECS26, \
    analyze_deep26_source  # noqa: E402
from app.plugins.deep_audit27 import SPECS, SPECS_BY_ID, \
    analyze_deep27_source  # noqa: E402
from app.plugins.deep_audit3 import SPECS_BY_ID as SPECS3, \
    analyze_deep3_source  # noqa: E402
from app.plugins.deep_audit8 import SPECS_BY_ID as SPECS8, \
    analyze_deep8_source  # noqa: E402
from app.plugins.recipient_first import \
    analyze_recipient_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
ACCESS_BY_ID = {s.id: s for s in ACCESS_SPECS}


def hits_for(src, pid):
    return analyze_deep27_source(src, SPECS_BY_ID[pid])


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


def test_batch26_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-27 detector.
    for group in (fx26.VULN, fx26.CLEAN, fx26.VARIANT):
        for fid, src in group.items():
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on batch-26 fixture {fid}: "
                    f"{hits}")
    for clean_id, src in fx26.EXTRA_CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on batch-26 extra clean "
                f"{clean_id}: {hits}")
    for pid in IDS:
        hits = hits_for(fx26.VULN_TRY_CATCH, pid)
        assert hits == [], (
            f"{pid}: fired on batch-26 try/catch fixture: "
            f"{hits}")


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors: the vault / LP / lending share
    # detectors, the merkle / permit / vesting neighbours, the
    # signature / randomness detectors, the recipient-first
    # withdraw / claim detectors, the BSC arbitrary-call
    # executor, and the five batch-26 detectors.
    neighbours = []
    neighbours.append(("vault_share_inflation",
                       lambda src, spec:
                       analyze_deep_source(src, spec)))
    neighbours.append(("lending_accumulator_donation_inflation",
                       lambda src, spec:
                       analyze_deep11_source(src, spec)))
    neighbours.append(("vesting_release_cancel_double_debit",
                       lambda src, spec:
                       analyze_deep12_source(src, spec)))
    neighbours.append(("permit_no_domain_separator",
                       lambda src, spec:
                       analyze_deep19_source(src, spec)))
    neighbours.append(("signature_replay_no_nonce",
                       lambda src, spec:
                       analyze_deep19_source(src, spec)))
    neighbours.append(("ecrecover_no_malleability_guard",
                       lambda src, spec:
                       analyze_deep19_source(src, spec)))
    neighbours.append(("weak_onchain_randomness",
                       lambda src, spec:
                       analyze_deep19_source(src, spec)))
    neighbours.append(("fee_on_transfer_overcredit",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    neighbours.append(("merkle_claim_no_claimed_marker",
                       lambda src, spec:
                       analyze_deep20_source(src, spec)))
    neighbours.append(("lp_mint_unverified_caller_supplied",
                       lambda src, spec:
                       analyze_deep24_source(src, spec)))
    neighbours.append(("merkle_proof_amount_unbound",
                       lambda src, spec:
                       analyze_deep25_source(src, spec)))
    neighbours.append(("push_payment_revert_dos",
                       lambda src, spec:
                       analyze_deep8_source(src, spec)))
    for pid in ("recipient_overdraw_withdraw",
                "recipient_unbacked_claim"):
        neighbours.append((pid, lambda src, spec_id:
                           analyze_recipient_source(src, spec_id)))
    neighbours.append(("access_control_arbitrary_call_injection",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("ecdsa_signature_replay_cross_chain",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    for pid in ("order_signature_validates_description_not_hash",
                "swap_output_trusted_report_no_receipt_check",
                "fee_claim_exceeds_accrued_fees",
                "settlement_swap_executes_caller_target_spends_approvals",
                "recorded_supply_caps_pool_reserves"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep26_source(src, spec)))
    specs = {}
    specs.update(SPECS1)
    specs.update(SPECS2)
    specs.update(SPECS3)
    specs.update(SPECS8)
    specs.update(SPECS11)
    specs.update(SPECS12)
    specs.update(SPECS19)
    specs.update(SPECS20)
    specs.update(SPECS24)
    specs.update(SPECS25)
    specs.update(SPECS26)
    specs.update(ACCESS_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            if pid not in specs and pid not in (
                    "recipient_overdraw_withdraw",
                    "recipient_unbacked_claim"):
                continue
            spec = specs.get(pid, pid)
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_lp_mint_names_the_mint_function():
    hits = hits_for(
        fx.VULN["lp_mint_no_minimum_liquidity_lock"],
        "lp_mint_no_minimum_liquidity_lock")
    assert [h["function"] for h in hits] == ["mint"]
    assert "sqrt" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_lp_mint_minimum_burn_silent():
    hits = hits_for(
        fx.CLEAN["lp_mint_no_minimum_liquidity_lock"],
        "lp_mint_no_minimum_liquidity_lock")
    assert hits == []


def test_lp_mint_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lp_gated"],
        "lp_mint_no_minimum_liquidity_lock")
    assert hits == []


def test_lp_mint_no_sqrt_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lp_no_sqrt"],
        "lp_mint_no_minimum_liquidity_lock")
    assert hits == []


def test_merkle_claim_names_the_claim_function():
    hits = hits_for(
        fx.VULN["merkle_claim_replayable_across_chains"],
        "merkle_claim_replayable_across_chains")
    assert [h["function"] for h in hits] == ["claim"]
    assert "chain" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_merkle_claim_chainid_bound_silent():
    hits = hits_for(
        fx.CLEAN["merkle_claim_replayable_across_chains"],
        "merkle_claim_replayable_across_chains")
    assert hits == []


def test_merkle_claim_no_payout_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["merkle_no_payout"],
        "merkle_claim_replayable_across_chains")
    assert hits == []


def test_vesting_names_the_release_function():
    hits = hits_for(
        fx.VULN["vesting_claim_overrelease_past_duration"],
        "vesting_claim_overrelease_past_duration")
    assert [h["function"] for h in hits] == ["release"]
    assert "100%" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_vesting_capped_end_silent():
    hits = hits_for(
        fx.CLEAN["vesting_claim_overrelease_past_duration"],
        "vesting_claim_overrelease_past_duration")
    assert hits == []


def test_vesting_capped_total_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["vest_capped_total"],
        "vesting_claim_overrelease_past_duration")
    assert hits == []


def test_vesting_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["vest_gated"],
        "vesting_claim_overrelease_past_duration")
    assert hits == []


def test_permit_names_the_permit_function():
    hits = hits_for(
        fx.VULN["permit_deadline_param_never_enforced"],
        "permit_deadline_param_never_enforced")
    assert [h["function"] for h in hits] == ["permit"]
    assert "deadline" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_permit_deadline_enforced_silent():
    hits = hits_for(
        fx.CLEAN["permit_deadline_param_never_enforced"],
        "permit_deadline_param_never_enforced")
    assert hits == []


def test_permit_no_signature_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["permit_no_sig"],
        "permit_deadline_param_never_enforced")
    assert hits == []


def test_bonding_curve_names_the_buy_function():
    hits = hits_for(
        fx.VULN["bonding_curve_price_from_raw_balance_no_virtual_reserve"],
        "bonding_curve_price_from_raw_balance_no_virtual_reserve")
    assert [h["function"] for h in hits] == ["buyTokens"]
    assert "raw balance" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_bonding_curve_virtual_reserve_silent():
    hits = hits_for(
        fx.CLEAN["bonding_curve_price_from_raw_balance_no_virtual_reserve"],
        "bonding_curve_price_from_raw_balance_no_virtual_reserve")
    assert hits == []


def test_bonding_curve_min_out_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["bond_min_out"],
        "bonding_curve_price_from_raw_balance_no_virtual_reserve")
    assert hits == []


def test_bonding_curve_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["bond_gated"],
        "bonding_curve_price_from_raw_balance_no_virtual_reserve")
    assert hits == []
