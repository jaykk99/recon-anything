"""Deep-audit batch-33 detectors: a flash loan that lends the
pool's own pricing balance, a per-user cap counter that is never
incremented, a gauge weight that ignores its account parameter,
proof verification with no context binding, and pool units
minted from the unrounded deposit while the collection rounds
down.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the batch-28 fixtures MUST stay silent under all
five (no cross-batch noise); the five new VULN fixtures MUST
stay silent under the relevant neighbours
(flash_loan_spot_balance_check, cap_counter_reset_by_setter,
reward_distribution_manipulation, rounding_iterated_drain,
staking_total_shares_mismatch, bridge_replay_unbound_digest,
fee_on_transfer_overcredit, amm_scale_rounding_wrong_direction,
withdraw_rounding_drain, merkle_patricia_trie_state_proof_
verifier, cp_proto_single_source_oracle), EXCEPT the documented
co-fire: spot_price_own_balance fires on the
pool_flashloan_lends_pricing_balance fixture by design - the
swap does price from its own balance; the new detector adds
the flash-loan dimension (the pool lends the very balance it
prices from). That co-fire is asserted explicitly, not
pretended silent. The registry discovers exactly 1495 plugins
including all five. The FP-regression rows (deep_audit13 +
deep_audit14) stay silent under all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit13_fixtures as fx13  # noqa: E402
import deep_audit14_fixtures as fx14  # noqa: E402
import deep_audit28_fixtures as fx28  # noqa: E402
import deep_audit33_fixtures as fx  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_lending import SPECS as LENDING_SPECS  # noqa: E402
from app.plugins.bsc_staking import SPECS as STAKING_SPECS  # noqa: E402
from app.plugins.business_logic import SPECS_BY_ID as SPECSBL, \
    analyze_business_logic_source  # noqa: E402
from app.plugins.cryptopack_protocol import \
    audit_protocol_source  # noqa: E402
from app.plugins.deep_audit10 import SPECS_BY_ID as SPECS10, \
    analyze_deep10_source  # noqa: E402
from app.plugins.deep_audit11 import SPECS_BY_ID as SPECS11, \
    analyze_deep11_source  # noqa: E402
from app.plugins.deep_audit2 import SPECS_BY_ID as SPECS2, \
    analyze_deep2_source  # noqa: E402
from app.plugins.deep_audit23 import SPECS_BY_ID as SPECS23, \
    analyze_deep23_source  # noqa: E402
from app.plugins.deep_audit33 import SPECS, SPECS_BY_ID, \
    analyze_deep33_source  # noqa: E402
from app.plugins.deep_audit4 import SPECS_BY_ID as SPECS4, \
    analyze_deep4_source  # noqa: E402
from app.plugins.deep_lowlevel import SPECS_BY_ID as SPECSLL, \
    analyze_deep_lowlevel_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
LENDING_BY_ID = {s.id: s for s in LENDING_SPECS}
STAKING_BY_ID = {s.id: s for s in STAKING_SPECS}


def hits_for(src, pid):
    return analyze_deep33_source(src, SPECS_BY_ID[pid])


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
        assert len(hits) == 1, (
            f"{pid}: vulnerable fixture must fire exactly once, "
            f"got {len(hits)}")
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


def test_batch28_fixtures_silent_under_all_five():
    # No cross-batch noise: the previous batch's fixtures must
    # not fire under any batch-33 detector.
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


def test_fp_regression_rows_silent_under_all_five():
    # The hand-read false-positive fixture shapes stay silent
    # under every batch-33 detector. (The 93-row fp_regression
    # in the task brief is backend/scripts/fp_regression.py,
    # which scores contract_logic rows - run separately, 93
    # PASS / 0 FAIL; the FP_REGRESSION fixture dicts here total
    # 8 rows: 5 in deep_audit13 + 3 in deep_audit14.)
    rows = dict(fx13.FP_REGRESSION)
    rows.update(fx14.FP_REGRESSION)
    assert len(rows) == 8
    for fid, src in rows.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on FP-regression {fid}: {hits}")


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors: the flash-loan spot-balance detector,
    # the cap-counter reset detector, the reward accumulator /
    # share-mismatch detectors, the bridge replay detector, the
    # fee-on-transfer deposit detector, the rounding detectors,
    # the MPT proof-validity detector, and the single-source
    # oracle protocol check. DOCUMENTED EXCEPTION: the
    # spot-price-own-balance detector fires on the flash-loan
    # fixture by design (the swap prices from its own balance)
    # - asserted in test_pool_flashloan_spot_price_cofire
    # below, and excluded from the silence assertion here.
    neighbours = []
    neighbours.append(("flash_loan_spot_balance_check",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("cap_counter_reset_by_setter",
                       lambda src, spec:
                       analyze_deep23_source(src, spec)))
    neighbours.append(("reward_distribution_manipulation",
                       lambda src, spec:
                       analyze_business_logic_source(src, spec)))
    neighbours.append(("rounding_iterated_drain",
                       lambda src, spec:
                       analyze_business_logic_source(src, spec)))
    neighbours.append(("staking_total_shares_mismatch",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("bridge_replay_unbound_digest",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    neighbours.append(("fee_on_transfer_overcredit",
                       lambda src, spec:
                       analyze_deep2_source(src, spec)))
    neighbours.append(("amm_scale_rounding_wrong_direction",
                       lambda src, spec:
                       analyze_deep11_source(src, spec)))
    neighbours.append(("withdraw_rounding_drain",
                       lambda src, spec:
                       analyze_deep10_source(src, spec)))
    neighbours.append(("merkle_patricia_trie_state_proof_verifier",
                       lambda src, spec:
                       analyze_deep_lowlevel_source(src, spec)))
    specs = {}
    specs.update(SPECS23)
    specs.update(SPECSBL)
    specs.update(SPECS2)
    specs.update(SPECS10)
    specs.update(SPECS11)
    specs.update(SPECSLL)
    specs.update(LENDING_BY_ID)
    specs.update(STAKING_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            spec = specs.get(pid)
            assert spec is not None, f"no spec for {pid}"
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")
        # The single-source oracle protocol check (a
        # protocol-level check, not a SPECS detector): the
        # flash-loan fixture prices from one balance, not from
        # a reserve ratio, so it must stay silent.
        cp_hits = [f for f in audit_protocol_source(src)
                   if f["check"] == "single_source_oracle"]
        assert cp_hits == [], (
            f"cp_proto_single_source_oracle fired on the "
            f"{vuln_id} fixture: {cp_hits}")


def test_pool_flashloan_spot_price_cofire():
    # DOCUMENTED CO-FIRE (see the fixtures module docstring):
    # spot_price_own_balance fires on the pool-flashloan VULN
    # fixture because the swap does price from its own balance.
    # That is the same hole from the pricing angle; the new
    # detector adds the flash-loan dimension (the pool lends
    # the very balance it prices from). It must NOT fire on the
    # other four vuln fixtures.
    src = fx.VULN["pool_flashloan_lends_pricing_balance"]
    hits = analyze_deep4_source(
        src, SPECS4["spot_price_own_balance"])
    assert hits, "spot_price_own_balance must co-fire on the " \
        "pool-flashloan fixture (the swap prices from its own " \
        "balance)"
    assert all(h["kind"] == "spot_price_own_balance"
               for h in hits)
    assert [h["function"] for h in hits] == ["swap"]
    for vuln_id, src2 in fx.VULN.items():
        if vuln_id == "pool_flashloan_lends_pricing_balance":
            continue
        hits = analyze_deep4_source(
            src2, SPECS4["spot_price_own_balance"])
        assert hits == [], (
            f"spot_price_own_balance fired on the {vuln_id} "
            f"fixture: {hits}")


def test_cap_setter_reset_pin():
    # The cap_setter_reset extra clean is the
    # cap_counter_reset_by_setter shape: the counter IS written
    # by a setter, so batch-33 stays silent - and the reset
    # detector MUST fire on it, pinning the boundary between
    # the two cap classes.
    src = fx.EXTRA_CLEAN["cap_setter_reset"]
    hits = hits_for(src, "cap_counter_never_incremented")
    assert hits == []
    reset_hits = analyze_deep23_source(
        src, SPECS23["cap_counter_reset_by_setter"])
    assert reset_hits, "cap_counter_reset_by_setter must fire " \
        "on the cap_setter_reset fixture (a setter re-arms the " \
        "counter)"
    assert all(h["kind"] == "cap_counter_reset_by_setter"
               for h in reset_hits)


def test_pool_flashloan_names_the_swap_function():
    hits = hits_for(
        fx.VULN["pool_flashloan_lends_pricing_balance"],
        "pool_flashloan_lends_pricing_balance")
    assert [h["function"] for h in hits] == ["swap"]
    assert "flashBorrow" in hits[0]["detail"]
    assert "reserve" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_pool_flashloan_stored_reserve_silent():
    hits = hits_for(
        fx.CLEAN["pool_flashloan_lends_pricing_balance"],
        "pool_flashloan_lends_pricing_balance")
    assert hits == []


def test_pool_flashloan_separate_vault_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["flash_separate_vault"],
        "pool_flashloan_lends_pricing_balance")
    assert hits == []


def test_pool_flashloan_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["flash_gated"],
        "pool_flashloan_lends_pricing_balance")
    assert hits == []


def test_pool_flashloan_no_swap_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["flash_no_swap"],
        "pool_flashloan_lends_pricing_balance")
    assert hits == []


def test_cap_counter_names_the_mint_function():
    hits = hits_for(
        fx.VULN["cap_counter_never_incremented"],
        "cap_counter_never_incremented")
    assert [h["function"] for h in hits] == ["mint"]
    assert "mintCount" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_cap_counter_incremented_silent():
    hits = hits_for(
        fx.CLEAN["cap_counter_never_incremented"],
        "cap_counter_never_incremented")
    assert hits == []


def test_cap_counter_time_only_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["cap_time_only"],
        "cap_counter_never_incremented")
    assert hits == []


def test_cap_counter_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["cap_gated"],
        "cap_counter_never_incremented")
    assert hits == []


def test_reward_weight_names_the_claim_function():
    hits = hits_for(
        fx.VULN["reward_weight_ignores_account_param"],
        "reward_weight_ignores_account_param")
    assert [h["function"] for h in hits] == ["claimRewards"]
    assert "_gaugeWeight" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_reward_weight_param_used_silent():
    hits = hits_for(
        fx.CLEAN["reward_weight_ignores_account_param"],
        "reward_weight_ignores_account_param")
    assert hits == []


def test_reward_weight_no_claim_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["weight_no_claim"],
        "reward_weight_ignores_account_param")
    assert hits == []


def test_reward_weight_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["weight_gated"],
        "reward_weight_ignores_account_param")
    assert hits == []


def test_proof_verification_names_the_verify_function():
    hits = hits_for(
        fx.VULN["proof_verification_no_context_binding"],
        "proof_verification_no_context_binding")
    assert [h["function"] for h in hits] == ["verifyStorageProof"]
    assert "stateRoot" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_proof_verification_bound_silent():
    hits = hits_for(
        fx.CLEAN["proof_verification_no_context_binding"],
        "proof_verification_no_context_binding")
    assert hits == []


def test_proof_verification_domain_separator_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["proof_domain_separator"],
        "proof_verification_no_context_binding")
    assert hits == []


def test_proof_verification_no_effect_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["proof_no_effect"],
        "proof_verification_no_context_binding")
    assert hits == []


def test_proof_verification_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["proof_gated"],
        "proof_verification_no_context_binding")
    assert hits == []


def test_lp_mint_names_the_deposit_function():
    hits = hits_for(
        fx.VULN["lp_mint_unrounded_shares_rounded_collection"],
        "lp_mint_unrounded_shares_rounded_collection")
    assert [h["function"] for h in hits] == ["addLiquidity"]
    assert "collected" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_lp_mint_divmul_fires():
    hits = hits_for(
        fx.VULN_DIVMUL,
        "lp_mint_unrounded_shares_rounded_collection")
    assert hits, "amount / unit * unit collection must still fire"
    assert all(h["kind"] ==
               "lp_mint_unrounded_shares_rounded_collection"
               for h in hits)
    assert [h["function"] for h in hits] == ["addLiquidity"]
    assert hits[0]["report_class"] == "candidate"


def test_lp_mint_measured_balance_silent():
    hits = hits_for(
        fx.CLEAN["lp_mint_unrounded_shares_rounded_collection"],
        "lp_mint_unrounded_shares_rounded_collection")
    assert hits == []


def test_lp_mint_no_rounding_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lp_no_rounding"],
        "lp_mint_unrounded_shares_rounded_collection")
    assert hits == []


def test_lp_mint_gated_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["lp_gated"],
        "lp_mint_unrounded_shares_rounded_collection")
    assert hits == []
