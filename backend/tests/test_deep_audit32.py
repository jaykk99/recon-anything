"""Deep-audit batch-32 detectors: authorization through
tx.origin, owner-reachable selfdestruct, unprotected
initializers, delegatecall to a caller-controlled target,
and owner-gated blacklists that freeze transfers.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate (the four recipient detectors); the blacklist
detector fires without a candidate classification (the freeze
power itself is the finding, medium severity). The
FIXED-recipient variant MUST fire trigger-only at low severity
(never a candidate); every clean control MUST stay silent under
ALL five detectors; every other plugin's vulnerable fixture MUST
stay silent under this one (no cross-talk); the batch-26, -27,
and -28 fixtures MUST stay silent under all five (no
cross-batch noise); the five new VULN fixtures MUST stay silent
under the relevant neighbours (initializer_flag_after_call,
multicall_arbitrary_delegatecall, proxy_delegatecall_selfdestruct,
bep20_blacklist_authority_check, plus the batch-26 and batch-27
detectors), EXCEPT the documented co-fires: the ungated
blacklist fixture fires under bep20_blacklist_authority_check
by design - asserted explicitly, not pretended silent - and
the batch-26 settle_delegatecall extra-clean fixture fires
under delegatecall_user_controlled_target by design: it is a
single delegatecall to a caller-supplied target, which is
clean ONLY in the multicall sense (no array, no loop) and is
exactly the shape the new detector owns. That co-fire is
asserted explicitly in test_delegatecall_fires_on_settle,
and the fixture is excluded from the blanket prior-batch
silence assertion there. The registry discovers exactly 1495
plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit26_fixtures as fx26  # noqa: E402
import deep_audit27_fixtures as fx27  # noqa: E402
import deep_audit28_fixtures as fx28  # noqa: E402
import deep_audit32_fixtures as fx  # noqa: E402
from app.plugins.bsc_bep20 import SPECS as BEP20_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_proxy import SPECS as PROXY_SPECS  # noqa: E402
from app.plugins.deep_audit25 import SPECS_BY_ID as SPECS25, \
    analyze_deep25_source  # noqa: E402
from app.plugins.deep_audit26 import SPECS_BY_ID as SPECS26, \
    analyze_deep26_source  # noqa: E402
from app.plugins.deep_audit27 import SPECS_BY_ID as SPECS27, \
    analyze_deep27_source  # noqa: E402
from app.plugins.deep_audit28 import SPECS_BY_ID as SPECS28, \
    analyze_deep28_source  # noqa: E402
from app.plugins.deep_audit32 import SPECS, SPECS_BY_ID, \
    analyze_deep32_source  # noqa: E402
from app.plugins.deep_audit7 import SPECS_BY_ID as SPECS7, \
    analyze_deep7_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["tx_origin_authorization",
                 "selfdestruct_present",
                 "unprotected_initializer",
                 "delegatecall_user_controlled_target"]
BEP20_BY_ID = {s.id: s for s in BEP20_SPECS}
PROXY_BY_ID = {s.id: s for s in PROXY_SPECS}


def hits_for(src, pid):
    return analyze_deep32_source(src, SPECS_BY_ID[pid])


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
            assert h["recipient"] in (
                "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_blacklist_fires_without_candidate():
    pid = "owner_blacklist_freeze"
    hits = hits_for(fx.VULN[pid], pid)
    assert hits, f"{pid}: vulnerable fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    for h in hits:
        assert h["code"], f"{pid}: no code evidence"
        assert h["detail"], f"{pid}: no detail"
        assert h["function"] == "addToBlacklist"
        assert h["gate_analysis"], \
            f"{pid}: no gate analysis (validator-ready bar)"
        assert h["severity"] == "medium"
        assert h.get("report_class") is None, (
            f"{pid}: the freeze power itself is the finding "
            f"- it must not carry a candidate classification")


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


def test_prior_batch_fixtures_silent_under_all_five():
    # No cross-batch noise: the batch-26, batch-27, and
    # batch-28 fixtures must not fire under any batch-32
    # detector. DOCUMENTED EXCEPTION: the batch-26
    # settle_delegatecall extra-clean fixture fires under
    # delegatecall_user_controlled_target by design (a
    # single delegatecall to a caller-supplied target is
    # clean only in the multicall sense) - asserted in
    # test_delegatecall_fires_on_settle, excluded here.
    for fxmod in (fx26, fx27, fx28):
        for group in (fxmod.VULN, fxmod.CLEAN, fxmod.VARIANT):
            for fid, src in group.items():
                for pid in IDS:
                    hits = hits_for(src, pid)
                    assert hits == [], (
                        f"{pid}: fired on prior-batch fixture "
                        f"{fid}: {hits}")
        for clean_id, src in fxmod.EXTRA_CLEAN.items():
            if (fxmod is fx26 and
                    clean_id == "settle_delegatecall"):
                continue
            for pid in IDS:
                hits = hits_for(src, pid)
                assert hits == [], (
                    f"{pid}: fired on prior-batch extra clean "
                    f"{clean_id}: {hits}")


def test_delegatecall_fires_on_settle():
    # DOCUMENTED CO-FIRE (see the module docstring): the
    # batch-26 settle_delegatecall fixture delegatecalls a
    # caller-supplied target in executeSwap, so the new
    # detector fires on it. It is trigger-only: the value
    # legs in the function pull tokens INTO the contract
    # (a FIXED destination), so under the receive rule the
    # stranger triggers code execution but the value lands
    # at a fixed destination.
    hits = hits_for(fx26.EXTRA_CLEAN["settle_delegatecall"],
                    "delegatecall_user_controlled_target")
    assert hits, "delegatecall detector must fire on the " \
        "settle_delegatecall fixture"
    assert all(h["kind"] == "delegatecall_user_controlled_target"
               for h in hits)
    assert hits[0]["function"] == "executeSwap"
    assert hits[0]["report_class"] == "trigger_only"
    assert hits[0]["recipient"] == "FIXED"
    assert hits[0]["severity"] == "low"


def test_new_vuln_fixtures_silent_under_neighbours():
    # The new VULN fixtures must not fire under the relevant
    # existing detectors. DOCUMENTED EXCEPTION: the blacklist
    # detector pair is split by gating - the ungated
    # blacklist fixture fires under
    # bep20_blacklist_authority_check by design, asserted in
    # test_blacklist_ungated_fires_under_bep20 below, and the
    # gated VULN fixture must stay silent under it.
    neighbours = []
    neighbours.append(("initializer_flag_after_call",
                       lambda src, spec:
                       analyze_deep7_source(src, spec)))
    neighbours.append(("multicall_arbitrary_delegatecall",
                       lambda src, spec:
                       analyze_deep25_source(src, spec)))
    neighbours.append(("proxy_delegatecall_selfdestruct",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    neighbours.append(("bep20_blacklist_authority_check",
                       lambda src, spec:
                       analyze_bsc_source(src, spec)))
    for pid in ("order_signature_validates_description_not_hash",
                "swap_output_trusted_report_no_receipt_check",
                "fee_claim_exceeds_accrued_fees",
                "settlement_swap_executes_caller_target_spends_approvals",
                "recorded_supply_caps_pool_reserves"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep26_source(src, spec)))
    for pid in ("lp_mint_no_minimum_liquidity_lock",
                "merkle_claim_replayable_across_chains",
                "vesting_claim_overrelease_past_duration",
                "permit_deadline_param_never_enforced",
                "bonding_curve_price_from_raw_balance_no_virtual_reserve"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep27_source(src, spec)))
    for pid in ("snapshot_position_sync_caller_writable",
                "share_price_excludes_subthreshold_collateral",
                "voucher_redeem_recipient_unbound",
                "period_exit_writes_new_period_exposure_snapshot",
                "withdraw_pays_other_account_balance"):
        neighbours.append((pid, lambda src, spec:
                           analyze_deep28_source(src, spec)))
    specs = {}
    specs.update(SPECS7)
    specs.update(SPECS25)
    specs.update(SPECS26)
    specs.update(SPECS27)
    specs.update(SPECS28)
    specs.update(BEP20_BY_ID)
    specs.update(PROXY_BY_ID)
    for vuln_id, src in fx.VULN.items():
        for pid, fn in neighbours:
            if pid not in specs:
                continue
            spec = specs[pid]
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_blacklist_ungated_fires_under_bep20():
    # DOCUMENTED SPLIT (see the fixtures module docstring):
    # the ungated blacklist setter is the bep20 detector's
    # shape (any stranger can blacklist), not the batch-32
    # shape (a gated admin freezes holders). It must fire
    # under bep20_blacklist_authority_check and stay silent
    # under owner_blacklist_freeze.
    spec = BEP20_BY_ID["bep20_blacklist_authority_check"]
    hits = analyze_bsc_source(fx.BLACKLIST_UNGATED, spec)
    assert hits, "bep20 blacklist detector must fire on the " \
        "ungated setter fixture"
    assert all(h["kind"] == "bep20_blacklist_authority_check"
               for h in hits)
    assert hits_for(fx.BLACKLIST_UNGATED,
                    "owner_blacklist_freeze") == []


def test_tx_origin_names_the_function():
    hits = hits_for(fx.VULN["tx_origin_authorization"],
                    "tx_origin_authorization")
    assert [h["function"] for h in hits] == ["sweep"]
    assert "tx.origin" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_tx_origin_msg_sender_silent():
    hits = hits_for(fx.CLEAN["tx_origin_authorization"],
                    "tx_origin_authorization")
    assert hits == []


def test_tx_origin_logged_silent():
    hits = hits_for(fx.EXTRA_CLEAN["tx_origin_logged"],
                    "tx_origin_authorization")
    assert hits == []


def test_selfdestruct_names_the_function():
    hits = hits_for(fx.VULN["selfdestruct_present"],
                    "selfdestruct_present")
    assert [h["function"] for h in hits] == ["kill"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_selfdestruct_timelocked_silent():
    hits = hits_for(fx.CLEAN["selfdestruct_present"],
                    "selfdestruct_present")
    assert hits == []


def test_selfdestruct_absent_silent():
    hits = hits_for(fx.EXTRA_CLEAN["selfdestruct_absent"],
                    "selfdestruct_present")
    assert hits == []


def test_initializer_names_the_function():
    hits = hits_for(fx.VULN["unprotected_initializer"],
                    "unprotected_initializer")
    assert [h["function"] for h in hits] == ["initialize"]
    assert "initializer" in hits[0]["detail"]


def test_initializer_modifier_silent():
    hits = hits_for(fx.CLEAN["unprotected_initializer"],
                    "unprotected_initializer")
    assert hits == []


def test_initializer_gated_silent():
    hits = hits_for(fx.EXTRA_CLEAN["init_gated"],
                    "unprotected_initializer")
    assert hits == []


def test_delegatecall_names_the_function():
    hits = hits_for(fx.VULN["delegatecall_user_controlled_target"],
                    "delegatecall_user_controlled_target")
    assert [h["function"] for h in hits] == ["execute"]
    assert "caller parameter" in hits[0]["detail"]


def test_delegatecall_setter_target_fires():
    hits = hits_for(
        fx.EXTRA_VULN["delegatecall_user_controlled_target"],
        "delegatecall_user_controlled_target")
    assert hits, "setter-controlled target must fire"
    assert all(h["kind"] == "delegatecall_user_controlled_target"
               for h in hits)
    assert hits[0]["function"] == "execute"
    assert "ungated public setter" in hits[0]["detail"]


def test_delegatecall_immutable_silent():
    hits = hits_for(fx.CLEAN["delegatecall_user_controlled_target"],
                    "delegatecall_user_controlled_target")
    assert hits == []


def test_delegatecall_allowlist_silent():
    hits = hits_for(fx.EXTRA_CLEAN["delegatecall_allowlist"],
                    "delegatecall_user_controlled_target")
    assert hits == []


def test_delegatecall_gated_silent():
    hits = hits_for(fx.EXTRA_CLEAN["delegatecall_gated"],
                    "delegatecall_user_controlled_target")
    assert hits == []


def test_blacklist_no_enforce_silent():
    hits = hits_for(fx.CLEAN["owner_blacklist_freeze"],
                    "owner_blacklist_freeze")
    assert hits == []
