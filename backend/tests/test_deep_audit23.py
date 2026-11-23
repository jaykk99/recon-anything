"""Deep-audit batch-23 detectors: accrual denominators, stale
capacity, resettable caps, recallable pots, non-zero-sum ledgers.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL five detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the registry discovers exactly 1495 plugins
including all five.

Adjudication pins:
- The accrual detector MUST stay silent on the
  lending-accumulator shape (division by plain totalSupply):
  the EXTRA_CLEAN fixture is that shape.
- The capacity detector MUST stay silent on the deep_audit20
  cover fixtures (cover_capacity_counts_unpaid_prior_period,
  PR #180, unmerged at build time): they have no snapshot
  variable and their payout reduces no collateral variable,
  so the snapshot-read + payout-without-refresh conjunction
  cannot hold. The three cover sources are copied verbatim
  from PR #180's deep_audit20_fixtures.py and pinned here.
- Relevant existing detectors MUST stay silent on all
  batch-23 fixtures (lending accumulator, Venus accrual
  omission, BEP-20 mint cap, share cancel desync, staking
  shares mismatch, claim callback flag, flash-loan spot
  balance). cover_capacity_counts_unpaid_prior_period and
  supply_cap_bypass_direct_transfer live on the unmerged
  PR #180 branch, so they are checked by the builder's
  scratch run against that branch, not in this suite.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit23_fixtures as fx  # noqa: E402
from app.plugins.deep_audit23 import SPECS, SPECS_BY_ID, \
    analyze_deep23_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = [
    "interest_accrual_near_zero_denominator_inflation",
    "stale_capacity_snapshot_after_payout",
    "cap_counter_reset_by_setter",
    "finalize_recallable_drains_pot",
    "internal_transfer_credit_without_debit",
]


def hits_for(src, pid):
    return analyze_deep23_source(src, SPECS_BY_ID[pid])


# ---------------------------------------------------------------------------
# deep_audit20 cover fixtures, copied verbatim from PR #180
# (backend/tests/deep_audit20_fixtures.py) to pin the #88214 /
# #88615 adjudication: no snapshot variable, no collateral
# reduction in the payout, so the stale-capacity detector
# must stay silent on all three.
# ---------------------------------------------------------------------------

_DA20_COVER_VULN = fx._TOKEN_IFACE + """
contract CoverPoolVuln {
    IERC20Like public token;
    uint256 public totalCollateral;
    uint256 public unpaidPriorPeriod;
    uint256 public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function availableCover() public view returns (uint256) {
        return totalCollateral - claimed;
    }

    function claim(uint256 amount) external {
        uint256 cover = availableCover();
        require(amount <= cover, "exceeds cover");
        claimed += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_DA20_COVER_VARIANT = fx._TOKEN_IFACE + """
contract CoverPoolFixed {
    IERC20Like public token;
    address public treasury;
    uint256 public totalCollateral;
    uint256 public unpaidPriorPeriod;
    uint256 public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
        treasury = msg.sender;
    }

    function availableCover() public view returns (uint256) {
        return totalCollateral - claimed;
    }

    function claim(uint256 amount) external {
        uint256 cover = availableCover();
        require(amount <= cover, "exceeds cover");
        claimed += amount;
        token.transfer(treasury, amount);
    }
}
"""

_DA20_COVER_CLEAN = fx._TOKEN_IFACE + """
contract CoverPoolClean {
    IERC20Like public token;
    uint256 public totalCollateral;
    uint256 public unpaidPriorPeriod;
    uint256 public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function availableCover() public view returns (uint256) {
        return totalCollateral - claimed - unpaidPriorPeriod;
    }

    function claim(uint256 amount) external {
        uint256 cover = availableCover();
        require(amount <= cover, "exceeds cover");
        claimed += amount;
        token.transfer(msg.sender, amount);
    }
}
"""


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1480():
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


def test_extra_vuln_fixtures_fire():
    for pid, src in fx.EXTRA_VULN.items():
        hits = hits_for(src, pid)
        assert hits, f"{pid}: extra vuln fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        assert all(h["report_class"] == "candidate"
                   for h in hits)


def test_accrual_names_the_borrow_function():
    hits = hits_for(
        fx.VULN["interest_accrual_near_zero_denominator_inflation"],
        "interest_accrual_near_zero_denominator_inflation")
    assert [h["function"] for h in hits] == ["borrow"]
    assert "netSupply" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_accrual_floor_silent():
    hits = hits_for(
        fx.CLEAN["interest_accrual_near_zero_denominator_inflation"],
        "interest_accrual_near_zero_denominator_inflation")
    assert hits == []


def test_accrual_plain_totalsupply_silent():
    # The lending-accumulator shape (deep_audit11): the rate
    # divides by plain totalSupply, not by a net-supply
    # expression - the accrual detector must stay silent.
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "interest_accrual_near_zero_denominator_inflation"],
        "interest_accrual_near_zero_denominator_inflation")
    assert hits == []


def test_accrual_inline_subtraction_spelling_fires():
    hits = hits_for(
        fx.EXTRA_VULN[
            "interest_accrual_near_zero_denominator_inflation"],
        "interest_accrual_near_zero_denominator_inflation")
    assert hits, "inline (totalSupply - reserves) did not fire"
    assert hits[0]["report_class"] == "candidate"


def test_accrual_reflection_rate_silent():
    # Live-corpus FP (2026-11-16): a reflection token's
    # _getRate divides by tSupply (totalSupply minus excluded
    # balances) but feeds no borrow - must stay silent.
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "interest_accrual_near_zero_denominator_inflation_reflection"],
        "interest_accrual_near_zero_denominator_inflation")
    assert hits == []


def test_accrual_reward_per_share_silent():
    # Live-corpus FP (2026-11-16): a staking reward-per-share
    # distribute divides by totalShares (updated by
    # subtraction) but the payout is pro-rata to the caller's
    # own shares and feeds no borrow - must stay silent.
    hits = hits_for(
        fx.EXTRA_CLEAN[
            "interest_accrual_near_zero_denominator_inflation_reward"],
        "interest_accrual_near_zero_denominator_inflation")
    assert hits == []


def test_capacity_names_the_sell_cover_function():
    hits = hits_for(
        fx.VULN["stale_capacity_snapshot_after_payout"],
        "stale_capacity_snapshot_after_payout")
    assert [h["function"] for h in hits] == ["sellCover"]
    assert "periodStartCapacity" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER-SUPPLIED"


def test_capacity_snapshot_refresh_silent():
    hits = hits_for(
        fx.CLEAN["stale_capacity_snapshot_after_payout"],
        "stale_capacity_snapshot_after_payout")
    assert hits == []


def test_capacity_live_read_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["stale_capacity_snapshot_after_payout"],
        "stale_capacity_snapshot_after_payout")
    assert hits == []


def test_deep_audit20_cover_fixtures_silent():
    # The #88214 shape (deep_audit20): capacity counts
    # collateral liable for an unpaid prior period, but there
    # is no period-start snapshot and the payout reduces no
    # collateral variable - so the #88615 conjunction cannot
    # hold and this detector must stay silent on all three.
    for src in (_DA20_COVER_VULN, _DA20_COVER_CLEAN,
                _DA20_COVER_VARIANT):
        hits = hits_for(src, "stale_capacity_snapshot_after_payout")
        assert hits == [], (
            "stale-capacity detector fired on a deep_audit20 "
            f"cover fixture: {hits}")


def test_cap_names_the_buy_function():
    hits = hits_for(
        fx.VULN["cap_counter_reset_by_setter"],
        "cap_counter_reset_by_setter")
    assert [h["function"] for h in hits] == ["buyPass"]
    assert "passSupply" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_cap_no_setter_silent():
    hits = hits_for(
        fx.CLEAN["cap_counter_reset_by_setter"],
        "cap_counter_reset_by_setter")
    assert hits == []


def test_cap_totalsupply_derived_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["cap_counter_reset_by_setter"],
        "cap_counter_reset_by_setter")
    assert hits == []


def test_cap_reset_to_zero_fires():
    hits = hits_for(
        fx.EXTRA_VULN["cap_counter_reset_by_setter"],
        "cap_counter_reset_by_setter")
    assert hits, "reset-to-zero spelling did not fire"
    assert hits[0]["report_class"] == "candidate"


def test_finalize_names_the_close_function():
    hits = hits_for(
        fx.VULN["finalize_recallable_drains_pot"],
        "finalize_recallable_drains_pot")
    assert [h["function"] for h in hits] == ["closePot"]
    assert "balanceOf(address(this))" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_finalize_flag_before_transfer_silent():
    hits = hits_for(
        fx.CLEAN["finalize_recallable_drains_pot"],
        "finalize_recallable_drains_pot")
    assert hits == []


def test_finalize_flag_after_transfer_fires():
    # A flag checked at entry but set AFTER the transfer
    # still fires: the transfer itself is unguarded.
    hits = hits_for(
        fx.EXTRA_VULN["finalize_recallable_drains_pot"],
        "finalize_recallable_drains_pot")
    assert hits, "flag-after-transfer spelling did not fire"
    assert hits[0]["report_class"] == "candidate"


def test_ledger_names_the_transfer_function():
    hits = hits_for(
        fx.VULN["internal_transfer_credit_without_debit"],
        "internal_transfer_credit_without_debit")
    assert [h["function"] for h in hits] == ["transferBetween"]
    assert "balances[to]" in hits[0]["detail"]
    assert hits[0]["recipient"] == "CALLER"


def test_ledger_matching_debit_silent():
    hits = hits_for(
        fx.CLEAN["internal_transfer_credit_without_debit"],
        "internal_transfer_credit_without_debit")
    assert hits == []


def test_ledger_external_transfer_silent():
    hits = hits_for(
        fx.EXTRA_CLEAN["internal_transfer_credit_without_debit"],
        "internal_transfer_credit_without_debit")
    assert hits == []


def test_existing_detectors_silent_on_batch23_fixtures():
    """Relevant existing detectors stay silent on every
    batch-23 fixture (vuln, clean, variant, extras)."""
    from app.plugins import deep_audit11 as da11  # noqa: E402
    from app.plugins import deep_audit3 as da3  # noqa: E402
    from app.plugins import deep_audit15 as da15  # noqa: E402
    from app.plugins import bsc_bep20  # noqa: E402
    from app.plugins import bsc_lending  # noqa: E402
    from app.plugins import bsc_staking  # noqa: E402
    from app.plugins.bsc_common import \
        analyze_bsc_source  # noqa: E402

    def _by_id(specs, pid):
        for s in specs:
            if s.id == pid:
                return s
        raise AssertionError(f"spec {pid} not found")

    checks = [
        ("lending_accumulator_donation_inflation",
         lambda src, spec: da11.analyze_deep11_source(src, spec),
         _by_id(da11.SPECS,
                "lending_accumulator_donation_inflation")),
        ("share_transfer_cancel_desync",
         lambda src, spec: da3.analyze_deep3_source(src, spec),
         _by_id(da3.SPECS, "share_transfer_cancel_desync")),
        ("claim_callback_before_claimed_flag",
         lambda src, spec: da15.analyze_deep15_source(src, spec),
         _by_id(da15.SPECS,
                "claim_callback_before_claimed_flag")),
        ("bep20_mint_cap_bypass",
         analyze_bsc_source,
         _by_id(bsc_bep20.SPECS, "bep20_mint_cap_bypass")),
        ("venus_accrue_interest_omission",
         analyze_bsc_source,
         _by_id(bsc_lending.SPECS,
                "venus_accrue_interest_omission")),
        ("flash_loan_spot_balance_check",
         analyze_bsc_source,
         _by_id(bsc_lending.SPECS,
                "flash_loan_spot_balance_check")),
        ("staking_total_shares_mismatch",
         analyze_bsc_source,
         _by_id(bsc_staking.SPECS,
                "staking_total_shares_mismatch")),
    ]
    all_fixtures = {}
    for group in (fx.VULN, fx.CLEAN, fx.VARIANT,
                  fx.EXTRA_CLEAN, fx.EXTRA_VULN):
        all_fixtures.update(group)
    for pid, fn, spec in checks:
        for fid, src in all_fixtures.items():
            hits = fn(src, spec)
            assert hits == [], (
                f"{pid}: fired on batch-23 fixture {fid}: "
                f"{hits}")
