"""Wiring the investigator loop fixes (Wave 1.1): priority tiers,
deep lanes in the fast path, and the deep_audit12-19 / bsc_* /
recipient_first families running in loop-driven scans.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app.batch_scan as bs  # noqa: E402
from app.plugins.priority import (  # noqa: E402
    BOUNTY_BOOST, CONTRACT_BOOST, LOW_PRIORITY, priority_for)


def test_contract_classes_not_cut_first():
    # Wave 1.1: bridge/defi/smartcontract/crypto leave LOW_PRIORITY
    # (MEDIUM default) so loop-driven contract scans keep them.
    for pid in ("bridge", "defi", "smartcontract", "crypto"):
        assert pid not in LOW_PRIORITY, pid
        assert priority_for(pid) == 2, pid  # MEDIUM, not LOW(3)


def test_bounty_boost_gains_contract_ids():
    assert len(CONTRACT_BOOST) >= 200
    for pid in ("contract_audit", "auto_validator", "contract_fuzz",
                "anvil_fork_probe", "fork_attack_path_complete",
                "zeroday_contract_guards",
                "recipient_mint_to_caller",
                "recipient_overdraw_withdraw",
                "zero_amount_withdrawal_full_balance",
                "residual_balance_sweep_ungated",
                "pancake_k_value_invariant_violation",
                "proxy_storage_collision_detector",
                "vault_underwrites_attacker_created_pool",
                "ecrecover_no_malleability_guard",
                "solana_cpi_privilege_escalation_tracer",
                "uups_authorize_upgrade_missing"):
        assert pid in CONTRACT_BOOST or pid in BOUNTY_BOOST, pid
        assert priority_for(pid, bounty=True) == 1, pid
    # Non-bounty runs are unchanged for the engines.
    assert priority_for("contract_audit", bounty=False) == 2


def test_deep_lanes_extended_in_fast_path():
    analyzers = bs._load_deep_analyzers()
    # Was 11 deep_audit families + protocol + guard detector (13).
    # Now 20 deep_audit + deep_lowlevel + deep_solana + recipient_first
    # + 11 bsc_* families + protocol + guard detector.
    assert len(analyzers) >= 30, len(analyzers)


def test_deep12_fires_in_loop_scan():
    import deep_audit12_fixtures as fx
    vuln = fx.VULN["zero_amount_withdrawal_full_balance"]
    kinds = {f.get("kind") for f in bs.scan_source(vuln, deep=True)}
    assert "zero_amount_withdrawal_full_balance" in kinds
    clean = fx.CLEAN["zero_amount_withdrawal_full_balance"]
    clean_kinds = {f.get("kind") for f in bs.scan_source(clean, deep=True)}
    assert "zero_amount_withdrawal_full_balance" not in clean_kinds


def test_deep_stays_superset_and_gated_stays_silent():
    # Pre-existing guarantees must survive the lane extension.
    ungated = ('pragma solidity 0.8.19;\n'
               'import "x/UUPSUpgradeable.sol";\n'
               'contract Vault is UUPSUpgradeable { mapping(address=>uint) b;\n'
               ' function _authorizeUpgrade(address n) internal override {}\n'
               ' function withdraw(address t) external {'
               ' (bool k,)=t.call{value:address(this).balance}(""); } }')
    shallow = {f.get("kind") for f in bs.scan_source(ungated)}
    deep = {f.get("kind") for f in bs.scan_source(ungated, deep=True)}
    assert deep >= shallow
    assert "uups_authorize_upgrade_missing" in deep
    gated = ('pragma solidity 0.8.19;\n'
             'import "x/UUPSUpgradeable.sol";\n'
             'contract USDG is UUPSUpgradeable {\n'
             ' function _authorizeUpgrade(address n) internal override'
             ' onlyRole(DEFAULT_ADMIN_ROLE) {} }')
    kinds = {f.get("kind") for f in bs.scan_source(gated, deep=True)}
    assert "uups_authorize_upgrade_missing" not in kinds
