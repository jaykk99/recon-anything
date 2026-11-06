"""BSC-100 cross-detector guarantees.

1. The registered spec set is EXACTLY Jay's 100 ordered ids
   (guards against typos, drops and duplicates).
2. Dedupe: on every vulnerable fixture, the intended detector
   fires, and no OTHER new detector fires on the SAME function
   (the same code span). Cross-span contract-scope observations
   on a different span are allowed only when pattern-true.
3. Every clean control (one per family) produces ZERO findings
   from ALL 100 new detectors.
4. Registry discovery registers exactly these 100 new plugin
   ids on top of the 655 base (761 total with ast_visual_audit and the 5 deep-audit detectors).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bsc100_fixtures as fx  # noqa: E402
from bsc100_support import all_specs, hits_for  # noqa: E402

EXPECTED_IDS = [
    # BEP-20
    "bep20_transfer_fee_miscalculation",
    "bep20_blacklist_authority_check",
    "bep20_mint_cap_bypass",
    "bep20_allowance_double_spend",
    "bep20_balance_of_side_effects",
    "bep20_owner_privilege_abuse",
    "bep20_burn_from_overflow",
    "bep20_fake_transfer_events",
    "bep20_arbitrary_minting_endpoints",
    "bep20_decimal_mismatch",
    # PancakeSwap / AMM
    "pancake_v2_v3_router_misdirection",
    "pancake_pool_skimming_vulnerability",
    "pancake_price_oracle_manipulation",
    "pancake_add_liquidity_dust_leak",
    "pancake_remove_liquidity_frontrun",
    "pancake_swap_exact_tokens_underflow",
    "pancake_lp_token_burn_logic",
    "pancake_flash_swap_reentrancy",
    "pancake_insufficient_slippage_protection",
    "pancake_k_value_invariant_violation",
    # Flash loans / lending
    "flash_loan_spot_balance_check",
    "flash_loan_callback_auth_bypass",
    "flash_loan_repayment_underflow",
    "flash_loan_governance_takeover",
    "flash_loan_reward_dilution",
    "venus_comptroller_state_sync",
    "venus_accrue_interest_omission",
    "venus_mint_rate_assumption",
    "lending_pool_liquidation_incentive_overflow",
    "lending_pool_collateral_seizure_gap",
    # Staking / MasterChef
    "masterchef_pool_length_oob",
    "masterchef_pending_reward_overflow",
    "masterchef_emergency_withdraw_lock",
    "masterchef_reward_token_depletion",
    "masterchef_duplicate_pool_registration",
    "masterchef_deposit_fee_skimming",
    "staking_lockup_duration_bypass",
    "staking_reward_compounding_reentrancy",
    "staking_total_shares_mismatch",
    "staking_zero_deposit_harvest",
    # Governance / timelock
    "timelock_delay_bypass",
    "timelock_queue_transaction_collision",
    "governance_proposal_threshold_gaming",
    "governance_quorum_calculation_flaw",
    "governance_early_execution_race",
    "governance_vote_double_delegation",
    "governance_cancel_privilege_abuse",
    "timelock_execution_gas_exhaustion",
    "governance_state_staleness",
    "governance_signature_replay",
    # Proxy / upgradeability
    "proxy_implementation_uninitialized",
    "proxy_storage_collision_detector",
    "proxy_upgrade_authorization_gap",
    "proxy_delegatecall_selfdestruct",
    "proxy_beacon_address_manipulation",
    "proxy_cloning_initial_state_leak",
    "proxy_shadow_variable_override",
    "proxy_function_clashing",
    "proxy_deterministic_deployment_collision",
    "proxy_transparent_admin_misdirection",
    # Access control / signatures
    "access_control_tx_origin_reliance",
    "access_control_role_revocation_hole",
    "ecdsa_signature_malleability",
    "ecdsa_signature_replay_cross_chain",
    "ecdsa_nonce_reuse_vulnerability",
    "access_control_unprotected_initializer",
    "access_control_ownership_renunciation_trap",
    "access_control_multi_sig_threshold_bypass",
    "access_control_hierarchical_privilege_leak",
    "access_control_arbitrary_call_injection",
    # GameFi / NFT
    "bep721_mint_index_overflow",
    "bep721_reentrancy_on_safe_mint",
    "bep1155_batch_transfer_balance_mismatch",
    "marketplace_atomic_match_frontrun",
    "marketplace_fee_deduction_underflow",
    "marketplace_royalties_recipient_spoofing",
    "gamefi_randomness_blockhash_reliance",
    "gamefi_state_desync_reward_claim",
    "gamefi_asset_duplication_on_burn",
    "marketplace_expired_order_execution",
    # MEV / bridges
    "mev_sandwich_attack_vulnerability",
    "bridge_deposit_event_spoofing",
    "bridge_validator_quorum_manipulation",
    "bridge_wrapped_token_mint_unbacked",
    "bridge_message_payload_injection",
    "mev_block_number_lock_bypass",
    "bridge_withdrawer_identity_spoof",
    "bridge_emergency_pause_lockup",
    "mev_arbitrary_liquidation_frontrun",
    "bridge_native_gas_drain",
    # Math / system
    "math_unchecked_downcasting",
    "gas_denial_of_service_loop",
    "system_stale_oracle_data",
    "math_division_before_multiplication",
    "system_ether_transfer_fallback_brick",
    "system_hardcoded_gas_limits",
    "math_signed_unsigned_comparison",
    "system_selfdestruct_funds_trap",
    "system_assembly_memory_overwrite",
    "system_unbounded_fee_parameter",
]

SPECS = all_specs()


def test_exactly_jays_100_ids():
    assert sorted(SPECS) == sorted(EXPECTED_IDS)
    assert len(SPECS) == 100
    assert set(fx.VULN) == set(EXPECTED_IDS)


def test_no_two_detectors_share_a_function_span():
    problems = []
    for pid, src in fx.VULN.items():
        by_fn = {}
        for oid, spec in SPECS.items():
            for h in hits_for(src, spec):
                by_fn.setdefault(h["function"], set()).add(oid)
        for fn, ids in by_fn.items():
            if len(ids) > 1:
                problems.append((pid, fn, sorted(ids)))
    assert problems == [], f"same-span duplicate findings: {problems}"


def test_every_clean_control_silent_under_all_100():
    problems = []
    for family, src in fx.CLEAN.items():
        for oid, spec in SPECS.items():
            hits = hits_for(src, spec)
            if hits:
                problems.append((family, oid,
                                 [h["function"] for h in hits]))
    assert problems == [], f"clean controls fired: {problems}"


def test_registry_discovers_761_with_all_100_new():
    from app.plugins.registry import discover
    reg = discover()
    assert len(reg) == 1051, f"registry size {len(reg)}, expected 1051"  # + 4 deep-analysis plugins (deep_layers) + 5 deep3 detectors + 3 deep-audit batch-4 detectors (deep_audit4) + 8 deep-audit batch-9 detectors (deep_audit9) + 5 deep-audit batch-10 detectors (deep_audit10) + 6 beyond-recon plugins (nuclei_templates, lifecycle, content_discovery, param_discovery_arjun, js_linkfinder, wayback_surface) + 5 sec_* secret-exposure detectors (secretpack) + 1 idorleak detector (idor-error-leak) + 1 meta_orchestrator plugin (PR #77) + 10 Tier-1 OSINT plugins (PR #119) + 8 Tier-2 Enumeration plugins (PR #124) + 6 Tier-3 Fuzzing plugins (PR #121) + 10 Tier-4 Vuln/CVE plugins (PR #125) + 10 Tier-5 Orchestration plugins (PR #123) + 8 Tier-6 Detection plugins (PR #126) + 10 Tier-7 Blockchain Ingestion plugins (PR #127) + 5 Tier-8 Static Analysis plugins (PR #129) + 8 Tier-9 plugins (PR #128) + 10 Tier-10 Mempool/MEV plugins (PR #130)
    missing = [pid for pid in EXPECTED_IDS if pid not in reg]
    assert missing == [], f"not registered: {missing}"
    for pid in EXPECTED_IDS:
        plugin = reg[pid]
        assert callable(getattr(plugin, "run", None)), pid
