"""Scan-time priority tiers for the scan budget (1500s since 2026-10-20).

A full scan has a HARD 1500s ceiling (was 80s, which cut most plugins and
made findings differ every run - Jay's order 2026-10-20: find more). The
runner dispatches plugins in
priority order and, as the budget runs out, stops starting new low-priority
plugins (they are recorded as ok(0) with a "skipped: time budget" note -
never an error, never a hang).

Tiers:
  HIGH (1) - direct vulnerability / exposure signal. These run first and are
             the last to be cut. Named by Jay: cves, leaks, exposures, vulns.
  MEDIUM (2) - default. Solid recon, runs after HIGH.
  LOW (3)  - slow enumeration with lower per-finding signal (subdomain brute
             force, wayback, deep crawls, crypto-adjacent scans). Runs last,
             cut first when the budget runs out.

Findings always win over speed: a cut plugin is never silently dropped, it
gets an explicit "skipped: time budget" note in its result reason.
"""
from __future__ import annotations

HIGH = 1
MEDIUM = 2
LOW = 3

# Direct vuln probes + exposure/leak finders: run first, cut last.
HIGH_PRIORITY = {
    "cves",
    "sqli", "nosqli", "xss", "ssrf", "ssti", "rce", "cmdi",
    "idor", "bola", "xpathi", "htmli", "logici", "traversal",
    "leaks", "secrets", "keyleak", "creds", "email_exposure",
    "email_breach", "opendir", "git", "backup", "cloud_buckets", "s3",
    "takeover", "infodisclosure", "auth", "auth_surface", "cors",
    "clickjack", "tls", "headers", "dns", "waf", "email_infra",
}

# Slow, low-signal enumeration: runs last, cut first on a tight budget.
# Includes the empirically slow plugins (timeouts/hangs seen 2026-10-18:
# bounty, docker, cloud_buckets, backup, artifacts, emails, enterprise,
# exif, favicon_hash, financial) and the brute-force/deep-crawl class.
LOW_PRIORITY = {
    "subdomains", "wayback", "connections", "deepcrawl", "crawler",
    "social", "usernames", "phones", "pastes", "dorks", "bounty",
    "emails", "exif", "favicon_hash", "enterprise", "financial",
    "mobile", "docker", "hypervisor", "k8s", "iot", "supplychain",
    "giftcards", "giftinfra", "nft", "rugpull",
    "tokenapproval", "walletcheck", "wallets", "cryptoconfig",
    "cards", "credential_strength", "hashid",
    "asn_scan", "rdap", "pivots", "registry", "cloud", "ldapi",
    # Hunter source enumerators (2026-10-21): passive dataset queries,
    # wide but shallow - same tier as the other enumeration sources.
    "reverse_ip", "passive_dns", "rapiddns",
    # Native crawler/enumerator tools: heavy by nature, run last so
    # findings lead and enumeration trails. (Jay's order 2026-10-18.)
    "katana", "hakrawler", "wget", "httrack", "gobuster", "feroxbuster",
    "gau", "waybackurls", "stealth_crawler", "threat_monitor",
    "subdomain_brute", "port_scan", "port_audit",
    # Full-app extraction plugins: heavy by nature, run last so findings
    # lead and enumeration trails. (Jay's order 2026-10-18.)
    "allsources", "assetmap", "filehunter", "jsdeep",
}


# Bounty mode (Jay's order 2026-10-19): high-impact vuln classes run FIRST.
# These find the big stuff - RCE/SQLi/SSTI/SSRF/XXE/auth/IDOR/secrets.
BOUNTY_BOOST = {
    "sqli", "nosqli", "ssti", "ssrf", "rce", "cmdi", "xxe", "xpathi",
    "idor", "bola", "idor_comparator", "auth", "auth_surface", "authscan",
    "traversal", "logici", "deserialization",
    "js_secrets", "secrets", "keyleak", "gitleaks_scan", "creds",
    "graphql", "graphql_deep", "apidiscover", "param_discovery",
    "endpointauth", "forms", "jsdeep",
}

# Contract detectors (Wave 1.1, investigator loop): the bounty
# queue is contract-first. Ids harvested from the SPECS of the
# deep_audit / deep_lowlevel / deep_solana / bsc_* /
# recipient_first families at master aa5194c, plus the named
# contract engine plugins. A detector id here runs FIRST in
# bounty mode instead of being cut first under budget.
CONTRACT_BOOST = {
    # deep_audit (5)
    "aa_validation_ungated", "diamond_cut_ungated", "ecrecover_zero_signer", "readonly_reentrancy_gap",
    "vault_share_inflation",
    # deep_audit2 (6)
    "bridge_replay_unbound_digest", "create2_metamorphic_redeploy", "eip7702_unverified_delegate", "fee_on_transfer_overcredit",
    "hook_cei_reentrancy", "l2_sequencer_uptime_missing",
    # deep_audit3 (5)
    "eip712_digest_unbound_to_payload", "inverted_division_zero_collapse", "share_transfer_cancel_desync", "transient_latch_unconsumed",
    "v4_hook_shared_delta_take_pair",
    # deep_audit4 (3)
    "bridge_proof_length_unvalidated", "bridge_root_zero_assertion", "spot_price_own_balance",
    # deep_audit5 (12)
    "default_admin_grant_exposed", "eip1271_magic_value_unchecked", "eip712_separator_unbound", "erc1155_batch_receiver_missing",
    "erc20_missing_return_guard", "erc2771_msg_sender_unbound", "erc721_mint_without_receiver_check", "multisig_threshold_setter_unsafe",
    "pause_coverage_missing", "renounce_role_last_admin", "signature_nonce_unconsumed", "two_step_ownership_missing",
    # deep_audit6 (9)
    "chainlink_price_unbounded", "hardcoded_decimals_scaling", "shadowed_state_variable_legacy", "strict_balance_equality",
    "swap_deadline_unbound", "swap_fixed_min_amount_out", "twap_observe_window_short", "unchecked_math_user_input",
    "view_price_no_reentrancy_protection",
    # deep_audit7 (12)
    "beacon_implementation_zero_accepted", "bridge_bytes_proof_length_unvalidated", "bridge_digest_no_destination_chain", "bridge_mint_burn_gate_asymmetry",
    "bridge_nonce_order_unenforced", "bridge_payload_slice_unbounded", "bridge_proof_nullifier_missing", "bridge_receiver_sender_unchecked",
    "bridge_static_gas_limit", "diamond_selector_collision", "initializer_flag_after_call", "uups_authorize_upgrade_missing",
    # deep_audit8 (14)
    "cross_function_guard_sibling", "ecdsa_recover_zero_unchecked", "empty_signature_accepted", "eth_send_stipend_brick",
    "fallback_state_write_extended", "hardcoded_hash_constant_mismatch", "merkle_leaf_single_hash", "multicall_value_reuse",
    "packed_encoding_collision", "push_payment_revert_dos", "raw_ecrecover_s_unbounded", "reentrancy_guard_uninitialized",
    "token_callback_caller_unverified", "weak_randomness_value_outcome",
    # deep_audit9 (8)
    "assembly_fmp_literal_corruption", "assembly_returndatacopy_unbounded", "block_number_as_time", "coinbase_decision_input",
    "growable_array_loop_no_pagination", "hardcoded_zero_role_address", "private_sensitive_state_var", "state_change_without_event",
    # deep_audit10 (5)
    "eip7702_low_slot_collision", "forwarder_execute_spoof", "liquidation_bonus_to_borrower", "multicall_2771_sender_spoof",
    "withdraw_rounding_drain",
    # deep_audit11 (5)
    "amm_scale_rounding_wrong_direction", "batch_deferred_check_flag_reset", "lending_accumulator_donation_inflation", "liquidation_residual_collateral_reborrow",
    "transient_slot_reuse_auth_bypass",
    # deep_audit12 (5)
    "aa_execute_ungated", "intent_deposit_ghost_credit_no_rollback", "scheduled_settlement_books_unpaid", "vesting_release_cancel_double_debit",
    "zero_amount_withdrawal_full_balance",
    # deep_audit13 (4)
    "paymaster_sponsorship_unbounded", "pyth_price_unsafe_unchecked", "residual_balance_sweep_ungated", "stale_permission_after_replacement",
    # deep_audit14 (5)
    "callback_token_cei_violation", "forwarder_library_msgdata_tail_confusion", "governance_no_snapshot_immediate_seat", "lending_collateral_price_provider_unvalidated",
    "vault_underwrites_attacker_created_pool",
    # deep_audit15 (5)
    "claim_callback_before_claimed_flag", "negative_fee_mint_inflation", "post_slash_erc4626_offset_inversion", "scaled_allowance_overapproval",
    "unsafe_narrowing_cast_collateral_zero",
    # deep_audit16 (2)
    "approval_binds_id_not_version", "zero_amount_withdraw_all",
    # deep_audit17 (1)
    "zeroday_exploit_chain",
    # deep_audit18 (1)
    "multitoken_deposit_length_mismatch",
    # deep_audit19 (4)
    "ecrecover_no_malleability_guard", "permit_no_domain_separator", "signature_replay_no_nonce", "weak_onchain_randomness",
    # deep_lowlevel (12)
    "circom_r1cs_underconstrained_wire_checker", "diamond_erc2535_facet_selector_tree", "eof_container_code_section_verifier", "erc4337_entrypoint_paymaster_simulator",
    "erc7579_modular_account_hook_inspector", "evm_cfg_basic_block_reconstructor", "gnosis_safe_fallback_handler_mutator_check", "halo2_lookup_table_range_profiler",
    "merkle_patricia_trie_state_proof_verifier", "symbolic_z3_storage_taint_tracer", "transient_storage_tstore_lifecycle_auditor", "zk_snark_verifier_vk_parameter_auditor",
    # deep_solana (6)
    "alt_address_lookup_table_resolver", "anchor_discriminator_collision_fuzzer", "jito_bundle_tip_auction_correlator", "solana_bpf_elf_syscalls_disassembler",
    "solana_cpi_privilege_escalation_tracer", "token2022_transfer_hook_program_resolver",
    # bsc_* (100)
    "access_control_arbitrary_call_injection", "access_control_hierarchical_privilege_leak", "access_control_multi_sig_threshold_bypass", "access_control_ownership_renunciation_trap",
    "access_control_role_revocation_hole", "access_control_tx_origin_reliance", "access_control_unprotected_initializer", "bep1155_batch_transfer_balance_mismatch",
    "bep20_allowance_double_spend", "bep20_arbitrary_minting_endpoints", "bep20_balance_of_side_effects", "bep20_blacklist_authority_check",
    "bep20_burn_from_overflow", "bep20_decimal_mismatch", "bep20_fake_transfer_events", "bep20_mint_cap_bypass",
    "bep20_owner_privilege_abuse", "bep20_transfer_fee_miscalculation", "bep721_mint_index_overflow", "bep721_reentrancy_on_safe_mint",
    "bridge_deposit_event_spoofing", "bridge_emergency_pause_lockup", "bridge_message_payload_injection", "bridge_native_gas_drain",
    "bridge_validator_quorum_manipulation", "bridge_withdrawer_identity_spoof", "bridge_wrapped_token_mint_unbacked", "ecdsa_nonce_reuse_vulnerability",
    "ecdsa_signature_malleability", "ecdsa_signature_replay_cross_chain", "flash_loan_callback_auth_bypass", "flash_loan_governance_takeover",
    "flash_loan_repayment_underflow", "flash_loan_reward_dilution", "flash_loan_spot_balance_check", "gamefi_asset_duplication_on_burn",
    "gamefi_randomness_blockhash_reliance", "gamefi_state_desync_reward_claim", "gas_denial_of_service_loop", "governance_cancel_privilege_abuse",
    "governance_early_execution_race", "governance_proposal_threshold_gaming", "governance_quorum_calculation_flaw", "governance_signature_replay",
    "governance_state_staleness", "governance_vote_double_delegation", "lending_pool_collateral_seizure_gap", "lending_pool_liquidation_incentive_overflow",
    "marketplace_atomic_match_frontrun", "marketplace_expired_order_execution", "marketplace_fee_deduction_underflow", "marketplace_royalties_recipient_spoofing",
    "masterchef_deposit_fee_skimming", "masterchef_duplicate_pool_registration", "masterchef_emergency_withdraw_lock", "masterchef_pending_reward_overflow",
    "masterchef_pool_length_oob", "masterchef_reward_token_depletion", "math_division_before_multiplication", "math_signed_unsigned_comparison",
    "math_unchecked_downcasting", "mev_arbitrary_liquidation_frontrun", "mev_block_number_lock_bypass", "mev_sandwich_attack_vulnerability",
    "pancake_add_liquidity_dust_leak", "pancake_flash_swap_reentrancy", "pancake_insufficient_slippage_protection", "pancake_k_value_invariant_violation",
    "pancake_lp_token_burn_logic", "pancake_pool_skimming_vulnerability", "pancake_price_oracle_manipulation", "pancake_remove_liquidity_frontrun",
    "pancake_swap_exact_tokens_underflow", "pancake_v2_v3_router_misdirection", "proxy_beacon_address_manipulation", "proxy_cloning_initial_state_leak",
    "proxy_delegatecall_selfdestruct", "proxy_deterministic_deployment_collision", "proxy_function_clashing", "proxy_implementation_uninitialized",
    "proxy_shadow_variable_override", "proxy_storage_collision_detector", "proxy_transparent_admin_misdirection", "proxy_upgrade_authorization_gap",
    "staking_lockup_duration_bypass", "staking_reward_compounding_reentrancy", "staking_total_shares_mismatch", "staking_zero_deposit_harvest",
    "system_assembly_memory_overwrite", "system_ether_transfer_fallback_brick", "system_hardcoded_gas_limits", "system_selfdestruct_funds_trap",
    "system_stale_oracle_data", "system_unbounded_fee_parameter", "timelock_delay_bypass", "timelock_execution_gas_exhaustion",
    "timelock_queue_transaction_collision", "venus_accrue_interest_omission", "venus_comptroller_state_sync", "venus_mint_rate_assumption",
    # recipient_first (6)
    "recipient_bridge_release_unproven", "recipient_mint_to_caller", "recipient_overdraw_withdraw", "recipient_rescue_to_param",
    "recipient_sig_value_to_self", "recipient_unbacked_claim",
    # named contract engine plugins
    "contract_audit", "auto_validator", "contract_fuzz",
    "anvil_fork_probe", "fork_attack_path_complete",
    "zeroday_contract_guards",
}


def priority_for(plugin_id: str, bounty: bool = False) -> int:
    """1 = HIGH (run first), 2 = MEDIUM (default), 3 = LOW (run last).

    In bounty mode, high-impact vuln classes jump the queue.
    """
    if bounty and (plugin_id in BOUNTY_BOOST
                   or plugin_id in CONTRACT_BOOST):
        return HIGH
    if plugin_id in HIGH_PRIORITY:
        return HIGH
    if plugin_id in LOW_PRIORITY:
        return LOW
    return MEDIUM


def tier_name(tier: int) -> str:
    return {HIGH: "high", MEDIUM: "medium", LOW: "low"}.get(tier, "medium")
