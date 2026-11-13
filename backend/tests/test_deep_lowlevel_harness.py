"""Plugin DAG, Pydantic schemas, and sandbox guard
(feat/deep-lowlevel-50).

- The DAG file loads and validates: every edge references a
  known node, and all 50 new plugin ids are nodes.
- The Pydantic harness contract: a valid PluginOutput validates;
  a simulation_only finding may never be a candidate.
- The sandbox guard: a bad config is flagged, a clean config
  passes, and run_guarded executes a trivial command and
  records an audit.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.agent_sandbox_guard import (  # noqa: E402
    SandboxConfig, run_guarded, validate_config)
from app.plugin_schema import (  # noqa: E402
    PluginInput, PluginOutput, PluginFinding, load_dag,
    validate_plugin_output)
from app.plugins.registry import discover  # noqa: E402

NEW_IDS = [
    "evm_cfg_basic_block_reconstructor",
    "symbolic_z3_storage_taint_tracer",
    "diamond_erc2535_facet_selector_tree",
    "transient_storage_tstore_lifecycle_auditor",
    "eof_container_code_section_verifier",
    "erc4337_entrypoint_paymaster_simulator",
    "erc7579_modular_account_hook_inspector",
    "zk_snark_verifier_vk_parameter_auditor",
    "circom_r1cs_underconstrained_wire_checker",
    "halo2_lookup_table_range_profiler",
    "solana_bpf_elf_syscalls_disassembler",
    "anchor_discriminator_collision_fuzzer",
    "solana_cpi_privilege_escalation_tracer",
    "token2022_transfer_hook_program_resolver",
    "alt_address_lookup_table_resolver",
    "jito_bundle_tip_auction_correlator",
    "cross_rollup_sequencer_liveness_monitor",
    "optimistic_fraud_proof_challenge_window_tracker",
    "blob_kzg_commitment_da_correlator",
    "gnosis_safe_fallback_handler_mutator_check",
    "bgp_rpki_roa_hijack_anomaly_detector",
    "quic_initial_packet_version_fingerprinter",
    "ja4_tls_client_hello_entropy_profiler",
    "tcp_isn_clock_skew_uptime_estimator",
    "dnssec_nsec3_zone_walker",
    "anycast_pop_bgp_latency_triangulator",
    "http3_qpack_dynamic_table_fingerprinter",
    "ebpf_xdp_packet_drop_signature_prober",
    "wasm_linear_memory_export_inspector",
    "v8_heap_snapshot_closure_secret_extractor",
    "electron_asar_integrity_bypass_checker",
    "mobile_apk_native_jni_symbol_dumper",
    "ios_macho_entitlement_plist_extractor",
    "graphql_federation_subgraph_entity_resolver",
    "protobuf_wire_format_schema_inferrer",
    "mqtt_wildcard_topic_acl_enumerator",
    "etcd_raft_consensus_keyspace_dumper",
    "consul_gossip_serf_member_enumerator",
    "aws_sts_assume_role_trust_policy_grapher",
    "oidc_jwks_kid_cache_poison_surface_check",
    "saml_xml_signature_wrapping_structural_linter",
    "kerberos_spn_asrep_roastability_auditor",
    "ldap_schema_acl_delegation_pathfinder",
    "git_packfile_dangling_blob_carver",
    "container_overlayfs_whiteout_layer_differ",
    "terraform_state_backend_drift_extractor",
    "sbom_cyclonedx_transitive_cve_linker",
    "stylometry_commit_cadence_timezone_profiler",
    "merkle_patricia_trie_state_proof_verifier",
    "agent_sandbox_syscall_deterministic_guard",
]


def test_dag_loads_and_covers_all_fifty():
    dag = load_dag()
    node_ids = {n.id for n in dag.nodes}
    for pid in NEW_IDS:
        assert pid in node_ids, f"DAG node missing: {pid}"
    # Every edge references a node that exists (validated by the
    # model, but assert it plainly too).
    for e in dag.edges:
        assert e.from_ in node_ids, f"edge from unknown {e.from_}"
        assert e.to in node_ids, f"edge to unknown {e.to}"
    assert len(NEW_IDS) == 50


def test_dag_wires_cfg_into_taint_into_exploit_chain():
    dag = load_dag()
    edges = {(e.from_, e.to) for e in dag.edges}
    assert ("evm_cfg_basic_block_reconstructor",
            "symbolic_z3_storage_taint_tracer") in edges
    assert ("symbolic_z3_storage_taint_tracer",
            "zeroday_exploit_chain") in edges
    assert ("agent_sandbox_syscall_deterministic_guard",
            "evidence_pack") in edges


def test_schema_accepts_valid_output():
    out = PluginOutput(
        plugin_id="evm_cfg_basic_block_reconstructor",
        findings=[PluginFinding(
            plugin_id="evm_cfg_basic_block_reconstructor",
            category="cfg",
            key="unguarded_value_op",
            value="withdraw reaches .call with no dominating guard",
            source="deep low-level detector",
            severity="high",
            report_class="candidate",
            proof="static")])
    assert validate_plugin_output(out.model_dump()) is not None


def test_schema_rejects_simulation_only_candidate():
    with pytest.raises(Exception):
        PluginFinding(
            plugin_id="erc4337_entrypoint_paymaster_simulator",
            category="paymaster",
            key="uncapped_paymaster",
            value="paymaster pays without a cap",
            source="deep low-level detector",
            severity="medium",
            report_class="candidate",
            proof="simulation_only")


def test_schema_input_validates():
    inp = PluginInput(
        plugin_id="evm_cfg_basic_block_reconstructor",
        target={"kind": "crypto_wallet",
                "value": "0x0000000000000000000000000000000000000000"})
    assert inp.plugin_id == "evm_cfg_basic_block_reconstructor"


def test_sandbox_guard_flags_bad_config():
    cfg = SandboxConfig(allowed_syscalls=[], blocked_syscalls=[],
                        allow_network=True, allow_wall_clock=True,
                        fixed_seed=None, cpu_seconds=0, memory_mb=0)
    kinds = {v.kind for v in validate_config(cfg)}
    assert "no_syscall_restriction" in kinds
    assert "network_allowed" in kinds
    assert "wall_clock_allowed" in kinds
    assert "no_fixed_seed" in kinds
    assert "no_resource_caps" in kinds


def test_sandbox_guard_passes_clean_config():
    cfg = SandboxConfig(
        allowed_syscalls=["read", "write", "openat", "close"],
        blocked_syscalls=["execve", "socket", "connect", "ptrace",
                          "mount", "keyctl", "bpf",
                          "perf_event_open"],
        allow_network=False, allow_wall_clock=False, fixed_seed=42,
        cpu_seconds=60, memory_mb=512)
    # Only the honest unenforceable_here note remains; the config
    # itself has no gap.
    kinds = {v.kind for v in validate_config(cfg)}
    assert kinds == {"unenforceable_here"}


def test_sandbox_guard_runs_command():
    cfg = SandboxConfig(fixed_seed=42, cpu_seconds=30, memory_mb=512,
                        timeout_s=30)
    result = run_guarded(["/bin/echo", "hi"], cfg)
    assert result.ok is True
    assert result.audit["returncode"] == 0
    assert "hi" in result.audit["stdout_tail"]
