# Plugin dependency DAG

Machine-readable form: `backend/app/plugin_dag.json` (validated by
`backend/app/plugin_schema.py: PluginDAG`). This doc is the human
reading of the same graph.

## Layers

- **Layer -1, harness guard.** `agent_sandbox_syscall_deterministic_guard`
  wraps every plugin run (rlimits, env scrub, cwd jail, timeout, audit
  log). It is not a producer: no plugin depends on it, every plugin
  runs under it. True seccomp-bpf syscall filtering is NOT claimed;
  the guard reports it as unenforceable-here.
- **Layer 0, parsers.** Raw bytes/text into structured artifacts:
  `evm_cfg_basic_block_reconstructor` (CFG blocks + guard dominance),
  `eof_container_code_section_verifier` (verified code sections),
  `merkle_patricia_trie_state_proof_verifier` (state proofs),
  `solana_bpf_elf_syscalls_disassembler` (syscall map),
  `wasm_linear_memory_export_inspector`, `protobuf_wire_format_schema_inferrer`,
  `git_packfile_dangling_blob_carver`, `container_overlayfs_whiteout_layer_differ`.
- **Layer 1, analyzers.** Pattern and symbolic checks over parser
  artifacts and source. The EVM analyzers read verified source;
  the Solana analyzers read Rust/Anchor source, IDL, or ELF;
  the infra analyzers read the target's public surface (passive
  only) or a supplied artifact. No analyzer reaches beyond its
  inputs: if a layer-0 artifact is absent, the analyzer degrades
  to ok(0) with a reason, never a guess.
- **Layer 2, correlators.** Combine analyzer outputs across
  contracts, bundles, and chains: `jito_bundle_tip_auction_correlator`,
  `cross_rollup_sequencer_liveness_monitor`,
  `optimistic_fraud_proof_challenge_window_tracker`,
  `blob_kzg_commitment_da_correlator`.
- **Layer 3, harness consumers.** The evidence pack (bundles
  analyzer outputs into the per-finding evidence pack), the
  auto-validator (live-probe verdicts), and the existing surface
  detectors that consume the new outputs: `cp_secret_nsec`
  (extracted secrets), `bank` / `bank_surface` (routing, TLS,
  zone, trust), `bridge` (routing, drop signatures, TLS).
  Two in-flight detectors also consume this DAG
  (`zeroday_exploit_chain`, `business_logic_invariants`); they are
  separate builders and are marked `planned_plugin` in the JSON.

## Key wirings

- CFG reconstructor -> Z3 storage taint tracer -> 0-day exploit
  chain and auto-validator. The CFG tells the tracer which blocks
  a value can reach; the tracer proves with Z3 whether an attacker
  can force a storage slot to a chosen value.
- EOF verifier -> CFG reconstructor. Only verified code sections
  are fed into CFG reconstruction.
- Diamond selector tree -> 0-day chain and validator. The tree is
  the selector-to-facet map; the chain detector reads it for
  shadowing and overwrite shapes.
- BPF disassembler -> CPI tracer, discriminator fuzzer,
  Token-2022 resolver. One ELF parse feeds all three Solana
  analyzers.
- ALT resolver -> Jito correlator. Resolved lookup-table
  addresses are what the bundle correlator checks for sandwich
  and tip-routing shapes.
- MPT proof verifier -> sequencer liveness and fraud-window
  tracker. State proofs are the evidence both monitors cite.
- Blob KZG correlator -> sequencer liveness -> fraud-window
  tracker. Missing DA explains stalled batches; stalled batches
  shorten the effective challenge window.
- Infra fingerprinters -> bank / bank_surface / bridge. Routing
  anomalies (BGP/RPKI, anycast), TLS fingerprints (QUIC, JA4,
  QPACK, TCP ISN), and zone exposure (NSEC3) feed the surface
  detectors that already know how to score a bank or bridge.
- Artifact inspectors -> secret detectors. Heap-snapshot,
  asar, APK/JNI, Mach-O, and packfile carvers feed
  `cp_secret_nsec` with extracted secrets (never raw values
  in the DAG: the artifact is the secret class and location).
- Config/cloud analyzers -> evidence pack. Trust graphs, drift
  reports, CVE links, SAML lint, Kerberos/LDAP audits, and the
  stylometry OPSEC exposure are bundled as evidence, not as
  standalone verdicts.

## Rules the DAG enforces

1. **Simulation-only producers are capped at UNVERIFIED.**
   `erc4337_entrypoint_paymaster_simulator` and
   `anchor_discriminator_collision_fuzzer` emit candidates whose
   `proof` field is `simulation_only`. The auto-validator never
   promotes them to VERIFIED_REAL; only a live eth_call probe
   from an unfunded stranger can do that.
2. **Passive only for infra fingerprinters.** The network
   fingerprinters (BGP, QUIC, JA4, TCP ISN, NSEC3, anycast,
   QPACK, XDP) read only what the target's public surface
   already sends during the scan's normal fetches, or the
   target's own public DNS/RPKI data. No port sweep, no
   crafted probing, no third-party enumeration. Anything that
   would need to actively probe or enumerate a third party's
   live infra beyond its public surface is detection-equivalent
   only (flag the exposure from public data).
3. **No guessing.** A plugin with no input artifact returns
   ok(0) with the reason named. A degraded scan is never
   reported as clean.
4. **Detection only.** No exploit execution, no broadcasting
   transactions, no pulling money out, no private-data access,
   no credential harvesting. Crypto.com is never a target.
5. **Stylometry is OSINT, not a vulnerability.** It profiles
   public commit metadata and flags OPSEC exposure. It never
   identifies a private individual and never feeds a verdict.
