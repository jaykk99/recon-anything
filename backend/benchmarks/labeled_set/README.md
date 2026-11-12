# Labeled regression set (Track 4)

Ground-truth labeled cases for measuring ReconAnything's inline
gates + validator v2, built from the project's own adjudication
history. Placement: `backend/benchmarks/labeled_set/`, next to the
existing `benchmarks/known_vuln_contracts.py` ground-truth module
that `tests/test_detection_benchmark.py` already uses.

## Files

- `labeled_set.jsonl` — one JSON record per case (379 cases).
- `build_labeled_set.py` — the builder that produced the set from
  the label sources below (rerunnable on a box that has them).
- `run_benchmark.py` — the offline regression harness.
- `benchmark_results.json` — output of the last real harness run.

## Record schema

`contract_id` (`chain:address`, or `fixture:<name>`), `chain`,
`address` (null for fixtures), `contract_name`, `function`,
`kind`, `bytecode` and/or `source` (as available; sources over
100 KB are not embedded), `expected_real_finding` (bool),
`vulnerability_type`, `verdict_class`, `notes`, `label_source`.

## Label sources (all verified present and used)

| Source | Cases added |
|---|---|
| recon-million-2026-11-06/results/corrections.jsonl | 32 |
| recon-v2-run-2026-11-08/results.jsonl (102-candidate v2 run) | 43 new (rest already in corrections) |
| recon-verify/verdicts.jsonl (2026-11-02 verification pass) | 120 (capped sample) |
| your_files/recon-findings-so-far-2026-11-05.md (1,098 findings) | 166 (all TRIGGER_ONLY in cap plan + samples) |
| benchmarks/known_vuln_contracts.py fixtures | 7 |
| tests/fixtures/fp_clean/*.sol | 11 |

Missing: the verify-182 sync dir
`~/workspace/recon-verify182-2026-11-07` is absent on this box.
The closest surviving artifact, `~/workspace/recon-verify/`
(2026-11-02 pass, 6,407 verdict rows over 1,540 contracts), was
used instead and is named as the label source on those records.

Class breakdown: 219 FALSE_POSITIVE, 91 UNVERIFIED, 51
TRIGGER_ONLY, 12 CLEAN_CONTROL, 6 KNOWN_VULNERABLE. No historical
case was ever VERIFIED_REAL, so `expected_real_finding` is true
only for the 6 canonical drain-pattern fixtures. Records #1 and
#2 are the MVK (BSC, claimReward) and aeWETH (Arbitrum,
withdrawTo) corrected false positives.

Deduped by (chain, address). Enrichment: verified source from the
v2-run / recon-verify src_caches (219 cases carry source),
bytecode/source from recon-rust-engine/sample1000.jsonl (23 cases
carry bytecode). crypto.com / Binance never appear as scan
targets: the builder excludes any case naming them (0 excluded —
none were present in the label sources).

## Gate rule

Any case with `expected_real_finding=false` that receives a
VERIFIED_REAL stamp from the harness pipeline is a FAIL. The
harness is offline measurement only; it never promotes anything
to VERIFIED_REAL in a production path. Cases that cannot be
live-probed offline are evaluated through the static gates /
validator logic that can run offline and are marked
`evaluation_mode=static_offline` in the results; fixture cases
are marked `fixture_analyzer`.
