# Crypto.com proxy implementations — full-plugin scan, Nov 18, 2026

**Date:** 2026-11-18 (runs executed 12:39–12:50 UTC).
**Ordered by:** daily code-quota grind, recon-anything lane (Tier 1).
**Follow-up to:** `~/workspace/crypto-com-deep-scan-2026-11-17/REPORT.md` §5,
which resolved both HackerOne proxy implementations first-hand via
`implementation()` eth_call but left them unscanned with the full plugin set.
**Code under test:** ReconAnything master `1266838e`
(`feat(contract): scan the dependency graph - surface + follow linked
contracts (#202)`), registry `discover()` = **1470**, import failures 0.
Batch 23 is merged on this master (PR #190), so all 30 deep-audit
detectors run from one backend for the first time: batches 20, 20b, 21,
22, 23, 24 (5 each).
**Boundaries held:** detection only; read-only live probes; no transactions
broadcast, no funds moved, no real-user accounts or data, nothing submitted
to HackerOne. Binance never touched.

## Verdict: VERIFIED_REAL: 0 — findings: 0 — candidates: 0

| Target | Address | Chain | Contract | Source | Plugins | Findings | Candidates | Time |
|---|---|---|---|---|---|---|---|---|
| LiquidETHV1 (CDCETH implementation) | `0x7e772ed6e4bfeae80f2d58e4254f6b6e96669253` | ethereum | LiquidETHV1 | yes (Blockscout, 81,452 chars) | 30 | 0 | 0 | 70.4s |
| CDCWrappedBTC (CDCBTC implementation) | `0xddcde8de19284cc5aab6db5ac6af1dcda175f5e2` | cronos | FiatTokenV2_1 | yes (Blockscout, 77,642 chars) | 30 | 0 | 0 | 24.4s |

Totals: 2 targets, 2 sourced, **60 plugin runs, 0 errors, 0 findings,
0 candidates**. Both contracts are Centre FiatToken V2_1-family logic
(`exchangeRate`, `oracle`, `permit`, `receiveWithAuthorization`,
`transferWithAuthorization`, `configureMinter`, `pause`, `blacklist`).
The proxies themselves were scanned Nov 17 (CDCETH proxy and CDCBTC proxy,
25 detectors each, 0 fires); this round closes the remaining gap by
scanning the implementation contracts that actually hold the logic.

## Why zero is real, not a harness failure

- Positive controls: the 6 batch test files plus their 6 plugin-run files
  pass on this exact master checkout — **173 passed in 32.62s**
  (`test_deep_audit{20,20b,21,22,23,24}.py` +
  `test_deep_audit{20,20b,21,22,23,24}_plugin_run.py`). The fixture tests
  assert VULN fixtures fire with their own kind and CLEAN fixtures stay
  silent, so working detectors returning nothing on these two contracts
  is a genuine negative.
- Cross-check: the same two targets were scanned earlier the same day
  from `/tmp` on the pre-merge backends (25 detectors on master `866932aa`,
  registry 1464, plus the 5 batch-23 detectors on PR #190 backend
  `dee3877e`, registry 1440): also 0 findings, 0 errors, with
  byte-identical source sizes (81,452 / 77,642 chars). The merge changed
  nothing about the outcome.
- Registry-count note: runtime `discover()` = 1470 here; the test pins in
  this tree also say 1470. `backend/app/nn/registry-plugin-ids.json`
  lists 1446 ids — stale by 24, same known drift noted Nov 17, not
  touched by this change.

## What this change adds to the repo

- `scans/crypto-com-2026-11-18/targets.json` — the two implementation
  contracts as scan targets (address, chain, proxy, source URLs, notes).
  The repo has no central target registry; this file is the target set
  for this scan, and the same two entries were also appended to the
  canonical round target set at
  `~/workspace/crypto-com-deep-scan-2026-11-15/targets.json` (now 20
  targets) so future rounds include them.
- `scans/crypto-com-2026-11-18/scan_impl30.py` — the scan driver, adapted
  from the Nov 17 round driver to run from inside the repo: it uses this
  repo's own `backend/` (relative path), loads targets from `targets.json`,
  runs all 30 deep-audit detectors, and writes findings/candidates/summary
  next to itself. Reproduce with `python3 scan_impl30.py` from this dir.
- `scans/crypto-com-2026-11-18/REPORT.md` (this file),
  `summary-<address>.json` (per-target counts/source/timing), and the
  empty `findings-<address>.jsonl` / `candidates-<address>.jsonl` files
  (0 bytes each — the empty evidence for the zero).
- `scans/crypto-com-2026-11-18/full-run.log` — the full run output.

## Caveats, recorded honestly

1. **The `implementation()` resolution was NOT re-verified live today.**
   Every Ethereum RPC tried timed out at connect (`ethereum.publicnode.com`,
   `eth.drpc.org`, `1rpc.io/eth`, 15s each) and `etherscan.io` /
   `api.etherscan.io` were unreachable from this VM during the run; the
   Cronos `implementation()` call also timed out. The Nov 17 first-hand
   resolution (via `ethereum.publicnode.com` and `cronos.drpc.org`) stands
   as last observed, and the fetched source (contract names `LiquidETHV1`
   / `FiatTokenV2_1`, matching sizes) is consistent with it — but a fresh
   `implementation()` re-check is still outstanding.
2. **Disk quota blocked the first half of the day.** All writes under
   `/home/hatch` failed with `EDQUOT` from ~12:18 UTC until ~12:44 UTC,
   when the quota freed (no files were deleted by this worker). The early
   scan runs therefore executed from `/tmp` against pre-existing
   worktrees; the authoritative run above executed from this worktree
   after home became writable again. One foreground scan attempt died
   with exit 120 and no output during the quota incident; the identical
   rerun completed cleanly.
3. **Cosmetic post-run edit:** the driver's startup label was renamed
   `new25_present` -> `new30_present` after the run (the run log still
   shows the old label). It affects only a print statement, not results.
4. **Coverage scope:** only the 30 source-level deep-audit detectors ran
   here. They are the detectors that could fire on verified FiatToken
   source; the full 1,470-plugin registry was not run over these two
   contracts in this round (the Nov 17 round likewise ran the 25/30 new
   detectors, not the full registry).
