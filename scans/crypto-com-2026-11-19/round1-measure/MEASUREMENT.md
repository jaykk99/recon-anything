# Round-1 false-positive fix — measurement

Round 1 (crypto.com 20-target full-registry scan, origin/master
`3f90afdf`, registry 1490) found 36 candidates: 34 FALSE_POSITIVE,
2 UNVERIFIED, 0 VERIFIED_REAL. This directory records the
before/after measurement of the 5 blamed detector families over
the 10 Round-1 targets that produced candidates, using
`measure_fix.py` (same candidate rule as `scan_fullreg.py`:
high/critical + CALLER / CALLER-SUPPLIED).

## Runs (candidates per plugin: CFG / Z3 / mint / eip712 / unchecked)

| Run | Backend | Total | CFG | Z3 | mint | eip712 | unchecked |
|---|---|---|---|---|---|---|---|
| baseline | master `3f90afdf` | 33 | 6 | 7 | 6 | 8 | 6 |
| gates-2 (read-only) | `feat/detector-live-gates-2-2026-11-19` @ `6beb6b3a` | 18 | 5 | 7 | 0 | 0 | 6 |
| after cherry-pick | this branch @ `4f048c0c` (cherry-pick of `3cbaf36b`) | 25 | 6 | 7 | 6 | 0 | 6 |
| after fixes | this branch (fixes + tests) | **2** | 0 | 2 | 0 | 0 | 0 |

Baseline reproduces 33 of the 36 expected rows; the 3 misses
(CFG `setOwner` WETH, CFG `approve` Match Ready Lions, Z3
`setOwner` DAI) are transient source-fetch misses, scattered
across plugins/targets, and each row fires in other runs. No
run produced a candidate outside the expected 36.

- Gates-2 genuinely silences eip712 x8, recipient_mint x6, and
  CFG `approve` x2 (ExpGear + Match Ready Lions). Its mint/claim
  machinery was NOT duplicated here.
- The cherry-pick silences exactly the 8 eip712 rows (25 = 33 - 8).
- The fixes in this branch silence the residual 23 false
  positives: CFG/Z3 `setOwner` x12 (DSAuth `auth`), CFG
  `approve` x2 (local declaration), recipient_mint x6
  (delegation to the `auth`-gated mint), unchecked_math x6
  (internal mint helpers, gated entries only).

## Residual (2 candidates, both UNVERIFIED, no detector fix can close them)

- `symbolic_z3_storage_taint_tracer` `updateMaxSupply` on
  Expedition Gear (`0xaE50f345502aD3395DB0099d38692f609F829B58`)
  and Match Ready Lions (`0xcCEf054E827A5e867194aD2cfBf8A83545D00cBF`):
  genuinely ungated public writes, kept firing by design
  (see `test_z3_updateMaxSupply_still_fires`).

## Guard tests

`backend/tests/test_detector_live_gates_2.py` (round-2 agent's
file, run from a /tmp copy against this backend): 10/28 pass at
baseline, 12/28 after these fixes (flipped
`test_super_delegated_role_gate_silences` and
`test_cfg_local_owner_declaration_is_not_a_state_write`; all 10
baseline passes intact). The remaining 16 failures pin the
round-2 agent's own mint/claim/CFG machinery
(`_live_gate_reason`, priced/entitlement/PoW/signature/claim
gates, deep_audit5 721-mint, CFG debit/delegatecall/
caller-funded/tokenhub), which this branch deliberately does
not duplicate. New tests:
`backend/tests/test_crypto_com_loop_round1_gates.py` (13 tests,
all pass).
