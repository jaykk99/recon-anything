# Self-writing detector loop + fork-PoC runner (Lane 3, 2026-11-15)

## The loop — `../codegen_loop.py`

When a scan needs a detector ReconAnything lacks, the system
generates it itself:

1. `gap` — mines `~/workspace/recon-continuous/results/candidates.jsonl`
   for the biggest uncovered shape.
2. `draft` — asks the LLM advisor chain (Bro gateway, model `bro`,
   `http://127.0.0.1:8898/v1/chat/completions`) for detector code. The
   draft is **untrusted text** until the gates pass; a gateway failure
   fails soft (no invented draft).
3. Install is a **reviewed edit**, never a paste. The first draft
   proved why: it read a `"payable"` key `_Scope` never sets, so it
   could never fire. See the analyzer docstring in
   `../plugins/deep_audit.py` (`_analyze_native_vault_inflation`).
4. `gate` — the planted positive fixture MUST fire; every negative
   MUST stay silent (WETH9, real OpenZeppelin ERC4626 in
   `fixtures/oz-erc4626.sol`, guarded vaults). Any miss or false
   positive = REJECTED, no registration.
5. `register` — verifies `discover()` sees the new plugin id and emits
   the runner-side registration fragment. The live runner is never
   edited by this script.

First generated detector: `native_vault_share_inflation`
(`deep_audit.py`). Gap: 452/747 backlog candidates are vault-template
contracts, yet `vault_share_inflation` requires `totalAssets()` and
fires 0 times on the planted native-ETH vault fixture. Gate: 7 passed
(`tests/test_codegen_native_vault.py`).

## Fork-PoCs — `fork_poc.py`, `pocs/`, `poc-runs/`, `poc_4_positive_control.py`

Fork-only, never live broadcast. Each PoC is a JSON definition
(hypothesis, steps, reads, what VERIFIED_REAL would still need) run
against a local `anvil --fork-url` instance. Sends use `--unlocked`
(anvil signs for its default accounts); no private key is handled
anywhere — `cast`'s `--private-key` raw-tx path fails against this
anvil build with a spurious "Insufficient funds" error.

Results (2026-11-15, fork blocks recorded in each run file):

| PoC | Target | Outcome |
|-----|--------|---------|
| poc-1 (+1b boundary) | AGVE `mintTo`, Arbitrum 0x848e… | Reverts `W37: Too large mint` at every amount incl. 1 wei: stranger minter limit is 0. Live amount-0 probe success was vacuous. Not stranger-drainable. |
| poc-2 | AGVE `withdrawTo`, Arbitrum 0x848e… | `mintTo` fails (same cap); `withdrawTo` reverts `ERC777: burn amount exceeds balance`: caller-metered, burns own balance. Not a stranger drain. |
| poc-3 | DRIP `mint`, BSC 0x20f6… | Reverts `not whitelisted`: mint is allowlisted. Not stranger-drainable. |
| poc-4 (positive control) | Planted InflatableVault, local anvil | Attack executes: victim deposits 1 ETH for 0.0833e18 shares, attacker drains vault to 0 wei, attacker net +0.9999 ETH, victim −1.0 ETH. Proves the harness works; the live PoC reverts are properties of those contracts. |

All fork verdicts stay UNVERIFIED by design. Nothing here is proof
for VERIFIED_REAL; each run file states exactly what live evidence
would still be needed.
