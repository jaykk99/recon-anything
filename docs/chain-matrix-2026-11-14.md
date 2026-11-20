# Chain coverage & findings — 2026-11-14

Test of ReconAnything's chain stack against 22 requested chains plus the
three stablecoins (USDT, USDC, DAI). One row per chain; 25 rows total.

Harness: `test_chain_matrix.py` (repo root). Raw data:
`runs/chain_matrix.json`. Regression gate:
`backend/tests/test_chain_health.py`. Reproduce with:

```bash
python3 test_chain_matrix.py --offline   # detection + routing only
python3 test_chain_matrix.py             # + keyless live probes
```

## Result (after fixes)

| Metric | Before | After |
|---|---|---|
| Address detection (checksum-validated) | 25 / 25 | **25 / 25** |
| Classified as a crypto target by the search bar | 13 / 25 | **25 / 25** |
| Chain detector actually scheduled for a pasted address | **0 / 25** | **25 / 25** |
| Live probe (where a lane exists) | 11 / 19 | **21 / 23** |
| EVM verified-source + static analysis | 6 / 6 configured chains | **7 / 7** (Avalanche added) |
| Chained contract source analyzed | 14.5 KB / 18 issues (USDT), 18.9 KB / 10 (BSC USDT), 21.0 KB / 12 (Polygon USDC), 21.1 KB / 12 (Arbitrum USDC), 1.5 KB / 1 (Optimism USDC), 21.1 KB / 12 (Base USDC), 10.8 KB / 12 (Ethereum USDC), 5.5 KB / 7 (DAI) | plus 12.7 KB / 12 (Avalanche USDC.e) |

`--offline` exits 0. The live run also exits 0: the two remaining live
failures (BCH, ZEC) are environmental and now surface as `DEGRADED`, not
as a clean result.

## Fix log

| ID | Severity | Status | What changed |
|---|---|---|---|
| F1 | Critical | **Fixed** | Address detectors (`AddressPackPlugin` in `cryptopack_util.py`) now accept `crypto_wallet`; `collect_texts` scans the target address itself; `chain_enrich` accepts wallet targets so the detected address is consumed and enriched in phase 2. 25/25 routing. |
| F2 | Critical | **Fixed for BTC/LTC/DOGE/DASH + TRON; BCH/ZEC degraded, not silent** | Blockchair (HTTP 430) replaced with Esplora (mempool.space, litecoinspace), dogechain.info, Dash Insight, and TronGrid-before-Tronscan. `chain_enrich` returns `DEGRADED` when every source refuses instead of OK/0. |
| F3 | Critical | **Fixed** | `_looks_like_btc` now verifies Base58Check + version byte, so SS58 keys are no longer labelled Bitcoin; Polkadot classifies as `dot`. |
| F4 | High | **Fixed** | `contract_chain.CHAINS` gained `avalanche` (43114, api.avax.network + publicnode, Sourcify source since avax Blockscout is 404, snowtrace explorer); aliases `avax`/`avaxc`; default probe order. Live: chainId 43114, 12.7 KB source, 12 findings. |
| F5 | High | **Fixed** | `polygon-rpc.com` (401 "API key disabled") removed from the Polygon RPC list; publicnode + dRPC answer 0x89. Live: 137/137. |
| F6 | Medium | **Fixed** | Classifier gained checksum-valid recognition for LTC, DOGE, DASH, BCH (cashaddr), TRX, XRP, ADA, ZEC, XMR, TON, SS58; Sui/Aptos via explicit `sui:` / `aptos:` prefix. 25/25 first-class. |
| F7 | Medium | **Mostly fixed** | New keyless lanes: Cardano (Koios), TON (Toncenter), Sui (GraphQL), Aptos (fullnode). Polkadot's only public API (Subscan) is API-key gated (HTTP 403), so it stays label-only; Monero stays detection-only by design. |
| F8 | Low | **Fixed** | Canonical-contract detector now covers USDT-TRON, USDT on BSC/Polygon, and USDC on Polygon/Arbitrum/Base/Optimism plus the Solana USDC/USDT mints. |

### Remaining limits (explicitly not "clean")

- **BCH and ZEC** still need a keyed source: Blockchair is the only
  indexer wired, it 430s keyless, and no keyless alternative answered
  (chaingraph 402, rest.bitcoin.com/insight/zcha.in unreachable). Both
  now report `DEGRADED: ... 1/1 chain lookup(s) refused upstream`.
- **Polkadot** has no keyless account API (Subscan 403).
- **Sui/Aptos** pasted bare (`0x` + 64 hex) are inherently ambiguous with
  hashes and each other; `sui:`/`aptos:` prefixes route them.

## Per-chain matrix (post-fix)

`plugins` = how many registered plugins would be scheduled if that
address were pasted as the scan target. `live` is one read-only call
through the project's own code path.

| Chain | Detector | Detect | Pasted target becomes | plugins | Live probe |
|---|---|---|---|---|---|
| Bitcoin | cp_btc_legacy | PASS | crypto_wallet | 470 | PASS balance 57.712, 67,503 txns |
| Litecoin | cp_ltc_validated | PASS | crypto_wallet | 470 | PASS (Esplora) |
| Dogecoin | cp_doge_validated | PASS | crypto_wallet | 470 | PASS (dogechain) |
| Bitcoin Cash | cp_bch_addr | PASS | crypto_wallet | 470 | FAIL HTTP 430 → DEGRADED |
| Dash | cp_dash_addr | PASS | crypto_wallet | 470 | PASS (Insight) |
| Ethereum | cp_eth_eip55 | PASS | crypto_wallet | 470 | PASS 1/1, 14.5 KB / 18 |
| Solana | cp_solana_addr | PASS | solana_contract | 32 | PASS RPC balance |
| BNB Chain | cp_eth_eip55 | PASS | crypto_wallet | 470 | PASS 56/56, 18.9 KB / 10 |
| TRON | cp_trx_validated | PASS | crypto_wallet | 470 | PASS 14,494.84 TRX (TronGrid) |
| Cardano | cp_ada_addr | PASS | crypto_wallet | 470 | PASS 1.0 ADA (Koios) |
| XRP Ledger | cp_xrp_addr | PASS | crypto_wallet | 470 | PASS 56,786.637 XRP |
| Toncoin | cp_ton_addr | PASS | crypto_wallet | 470 | PASS (Toncenter) |
| Polkadot | cp_dot_addr | PASS | crypto_wallet | 470 | n/a Subscan key-gated |
| Sui | cp_sui_addr | PASS | crypto_wallet (via `sui:`) | 470 | PASS 2,400.568 SUI (GraphQL) |
| Aptos | cp_aptos_addr | PASS | crypto_wallet (via `aptos:`) | 470 | PASS (fullnode) |
| Monero | cp_xmr_standard | PASS | crypto_wallet | 470 | n/a by design |
| Zcash | cp_zec_addr | PASS | crypto_wallet | 470 | FAIL HTTP 430 → DEGRADED |
| Polygon | cp_eth_eip55 | PASS | crypto_wallet | 470 | PASS 137/137, 21.0 KB / 12 |
| Avalanche C-Chain | cp_eth_eip55 | PASS | crypto_wallet | 470 | PASS 43114/43114, 12.7 KB / 12 |
| Arbitrum | cp_eth_eip55 | PASS | crypto_wallet | 470 | PASS 42161, 21.1 KB / 12 |
| Optimism | cp_eth_eip55 | PASS | crypto_wallet | 470 | PASS 10, 1.5 KB / 1 |
| Base | cp_eth_eip55 | PASS | crypto_wallet | 470 | PASS 8453, 21.1 KB / 12 |
| USDT (ETH) | cp_web3_canonical_contracts | PASS | crypto_wallet | 470 | PASS 14.5 KB / 18 |
| USDC (ETH) | cp_web3_canonical_contracts | PASS | crypto_wallet | 470 | PASS 10.8 KB / 12 |
| DAI (ETH) | cp_web3_canonical_contracts | PASS | crypto_wallet | 470 | PASS 5.5 KB / 7 |
| Avalanche X-Chain | cp_avax_addr | PASS | crypto_wallet | — | n/a bech32-only |

Monero sub-formats (integrated, subaddress) and Bitcoin
taproot/bech32 both validated in the same detector sweep (not separate
rows).

## Verification

- `python3 test_chain_matrix.py --offline` → 25/25 detection, 25/25
  crypto-classified, 25/25 detector scheduled, exit 0.
- `python3 test_chain_matrix.py` → 21/23 live probes pass; 25/25
  detection/routing; exit 0.
- `pytest backend/tests/test_chain_health.py backend/tests/test_chain_enrich.py
  backend/tests/test_crypto_pack.py backend/tests/test_contract_recon.py
  backend/tests/test_bsc_rpc_failover.py backend/tests/test_chain_data.py`
  → 438 passed, 4 skipped.
- Wider sweep over every test module importing the changed modules
  (`classifier`, `chaindata`, `contract_chain`, `chain_enrich`,
  `cryptopack_util`): **1101 passed, 10 skipped, 4 failed**. All four
  failures are missing external tooling in this sandbox
  (`mythril` adapter returns no hits; the AST map plugin reports
  `ast_map_not_produced` without solc/surya) — unrelated to these
  changes and reproduced in isolation.
- Live end-to-end enrichment: BTC `chain_enrich` returns
  `enriched 1` with a real balance/activity finding; BCH returns
  `DEGRADED: ... refused upstream` (never a clean OK).

## Not tested

FastAPI server/API, UI, auth, write paths, the remaining ~1,400 plugins,
non-EVM contract analysis depth (Solana/Cardano/XRP/Sui source plugins),
and any scan against a live third-party target. Latency figures are
single probes from this sandbox.

## Method notes

- Detection runs the registered plugin class over a stubbed page through
  `collect_texts` → `PATTERNS` → checksum validator, i.e. the real code
  path, not a reimplementation.
- The live EVM probe uses `contract_chain._rpc_post`, `rpc_get_code`,
  `fetch_verified_source` and `analyze_contract_source`; non-EVM probes use
  `chaindata` constants and parsers (Esplora, dogechain, Insight,
  TronGrid, Koios, Toncenter, Sui GraphQL, Aptos fullnode).
- Address samples are deterministic, checksum-correct fixtures (BIP-173
  vector, Satoshi genesis address, cashaddr spec vector, EIP-55 spec
  vector, SS58, TON CRC16, XMR Keccak) generated with the pack's own
  encoders.
