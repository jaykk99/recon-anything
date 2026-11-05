# Crypto gap plugins + finding chaining (2026-10-27)

## Audit before building (registry at f5f55ce: 616 plugins, 211 cp_*, 34 phase-2)

Already covered, therefore NOT duplicated:
- Validated per-chain wallet addresses, ENS, lightning, payment URIs,
  miners, drainer/clipboard patterns, leaked secrets/keystores, Web3
  infra (known RPC hosts, chain IDs, token/NFT contracts in context,
  known DEX routers, bridges, Solana programs, oracles, Safe refs,
  hardhat artifacts, WalletConnect IDs, SIWE).
- Canonical contracts (WETH, USDT, USDC, DAI, Permit2, Seaport, ENS).
- Verified-source auditors: contract_audit, defi_risk, smartcontract
  (reentrancy, tx.origin, delegatecall, selfdestruct, proxy patterns,
  pause, mint, fees, oracles) on source fetched via chain APIs.
- Phase-2 chaining already existed implicitly: chain_osint and
  contract_audit consume contract_addresses, endpointauth consumes
  endpoints, jsdeep consumes js, graphql_deep consumes
  graphql_endpoints, email_breach/keyleak consume emails. No central
  map, cap, depth policy, or audit trail existed.

## Added

Task 1, `backend/app/plugins/cryptopack_web3_gaps.py` (all passive,
homepage + same-domain JS only, no chain calls, no signing/sending):
- cp_web3_token_abi: token symbol/decimals pairs + privileged ABI
  function names (mint, burn, pause, blacklist, ...).
- cp_web3_wallet_roles: role-attributed wallet addresses
  (owner, treasury, feeRecipient, devWallet, vault, admin, beneficiary).
- cp_web3_rpc_misconfig: http RPC URLs, RPC ports over http,
  localhost/loopback RPC endpoints in client code. Never probed.
- cp_web3_rpc_method_refs: eth_sendTransaction,
  personal_unlockAccount, eth_sign references in public JS. No RPC call.
- cp_web3_proxy_slots: EIP-1967 implementation/admin/beacon slot
  constants (computed as keccak(label)-1) + proxy admin names in
  served artifacts.

Task 2, `backend/app/finding_chain.py` + `backend/app/plugins/chain_followups.py`:
- CHAIN_RULES maps finding-key prefixes and bus kinds to followup
  plugins (cmd_dns, cmd_http, endpointauth, jsdeep, contract_audit,
  chain_osint, email_breach, keyleak, graphql_deep, appintel).
- Depth limit 2, cap 20 plan items / 30 probes / 5 sub-links per
  item, dedupe, same-target scope check, crypto.com refused, full
  audit list on ctx.shared["chain_audit"].
- chain_followups (phase 2, graph) executes same-target web probes
  via the cached ctx.probe path and emits chain_plan findings for
  delegated followups. It publishes nothing back into the bus, so
  chaining cannot loop or fan out.
- Refinement (2026-10-27, Jay): deeper than pattern matches.
  Depth 1 probes confirm a finding for real (subdomain live,
  endpoint/JS status). Depth 2 follows links actually present in a
  depth-1 probe's text (href/src/bare URLs, including config/JS
  references the page itself links to), same target only, once,
  finding key chain_subfinding_link. Paths are never guessed or
  brute-forced, no login/auth bypass/credential use: credential
  URLs are skipped, secret-shaped items are masked (value + SHA-256
  fingerprint only) and never probed. A target exposing no secret
  gets no secret finding: nothing here guarantees one.

## Left out, and why (detection-only line)

- Credential-bearing RPC URLs: PackPlugin redaction is per-class and
  a credential URL needs value-level redaction; cp_secret_* /
  cp_node_rpc_creds already cover RPC credentials. The http patterns
  refuse to match any URL containing userinfo.
- Live chain reads (balances, holders, on-chain admin): left to
  chain_osint / contract_audit, which already do them read-only.
- Anything that would sweep, drain, sign, send, brute-force, bypass
  auth, confirm an exploit, or take over a contract: not built.
- A runner-level auto-enqueue of followup plugin jobs from findings:
  not built. All plugins already run in a run; this layer makes the
  chain explicit and auditable instead of adding a second scheduler
  with its own failure modes. That is a deliberate scope cut, not an
  oversight: the executing plugin plus the delegated phase-2 plugins
  already cover the followups the rules name.

## Proof

- `backend/tests/test_crypto_chain.py`: 12 tests (per-plugin
  positives + clean-page negatives, credential-URL non-leak,
  registry size 622, rule followups exist, dedupe/cap/depth/scope,
  blocked domain, secret masking, depth-2 link following with
  off-target and credential links refused, chain plugin execution
  without bus loop).
- Canary `canary-crypto-chain` (local fixtures only, stubbed ctx):
  all 5 new plugins fired on one fixture page and chain_followups
  produced a chain_plan (dig) + a chain_subdomain_live (HTTP 200)
  finding, with audit entries and no new bus items. The depth-2
  path is covered by the link-following test above (probed page
  text containing a same-target /docs link, an off-target link,
  and a credential link: only /docs is probed).
- Full suite: see PR report (python3 -m pytest from backend/).
