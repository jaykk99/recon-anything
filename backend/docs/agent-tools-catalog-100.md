# Agent-tools catalog: the 100-tool list, mapped

Jay's fourth catalog (100 Web3 security / auditing / wallet tools,
pasted Nov 11). Add-all rule: every item gets a plugin, a
detection-equivalent, or a named reason. Nothing dropped silently.

Dispositions:

- **LIVE** — a tool in this PR (`agent_*` on the MCP server, v2.2.0).
- **COVERED** — the capability already exists in the ReconAnything
  plugin registry (1,335 plugins on this branch) or in a merged PR.
- **EQUIV** — a detection-equivalent in this PR: the scanner flags the
  hole the tool would find, it does not run the tool's attack.
- **KEYED** — needs a sign-in, API key, or paid plan. Not built;
  keyless-only rule.
- **REF** — reference-only: a course, checklist, platform, company,
  or framework, not a runnable scanner capability.
- **UNVERIFIED** — no keyless public runner found; the capability
  class is covered by the registry.

Runners already on this machine (verified Nov 12): foundry
(cast/forge/anvil/chisel), aderyn, echidna, medusa, heimdall in
`~/workspace/tools/audit/bin/`; venvs `venv-slither` (slither 0.11.6
+ solc), `venv-mythril` (mythril 0.24.8), `venv-semgrep`,
`venv-manticore`, `venv-halmos`, `venv-securify`, `venv-wake` in
`~/workspace/tools/audit/`. Slither and Mythril are the two wired
into MCP tools in this PR; the other venvs are present but unwrapped
(their classes are covered by the EQUIV rows below).

| # | Tool | Disposition | How / why |
|---|------|-------------|-----------|
| 1 | Slither | LIVE | `agent_slither` (this PR). Pragma-matched solc, JSON detectors, 8/8 smoke OK. |
| 2 | Aderyn | EQUIV | Binary present (`audit/bin/aderyn`), no dedicated MCP tool in this PR. Static-analysis class covered by `agent_slither`. |
| 3 | Mythril | LIVE | `agent_mythril` (this PR). Smoke: 0 issues on AIDoge. |
| 4 | MythX | KEYED | Paid API, needs account + key. Static class covered by `agent_slither`. |
| 5 | Manticore | EQUIV | Venv present (`venv-manticore`), no wrapper in this PR. Symbolic-execution class covered by `agent_mythril`. |
| 6 | Securify | EQUIV | Venv present (`venv-securify`), no wrapper in this PR. Static class covered by `agent_slither`. |
| 7 | Oyente | REF | Unmaintained; superseded by Mythril. Class covered by `agent_mythril`. |
| 8 | Semgrep | EQUIV | Venv present (`venv-semgrep`), no wrapper in this PR. Pattern-matching class covered by the registry's own pattern detectors. |
| 9 | Echidna | EQUIV | Binary present (`audit/bin/echidna`), no wrapper in this PR. Fuzz class covered by `agent_fuzz` (bounded invariant fuzz on a fork). |
| 10 | Halmos | EQUIV | Venv present (`venv-halmos`), no wrapper in this PR. Fuzz class covered by `agent_fuzz`. |
| 11 | Certora | KEYED | Prover, paid, needs account. Formal-verification class has no keyless equivalent here. |
| 12 | Foundry | LIVE | `agent_cast` / `agent_forge` / `agent_anvil` (this PR). |
| 13 | Hardhat | EQUIV | JS toolchain, no keyless local install here. Fork/test class covered by `agent_forge` / `agent_anvil` (Foundry equivalents). |
| 14 | Brownie | EQUIV | Unmaintained Python toolchain. Class covered by `agent_forge` / `agent_anvil`. |
| 15 | Anvil | LIVE | `agent_anvil` (this PR). |
| 16 | Solhint | REF | Style linter only, no security findings. Security side covered by `agent_slither`. |
| 17 | EthLint | REF | Style linter only, no security findings. Security side covered by `agent_slither`. |
| 18 | SmartCheck | REF | Unmaintained. Static class covered by `agent_slither`. |
| 19 | SolidityScan | KEYED | Paid API. Static class covered by `agent_slither`. |
| 20 | Diligence Fuzzing | KEYED | ConsenSys paid service. Fuzz class covered by `agent_fuzz`. |
| 21 | sFuzz | EQUIV | Fuzz class covered by `agent_fuzz`. |
| 22 | ChainFuzz | EQUIV | Fuzz class covered by `agent_fuzz`. |
| 23 | Ultrafuzz | EQUIV | Fuzz class covered by `agent_fuzz`. |
| 24 | Fyzz | EQUIV | Fuzz class covered by `agent_fuzz`. |
| 25 | Octopus | EQUIV | Unmaintained decompiler. Bytecode class covered by the registry's bytecode detectors + `agent_fetch` (Sourcify). |
| 26 | Panoramix | EQUIV | Decompiler (web). Readable via `agent_fetch`; bytecode class covered by registry detectors. |
| 27 | Dedaub | EQUIV | Decompiler; full API needs a key. Public pages readable via `agent_fetch`; bytecode class covered by registry detectors. |
| 28 | abi-decompiler | EQUIV | Decompiler class covered by registry bytecode detectors + `agent_fetch`. |
| 29 | sc-auditor | EQUIV | Audit-helper CLI/LLM workflow. Class covered by `agent_slither` / `agent_mythril` + the registry. |
| 30 | solidity-auditor | EQUIV | Same as sc-auditor. |
| 31 | vyper-auditor | EQUIV | Same as sc-auditor, for Vyper. |
| 32 | rust-auditor | EQUIV | Same as sc-auditor, for Rust contracts. |
| 33 | GPTScan | KEYED | Needs an LLM API key. Static class covered by `agent_slither`. |
| 34 | AuditBase | KEYED | Platform, needs sign-in. |
| 35 | Octane | KEYED | Paid. |
| 36 | Solodit | REF | Checklist / reference resource. |
| 37 | Secureum | REF | Checklist / reference resource. |
| 38 | Tenderly | KEYED | Needs an account (free tier still needs sign-in). Sim class covered by `agent_simulate` / `agent_time_travel` (fork sims, no account). |
| 39 | Phalcon BlockSec | KEYED | Needs sign-in. Monitoring class covered by `defense_monitor` (PR #171) + the transition watcher. |
| 40 | MetaDock | EQUIV | Wallet-security browser extension. Detection class covered by the registry's approval / permit / token-risk detectors + `agent_explorer` reads. No extension built (not a scanner capability). |
| 41 | Pocket Universe | EQUIV | Same as MetaDock: tx-simulation class covered by `agent_simulate` (fork sim) + registry detectors. |
| 42 | Wallet Guard | EQUIV | Same as MetaDock. |
| 43 | Blowfish | EQUIV | Same as MetaDock. |
| 44 | Stelo | EQUIV | Same as MetaDock. |
| 45 | Fire | EQUIV | Same as MetaDock. |
| 46 | Web3 Antivirus | EQUIV | Same as MetaDock. |
| 47 | ScamSniffer | EQUIV | Phishing / drainer detection class covered by registry detectors + `agent_search` / `agent_fetch` (public scam lists). |
| 48 | AegisWeb3 | EQUIV | Same as MetaDock. |
| 49 | Kerberus Sentinel3 | EQUIV | Same as MetaDock. |
| 50 | Interlock | EQUIV | Same as MetaDock. |
| 51 | Revoke.cash | COVERED | Allowance reads via `agent_explorer` + the registry's approval plugins (`permit2_allowance_abuse`, approvals family). |
| 52 | DeFiLlama Anti-Phishing | EQUIV | Public phishing lists readable via `agent_fetch`. |
| 53 | Rabby | REF | A wallet, not a scanner. |
| 54 | Blockaid | KEYED | API needs a key. Detection class covered by registry token-risk plugins. |
| 55 | GoPlus Security | EQUIV | Public token-security API is keyless for reads; reachable via `agent_fetch`. |
| 56 | Webacy | KEYED | Risk-scoring API needs a key. |
| 57 | FailSafe | KEYED | Needs an account. |
| 58 | Nefture | KEYED | Needs an account. |
| 59 | GateKeep | KEYED | Needs an account. |
| 60 | ChainAware.ai | KEYED | Needs an API key. |
| 61 | CUBE3 AI | KEYED | Needs an API key. |
| 62 | MonitorChain | KEYED | Monitoring service, needs sign-in. Class covered by `defense_monitor` (PR #171). |
| 63 | Forta | KEYED | Detection-bot network; running bots needs a subscription. Monitoring class covered by `defense_monitor` (PR #171). |
| 64 | OpenZeppelin Defender | KEYED | Needs sign-in. |
| 65 | Hackless | KEYED | Paid alerting. |
| 66 | Blocknative | KEYED | Mempool API needs a key. Mempool lane here is read-only by design. |
| 67 | PeckShield Alert | KEYED | Paid alerting. |
| 68 | MistTrack | KEYED | Needs an account. Fund-flow class covered by the fund-flow tracer (PR #166). |
| 69 | Bitquery | KEYED | Needs an API key. |
| 70 | Ethtective | EQUIV | Scam DB; public pages readable via `agent_fetch` / `agent_search`. |
| 71 | Dune Analytics | KEYED | Queries need an API key. On-chain data class covered by `agent_explorer` (keyless Blockscout). |
| 72 | Nansen | KEYED | Paid. |
| 73 | Breadcrumbs | KEYED | Paid / keyed intel. Fund-flow class covered by the fund-flow tracer (PR #166). |
| 74 | DeBank | KEYED | Portfolio API needs a key. Holdings class covered by `agent_explorer`. |
| 75 | Chainalysis | KEYED | Paid intel. Fund-flow class covered by the fund-flow tracer (PR #166). |
| 76 | Elliptic | KEYED | Paid intel. Same as Chainalysis. |
| 77 | TRM Labs | KEYED | Paid intel. Same as Chainalysis. |
| 78 | TokenSniffer | EQUIV | Rug-check web service; detection class covered by registry token-risk plugins + `agent_fetch` / `agent_explorer` reads. |
| 79 | QuillCheck | EQUIV | Same as TokenSniffer. |
| 80 | BSCheck | EQUIV | Same as TokenSniffer. |
| 81 | RektRadar | EQUIV | Same as TokenSniffer. |
| 82 | Rugscreen | EQUIV | Same as TokenSniffer. |
| 83 | Sharpe Rug Check | EQUIV | Same as TokenSniffer. |
| 84 | TRONSEC | EQUIV | Same as TokenSniffer, for TRON. |
| 85 | RugLens | EQUIV | Same as TokenSniffer. |
| 86 | token-launch-scan | EQUIV | Same as TokenSniffer, for launches. |
| 87 | HostDeFi | REF | Hosting, not a scanner. |
| 88 | Web3 Decoder | EQUIV | Decompiler web tool; readable via `agent_fetch`; bytecode class covered by registry detectors. |
| 89 | MetaVision CVE Oracle | EQUIV | CVE DB; readable via `agent_fetch` / `agent_search`. |
| 90 | Kerne Verify Anything | KEYED | Verification service, needs sign-in. |
| 91 | Bounty Radar | REF | Bounty aggregator, not a scanner. |
| 92 | Darkmoon | UNVERIFIED | No keyless public runner found. Capability class covered by registry detectors. |
| 93 | Bumblebee scanner | UNVERIFIED | No keyless public runner found. Capability class covered by registry detectors. |
| 94 | Agentic Stack | REF | Agent framework, not a scanner. |
| 95 | Seal Incident Response | REF | Incident-response org, not a tool. |
| 96 | Ethernaut | REF | Training / CTF content. Fork-testing class covered by `agent_fuzz` / `agent_write_poc`. |
| 97 | Damn Vulnerable DeFi | REF | Training / CTF content. Same as Ethernaut. |
| 98 | Capture the Ether | REF | Training / CTF content. Same as Ethernaut. |
| 99 | CryptoHack | REF | Training / CTF content. Same as Ethernaut. |
| 100 | ZIION | UNVERIFIED | No keyless public runner found. Capability class covered by registry detectors. |

## Counts

- LIVE (this PR): 4 (Slither, Mythril, Foundry, Anvil — via
  `agent_slither`, `agent_mythril`, `agent_cast` / `agent_forge` /
  `agent_anvil`).
- COVERED (existing registry / merged PR): 1 (Revoke.cash).
- EQUIV (detection-equivalent in this PR): 45.
- KEYED (needs sign-in / key / paid): 32.
- REF (reference-only): 15.
- UNVERIFIED (no keyless runner found): 3.

Total: 100. Nothing dropped silently.

## Notes

- The `agent_*` tools are detection-only. Fork / sim / fuzz results
  are always UNVERIFIED; only a live-probe-verified stranger drain
  is VERIFIED_REAL.
- Attack capabilities from the catalog (exploit modules,
  brute-forcing, auth bypass, private-data access) are NOT built:
  the scanner flags the hole, it never runs the attack.
- Hardware-lab items from the earlier catalogs (ChipWhisperer,
  Proxmark3, Ledger/Trezor CLI, JTAG, etc.) are recorded as
  needing the lab; they are not in this 100.
- Solc coverage note (Nov 12 smoke): installed solc versions are
  0.4.15, 0.4.18, 0.5.17, 0.6.4, 0.6.12, 0.7.6, 0.8.7, 0.8.10,
  0.8.18, 0.8.19, 0.8.20, 0.8.26, 0.8.33. Sources pinned to a
  version not installed (most commonly `=0.5.16`, 36 of the 44
  unsat single-file sources in the 1,000-record sample) fail
  honestly with "no installed solc satisfies this source's pragma".
  New solc downloads are blocked by the disk-quota wave at the
  time of writing.
