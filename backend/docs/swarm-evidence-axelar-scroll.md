# Swarm evidence: AxelarGateway on Scroll (proof run)

Proof run of the autonomous multi-agent swarm on one real target,
by hand, end to end. Every number below comes from the run log
(`backend/docs/swarm-runs/swarm-run-swarm-axelar-2026-11-14b.json`,
run id `swarm-axelar-2026-11-14b`); nothing is simulated or invented.

- **Target:** AxelarGateway, Scroll
- **Address:** `0x16C22cbDD77350b1AC88AdDA344F691c12f41960`
- **Queue row:** `recon-continuous/targets-2026-11-12/fresh-deploys-more-chains.jsonl`
  (`fresh_7d: true`, first seen 2026-11-09, block 35662966,
  creator `0xb1209b087e544785138784a50933d163a9087a7d`)
- **Why this target:** Axelar is a cross-chain bridge gateway:
  the highest-value fresh deploy in the queue ($100k-grade class).
- **Verdict: TRIGGER_ONLY** (0 candidates, 0 verified real)
- **Run time:** 121.3s for the one target

## What each agent did

### Scout

- Verified source fetched from Blockscout Scroll:
  39,764 chars, contract `AxelarGateway`, 54 functions, via
  `https://blockscout.scroll.io/api?module=contract&action=getsourcecode&address=0x16C22cbDD77350b1AC88AdDA344F691c12f41960`
- Static scan engine: `batch_scan.scan_source(deep=True)`
  (full CPU detection stack). **48 findings, worst severity
  critical.**
- Strongest findings:
  - `delegatecall_untrusted`, critical, function `upgrade`:
    "function 'upgrade' delegatecalls to a non-hardcoded target
    (newImplementation)".
  - `guard_convention_break`, high, function `execute`: "public
    state-changing function 'execute' uses no access guard".
  - `missing_access_control`, medium, function `execute`.
  - `privileged_function` (mint), high, `isContractCallAndMintApproved`,
    `mintLimiter`, `tokenMintLimit`, `tokenMintAmount` (view getters,
    no gate found by the scanner; they only read state).
  - 2x `secret_string`, high, flagging the `KEY_GOVERNANCE` /
    `KEY_MINT_LIMITER` bytes32 constants as "ethereum_private_key".
    These are storage-slot hashes, not keys: false positives from
    the scan stack, reported as-is, not acted on.
- Native balance: 0 wei (a message gateway holds no native ETH).
- Related addresses: 3 extracted from source, all 3 dropped after
  the code check (they are bytes32 storage-slot constants, not
  contracts, so nothing was chained). 0 chained targets.
- View calls from the stranger: `owner()`, `totalSupply()`,
  `name()`, `symbol()`, `decimals()` all reverted (`execution
  reverted`): the contract has none of those functions. Correct.

### Hypothesizer

- Story: "Stranger calls `upgrade()` on the target; the
  `delegatecall_untrusted` finding says value moves to unknown."
- Kind: story. Function: `upgrade`. Recipient: unknown.
  Severity: critical. Next test: fork_sequence.
- Note the honest limit: `upgrade()` is `onlyGovernance`, and the
  recipient is unknown, so this is a story about a privileged
  function, not a demonstrated stranger payout. That is why the
  run ends TRIGGER_ONLY, not a candidate.

### ForkTester

- Engine: `state_override` (no local EVM is installed in this
  sandbox: no anvil, no ganache, no foundry; installs are blocked).
  Each planned step ran as a live `eth_call` from the stranger
  against the public Scroll RPC, with a 1 ETH balance override.
  State did NOT carry between steps: a per-step execution check,
  not a sequence simulation, and never proof.
- Planned: 9 sequences. Executed: 17 step outcomes.
- Real outcomes (all live `eth_call`, stranger sender):
  - `upgrade()` (hypothesis function): NOT called, arguments
    unknowable (3 args: address, bytes32, bytes; the swarm never
    invents meaningful arguments).
  - `governance()` (setup, x8): called, returned
    `0x0000000000000000000000000000000000000000000000000000000000000000`
  - `mintLimiter()`: called, returned `0x00...0` (32 zero bytes)
  - `tokenMintLimit()`: called, returned `0x00...0`
  - `callContract`, `callContractWithToken`,
    `isContractCallApproved`, `isContractCallAndMintApproved`,
    `validateContractCall`, `validateContractCallAndMint`:
    NOT called, arguments unknowable (multi-arg).
- The zero returns are consistent with the target being the
  gateway **implementation (logic) contract**, not the user-facing
  proxy (see caveats): its own storage is empty by design.

### LiveProber

Read-only `eth_call` probes from the unfunded stranger
`0x000000000000000000000000000000000000dEaD`, live Scroll RPC:

| Call | Result |
|---|---|
| `owner()` (`0x8da5cb5b`) | `execution reverted` (no such function) |
| `paused()` (`0x5c975abb`) | OK, `0x00...0` (not paused) |
| `implementation()` (`0x5c60da1b`) | OK, `0x00...0` (see caveats) |
| `authModule()` (`0x64940c56`) | OK, `0x0000000000000000000000003d3c73e91b1b0c243f1437f2d8363b1d5b093bd0` |
| `totalSupply()` (`0x18160ddd`) | `execution reverted` (no such function) |
| `upgrade()` (`0xd55ec697`, hypothesis fn) | `execution reverted` (wrong arity / gated) |

- `authModule()` returning `0x3d3c73e91b1b0c243f1437f2d8363b1d5b093bd0`
  cross-checks: that is the real AxelarAuthWeighted contract, also
  in the fresh-deploys queue. The probes hit the real contract.
- Candidates built: 0. The story's recipient class is UNKNOWN,
  and only CALLER / CALLER-SUPPLIED count as real, so no candidate
  was built and the validator was correctly never invoked.
- Verdict: TRIGGER_ONLY.

### Reporter

- Wrote `swarm-evidence-scroll-0x16C22cbD.md` +
  `swarm-evidence-scroll-0x16C22cbD.json` in
  `backend/docs/swarm-runs/` (generated by the run itself).

## Metrics (this run)

| Metric | Swarm (this run) | Manual wave-1 baseline |
|---|---|---|
| Targets attempted | 1 | 5 |
| Targets completed | 1 | 5 |
| Findings | 48 | 209 (over 5 targets) |
| Candidates | 0 | 0 |
| Verified real | 0 | 0 |
| Time | 121.3s (121.3s/target) | not timed per target |

The swarm did in ~2 minutes, unattended, what the manual loop did
by hand: read a target, form a story, test it on a fork stand-in,
probe it live, and write the evidence. It found no candidate on
this target, same as the manual baseline found none on its five.
That is the honest result: the gateway's privileged functions are
gated (`onlyGovernance` / `onlySelf` / operator proof), and the
one critical finding (`upgrade` delegatecall) has no stranger
payout path. No inflation: 0 verified real is the result.

An earlier run of the same target (run id
`swarm-axelar-2026-11-14`, 160.5s) reached the same verdict but
attempted 4 targets: the Scout's related-address extractor had
chained 3 storage-slot hashes as if they were contracts. That bug
is fixed (code check before chaining) and the fix is proven by
this run: 1 target, 0 chained.

## Caveats (read before quoting this run)

1. **eth_getCode failed during the run.** All 6 attempts across
   the 3 Scroll endpoints failed (`IncompleteRead`, flaky egress),
   so the Scout recorded `has_code: false`. That is a measurement
   failure, not a fact: bytecode was confirmed independently
   before the run with a direct `eth_getCode` call
   (18,717 bytes, starting `0x6080604052...`).
2. **The target is the implementation (logic) contract, not the
   user-facing proxy.** Evidence: 18,717 bytes of code (a minimal
   proxy is ~100 bytes), `authModule` is `address public immutable`
   (immutables live in bytecode, so it reads correctly), and
   storage-reading views (`governance()`, `implementation()`,
   `mintLimiter()`) return 0 because the logic contract's own
   storage is empty by design. The proxy users interact with is a
   different address. The verdict concerns this contract as
   deployed; a proxy-side investigation would be a follow-up.
3. **Fork step is a stand-in here, not a real fork.** No anvil /
   ganache exists in this sandbox. The 17 step outcomes are real
   `eth_call` executions, but state does not carry between steps,
   so multi-call sequences (deposit-then-sweep style) are not
   tested end to end. On a machine with anvil installed the same
   code runs a real fork (`ForkTester._run_local_fork`).
4. **Scout dominates the clock** (97.9s of 121.3s): source fetch
   retries + the deep scan stack. The probes themselves took
   ~9.5s.
