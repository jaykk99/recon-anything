# Swarm evidence: AxelarGateway

- **Chain:** scroll
- **Address:** `0x16C22cbDD77350b1AC88AdDA344F691c12f41960`
- **Verdict:** TRIGGER_ONLY
- **Generated:** 2026-11-14T08:00:53Z
- **Fresh 7d:** True

## Scout (what the contract is)

- Has bytecode: False (0 bytes)
- Native balance: 0 wei (0.0 ETH)
- Verified source: True (length 39764 chars via https://blockscout.scroll.io/api?module=contract&action=getsourcecode&address=0x16C22cbDD77350b1AC88AdDA344F691c12f41960)
- Scan engine: batch_scan.scan_source(deep=True)
- Findings: 48 (worst severity: critical)
- Related addresses: none
- Related dropped (no code / not contracts): 3

### View calls (stranger sender, live RPC)

- `owner`: FAILED, `execution reverted`
- `totalSupply`: FAILED, `execution reverted`
- `name`: FAILED, `execution reverted`
- `symbol`: FAILED, `execution reverted`
- `decimals`: FAILED, `execution reverted`

### Scout errors

- eth_getCode failed: all RPC endpoints failed for eth_getCode on scroll (6 attempts): https://1rpc.io/scroll: IncompleteRead: IncompleteRead(0 bytes read)

## Hypothesizer (the attack story)

- Kind: story
- Story: Stranger calls upgrade() on the target; the delegatecall_untrusted finding says value moves to unknown.
- Function: `upgrade`
- Recipient: unknown
- Next test: fork_sequence
- Engine: swarm-hypothesis-fallback

## ForkTester (fork test)

- Engine: state_override
- Planned sequences: 9
- Executed: True (17 step outcomes)
- State carried between steps: False
- Note: no local EVM installed; each step ran as a live eth_call from the stranger against the public RPC (balance override only). State did NOT carry between steps: per-step execution check, not a sequence simulation, and never proof.

- `upgrade` (target): NOT called, arguments unknowable
- `governance` (setup): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `callContract` (target): NOT called, arguments unknowable
- `governance` (setup): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `callContractWithToken` (target): NOT called, arguments unknowable
- `governance` (setup): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `isContractCallApproved` (target): NOT called, arguments unknowable
- `governance` (setup): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `isContractCallAndMintApproved` (target): NOT called, arguments unknowable
- `governance` (setup): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `validateContractCall` (target): NOT called, arguments unknowable
- `governance` (setup): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `validateContractCallAndMint` (target): NOT called, arguments unknowable
- `governance` (setup): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `mintLimiter` (target): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `governance` (setup): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `tokenMintLimit` (target): called, returned `0x0000000000000000000000000000000000000000000000000000000000000000`

## LiveProber (live read-only probes, stranger sender)

- Sender: `0x000000000000000000000000000000000000dEaD` (unfunded stranger, no keys)
- Candidates built: 0
- Verdicts: []

- `owner()` from stranger: FAILED, `execution reverted`
- `paused()` from stranger: OK, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `implementation()` from stranger: OK, returned `0x0000000000000000000000000000000000000000000000000000000000000000`
- `authModule()` from stranger: OK, returned `0x0000000000000000000000003d3c73e91b1b0c243f1437f2d8363b1d5b093bd0`
- `totalSupply()` from stranger: FAILED, `execution reverted`
- `upgrade()` from stranger: FAILED, `execution reverted`

- Trigger-only: recipient class UNKNOWN is trigger-only: only CALLER / CALLER-SUPPLIED count as real

## Rules compliance

- Detection only; no transaction sent, no funds moved.
- Live probes are read-only eth_call from the unfunded stranger.
- Fork outcomes are analysis signal only, never proof; VERIFIED_REAL can only arrive via the validator path.
- crypto.com was never a target.

