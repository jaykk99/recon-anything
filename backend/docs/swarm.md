# Autonomous Multi-Agent Swarm

A small team of researcher agents, coordinated, not a free-for-all.
Pure Python stdlib, no new dependencies. Detection only.

## Roles

| Agent | Job |
|---|---|
| **Coordinator** (`coordinator.py`) | Assigns targets, caps concurrency (default 2 parallel targets), dedupes by `chain:address`, enforces the hard rules at intake, chains to related addresses (depth 1). Never investigates, never probes, never scores a verdict. |
| **Scout** (`scout.py`) | Reads everything about one target: bytecode, native balance, live chain id, well-known view calls from the stranger, verified source via Blockscout, static findings via `batch_scan.scan_source(deep=True)` (labelled regex fallback when that stack is unavailable), related addresses for chaining. |
| **Hypothesizer** (`hypothesis.py`) | Turns findings into one concrete attack story: what the attacker calls, what moves, who receives it, what test comes next. Reuses the investigator loop's `form_hypothesis` when present; standalone fallback uses the same drain-kind vocabulary. A finding without a drain kind + named function is a lead, not a story. |
| **ForkTester** (`fork.py`) | Plans stateful sequences (setup, then sensitive call) and executes them. Engines in order: `anvil` (real local fork), `ganache` (real local fork), `state_override` (each step as a live `eth_call` from the stranger against the public RPC; state does NOT carry between steps), `plan_only`. Every outcome is `sim_derived` and never proof. |
| **LiveProber** (`probe.py`) | Read-only live `eth_call` probes from the unfunded stranger against the real contract in its current state. Records raw return/revert data. Builds validator candidates only for CALLER / CALLER-SUPPLIED recipients. Verdicts come only from the existing validator path (passthrough); when the validator is unavailable the verdict stays UNVERIFIED with the reason recorded. |
| **Reporter** (`reporter.py`) | Writes the markdown evidence + JSON record per target, with the actual probe outputs in them. Never upgrades a verdict. |
| **Blackboard** (`bus.py`) | The one shared surface: append-only, JSON-serializable event log plus an in-memory blob store for large payloads (source, ABI) that never bloats the log. Agents never talk to each other directly. |
| **Triage** (`triage.py`) | Ranks what to investigate first: value first ($100k floor; unknown value sorts after known value, never dropped), worst severity second, fresh_7d third. The NN scorer (`app/nn`, branch `feat/nn-scorer`) is wired in through `try_nn_ranker()` when importable: its mean score breaks ties inside the value bucket. On master, where `app/nn` does not exist yet, the hook degrades to the heuristic and says so. Triage ranks; it never predicts VERIFIED_REAL. |

## Hard rules (enforced in `rules.py`, not just documented)

- Detection only. Read-only live probes from the unfunded stranger
  (`0x000000000000000000000000000000000000dEaD`, no keys, no funds).
- No transactions, no drains, no exploit execution, no fund-taking.
  The RPC client allowlists read-only methods (`eth_call`,
  `eth_getCode`, `eth_getBalance`, `eth_getStorageAt`,
  `eth_getTransactionCount`, `eth_chainId`, `eth_blockNumber`,
  `eth_getBlockByNumber`); anything else raises before it is built.
- Only CALLER / CALLER-SUPPLIED recipients count as real.
  FIXED / HOLDER-SELF / OWNER / UNKNOWN are trigger-only.
- crypto.com is never a target (name/label/creator matching +
  address denylist hook).
- The swarm never constructs a VERIFIED_REAL verdict. That verdict
  may only arrive as a passthrough from the validator path.
- NO-SIMULATION rule: fork/state-override outcomes are analysis
  signal only. VERIFIED_REAL needs the validator's live-chain
  stranger probe.

## Running it

```bash
cd backend
python -m app.swarm.run --queue /path/to/targets.jsonl \
    --max-targets 5 --fresh-only --concurrency 2 \
    --out-dir backend/docs/swarm-runs
```

Queue rows are JSONL target dicts (`chain`, `address`, `name`,
`fresh_7d`, `value_usd`, ...), the same shape as
`recon-continuous/targets-2026-11-12/fresh-deploys-more-chains.jsonl`.

Single target, by hand:

```bash
python -m app.swarm.run --queue targets.jsonl --chain scroll \
    --address 0x16C22cbDD77350b1AC88AdDA344F691c12f41960 \
    --concurrency 1 --out-dir backend/docs/swarm-runs
```

The run prints a JSONL event log to stdout (replayable even where
file writes are restricted) and writes one evidence markdown + JSON
per target plus a run-metrics JSON into `--out-dir`. Exit code is 0
even when zero targets verify: 0 verified is an honest result, not
a failure.

## Tests

```bash
cd backend
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_swarm.py \
    -p no:cacheprovider -q
```

24 tests, all in-memory (fake RPC transport, no network, no file
writes): Keccak vectors (cross-checked against the repo's own
`cryptopack_util.keccak256`), selector table, rule enforcement,
blackboard, triage ordering, hypothesis stories vs leads, fork
planning, probe recipient gating, coordinator dedupe + error
isolation, reporter rendering.

## Wiring points (for the sibling branches)

- **NN scorer** (`feat/nn-scorer`): `triage.try_nn_ranker()` imports
  `app.nn.pipeline.load_model` / `score_finding_dicts` when present.
  Pass any `finding -> float` callable as `nn_score_fn` to
  `rank_targets` / `Coordinator` instead.
- **Investigator loop** (PR #177): `hypothesis.py` prefers
  `investigator.hypothesis.form_hypothesis`; `probe.py` prefers
  `investigator.validate.validate_candidates` (raised cap, strips
  simulation evidence) and falls back to
  `plugins.auto_validator.validate_candidate`.
- **Multi-hop call graph** (PR #178): the Scout's
  `related_addresses` are the chaining leads; the Coordinator
  enqueues them at depth 1, deduped, through the same intake
  filter. A call-graph plugin can replace the regex extractor by
  posting richer `related_addresses` to the Scout report.
- **Fork planner**: `fork.plan_fork` prefers
  `plugins.anvil_fork_probe.plan_sequences`, falls back to the
  local source parser.

## Metrics (honest)

The swarm is a system, not a classifier, so report what it did,
not an accuracy number:

- targets attempted / completed / errored / rejected
- findings total, candidates total, verified real (expect 0),
  trigger-only
- elapsed seconds, seconds per target

Manual wave-1 baseline (Nov 13): 5 targets, 209 findings,
0 candidates, 0 verified real. The swarm is better than that
baseline only if it finds candidates the manual loop missed, or
does the same work with less operator time per target: measure
both, claim neither without the numbers.

## Limits

- No local EVM in this sandbox (no anvil, no ganache, no foundry;
  installs are blocked), so the fork step runs on the
  `state_override` engine here: per-step live `eth_call`
  executions, state not carried between steps. On a machine with
  anvil installed the same code runs a real fork.
- Blockscout source fetch is best-effort: the explorer endpoints
  drop connections under this sandbox's egress, so some runs are
  bytecode-only. That is recorded, not papered over.
- The swarm investigates contracts, not web/API/infra targets.
- It does not predict VERIFIED_REAL, does not open PRs, does not
  merge. It writes evidence; a human (or the validator) decides.
