# MARL + Game Theory for ReconAnything

Multi-agent reinforcement learning, game-theoretically: the recon /
target interaction is modelled as a two-player zero-sum
imperfect-information game and solved with Counterfactual Regret
Minimization (CFR). Pure Python stdlib, no new dependencies.

Files:

- `backend/app/nn/cfr.py` — generic CFR engine, Kuhn poker,
  rock-paper-scissors, matrix games, exact best-response
  exploitability.
- `backend/app/nn/marl.py` — the evasion game, the real-data
  replay evaluation, CLI (`python -m app.nn.marl`).
- `backend/tests/test_nn_marl.py` — 11 tests.
- `backend/docs/nn-marl-eval.json` — the full evaluation output
  (solution + all 15 replay cells).

## No-simulation rule

Restated Nov 14 (Jay's order): no simulated data anywhere in
ReconAnything, real workflow only, real numbers, nothing invented.
This module complies:

- There is no Monte Carlo simulator and no synthetic fallback data.
  An earlier draft had both; they were removed.
- The evaluation is a DETERMINISTIC REPLAY over the real candidate
  rows: what each probe policy would have picked, and how many
  probes it would have spent to reach each real finding's lane.
  Same rows and policy always give the same numbers.
- Kuhn poker and rock-paper-scissors appear only as unit self-tests
  proving CFR converges. They are never evaluation results.
- Nothing here predicts VERIFIED_REAL. There are 0 real verified
  rows in the data; the 2 VERIFIED_REAL rows in the file are
  already-adjudicated simulation-path false positives and are
  dropped on load, exactly as the nn-scorer training data does.

## The game

- Chance deals a hidden vulnerability lane L from the empirical
  distribution over the real candidates.
- The defender (target/owner, player 1) knows L and picks an opsec
  move: none, owner_rotation, burner_wallet, proxy_hop, redeploy,
  timestamp_jitter.
- The attacker (recon, player 0) picks a probe lane. It knows
  neither L nor the defender's move: one infoset.
- Chance decides detection: a probe pays off only when it hits the
  right lane, the finding is worth validating (UNVERIFIED), and the
  defender's opsec did not hide it.
- Payoff to the attacker: 1 for a detection, 0 otherwise, minus a
  0.05 probe cost, plus the defender's move cost (zero-sum pricing:
  the defender pays for its own opsec).

The 22 observed plugins are collapsed to 6 lanes so the game stays
small enough for exact CFR: math (unchecked_math_user_input), logic
(contract_logic), upgrade (uups_authorize_upgrade_missing), mint
(recipient_mint_to_caller), bridge (all bridge_* plus
recipient_bridge_release_unproven), other (the long tail).

## What is real and what is assumed

REAL (measured from `~/workspace/recon-continuous/results/
candidates.jsonl`, 727 lines, 725 usable rows after dropping the 2
VERIFIED_REAL rows; 620 UNVERIFIED):

| lane | n | prior | UNVERIFIED rate | UNVERIFIED rows |
|------|---|-------|-----------------|-----------------|
| math | 487 | 0.6717 | 0.9959 | 485 |
| logic | 69 | 0.0952 | 0.6812 | 47 |
| other | 66 | 0.0910 | 0.4394 | 29 |
| upgrade | 37 | 0.0510 | 0.9730 | 36 |
| mint | 35 | 0.0483 | 0.3714 | 13 |
| bridge | 31 | 0.0428 | 0.3226 | 10 |

REAL (observed defender behaviour, `transition_events.jsonl`): the
only opsec move actually observed is the owner flip: 52 flips on
11 watched addresses, Nov 5-14 2026. Roughly every watched address
flipped at least once, in both directions, which is also consistent
with unreadable owner slots rather than deliberate rotation. No
redeploy, burner, proxy-hop or timestamp move is observed in the
data. The empirical defender scenario therefore mixes only
owner_rotation / none, 50/50.

ASSUMED (synthetic, labelled as such everywhere): the evasion
multipliers `EVASION_MULT`, i.e. how much each opsec move hides
each lane (owner rotation hides owner-gated lanes, burner wallets
hide recipient lanes, proxy hops hide bridge lanes, redeploy hides
everything but costs the most, timestamp jitter slightly hides
math). No data measures these. They are explicit modelling choices,
not measurements. Change them and the equilibrium moves; the CFR
machinery does not care. Every evasion-adjusted number below is
labelled assumption-dependent.

## CFR validation (self-tests, not evaluation)

- Kuhn poker, 1500 iterations: game value -0.0554 (known -1/18 =
  -0.0556), exploitability 0.0141. Exploitability falls with
  iterations (0.0466 at 100 iterations, 0.0141 at 1500).
- Rock-paper-scissors, 2000 iterations: both average strategies
  within 0.07 of uniform, value -0.0001, exploitability 0.0380.
- Evasion game, 2000 iterations: exploitability 0.0004.

Correctness note: the first version of the CFR engine did not fold
chance probabilities into the players' reaches, so rare lanes
counted the same as common ones. The evasion game stalled at value
0.227 with the attacker over-probing logic, while pure math
guarantees 0.385. Folding the chance probability into both reaches
at chance nodes fixed it (Kuhn and RPS are unaffected: Kuhn chance
is uniform, RPS has no chance). The fix is what the tests pin down.

## Equilibrium found (2000 CFR iterations)

- Game value (attacker payoff per round): 0.3856.
- Exploitability: 0.0004. This matches the analytic equilibrium,
  computed independently by hand.
- Attacker equilibrium mix: math 1.000, everything else 0.000.
  Probe math. The math lane's expected value per probe
  (prior 0.6717 x rate 0.9959 = 0.669) is an order of magnitude
  above the next lane (logic 0.065), so the single-probe
  equilibrium is stark: always probe math.
- Defender equilibrium mix: redeploy 0.999 on math targets, none
  0.999 on every other lane. Against a math-only attacker, the
  defender's only useful move is the expensive redeploy on math
  targets (halves detection, costs 0.15); everywhere else the
  cheapest move (none) is best because the attacker never probes
  there.

## Replay evaluation (real rows, deterministic)

Each real candidate row is one target. A policy is an ORDER (fixed
lane sequence; probes to reach a lane is its position, or never)
or a MIX (per-probe distribution; exact geometric expectations,
no sampling). Coverage is the share of the 620 real UNVERIFIED
rows whose lane the policy reaches within the probe budget.
Probes are counted over all 725 rows: a false-positive row still
costs probes, it just never counts as a find.

Policies:

- cfr-mix: sample each probe from the equilibrium mix (pure math).
- cfr-rank: lanes ranked by equilibrium mix weight, ties by
  expected value: math > logic > upgrade > other > mint > bridge.
  This is the multi-probe reading of the 1-round equilibrium.
- static29: the lanes the curated 29 reaches, in first-appearance
  order: other > logic > bridge > mint. It never reaches math or
  upgrade.
- yield: lanes in expected-value order (math > logic > upgrade >
  other > mint > bridge). Control policy.
- random: uniform mix over the 6 lanes. The baseline, shown
  everywhere below.

Headline finding, from the real data alone: the static curated-29
order never probes the math or upgrade lanes, which hold 521 of
the 620 worth-validating rows (84.0%). Those candidates were found
by the widened/deep plugin sets, not the default 29. Any policy
that leads with math reaches them; the default order cannot, at
any budget.

### Budget 1 probe per target

| policy | coverage | finds / 100 probes | mean probes / target | evasion-adj (cfr defender) |
|--------|----------|-------------------|---------------------|---------------------------|
| cfr-mix | 0.782 | 66.89 | 1.00 | 33.49 |
| cfr-rank | 0.782 | 66.90 | 1.00 | 33.49 |
| static29 | 0.047 | 4.00 | 1.00 | 4.00 |
| yield | 0.782 | 66.90 | 1.00 | 33.49 |
| random | 0.167 | 14.25 | 1.00 | 8.69 |

### Budget 3 probes per target

| policy | coverage | finds / 100 probes | mean probes / target | evasion-adj (cfr defender) |
|--------|----------|-------------------|---------------------|---------------------------|
| cfr-mix | 0.782 | 40.38 | 1.66 | 20.22 |
| cfr-rank | 0.916 | 50.18 | 1.56 | 28.78 |
| static29 | 0.139 | 4.36 | 2.72 | 4.36 |
| yield | 0.916 | 50.18 | 1.56 | 28.78 |
| random | 0.421 | 14.25 | 2.53 | 8.69 |

### Budget 6 probes per target

| policy | coverage | finds / 100 probes | mean probes / target | evasion-adj (cfr defender) |
|--------|----------|-------------------|---------------------|---------------------------|
| cfr-mix | 0.782 | 25.33 | 2.64 | 12.68 |
| cfr-rank | 1.000 | 45.55 | 1.88 | 27.76 |
| static29 | 0.160 | 2.76 | 4.94 | 2.76 |
| yield | 1.000 | 45.55 | 1.88 | 27.76 |
| random | 0.665 | 14.25 | 3.99 | 8.69 |

Per-lane coverage at budget 6, static29: math 0/485, upgrade
0/36, other 29/29, logic 47/47, bridge 10/10, mint 13/13. It
finds 99 of 620 real rows and spends 4.94 probes per target doing
it, mostly re-probing math and upgrade targets it can never reach
(487 math rows x 6 probes each).

The evasion-adjusted column is assumption-dependent: it multiplies
each reached row by the expected evasion multiplier under the
equilibrium defender (redeploy on math, none elsewhere), so the
math finds are halved. Under the empirical defender (owner flips
only) the adjustment is small: cfr-rank at budget 6 is 44.28
finds / 100 probes instead of 45.55, static29 is 2.63 instead of
2.76. Full per-scenario numbers are in `nn-marl-eval.json`.

## What the CFR policy does and does not add

Plainly: cfr-rank and the naive yield order produce IDENTICAL
numbers at every budget, because the 1-round equilibrium is pure
math and the rank order that follows from it is exactly the
expected-value order. CFR's contribution here is not a different
ordering. It is (a) the equilibrium itself, which justifies
leading with math from game theory rather than from a hunch,
(b) the defender's best response, which says a math-focused
attacker should expect redeploys on math targets (detection
halved, evasion-adjusted finds roughly halved), and (c) a
solver that is validated against known games and can be re-run
when the lane priors, rates, or assumed multipliers change. If
the multipliers change enough, the equilibrium moves and the
ordering follows it; the yield order would not notice.

The single-probe mix (cfr-mix) is the literal equilibrium policy:
at budget 1 it is the best policy in the table (66.89 finds /
100 probes), but it never reaches non-math lanes, so at budget 6
it is beaten by its own ranked version (25.33 vs 45.55). The
1-round game is myopic; the ranked version is the honest
multi-probe extension, not a solved sequential game.

## Limits

- The game is 1 round, 1 probe. The multi-probe policy is
  rank-by-equilibrium-weight, not a solved sequential game. A
  sequential (multi-round, re-probe with memory) equilibrium is
  future work and would need a bigger game.
- The evasion multipliers are assumed, not measured. The
  equilibrium's shape (probe math, defender redeploys on math)
  is driven mostly by the real prior x rate gap, which is large,
  but the exact game value (0.3856) and the evasion-adjusted
  figures move with the table.
- The defender's actual per-target move is unobserved. Only owner
  flips are observed, and a flip may be an unreadable owner slot
  rather than deliberate rotation. The empirical defender scenario
  is the only one grounded in observed behaviour, and it only
  covers owner rotation.
- The replay counts probes to reach a row's lane. It does not model
  chain selection (bsc is 89% of rows), per-plugin runtime cost,
  or rate limits; a probe is a probe. It does not model the
  scanner actually running: the math-lane findings in the data
  came from the widened/deep sets, and the replay compares the
  default-29 order against policies as if each ran alone.
- Coverage is about reaching already-promoted UNVERIFIED
  candidates, not discovering new vulnerabilities and not proving
  anything live. No finding here is VERIFIED_REAL, and none can
  be: that verdict needs a live-chain probe from an unfunded
  stranger, which this module never performs.
- The 725 rows are already triage-promoted candidates (high
  severity, scanner-selected), not a random sample of contracts.
  The lane prior is the prior over candidates, not over contracts.

## How to run

From `backend/`:

```bash
python -m app.nn.marl --iterations 2000 --budgets 1,3,6 \
    --out docs/nn-marl-eval.json
python -m pytest tests/test_nn_marl.py -v
```

`--candidates` points at a different candidates.jsonl. If the file
is absent the evaluation fails loudly instead of substituting
synthetic data.
