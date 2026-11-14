# Active Inference & the Free Energy Principle for ReconAnything triage

Branch module only. The live scanner is untouched; this is a
replacement for its static queue order, ready to be wired in once
it has been run live.

## What it replaces

`runner.py` drains queues in strict static order (`QUEUE_PRIORITY`:
fresh, transitions, legacy, zeroday_tail, bytecode, market_deep,
bnb_tier3, keyword_search), and within a queue in file order. The
file order inside `bnb_tier3` is stake-descending, and
worth-validating contracts have *lower* stake (see below), so the
static order front-loads the worst rows twice: the emptiest queues
first, and inside the richest queue the least promising contracts
first. The replay below measures exactly how much that costs.

## Generative model

One contract, one hidden binary state:

- `S = worth-validating`: a live probe would promote the contract to
  an UNVERIFIED candidate. This is the only positive label the
  triage model ever predicts. The module never predicts
  VERIFIED_REAL.
- `S = FP`: the contract's findings are false positives /
  trigger-only noise.

The agent holds two linked beliefs per contract:

- `q = P(S = worth)`, the decision probability. Prior mean from the
  queue base rate plus a stake adjustment (below). Updated by exact
  binary Bayes on every observation, using the query's likelihood
  ratio. Promote/drop thresholds apply to `q` (defaults 0.85 /
  0.05).
- A Beta distribution over `theta`, the population parameter behind
  `q`, on a 101-point grid. Updated with the mixture likelihood
  `P(obs | theta) = theta * P(obs | S=worth) + (1 - theta) *
  P(obs | S=FP)`. It carries the parameter uncertainty used for the
  variational free-energy accounting.

Missing data widens the prior: symbol unknown, stake unknown,
source unverified, owner unknown, and the share of lanes still
unprobed each shrink the Beta strength (`kappa = 20 * (1 - 0.5 *
missing)`), which raises entropy and therefore EIG. The loop is
drawn to the contracts it knows least about, all else equal.

## Queries, EIG, and free energy

A query is one recon observation with a cost in probe-units and a
binary likelihood model `(sens, fpr) = (P(fire | worth), P(fire |
FP))`. Six cheap lane queries (cost 0.1 each) plus one full-contract
probe (cost 1.0, reveals `S` exactly, modelled as sens=1, fpr=0).

For each candidate query the loop computes:

- **Expected Information Gain (EIG)**, in bits:
  `H(q) - E_obs[H(q | obs)]`, the expected reduction of the
  decision entropy.
- **Expected free energy** `G = -EIG + lambda * cost - reward *
  P(promote after the query)`. The first term is epistemic value,
  the second the expected free-energy cost of acting, the third an
  optional pragmatic term. With `reward = 0` the loop minimises
  `-EIG + lambda * cost`.
- **Ranking**: highest EIG per unit cost. Pure EIG would always fire
  the full probe, so cost enters through `G`; EIG-per-cost is the
  free-energy-consistent ranking at `lambda = 1`. Note the `reward`
  term is reported in `G` but does not change the ranking, which is
  EIG-per-cost (see Limits).

After each observation the belief updates by exact Bayes, and the
variational free energy `F[q] = KL(q || prior) - E_q[log p(obs |
theta)]` over the theta-posterior is recorded. For the exact
posterior `F = -log p(obs)` (the surprise); in general `F >= -log
p(obs)`, with the gap equal to the KL divergence from the exact
posterior (covered by a unit test).

## Calibration (all real, fit-half only)

Split: `md5(chain:address) % 2 == 0` — 2,344 addresses, 274 worth.
Every constant below comes from that half. The replay runs on the
other half.

Queue base rates, shrunk `k = 20` toward the global fit-half rate
0.117 (`(worth + 20*0.117) / (n + 20)`):

| queue | n | worth | prior |
|---|---|---|---|
| fresh | 212 | 0 | 0.0101 |
| transitions | 0 | 0 | 0.1170 (global fallback) |
| legacy | 19 | 1 | 0.0856 |
| zeroday_tail | 107 | 8 | 0.0814 |
| bytecode | 46 | 0 | 0.0355 |
| market_deep | 310 | 1 | 0.0101 |
| bnb_tier3 | 1628 | 261 | 0.1598 |
| keyword_search | 22 | 3 | 0.1271 |

Stake effect: 1-D grid search on the fit-half gives beta `-0.25`
on `log10(stake_usd + 1)` (mean 2.12), log-likelihood -730.6 vs
-767.1 queue-only. Worth-validating contracts have lower stake.

Lane likelihoods (a lane "fires" when any plugin in its group
fired on the contract in its historical batch):

| lane | sens | fpr | LR+ | LR- |
|---|---|---|---|---|
| source_verification | 0.987 | 0.823 | 1.20 | 0.07 |
| recipient_probe | 0.035 | 0.042 | 0.82 | 1.01 |
| gate_analysis | 0.889 | 0.237 | 3.75 | 0.15 |
| bytecode_deep | 0.995 | 0.820 | 1.21 | 0.03 |
| proxy_impl | 0.998 | 0.822 | 1.21 | 0.01 |
| arithmetic_guards | 0.929 | 0.230 | 4.05 | 0.09 |

Two lanes do almost all the work (`arithmetic_guards`,
`gate_analysis`); three are near-always-on (their *negative*
outcome is the informative one: a contract where `contract_recon`
does not fire is very likely FP); `recipient_probe` is
near-useless (sens 0.035) and the loop correctly almost never
fires it (0 times in the replay below).

## The scorer hook

`belief_from_scorer(pi, p_score)` combines a prior mean with a
v1/v2 scorer output by log-odds pooling (posterior odds = prior
odds * scorer odds), treating the scorer as one calibrated
observation. It is an approximation: the scorer was trained on the
same plugin outputs the lanes read, so its errors correlate with
the lanes'. The replay does **not** use this path, because a
scorer output only exists after a probe has produced findings;
the replay measures the prior + lane-observation loop. The hook is
unit-tested, not evaluation-tested.

## Drop-in for the scanner

```python
from app.nn.active_inference import pick_next_contract
nxt = pick_next_contract(contracts)  # list of contract dicts
# {"contract": {...}, "query": "arithmetic_guards",
#  "eig_bits": ..., "eig_per_cost": ...,
#  "expected_free_energy": ..., "q_before": ..., ...}
```

`contracts` are queue rows (`chain`, `address`, `queue`,
`stake_usd`, `symbol`, plus optional `source_verified`,
`owner_known`, `probed_lanes`). Beliefs are state: the live
scanner must persist them between runs (pass them back via the
`beliefs` argument). That persistence is NOT built here, and the
live scanner is NOT modified by this branch.

## Replay evaluation (real record only)

### No-simulation rule

Restated Nov 14: no simulated data anywhere in ReconAnything. This
replay consumes **only real recorded outcomes**:

- A lane query's outcome is a real recorded fact: whether any
  plugin in that lane's group fired on that contract in its
  historical batch (`results/batches.jsonl`).
- A full probe's outcome is a real recorded verdict
  (`results/candidates.jsonl`: UNVERIFIED = worth-validating).
- Nothing is sampled, generated, or invented. No probe outcome is
  simulated.

The only counterfactual is the **order** in which real records are
consumed: the loop chooses a different probe order than history
did. This is a reordering of the real record, not a simulation of
new observations. Synthetic distributions appear only in the unit
self-tests of the entropy/EIG math and are never presented as
evaluation numbers.

### Protocol

- Pool: the 4,681 unique scanned addresses with known historical
  labels. Unscanned queue rows have no label and are excluded.
- Split-half as above; priors and lane likelihoods fit on the
  fit-half only; replay on the eval-half only: **2,337 contracts,
  287 worth-validating**.
- Baselines on the same eval-half at the same probe budgets:
  static = `QUEUE_PRIORITY` order, queue-file order within a
  queue; random = seed-42 shuffle. Both spend 1.0 probe-unit per
  contract and "find" a contract by fully probing it (perfect
  knowledge by construction).
- Budgets are probe-units: full probe 1.0, lane read 0.1.
- Run with: `python -m app.nn.replay_active_inference --budgets
  100 250 500 1000 [--promote-q 0.99 --eig-variant-label
  eig-confirm]`

### Results

Worth-validating contracts found per probe budget (eval-half,
287 total worth):

| method | 100 | 250 | 500 | 1000 |
|---|---|---|---|---|
| static | 0 | 3 | 13 | 16 |
| random (seed 42) | 15 | 35 | 76 | 138 |
| EIG loop, promote 0.85 | 0 | 2 | **257** (+106 false) | **262** (+106 false) |
| EIG loop, promote 0.99 ("confirm") | 0 | 2 | 23 (0 false) | **262** (0 false) |

Decision-entropy reduction per probe-unit spent:

| method | 100 | 250 | 500 | 1000 |
|---|---|---|---|---|
| static | 0.057 | 0.078 | 0.156 | 0.220 |
| random | 0.560 | 0.543 | 0.551 | 0.547 |
| EIG loop, promote 0.85 | 2.298 | 2.527 | 1.587 | 1.298 |
| EIG loop, promote 0.99 | 2.298 | 2.527 | 1.587 | 1.082 |

At budget 1000 the 0.85 loop resolved the entire eval pool
spending only **684** probe-units (promoted 363, dropped the
rest); the confirm variant spent 999.9. Query mix at budget 500
(0.85): 1,777 arithmetic_guards, 700 gate_analysis, 343
proxy_impl, 218 full_probe, 0 source_verification, 0
bytecode_deep, 0 recipient_probe.

### What the numbers mean

- **Information efficiency is the clear win.** The loop reduces
  decision entropy 4–40x faster per probe-unit than random, and
  10–40x faster than static. It spends the early budget on 0.1-unit
  lane reads that drop most contracts after a single negative lane
  (e.g. a negative arithmetic_guards lane takes q 0.20 to 0.02),
  instead of burning 1.0 unit per contract in fresh-first order.
- **Yield follows, but only once the budget is big enough to finish
  resolving contracts.** At budget 100 the loop finds 0 worth
  (it spent 100 units triaging 642 contracts with lanes and
  promoted none yet); at 500 it finds 257 of 287 (90% recall),
  3.4x random and 20x static. Below ~250 units the loop is still
  gathering evidence and the baselines' "probe-and-know" finds
  more. Do not deploy this loop on tiny budgets expecting
  immediate yield.
- **The 0.85 threshold buys recall with false promotes.** 257
  found + 106 false promotes = 71% precision at budget 500.
  Those 106 would waste downstream validator effort. The 0.99
  "confirm" variant (promotion effectively requires a full probe)
  has 0 false promotes and the same 262 recall at budget 1000 —
  but only 23 found at budget 500, because pure-EIG ranking
  prefers full-probing mid-q contracts (max entropy, ~1 bit)
  over confirming high-q ones (~0.56 bits). EIG-maximisation is
  not yield-maximisation.
- **Static is worse than random.** Fresh-first burns the first
  ~700 eval probes on queues whose worth rate is 0–8%, and
  stake-descending order inside bnb_tier3 front-loads the
  lowest-yield rows. Random beats static 6–9x at every budget.

## Limits (read before wiring this in)

1. **Replay, not live.** The loop has never been run live. A live
   run reads today's chain state; contracts change (state
   transitions, proxy upgrades), so live lane outcomes can differ
   from the historical batch reads. The numbers above are the
   loop's performance on the historical record only.
2. **Circularity in the lane likelihoods.** The labels
   (UNVERIFIED candidates) are themselves produced from the same
   plugin outputs the lanes read, so sens/fpr are optimistic: a
   lane that helps promote a candidate will look more
   discriminative than it is. The split-half limits overfitting
   but not this structural circularity. Treat the EIG magnitudes
   as upper bounds.
3. **Marginal, not conditional, likelihoods.** Each lane's
   (sens, fpr) is fit marginally. Lanes correlate (a contract
   that fires `gate_analysis` usually fires `arithmetic_guards`
   too), so sequential updates double-count shared evidence and
   `q` moves faster than it should. The thresholds were not
   recalibrated for this; the 106 false promotes are partly
   this effect.
4. **EIG is not yield.** See the confirm variant: ranking by
   EIG-per-cost under-invests in confirming likely-worth
   contracts at mid budgets. The `reward` term in expected free
   energy is the intended fix, but it currently only affects the
   reported `G`, not the ranking. A reward-weighted ranking is
   future work, not in this branch.
5. **Priors go stale.** Queue rates and lane likelihoods are
   frozen at the Nov 14 fit-half. If the scanner's plugin set or
   the chain mix changes, refit them (the replay script documents
   the protocol) instead of trusting these numbers.
6. **Scorer path unevaluated.** The `belief_from_scorer` hook is
   unit-tested only; the replay does not exercise it (findings
   only exist post-probe).
7. **Thresholds are not tuned.** 0.85 / 0.05 were chosen, not
   searched. The 0.85 vs 0.99 comparison above is the only
   threshold evidence; a sweep on the fit-half is future work.
8. **Cost model is an assumption.** Lane = 0.1, full probe = 1.0
   probe-units. Real costs are seconds (historical batches: mean
   204 s, median 99 s per contract); the 0.1 figure assumes one
   plugin-group read costs ~1/10 of the curated 29-plugin set.
   If the true ratio differs, the EIG-per-cost ranking shifts.

## Files

- `backend/app/nn/active_inference.py` — the loop (stdlib only).
- `backend/app/nn/replay_active_inference.py` — the replay
  harness (reads `~/workspace/recon-continuous` by default).
- `backend/tests/test_nn_active_inference.py` — 18 unit tests
  (synthetic distributions for the math only, never evaluation).
- `backend/docs/nn-active-inference.md` — this file.
