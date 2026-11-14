# Bayesian Program Learning (BPL) + Solomonoff Induction

A Universal Inference Engine for ReconAnything. It reverse-engineers the
hidden generative program behind a target's observed behaviour, instead of
just pattern-matching past events. Pure Python stdlib, no new dependencies.

## The three components

1. **Hypothesis Synthesizer** (`synthesizer.py`) — generates probabilistic
   state machines as executable Python code. A program says: how often the
   entity acts (lognormal inter-arrival times, optional burst component),
   which chain/group it acts on (categorical, optionally sticky), and which
   contract type / flip direction it produces (categorical, optionally
   sticky). Every emitted program is AST-verified (`program.py`) before it
   may run: no imports, no `open`/`eval`/`exec`, no dunders, no loops
   (guaranteed termination), seeded RNG only, no builtins.
2. **Likelihood Engine** (`likelihood.py`) — executes each program against
   real observed event streams and scores how accurately it predicts real
   timestamps and artifacts. Scoring is always on held-out events the
   program was not fitted to.
3. **Evolutionary Program Search** (`search.py`) — MCMC (Metropolis-Hastings)
   plus genetic refinement (tournament selection, crossover, mutation).
   Programs that fail to predict new events die; programs that predict
   accurately survive and compound. A Kolmogorov-complexity prior gives
   shorter programs higher prior probability: `log_prior = -bits * ln 2`
   (Solomonoff induction / Occam as math).

A fitted program is a runnable **digital twin** (`twin.py`) for
counterfactual simulation ("what if this chain went away?"). Twin output
is labelled hypothetical. It is NEVER a finding, NEVER a candidate, NEVER
evidence about a live target.

## First domain

Smart-contract deployer behaviour and wallet/transaction patterns:
fresh deploys grouped by creator (370 rows), plus owner-transition events
grouped by token symbol (52 rows). Real data only, read from
`~/workspace/recon-continuous/`. Entities with fewer than 5 events are
reported as insufficient data, never modelled from invented events.

## Run

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m backend.app.bpl.evaluate
```

Prints a JSON report: per-entity holdout log-likelihood for BPL vs the
periodic and Markov baselines, description lengths, the best program in
plain words and as source, and the worked example (busiest deployer) with
its twin.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest backend/tests/test_bpl.py -q
```

## Baselines and honesty

- Periodic baseline: fixed median interval, most-common group/kind.
- Markov baseline: empirical transition counts + empirical interval spread.
- The v1/v2 NN scorer is NOT a baseline here: it is a finding-triage
  classifier, a different task from predicting the next event in a
  timeline. Comparing its accuracy to event log-likelihood would be
  dishonest, so it is excluded.
- A perfect prediction is flagged as overfit or a toy result, not a win.
- Data is sparse (22 creators with 3+ deploys). Expect modest edges over
  baselines; a program that does not beat the Markov baseline on holdout
  is reported as such, and the report says what data would be needed
  (more events per creator, longer observation windows).

## Rules

Detection only. Read-only data. No transactions, no drains, no exploit
execution, no auth bypass, no private-data access. crypto.com is never a
target. Never predicts VERIFIED_REAL. No simulated data is presented as
real anywhere: the twin is simulation, labelled as such, and never mixed
into findings.
