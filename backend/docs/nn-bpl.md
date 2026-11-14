# Bayesian Program Learning + Solomonoff Induction (`backend/app/nn/bpl.py`)

Universal inference for ReconAnything: learn the minimal generative
program that explains a deployer / wallet behaviour trace, then
predict what happens next from the posterior over programs.

## What it is not

- **Not the NN scorer.** The v1 scorer (81-32-16-1, test acc 0.8897,
  ROC AUC 0.9781) and v2 scorer (255-64-32-1, test acc 0.9103, AUC
  0.9697) rank *findings* for triage. BPL ranks *programs that
  generate behaviour traces*. Different object, different numbers,
  not comparable and not a replacement.
- **Not `feat/nn-bayesian`.** That branch puts uncertainty over NN
  *scores* (calibration of the scorer). BPL puts a posterior over
  *programs*. No code is shared and nothing is duplicated.
- **Not `feat/nn-synthesis`.** That branch synthesises *tools*
  (sandboxed code generation). BPL learns *generative programs of
  behaviour* (what a deployer does next). No overlap.
- **Not a verifier.** BPL never predicts VERIFIED_REAL, never touches
  a live chain, never sends a transaction. Triage only.

## The DSL

A trace is a list of event strings from a finite alphabet
(`bpl.ALPHABET`, 177 events):

| Event | Meaning |
|---|---|
| `DEPLOY:<kind>:<chain>[:fresh]` | a deploy; kind in `proxy, nft, token, other`; chain in `scroll, optimism, linea, avalanche, ethereum, bsc, base, arbitrum, polygon`; `:fresh` when `fresh_7d` |
| `OWNER_SET` / `OWNER_CLEAR` | owner set / removed (owner flips) |
| `UPGRADE` | proxy implementation change |
| `FUND_IN:<bucket>` / `FUND_OUT:<bucket>` | fund movement, bucket `small, med, large` |

A program is a list of ops:

- `Emit(event)` — emit one fixed event.
- `Repeat(count, body)` — unroll `body` (Emits only) `count` times.
  Count 2..6, body length 1..4, nesting depth at most 1.

A program deterministically expands (unrolls) to exactly one trace.
The flat program (one `Emit` per observed event) always exists, so
inference never comes up empty.

## The Solomonoff prior (approximation)

True Solomonoff — a prior over all Turing machines weighted by
`2^-length` — is uncomputable. This engine approximates it over the
DSL with a fixed prefix code. The description length `L(program)` in
bits is:

- 1 bit to terminate the program,
- per op: 1 bit for the op type (Emit vs Repeat),
- `Emit`: `log2(|alphabet|)` bits to name the event,
- `Repeat`: `log2(5)` bits for the count (2..6) plus the body's cost.

Prior: `P(program) ∝ 2^-L(program)`. Shorter programs are
exponentially preferred — the Solomonoff intuition, restricted to
this DSL. Call it what it is: an MDL / MML prior, not a universal
prior over all computable hypotheses.

## Likelihood and posterior

A noisy channel between a program's expansion `g` and the observed
trace `t` (defaults `eps=0.05`, `gap=0.10`):

- per aligned position: match `1-eps`, mismatch `eps/(A-1)`
  (`A` = alphabet size),
- per extra / missing event: factor `gap`.

`log P(program | t) = log P(t | program) - L(program) * ln 2`
(up to a constant). Programs are ranked by this log-posterior.

## Search

Beam search over program prefixes (`infer_programs`):

- A partial program is extended by `Emit(next observed event)` or by
  a `Repeat` whose unrolling matches the upcoming segment exactly
  (including *overshooting* repeats that run past the end of the
  trace — those are what make prediction possible: a program
  inferred on a prefix whose unrolling continues one event past it
  is predicting that event).
- Partial programs are pruned by "excess over flat":
  `bits-so-far - covered * EMIT_BITS`. Raw bits are not comparable
  across partial programs that covered different numbers of events;
  the excess is, and at completion it ranks programs exactly by
  total description length.
- Complete programs are ranked by full posterior. The flat program
  is always in the beam.

Multi-trace learning (`learn_shared_programs`): run inference per
trace, pool the candidates, re-rank by posterior on the whole set —
one prior cost, likelihood summed over traces. A program that
explains many traces earns its description length many times over.
That shared-program step is the universal-inference part.

## Prediction

`predict_next(prefix, programs)`: each program votes for the event
its expansion emits right after the prefix, weighted by its
posterior on *this* prefix (`P(prefix | program)` under the noise
channel times the prior). Programs whose expansion is exhausted at
the prefix abstain. Votes aggregate into a next-event distribution.
Every prediction cites the programs behind it and their weights
(`Prediction.citations`).

## Files

- `backend/app/nn/bpl.py` — engine: DSL, prior, likelihood,
  beam search, prediction, frequency / Markov baselines.
- `backend/app/nn/synth.py` — synthetic program/trace generation.
  **Synthetic only**: ground truth for tests and benchmarks. Nothing
  generated here is ever presented as a real finding.
- `backend/app/nn/evaluate_bpl.py` — honest evaluation runner
  (`python3 -m app.nn.evaluate_bpl` from `backend/`).
- `backend/tests/test_nn_bpl.py` — 10 tests, stdlib only.

`backend/app/nn/__init__.py` on this branch exports only the BPL
names. The sibling `feat/nn-scorer` branch adds the same file with
the MLP scorer exports; when the branches meet, merge the two
export lists by hand — neither side's exports may be dropped.

## Honest evaluation

Run with `python3 -m app.nn.evaluate_bpl` (2026-11-14, this box).
Real files at time of run: `fresh-deploys-more-chains.jsonl` 370
rows, `transition_events.jsonl` 54 rows (the dispatch brief said 52;
two rows arrived since), `candidates.jsonl` 727 rows.

### Real data (first domain: fresh deploys + transitions)

- 224 per-creator deploy traces (225 creator keys, one null-creator
  group of 6 rows dropped). Lengths: 190x1, 12x2, 9x3, 5x4, 2x6, 2x7,
  1x8, 1x9, 1x21, 1x39. **190 of 224 traces are a single deploy.**
- Deploy kind tokens: proxy 162, other 136, token 6, nft 60.
  The `other` bucket is coarse (DeploymentFeeContract,
  MockInterestRouter, Counter, ...), so "repeat other:scroll" below
  may hide distinct contracts.
- 54 transition traces, **all length 1** — an owner flip is a single
  event, not a behaviour trace; nothing to learn from or predict.
- Combined deploy+owner traces: **0** — no address appears in both
  files (deploys are scroll/optimism, flips are ethereum/bsc).
  Candidates overlap: 0 addresses with fresh-deploys, 2 with
  transitions. `candidates.jsonl` is finding-level data and is not
  used for program learning.
- Coverage: 33/224 traces compressible (best program shorter than
  flat) = **14.7%**, all via Repeat; mean description-length ratio
  (best/flat) **0.931**. Out-of-alphabet events: 0.
- Held-out last-event prediction (traces len >= 2, n=34):
  **BPL 32/34 = 0.941, Markov (leave-one-out) 29/34 = 0.853,
  frequency 11/34 = 0.324, random ~0.125.**
- Top shared programs on the real traces are trivial repetition,
  e.g. `Repeat(2, [Emit('DEPLOY:other:scroll')])`.

What this supports: BPL compresses 14.7% of real traces and predicts
the repetitive ones well. What it does NOT support: any claim that
BPL understands deployer behaviour in general. The real traces are
nearly degenerate — mostly single deploys, the rest mostly the same
deploy shape repeated — and the BPL-vs-Markov margin on real data is
3 traces out of 34. The real data is too thin and too repetitive to
benchmark inference. Say so in any summary; do not quote 0.941
without the n=34 and the repetition caveat.

### Synthetic benchmark (primary benchmark for the machinery)

Traces generated from known DSL programs (phase-ambiguous cycles
included, which order-1 Markov provably cannot resolve), held-out
last-event top-1 accuracy:

| set | n_held | BPL | Markov | Frequency |
|---|---|---|---|---|
| seed 7, noise 0 | 36 | **0.778** | 0.278 | 0.222 |
| seed 42, noise 0 | 57 | **0.719** | 0.193 | 0.246 |
| seed 123, noise 0 | 57 | **0.754** | 0.035 | 0.158 |
| seed 42, noise 0.05 | 59 | **0.508** | 0.102 | 0.085 |

These numbers are synthetic and labelled as such. They show the
inference machinery works and that the structural advantage (programs
over Markov) is real on traces with phase structure — not that it
transfers to live deployers, where the data above shows almost no
phase structure to exploit.

On the no-simulation rule (restated Nov 14: no simulated data in
ReconAnything scanning, real workflow only): the synthetic traces
here are test/benchmark fixtures for the engine itself, the same
category as Anvil fixtures for tool self-tests. They are never fed
into scanning, never presented as findings, and every number derived
from them is labelled synthetic.

## Assumptions and limits

1. The alphabet is fixed and hand-built. A new chain, a new deploy
   shape, or a new behaviour kind is out-of-alphabet until added.
   The engine still runs (Emit costs the same), but the prior no
   longer reflects the true choice set.
2. `Repeat` bodies are Emits only, length <= 4, count <= 6, depth
   <= 1. Longer cycles, nested loops, conditionals ("if the deploy
   was fresh, then..."), and data-dependent behaviour (amounts,
   addresses, timing gaps) are not expressible. Timing is not
   modelled at all.
3. Programs are deterministic generators plus an iid substitution /
   gap noise channel. Real behaviour is neither deterministic nor
   iid-noise; the channel is a scoring convenience, not a claim
   about how deployers work.
4. Beam search is approximate. It finds the shortest program in the
   tests, but there is no guarantee it finds the global posterior
   mode on an arbitrary trace; widen the beam if it misses structure.
5. The prior is uniform over counts (all counts cost `log2(5)` bits)
   and over alphabet events. It encodes no domain knowledge, e.g.
   that proxies are more common than tokens.
6. Prediction needs a program that overshoots the prefix. A prefix
   with no compressible structure yields only the flat program,
   which abstains — prediction then returns nothing rather than
   guessing. That is by design.
7. Cost is small: inference on a 40-event trace runs in well under a
   second on this CPU box; the full eval (real + synthetic, ~600
   traces) runs in seconds.

## Integration points (for later, not built here)

- **With `feat/nn-bayesian` (score uncertainty):** BPL posterior
  weights are calibrated probabilities over programs; they could
  feed the Bayesian scorer's uncertainty as an additional,
  independent uncertainty source (program-space uncertainty vs
  weight-space uncertainty). Not wired up; the two posteriors are
  over different objects and must not be multiplied naively.
- **With `feat/nn-synthesis` (tool generation):** a BPL-discovered
  program is a compact behavioural signature; it could seed a
  synthesis template ("watch for this deploy pattern") or be
  compiled into a detector. Synthesis owns codegen; BPL owns the
  signature. Neither branch existed as a worktree at build time
  (nn-synthesis had no tree; nn-bayesian was mid-restructure), so
  these are documented seams, not code.
- **With the NN scorer:** a trace-level BPL feature (e.g. best
  program's compression ratio, or the posterior mass on the top
  program) could one day join the scorer's feature vector as a
  behaviour feature. That needs a labelled set linking traces to
  outcomes, which does not exist yet.
