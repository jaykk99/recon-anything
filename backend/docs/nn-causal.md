# Structural Causal Models / Causal AI (Do-Calculus) for ReconAnything

Pure Python stdlib, zero new dependencies. Code:
`backend/app/nn/causal.py`, evaluation `backend/app/nn/causal_eval.py`,
tests `backend/tests/test_nn_causal.py`.

Triage only. This never predicts `VERIFIED_REAL`, never executes an
exploit, never moves funds, never bypasses auth. Live probes stay
read-only. crypto.com is never a target.

## What it is

The NN scorers (v1 81-32-16-1, v2 255-64-32-1) learn
`P(label | features)` — association. This module learns and queries
`P(label | do(X = x))` — what happens when we **intervene**. The
difference matters the moment anyone asks "what if": what if this
owner goes offline, what if this plugin's finding were acted on,
what if the chain mix were different. Association cannot answer
those; a structural causal model (SCM) can, **when the effect is
identified**, and says so explicitly when it is not.

## The model

A Pearl SCM: a DAG plus one structural equation (a conditional
probability table, CPT) per node.

**Nodes** (`build_recon_graph`):

| node | meaning | observed |
|---|---|---|
| `chain` | chain the target lives on | yes |
| `plugin` | plugin that fired | yes |
| `function` | function the finding is in | yes |
| `recipient_class` | CALLER / CALLER-SUPPLIED / ... | yes |
| `latent_vuln` | the true underlying vulnerability | **no** |
| `worth_validating` | triage label (1 = UNVERIFIED, 0 = likely FP) | yes |
| `live_probe` | success / revert / transport_error | yes |
| `owner_change` | an owner flip was recorded | yes |
| `next_owner` | what the owner changed to (renounced / new_owner) | only when a flip happened |
| `backup_infra` | infra the operator would spin up next if the owner/server went offline | **no** |

**Edges** (each documented in `RECON_ASSUMPTIONS` in the code):
`chain -> plugin`, `chain -> owner_change`, `chain -> next_owner`,
`plugin -> function`, `plugin -> recipient_class`,
`latent_vuln -> plugin`, `latent_vuln -> worth_validating`,
`latent_vuln -> live_probe`, `plugin -> worth_validating`,
`owner_change -> next_owner`, `owner_change -> backup_infra`.

CPTs are fitted by counting with Laplace smoothing. Two honesty
rules are built into `StructuralModel.fit`:
- A node with an **unobserved parent** (e.g. `plugin`, whose parent
  includes `latent_vuln`) is **not** fitted by counting — that would
  pretend the latent is observed. It gets a uniform CPT and fit
  count 0. Fitting it would need EM, which is out of scope here.
- A value outside a node's domain collapses to `"other"` when the
  domain has one (rare plugins/functions); otherwise that row is
  skipped for that node. A target with no recorded flip gets
  `owner_change = 0` and **no** `next_owner` key — the next owner
  is unobserved there, never defaulted.

## The do-calculus used

- **Do-operator (graph surgery).** `model.intervene({X: x})` cuts
  every edge into X and replaces X's CPT with a point mass at x.
  `interventional_dist` then enumerates the mutilated joint
  exactly (state-space cap 250k; Monte Carlo fallback with a
  fixed seed above that). This is `P(Y | do(X=x))`, not the
  observational `P(Y | X=x)`.
- **Identification (back-door criterion).** `identify_effect`
  searches for the smallest set of *observed* non-descendants of X
  that d-separates X and Y in the graph with X's outgoing edges
  removed. If none exists it names the blocker (usually a
  back-door path through an unobserved node). `estimate_effect`
  then applies the adjustment formula
  `P(Y | do(X=x)) = sum_z P(Y | X=x, Z=z) P(Z=z)` to rows.
- **d-separation.** Ancestral-graph + moralization (Lauritzen):
  restrict to ancestors of {X, Y} ∪ Z, marry parents, drop
  directions, delete Z, test reachability.
- **Counterfactuals (twin networks).**
  `CounterfactualEngine` rewrites each equation as a deterministic
  function of its parents plus one exogenous uniform noise variable
  (inverse-CDF on the CPT), then does abduction / action /
  prediction: rejection-sample noise vectors matching the evidence,
  apply `do()`, read off the target. The answer always carries its
  assumptions and a confidence (`high`/`medium`/`low`/
  `unidentified`) derived from the abduction acceptance count.
  A collapsed acceptance returns `distribution: None` and
  `confidence: "unidentified"` instead of a confident-looking
  number.

Do-calculus rules 1–3 are what justify the above: rule 2 (action /
observation exchange) is what the back-door adjustment implements;
rule 3 (deletion of actions) is what lets `do()` ignore upstream
causes of the intervened node.

## The backup-infra question

`predict_backup_infra(model, evidence, ...)` answers: "if this
owner/server went offline, which backup infra would the operator
spin up next?" It runs the counterfactual query on the learned
mechanism — **but only when the mechanism is actually observed**:
the target's CPT must be fitted from >= 30 rows. Otherwise it
returns `prediction: None`, `confidence: "unidentified"`, and the
reason. An invented backup-infra prediction would be worse than
none.

## Honest evaluation — real data only

Per the restated NO-SIMULATION RULE (Nov 14): **real workflow,
real numbers, nothing invented.** This section reports only
`candidates.jsonl` (727 rows) and `transition_events.jsonl`
(54 events at run time — the watcher appends live, so the count
moves; the brief's "52" was the count at dispatch). Synthetic
graphs appear **only** in the unit self-tests
(`test_nn_causal.py`), where they prove the engine against known
ground truth; **their results are never presented as evaluation
numbers**.

Run it: `python3 -m app.nn.causal_eval` (from `backend/`).

### Data

- Labeled rows: **725** (620 worth-validating / 105 likely-FP;
  2 `VERIFIED_REAL` rows excluded, same rule as the scorer's
  `data.py` — they are already-adjudicated simulation-path false
  positives, real verified count is 0).
- Fixed holdout: stratified, seed 42, 20% → **145 test rows**
  (124 pos / 21 neg), the same split the v1/v2 numbers refer to.
  The majority accuracy reproduces exactly (0.8552), confirming
  the split matches.
- Transitions: **54 owner flips on 11 addresses**, 0 implementation
  changes, 27 flips to null (renounced) / 27 from null.
  P(renounced | flip) = 0.50.
- Overlap: only **2 of the 11** flipped contracts ever appear in
  candidates — "what finding follows a flip" has no testable
  sample.

### Holdout triage (145 rows)

| method | accuracy | log-loss | Brier |
|---|---|---|---|
| majority baseline | 0.8552 | 0.4136 | 0.1239 |
| correlation-only P(label \| plugin) | 0.9172 | 0.1642 | 0.0533 |
| causal, back-door-adjusted P(label \| do(plugin)), adjusting for chain | 0.9172 | 0.2133 | 0.0609 |
| reported v1 scorer (reference, not recomputed) | 0.8897 | — | — |
| reported v2 scorer (reference, not recomputed) | 0.9103 | — | — |

Read this plainly: the causal adjustment **does not beat** the
correlation baseline at prediction (same accuracy, 133/145 rows;
worse log-loss — the adjusted probabilities are less extreme).
That is expected, not a failure: adjustment removes confounding
bias for *intervention* questions; it does not add predictive
signal. The 1-row edge over the reported v2 number (133 vs 132
rows) is noise on n=145, not a win claim. The value of the causal
model is the "what if" answers, not a higher accuracy.

Chain confounding is real in the data, and adjustment moves the
estimates: base label rates by chain are bsc 0.9066 (n=514),
ethereum 0.3226 (n=31), base 0.3333 (n=15). Examples
(raw → chain-adjusted P(label=1 | do(plugin))):
`contract_logic` 0.684 → 0.817 (n=55 train),
`unchecked_math_user_input` 0.992 → 0.945 (n=392),
`uups_authorize_upgrade_missing` 0.938 → 0.895 (n=30),
`recipient_bridge_release_unproven` 0.091 → 0.142 (n=9).
Small-plugin gaps are noisy; the big-plugin gaps are the signal.

### Identification on the real graph

- `PLUGIN -> WORTH_VALIDATING`: **not identifiable**. A back-door
  path runs through the unobserved `latent_vuln` (the true
  vulnerability causes both the plugin firing and the verdict).
  No observed adjustment set can block it. Any number presented
  as "the causal effect of plugin X on the verdict" from
  candidate rows alone would be unjustified.
- `OWNER_CHANGE -> NEXT_OWNER`: **identifiable**, adjusting for
  `chain`.
- `OWNER_CHANGE -> BACKUP_INFRA`: **graphically identified**
  (no back-door path) but **not estimable**: the mechanism was
  fitted from 0 rows. Identification is not estimation — the
  query still returns `unidentified`.

### Transition held-out test — flagged as a toy result

Setup: last flip per multi-flip address held out (n=8); predict
its direction (renounced vs new owner) from the mechanism fitted
on earlier flips.

| method | accuracy (n=8) |
|---|---|
| mechanism P(after_null \| before_null, chain) | **1.00 (8/8)**, 95% Wilson (0.68, 1.00) |
| majority direction | 0.25 (2/8) |
| random (expected) | 0.50 |

**This perfect score is a toy result, not a win — do not quote it
as one.** The flips alternate set/null almost perfectly per
address (e.g. `0x2260fac5…`: before S N S N, after N S N S;
mechanism table: P(after=null | before=set) = 0.963,
P(after=null | before=null) = 0.046). A renounced owner **cannot
be re-set on-chain** — renouncement is irreversible — yet the data
shows null → set transitions repeatedly (up to 11 flips on one
address). These are read flapping (the watcher alternately reading
null vs an address), not operator behaviour. The 8/8 predicts the
toggle of a flapping sensor. The transition data therefore cannot
support any causal claim about what follows an owner change.

### Backup-infra question on real data

`predict_backup_infra(..., target="backup_infra")` returns
**`prediction: None`, `confidence: "unidentified"`** — the
mechanism was fitted from 0 rows. Correct behaviour: no
follow-on deployment is recorded after any flip.

The narrower identified mechanism it *can* answer:
P(next_owner | do(owner_change)) from the 54 flips is
renounced 0.50 / new owner 0.50 — a coin flip, and (per above)
probably a sensor artefact anyway.

## Limits — stated plainly

1. **The real data is too thin for an honest causal claim about
   what follows an owner change.** 54 flips, 11 addresses, 0
   implementation changes, 2 addresses overlapping candidates,
   and the flips themselves look like read flapping. Nothing in
   this module should be quoted as "the causal effect of an owner
   change" on findings, implementations, or backup infra.
2. **The headline effect is unidentifiable.** `PLUGIN ->
   WORTH_VALIDATING` is confounded by the unobserved true
   vulnerability. The module reports this; it does not work
   around it.
3. **Causal adjustment does not improve triage prediction here**
   (same accuracy, worse log-loss). Use the NN scorer for ranking;
   use this module for "what if" questions on identified effects
   and for saying no when an effect is not identified.
4. **Counterfactuals assume the SCM is right** (causal
   sufficiency, invariant noise, surgical interventions). Those
   assumptions are listed on every answer; they are not verified
   by this data.
5. **Fitting is counting, not EM.** Nodes with unobserved parents
   stay uniform. Exact enumeration caps at 250k states.
6. **The transition file is live.** Counts move as the watcher
   appends; re-run the eval for current numbers.

## What would make the causal claims real

- A `VERIFIED_REAL` set with actual live-probe-verified outcomes
  (currently 0 real rows) — without it, the label side has no
  ground truth to anchor `latent_vuln`.
- Follow-on events recorded per contract after a flip (new
  implementation deployed, new owner set, infra spun up) — this
  is what would identify the backup-infra mechanism.
- Owner reads that do not flap (or a flap flag on the watcher) —
  until then, transition "mechanisms" are sensor artefacts.
- An instrument or a second independent read of the latent
  vulnerability (e.g. a second validator family) to break the
  plugin/verdict confounding.

## Tests

`python3 -m pytest tests/test_nn_causal.py` — 20 tests, all on
small hand-built graphs with known ground truth (unit self-tests
of the tool itself, per the Nov 14 rule — not evaluation):
graph build + cycle rejection, d-separation (chain / fork /
collider), do-operator surgery, confounded / collider / mediation
effects vs known truth, back-door identification (identifiable
and latent-confounded), adjustment recovering the truth from
sampled rows, counterfactuals with known answers (XOR twin
network, backup-infra query), recon graph build + identification,
backup-infra prediction on a known mechanism and on a thin one,
model save/load round-trip. All 20 pass.
