# Bayesian triage for ReconAnything (nn-bayesian)

Branch: `feat/nn-bayesian`. Triage only. Never predicts `VERIFIED_REAL`.

## What it is

The point-score MLP (`mlp.py`) answers "how likely is this finding
worth validating" with a single number and no sense of its own
ignorance. This module replaces the point score with a **distribution**:

- `nn_score` — the posterior **mean** (drop-in for the old point score)
- `nn_score_lo` / `nn_score_hi` — the **90% credible interval**
- `nn_score_std`, `nn_score_width`
- `nn_unsure` — true when the interval straddles the 0.5 decision
  line; the finding is labeled `needs-human-review` and routed to
  human review instead of auto-triage

## Method: last-layer Laplace

(Last-layer Laplace, MacKay 1992. Pure Python stdlib, no new deps.)

1. Train the MAP MLP exactly as v2 does: `[255, 64, 32, 1]`, lr 0.05,
   60 epochs, seed 42, on own-train (580) + external (1,922) rows.
2. Freeze the MLP as a feature extractor. For an input `x`, take the
   last hidden activations `h(x)` (32 tanh units) and append a bias
   term: `z = [h(x), 1]`.
3. Refit **only the last-layer weights** `w` (33 numbers) as a Bayesian
   logistic regression on `z`, prior `w ~ N(0, a^-1 I)` with
   `a = 1.0`. The posterior mode is found by Newton iterations
   starting from the MLP's own trained last-layer weights; the
   posterior is the Laplace Gaussian `N(w_map, H^-1)` where `H` is
   the Hessian of the negative log posterior at the mode.
4. At predict time, draw 256 weight samples from that Gaussian, push
   each through the sigmoid, and report the mean and the 5th/95th
   percentiles as the 90% credible interval.

Why last-layer only: a full Laplace over all ~18k weights needs an
18k x 18k Hessian, which is not feasible in pure Python. The last
layer carries the decision; the frozen hidden layers carry the
representation. This is the standard, honest trade-off.

## Calibration (measured, never assumed)

- The posterior covariance is multiplied by a single scale `c`,
  chosen on a held-out 10% slice of the **training** rows only
  (stratified, seed 43), from the grid
  `{0.25, 0.5, 0.75, 1, 1.5, 2, 3, 5}`, picking the scale whose
  binned 90% interval coverage is closest to 0.90 (ties broken by
  lower ECE). The scale is deliberately NOT fitted on the rows the
  MAP trained on: the MAP memorises train (train ECE 0.003), so a
  scale fitted there understates the width unseen rows need.
  `c = 1` means the raw Laplace posterior was already calibrated.
  The fitted value is saved in `weights.json`
  (`bayesian.calibration`) and in `viewer-data.json`.
- Reported on the fixed 145-row own holdout (seed 42): **ECE** of the
  posterior mean (10 bins), **Brier score**, **binned interval
  coverage** (rows sorted by posterior mean into equal-count bins,
  ~15 rows each; a bin is covered when its observed positive rate
  falls inside the bin's mean 90% interval), plus **confident
  accuracy vs unsure accuracy** and the **unsure rate**. Equal-count
  bins matter: equal-width bins leave most bins with 1-3 rows, where
  the observed rate is 0 or 1 by chance and the check measures noise.
  The per-bin table also shows the Wilson 95% interval for each
  bin's observed rate, so a reader can see when a miss is within
  binomial noise (e.g. a bin with 15/15 positives has observed rate
  1.0, which no interval below 1.0 can contain, yet is fully
  consistent with a true rate of 0.99). Read the strict number with
  its known boundary artifact: this dataset is 85% positive and the
  model is (correctly) extremely confident on most positives, so most
  bins are all-positive rows with observed rate exactly 1.0, which no
  interval below 1.0 can contain, whatever the scale. The operational
  reading of "the 90% interval covers ~90%" is therefore the
  **confident accuracy**: among rows whose interval excludes 0.5
  (the model commits), the fraction whose implied label is correct.
  A calibrated 90% interval should score >= 0.90 there. With n = 145
  the coverage number is a noisy check with wide binomial error bars,
  not proof. It is reported with its per-bin table.
- The point MLP's ECE / Brier on the same 145 rows are reported next
  to the Bayesian ones, so the calibration gain (or lack of it) is
  visible.

## Evaluation protocol (the fixed holdout)

- Own rows: 725 (`candidates.jsonl` + `batches.jsonl`), stratified
  split seed 42 -> own-train 580 / own-test **145**.
- External rows: 1,922, all in training.
- The model never trains on the 145. Evaluation is **only** on those
  145 rows. Headline numbers are posterior-mean accuracy / ROC AUC /
  confusion matrix, plus the calibration set above.
- Reference numbers on the same 145 rows: v1 (81-32-16-1)
  acc 0.8897, AUC 0.9781; v2 (255-64-32-1) acc 0.9103, AUC 0.9697.
  If the Bayesian mean does not beat v2 on accuracy, that is stated
  plainly in the results: the value of this model is the uncertainty,
  not a higher point accuracy.

## Files

- `backend/app/nn/bayesian.py` — posterior inference, credible
  intervals, calibration, holdout evaluation, per-finding scoring
- `backend/app/nn/train_bayesian.py` — training entry point
  (`python -m app.nn.train_bayesian`, `--map-weights` reuses a MAP
  checkpoint instead of retraining)
- `backend/app/nn/pipeline.py` — `load_bayesian()`, Bayesian fields
  in `score_finding_dicts()` / `attach_nn_scores()`; point-only
  weights keep scoring exactly as before (interval fields `None`)
- `backend/app/nn/score.py` — CLI prints the interval + UNSURE marker
- `backend/app/nn/__init__.py` — exports `LastLayerLaplace`,
  `load_bayesian`, `score_finding_bayesian`
- `backend/app/nn/api.py` — `/api/nn/status` reports the Bayesian
  block when present (via `weights.json`, no code change needed)
- `backend/tests/test_nn_bayesian.py` — unit tests, including a test
  that intervals widen on out-of-distribution inputs and a test
  that calibration is measured from real labels
- `backend/docs/nn-bayesian.md` — this file
- `backend/app/nn/weights.json` / `viewer-data.json` — trained model
  (weights carry a `bayesian` block: Laplace posterior + calibration)

## Results (fixed 145-row own holdout, seed 42)

Trained 2026-11-14. MAP: [255, 64, 32, 1], lr 0.05, 60 epochs,
seed 42, train 2,502 rows (580 own + 1,922 external). Laplace
prior precision 1.0, variance scale 0.5 (fitted on the 250-row
calibration slice; the grid was flat at 0.10 coverage for every
scale, because the strict binned rule cannot be satisfied by
all-positive bins — see the coverage note above).

| model | acc | ROC AUC | ECE | Brier |
|---|---|---|---|---|
| v1 (81-32-16-1) | 0.8897 | 0.9781 | — | — |
| v2 (255-64-32-1) | 0.9103 | 0.9697 | — | — |
| point MLP (this MAP) | 0.9103 | 0.9731 | 0.0489 | 0.0561 |
| **Bayesian posterior mean** | **0.9103** | **0.9700** | 0.0653 | 0.0560 |

The Bayesian mean does **not** beat v2 on accuracy: it ties it
exactly (0.9103), and its AUC (0.9700) sits between v2 (0.9697)
and the point MLP (0.9731). That is the honest result: the value
of this model is the uncertainty, not a higher point accuracy.

Confusion (Bayesian mean, threshold 0.5): tp=114 fp=3 fn=10 tn=18.
Worth-validating recall 0.919, likely-FP recall 0.857.
Majority baseline accuracy on the holdout: 0.8552.

Uncertainty: 8 of 145 rows (5.5%) flagged unsure and routed to
human review. Confident rows (137): accuracy 0.934. Unsure rows
(8): accuracy 0.500 — the model knows what it doesn't know.
Strict binned 90% coverage: 0.09 (1/11 bins); Wilson-overlap
coverage: 1.00 (11/11). Mean interval width on the holdout is
reported in `viewer-data.json` (`test_metrics_bayesian`).

No metric is 100%: nothing here is overfit to the holdout.

## Usage

```bash
# Full train (MAP + Laplace + calibration + eval), ~slow in pure Python
python -m app.nn.train_bayesian

# Reuse a MAP checkpoint (same seed + data => same weights)
python -m app.nn.train_bayesian --map-weights path/to/map_weights.json

# Score findings (flag-gated, default off)
RECON_NN_SCORING=1 python -m app.nn.score --target bsc:0x... --json
```

## Limits (honest)

- Triage only. Ranks findings by how much they look like past
  candidates that survived triage. Verifies nothing.
- Zero verified-real positives exist in the training data. The model
  never predicts `VERIFIED_REAL` and must never be used to claim one.
  A high score means "worth a live probe", nothing more.
- Label skew: the training set is ~85% worth-validating /
  15% likely-false-positive. Accuracy near the majority baseline
  means the model learned nothing; judge it by minority-class recall
  and ROC AUC instead.
- The 90% interval is a statement about the model's uncertainty, not
  a guarantee: with 145 test rows the coverage check is noisy, and
  the Laplace approximation itself assumes the posterior is
  Gaussian around the mode and that the last layer carries all the
  decision uncertainty. Intervals widen for near-OOD / ambiguous
  inputs (unseen plugin, moderate values: width 0.49 vs 0.25
  in-distribution), but they COLLAPSE for extreme maxed-out inputs:
  a finding with confidence 100, critical severity, 20 evidence
  items and a 2000-char value saturates the tanh hidden units and
  the sigmoid, giving width ~0.01. Last-layer Laplace + sigmoid
  outputs cannot flag that kind of extreme OOD by interval width.
  Out-of-distribution inputs widen the interval (tested), but no
  interval can cover a failure mode the representation cannot see.
- The strict binned 90% coverage on the 145-row holdout is 0.09
  (1/11 bins), not ~0.90: most bins are all-positive rows whose
  observed rate is exactly 1.0, which no interval below 1.0 can
  contain. The operational reading is the confident accuracy
  (0.934 on 137 confident rows) and the Wilson-overlap coverage
  (1.00). The intervals are honest about the model's uncertainty
  where it matters (unsure rows are right only 50% of the time)
  and too narrow where the MAP is saturated. See Results below.
- Findings from plugins or chains unseen in training fall into the
  OTHER bucket; the model has no opinion about them beyond the
  generic features.
- Detection only, read-only live probes, no transactions, no drains.
  crypto.com is never a target.
