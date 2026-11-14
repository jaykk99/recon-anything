# Spiking Neural Network (SNN) triage — `backend/app/nn/snn.py`

Event-driven leaky integrate-and-fire (LIF) triage scorer for
ReconAnything plugin findings. Pure Python stdlib, no new
dependencies. It scores the **same 255-dim features as the v2 MLP**
(`features.py`), so the two models are directly comparable on the
same fixed holdout.

## What it is

- **Input:** one finding's feature vector, rate-coded into spike
  trains over `T` timesteps. Each feature value in [0, 1] is the
  firing probability per step (deterministic, seeded Bernoulli), so
  a finding becomes a short event stream, not a static vector.
- **Network:** 255 -> 32 LIF -> 2 LIF (one neuron per triage class:
  index 0 = likely-false-positive, index 1 = worth-validating).
  Membrane: `v <- beta * v + I`, spike when `v >= threshold`,
  hard reset to 0. Default `beta = 0.9`, `threshold = 1.0`,
  `T = 32`.
- **Readout:** spike counts `c0, c1` over the window.
  Score = `sigmoid(8 * (c1 - c0) / T)`. The score is averaged over
  5 independent encodings at predict time: a single rate-coded
  readout is noisy (one spike more or less flips the count
  difference), and averaging is what makes the score stable.
- **Learning:** surrogate gradient + backpropagation through time.
  The fast-sigmoid surrogate derivative
  `surr'(v) = 1 / (k * |v - threshold| + 1)^2` with `k = 5` stands
  in for the non-differentiable spike. Loss is class-weighted binary
  cross-entropy on the spike-count readout (balanced weights: the
  data is ~85% worth-validating). Mini-batch SGD, lr 0.2.
  STDP was not used: it is unsupervised and does not fit a labeled
  triage objective.
- **Init calibration:** before training, the hidden/output biases
  are nudged until both layers fire at a healthy rate on a sample
  of the training rows (labels not used). A LIF layer that never
  fires gets almost no surrogate gradient, so training stalls;
  the right bias depends on how many inputs spike per step, which
  varies by task. This is initialization only.
- **Event-driven / sparse:** most features are 0 (only one plugin
  block is live per finding), so the forward pass only touches the
  inputs that actually spike at each step. That keeps training to
  seconds-per-epoch of CPU instead of the minutes a dense
  implementation would take.

## What it is not

Triage only. It ranks findings by how much they look like past
candidates that survived triage. It never predicts VERIFIED_REAL:
there are zero verified-real positives in the training data, so the
model has never seen one and must never claim one. Detection only,
read-only live probes, no transactions, no drains. crypto.com is
never a target.

## Train / evaluate

```bash
cd backend
python -m app.nn.snn \
  --external app/nn/external_findings.jsonl \
  --feature-cache /tmp/snn_cache.json   # optional, speeds retrains
# writes app/nn/snn_weights.json + app/nn/snn_viewer_data.json

python -m app.nn.snn --eval-only app/nn/snn_weights.json
```

Holdout: the **fixed own-test split**, `stratified_split(own 725,
test_frac=0.2, seed=42)` -> **145 rows** (124 worth-validating /
21 likely-false-positive). Training rows are the other 580 own rows
plus all 1,922 external rows. External rows never enter the holdout:
the holdout measures performance on Jay's own scanner rows only,
exactly like the v1/v2 numbers.

## Honest results (fixed 145-row own holdout, seed 42)

<!-- METRICS: from snn_viewer_data.json, trained 2026-11-14T08:49:35Z -->

| model | test acc | ROC AUC | WV recall | FP recall | confusion (tp/fp/fn/tn) |
|---|---|---|---|---|---|
| v1 MLP 81-32-16-1 | 0.8897 | 0.9781 | — | — | — |
| v2 MLP 255-64-32-1 | 0.9103 | 0.9697 | — | — | — |
| v2 MLP re-measured (weights.json snapshot in this dir, trained 2026-11-14T07:31:50Z) | 0.9310 | 0.9804 | 0.935 | 0.905 | 116/2/8/19 |
| **SNN 255-32-2, T=32** | **0.8828** | **0.9649** | **0.863** | **1.000** | **107/0/17/21** |

Train acc 0.9784 / train AUC 0.9974 (gap to test 0.8828: some
memorisation, but test is not 100%, so no overfit flag). Loss
0.452 -> 0.082 over 15 epochs; hidden spike rate 0.520.

Majority baseline on the holdout is 0.8552 (predict
worth-validating for everything). Accuracy near that means the
model learned nothing; judge by minority-class (likely-FP) recall
and ROC AUC instead.

## What the SNN is good for

The SNN does not beat the MLP on this tabular triage task (see the
table: 0.8828 acc / 0.9649 AUC vs v2's 0.9103 / 0.9697, and 0.9310 /
0.9804 for the re-measured v2 snapshot). That is the expected
outcome: SNNs shine on temporal event streams, and a single
finding's feature vector is a static snapshot, not a stream. What
the SNN does give:

- **Perfect likely-FP recall (1.000, 21/21):** it never promotes a
  false positive to worth-validating (fp = 0). The cost is
  worth-validating recall 0.863: it holds back 17 of 124 real ones.
  As a conservative first filter it wastes zero validator probes;
  as the only ranker it would miss 14% of the real candidates.
- **Event-stream behaviour:** the score comes from spikes over
  time, so the same finding can be re-scored as a stream of
  time-ordered events (e.g. a finding whose evidence arrives in
  stages), and the readout is a count, not a single dot product.
- **Sparsity:** only spiking inputs cost compute; silent features
  cost nothing. On event-heavy workloads that is the efficiency
  story.
- **A second opinion:** where the MLP and SNN disagree, the
  disagreement itself is a triage signal worth a human look.

Use the MLP for the ranking. Use the SNN where the event-stream
shape matters, or as a cross-check.

## Wiring

- `snn.py` exposes `SNN`, `load_snn_model`,
  `score_finding_dicts_snn` (pipeline-compatible shape).
- `pipeline.load_model` accepts both `recon-nn-weights/1` (MLP)
  and `recon-nn-snn-weights/1` (SNN): the SNN duck-types the MLP
  (`predict_proba`), so `pipeline.score_finding_dicts` and
  `python -m app.nn.score --weights app/nn/snn_weights.json` work
  with either file unchanged.
- `app/nn/__init__.py` exports `SNN`, `load_snn_model`,
  `score_finding_dicts_snn`.

## Limits

- Rate-coding noise: the readout is a count over a short window,
  so scores are noisier than the MLP's; the 5-sample average at
  predict time mitigates it but does not remove it.
- 145-row holdout with 21 negatives: the likely-FP recall is
  measured on 21 rows, so one row is ~5 points. Do not over-read
  small differences.
- The model has no opinion about plugins/chains unseen in
  training beyond the generic features (OTHER bucket).
- Any accuracy of 100% on this data would be overfitting, not a
  win; it is not claimed anywhere here.
