# NN triage scorer — viewable, trainable neural network

A small multilayer perceptron (pure Python stdlib, zero new deps) that
scores plugin findings and ranks them by triage priority. It runs on
the Linux box and in Termux exactly as it runs here: no torch, no
sklearn, no numpy.

## What it is

- `backend/app/nn/mlp.py` — the network: configurable layers, tanh
  hidden units, sigmoid output, mini-batch SGD, backprop, JSON
  save/load.
- `backend/app/nn/features.py` — finding dict -> feature vector. Every
  feature comes from a field that really exists in the finding dicts
  the scanner writes (plugin, key, severity, bounty value, confidence,
  recipient class, chain, evidence: source origin, bytecode-only flag,
  detector outcome, gate analysis, contract role, report class,
  proxy/implementation addresses, function, value length, risk).
- `backend/app/nn/data.py` — labeled data: candidates.jsonl joined
  back to batches.jsonl on (chain, address, plugin, key) for the full
  evidence dicts.
- `backend/app/nn/train.py` — training CLI + honest metrics.
- `backend/app/nn/score.py` — score any target: runs the plugin set
  against it, ranks every finding.
- `backend/app/nn/pipeline.py` — optional pipeline wiring (flag-gated,
  default off).
- `backend/app/nn/viewer.html` — the dashboard (static, no CDN, works
  offline and as `file://`).
- `backend/app/nn/api.py` — `GET /nn` (viewer), `GET /api/nn/status`,
  `POST /api/nn/score` (behind the app's normal gate).

## Train

From `backend/`, with the backend venv python (the scorer needs the
plugin registry; plain scoring of a findings file works with system
python too):

```bash
python -m app.nn.train
```

Reads `~/workspace/recon-continuous/results/candidates.jsonl` and
`batches.jsonl` by default (`--candidates` / `--batches` to override).
Writes `backend/app/nn/weights.json` and `viewer-data.json`, and
refreshes the embedded metrics in `viewer.html`. Prints real metrics:
train/test accuracy, majority-baseline accuracy, ROC AUC,
precision/recall for both classes, the confusion matrix, and grouped
permutation feature importance.

Options: `--epochs 60 --hidden 32,16 --lr 0.05 --seed 42
--test-frac 0.2 --limit N`.

## View

```bash
# standalone, no backend needed:
python3 -m http.server 8000 --directory backend/app/nn
# then open http://localhost:8000/viewer.html
```

Or, with the backend running, open `/nn`. The dashboard shows the
architecture diagram, training loss/accuracy curves, confusion matrix,
per-feature importance, dataset stats, and a live "score a target"
panel (posts to `/api/nn/score` when the backend is up; otherwise it
shows the CLI command).

## Score any target

```bash
# a contract (curated 29-plugin set; --plugin-set stepb for the 301-plugin set)
python -m app.nn.score --target bsc:0xbe1936a67f503e0eaf2434b0cf9f4e3d7100008a
# a URL or domain (bounded plugin run, passive keyless plugins first)
python -m app.nn.score --target https://example.com --max-plugins 40
# findings you already have (any target type, no plugins run)
python -m app.nn.score --findings findings.jsonl
# full JSON output
python -m app.nn.score --target bsc:0x... --json
```

Each finding comes back with `nn_score` (0-1), `nn_label`
(`worth-validating` / `likely-false-positive`) and `nn_top_features`
(the 3 features most responsible for the score, by leave-one-out).

## Wire into the pipeline (optional, default off)

```bash
RECON_NN_SCORING=1  # worker env
```

With the flag set, `backend/app/runner.py` scores every finding after
its plugin runs and attaches `nn_score` / `nn_label` /
`nn_top_features` into the finding's evidence before persist. With
the flag unset (the default) nothing changes: no model is loaded and
findings pass through untouched. Scoring never breaks a scan — any
failure leaves findings unscored.

From Python:

```python
from app.nn.pipeline import attach_nn_scores, score_finding_dicts
scored = score_finding_dicts(finding_dicts)  # ranked, in place
```

## Honest limits — read before trusting a score

1. **Triage only.** A high score means "looks like past candidates
   that survived triage, worth a live probe". It does not verify
   anything. It never predicts VERIFIED_REAL.
2. **Zero verified-real positives.** The training data has no real
   verified drain in it (the 2 VERIFIED_REAL rows are adjudicated
   simulation-path false positives and are excluded from training).
   The model has never seen a real one and must never be used to
   claim one.
3. **Label skew.** The training set is ~85% worth-validating / ~15%
   likely-false-positive. A model that predicts "worth validating"
   for everything already scores ~85% accuracy. Accuracy alone means
   nothing: judge the model by likely-false-positive recall and ROC
   AUC, printed next to the majority baseline on every run and in
   the viewer.
4. **Small data.** 725 labeled rows (620 positive, 105 negative)
   after the join. The network is small on purpose; a bigger model
   would just memorise these rows.
5. **Unseen plugins/chains fall into the OTHER bucket.** The model
   has no opinion about them beyond the generic features (severity,
   confidence, value length, evidence presence).
6. **Features are scan-time only.** Validation verdicts and live-probe
   outcomes are label-side and are never fed in as features.

## Tests

```bash
pytest tests/test_nn_mlp.py tests/test_nn_features.py \
       tests/test_nn_pipeline.py tests/test_nn_viewer.py -q
pytest tests/test_nn_train.py -q   # trains on the real candidates file;
                                   # skipped automatically when the file
                                   # is absent (e.g. CI)
```
