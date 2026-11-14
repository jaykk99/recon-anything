# NN triage scorer — viewable, trainable neural network

A small multilayer perceptron (pure Python stdlib, zero new deps) that
scores plugin findings and ranks them by triage priority. It runs on
the Linux box and in Termux exactly as it runs here: no torch, no
sklearn, no numpy.

## What it is

- `backend/app/nn/mlp.py` — the network: configurable layers, tanh
  hidden units, sigmoid output, mini-batch SGD, backprop, JSON
  save/load.
- `backend/app/nn/features.py` — finding dict -> feature vector.
  V2 spec: every plugin gets its own block of 8 inputs (fired,
  confidence, severity, risk, finding count on this target, gate
  present, gate says "no caller gate", detector outcome present).
  Only the finding's own plugin block is live in a row; the other
  blocks read all-zero. Plus the top finding key (one-hot), bounty
  value, recipient class, chain, source origin, bytecode-only flags,
  contract role, report class, proxy/implementation presence,
  function presence/length, value length, evidence count. 255 inputs
  with a full top-24 plugin/key vocab (was 81 in the v1 spec, where
  each plugin was a single one-hot).
- `backend/app/nn/data.py` — labeled data: candidates.jsonl joined
  back to batches.jsonl on (chain, address, plugin, key) for the full
  evidence dicts, plus the per-plugin finding count on each target.
- `backend/app/nn/build_external_dataset.py` — builds the external
  training set from public audit findings (below) into
  `backend/app/nn/external_findings.jsonl`.
- `backend/app/nn/train.py` — training CLI + honest metrics.
  `--external` adds the external rows to Jay's own rows.
- `backend/app/nn/score.py` — score any target: runs the plugin set
  against it, ranks every finding. Stamps the per-plugin finding
  count from the run being scored.
- `backend/app/nn/pipeline.py` — optional pipeline wiring (flag-gated,
  default off).
- `backend/app/nn/viewer.html` — the dashboard (static, no CDN, works
  offline and as `file://`).
- `backend/app/nn/api.py` — `GET /nn` (viewer), `GET /api/nn/status`,
  `POST /api/nn/score` (behind the app's normal gate).

## External training data (public sources only)

Jay's own rows are 725 scanner candidates. The external set adds
other people's public findings, mapped into the same row shape:

| Source | Rows | Label | Why it counts |
|---|---|---|---|
| ScaBench curated-2025-08-18 (MIT) | 351 | 1 | Published Code4rena / Cantina / Sherlock findings, High/Medium |
| xanoutas/solidity-security-findings (HF) | 450 | 1 | Confirmed Code4rena / Sherlock findings, High/Medium, deduped by title |
| audit-findings-dataset (mmlliu, HF) | 450 | 1 | Audit-contest findings, Critical/High/Medium, titles cleaned of warden handles |
| DeFiHackLabs incidents (defihack.json) | 378 | 1 | Confirmed fund-loss exploits, all High |
| Sherlock judging "Invalid" issues | 293 | 0 | Judge-labeled invalid findings — the honest likely-FP rows |

Standard external set: 1,922 rows (1,629 positive / 293 negative).
Combined with Jay's 725 (620 / 105): 2,647 rows, 85% positive —
the same skew ratio as the own-only data. A bigger variant
(xanoutas + audit-findings caps raised to 1,200 each) is 3,422
external rows; it was tried and kept only if held-out metrics
improved (see the PR description for the numbers).

Labeling rules, enforced by the builder, never invented:
- Label 1 only for judge/audit-confirmed High/Medium (Critical
  kept as critical) or confirmed fund-loss exploits.
- Label 0 only for Sherlock findings the judges labeled Invalid.
- Low / informational audit findings are dropped, not relabeled:
  they are real, so calling them false positives would be a lie.
- Slither-only candidates and unconfirmed tool output are dropped.
- Every row carries its provenance (dataset, platform, source id,
  source URL) and the builder prints a full drop report.
- Keyword mapping from finding text to a ReconAnything plugin id
  only fires on a clear class match (reentrancy, access control,
  oracle, flash loan, ...); no match leaves the plugin blank, which
  the extractor reads as the OTHER bucket.
- Confidence is 85, fixed, for every external row: own scanner
  findings cluster at 80-90, so 85 sits inside the real distribution
  and does not mark a row as external. The source gives no
  confidence, so none is claimed.

Rebuild it (public fetches only, no keys, no logins):

```bash
# fetch the xanoutas + audit-findings rows (HuggingFace rows API):
python3 fetch_xanoutas.py        # -> /tmp/xanoutas-rows.jsonl
python3 fetch_auditfindings.py   # -> /tmp/auditfindings-rows.jsonl
# fetch Sherlock Invalid issues (gh api, search API):
python3 fetch_sherlock_invalid_search.py  # -> /tmp/sherlock-invalid.jsonl
# defihack.json + scabench JSON come straight from GitHub raw.
python -m app.nn.build_external_dataset --scabench <path-or-url> \
  --xanoutas /tmp/xanoutas-rows.jsonl --xanoutas-cap 450 \
  --defihack /tmp/defihack.json \
  --sherlock-invalid /tmp/sherlock-invalid.jsonl \
  --audit-findings /tmp/auditfindings-rows.jsonl --audit-findings-cap 450 \
  --out backend/app/nn/external_findings.jsonl
```

## Train

From `backend/`, with the backend venv python (the scorer needs the
plugin registry; plain scoring of a findings file works with system
python too):

```bash
python -m app.nn.train
```

Reads `~/workspace/recon-continuous/results/candidates.jsonl` and
`batches.jsonl` by default (`--candidates` / `--batches` to override).
Add `--external backend/app/nn/external_findings.jsonl` to train on
Jay's rows plus the external set. Writes
`backend/app/nn/weights.json` and `viewer-data.json`, and refreshes
the embedded metrics in `viewer.html`. Prints real metrics:
train/test accuracy, majority-baseline accuracy, ROC AUC,
precision/recall for both classes, the confusion matrix, and grouped
permutation feature importance.

Options: `--epochs 60 --hidden 32,16 --lr 0.05 --seed 42
--test-frac 0.2 --limit N`. The v2 model trains at 255 inputs; the
sweep that picked its config is in the PR description (epochs and
hidden width were chosen by honest held-out accuracy, not by
memorizing the test set — a 100% test score would be reported as
overfit, never as a win).

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
3. **Label skew.** The combined training set is ~85%
   worth-validating / ~15% likely-false-positive (2,249 / 398 of
   2,647 rows; the exact split is computed on every run and printed
   in the viewer). A model that predicts "worth validating" for
   everything already scores ~85% accuracy. Accuracy alone means
   nothing: judge the model by likely-false-positive recall and ROC
   AUC, printed next to the majority baseline on every run and in
   the viewer.
4. **Small data.** 2,647 labeled rows in the combined set (725 of
   Jay's own + 1,922 external). The network is small on purpose; a
   bigger model would just memorise these rows. The v2 spec has 255
   inputs and more first-layer weights than v1 — held-out metrics,
   not train metrics, decide whether that capacity helped.
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
