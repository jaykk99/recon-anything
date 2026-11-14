# Job 2 training record — pushing honest own-holdout accuracy past v2's 0.9103

Date: 2026-11-14. Branch: `feat/nn-v2-job2-sweep` (off `feat/nn-scorer`).
Scripts: `nn-logs/sweep_job2.py` (batch 1), `nn-logs/sweep_job2b.py`
(batch 2), `nn-logs/fetch_external_rows.py`,
`nn-logs/build_external_3422.py`. Raw results:
`nn-logs/job2/sweep-results.jsonl` (batch 1),
`nn-logs/job2/sweep-results-b2.jsonl` (batch 2).
Logs: `nn-logs/job2-sweep*.log`, `nn-logs/job2-fetch.log`.

## Verdict: v2 stands. No variant honestly beats it.

Nothing trained here beats v2 (0.9103 on the fixed 145-row own
holdout) by more than the seed noise. The shipped v2 weights from
Job 1 (`feat/nn-v2-shipped-weights`) stay shipped. This branch
commits the training record + the dropout implementation only.

## Fixed benchmark (same for every variant)

- Frozen own dataset: `candidates.jsonl.bak-20261114` (725 rows;
  `candidates.jsonl` has been edited since by the Nov 14 audit, so
  the frozen file is the benchmark). Stratified split seed 42:
  580 own-train / 145 own-test. Holdout frozen at
  `nn-logs/own-holdout-145-bak.jsonl` (Job 1).
- Training: 580 own-train + external rows. Batch 1/2-replication:
  1,922 external rows (ScaBench 351, xanoutas 450, defihack 378,
  Sherlock-invalid 293, audit-findings 450). Batch 2 ext3422:
  3,422 external rows (xanoutas + audit-findings caps 1,200).
- Features: v2 spec, 255 inputs. No new features (v3 proved more
  inputs memorize). No synthetic data anywhere. Triage-only.
- Primary metric: accuracy at threshold 0.5 on the frozen 145-row
  holdout, plus ROC AUC, confusion, FP recall, and train accuracy
  (memorization check). Secondary: same 145 rows under CURRENT
  (post-audit) labels — one holdout row (Gravity base
  `contract_logic` mint) was re-adjudicated FP after the freeze;
  current-labels scores run ~1 row higher and do not change any
  conclusion.

## Noise floor (measured, not assumed)

The baseline config (255-64-32-1, lr 0.05, l2 1e-4, 120 epochs)
across seeds 42/43/44 scores 0.9103 / 0.9172 / 0.9103 (mean
0.9126). One holdout row = 0.69%. Any single-seed gain of 1 row
is noise; a real beat needs a multi-seed mean clearly above the
baseline mean. The early-stopping curve (base-chunked) shows the
same churn: ep20 0.8897, ep40 0.9103, ep60 0.8966, ep80 0.9310,
ep100 0.9034, ep120 0.9172 — the ep80 0.9310 is selection noise
(it collapses by ep100) and was NOT shipped.

## Batch 1 results (seed 42 unless noted; frozen holdout)

| variant | test acc | AUC | confusion (tn/fp/fn/tp) | FP recall | train acc |
|---|---|---|---|---|---|
| base-single (v2 repro) | 0.9103 | 0.9685 | 18/3/10/114 | 0.8571 | 0.9892 |
| base-seed43 | 0.9172 | 0.9689 | 17/4/8/116 | 0.8095 | 0.9884 |
| base-seed44 | 0.9103 | 0.9681 | 18/3/10/114 | 0.8571 | 0.9888 |
| base-chunked ep80 | 0.9310 | 0.9743 | 13/8/2/122 | 0.6190 | 0.9852 |
| l2-1e-3 | **0.9241** | 0.9747 | 18/3/8/116 | 0.8571 | 0.9884 |
| l2-1e-2 | 0.9103 | 0.9770 | 19/2/11/113 | 0.9048 | 0.9880 |
| l2-3e-2 | **0.9241** | 0.9724 | 19/2/9/115 | 0.9048 | 0.9856 |
| small-32-16 | 0.8966 | 0.9700 | 18/3/12/112 | 0.8571 | 0.9892 |
| ep60 | 0.8966 | 0.9720 | 18/3/12/112 | 0.8571 | 0.9880 |
| drop-0.2 | 0.9103 | 0.9708 | 18/3/10/114 | 0.8571 | 0.9892 |
| drop-0.3 + l2-1e-3 | 0.9103 | 0.9704 | 18/3/10/114 | 0.8571 | 0.9888 |
| neg-dup2 | 0.9103 | 0.9662 | 18/3/10/114 | 0.8571 | 0.9892 |

Dropout was added to `backend/app/nn/mlp.py` (inverted dropout on
hidden units, training only) and verified: dropout=0 is
bit-identical to the old code, and the dropout gradient matches a
finite-difference check to 5e-10 (`nn-logs/test_dropout.py`).
Dropout changes nothing on this holdout: both dropout variants
reproduce v2's confusion exactly.

## Batch 2 results (seed replication + bigger external set)

| variant | test acc | AUC | confusion | FP recall | train acc |
|---|---|---|---|---|---|
| l2-1e-3 seed43 | 0.9103 | 0.9727 | 17/4/9/115 | 0.8095 | 0.9884 |
| l2-1e-3 seed44 | 0.8966 | 0.9704 | 18/3/12/112 | 0.8571 | 0.9876 |
| l2-3e-2 seed43 | 0.9241 | 0.9693 | 15/6/5/119 | 0.7143 | 0.9832 |
| l2-3e-2 seed44 | 0.9034 | 0.9720 | 19/2/12/112 | 0.9048 | 0.9856 |
| l2-1e-2 seed43 | 0.9241 | 0.9743 | 18/3/8/116 | 0.8571 | 0.9860 |
| ext3422-base | 0.9103 | 0.9697 | 18/3/10/114 | 0.8571 | 0.9933 |
| ext3422-l2-1e-3 | 0.9103 | 0.9716 | 16/5/8/116 | 0.7619 | 0.9920 |
| ext3422-l2-3e-2 | 0.9241 | 0.9689 | 11/10/1/123 | 0.5238 | 0.9178 |

The last row is NOT a beat, despite the 0.9241: train accuracy
collapsed to 0.9178 (strong L2 + more data underfit the training
set), the model just predicts positive far more aggressively (123
of 124 holdout positives caught, but 10 of 21 negatives wrong —
FP recall 0.5238, the worst of all 20 variants), and its AUC
0.9689 ties v2's 0.9685. It is an operating-point artifact on an
85%-positive holdout, not a better ranker. Single seed, no
replication.

Three-seed means (frozen holdout): base 0.9126, l2-1e-3 0.9103,
l2-3e-2 0.9172. The best mean lead is +0.7 rows over baseline —
inside the noise band. Every L2 strength hits 0.9241 on some seed
and ~0.90 on another; the 0.9241 level is a plateau this model
class reaches by luck, not a config property.

More real external data does not help either: the 3,422-row set
(base config) reproduces v2's confusion exactly (0.9103), with
train acc rising to 0.9933 — more memorization, no holdout gain.
The bigger set was built from fresh public fetches
(`fetch_external_rows.py`, HF datasets-server rows API, no keys:
xanoutas 18,869 rows, mmlliu audit-findings 23,625 rows) with the
documented caps 1,200/1,200; the 293 Sherlock-invalid rows were
carried over verbatim from the current external file (the original
gh search script is gone; re-fetching would not reproduce the
exact set).

## Memorization check

Every variant's train accuracy sits at 0.984–0.993 while test
accuracy sits at 0.897–0.924. The train/test gap (~8 points) is
present in v2 itself and in every variant; no variant shows the
v3 pattern (train ~1.0 + test drop). Nothing here is memorization
beyond what v2 already does — and nothing closes the gap either.

## What would actually move this

- The holdout is the bottleneck, not the model: 145 rows with 21
  negatives cannot resolve a 1–2 row gain. A bigger honest own
  holdout (more adjudicated scanner candidates) is the only way to
  measure a real improvement.
- The remaining errors are borderline rows that flip with seed;
  all configs saturate around 0.91–0.92 acc / 0.97 AUC on this
  holdout. Feature work (not more regularization) is the next
  lever, and it needs the bigger holdout to judge.
- Do NOT ship the ep80 chunked checkpoint (0.9310): it is a
  holdout-selected checkpoint whose neighbours score 0.8966–
  0.9172. Shipping it would be fitting the test set.
