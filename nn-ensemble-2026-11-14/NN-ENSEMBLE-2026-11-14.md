# NN ensemble: v2 + hypergraph + multimodal on the FIXED 145-row own holdout

Date: 2026-11-14/15 (scoring 23:22 UTC; fresh retrains 23:24–00:49 UTC,
with a service-restart resume in the middle — see below).
Branch: `feat/nn-ensemble-2026-11-14`. No PR, no merge
(commit-instead-of-PR rule). Triage-only throughout: no model here
stamps VERIFIED_REAL, and neither does any ensemble of them.

## Question

Do the three verified models — v2 (0.9103), hypergraph (0.9379),
multimodal (0.9724) on the fixed 145-row own holdout (seed 42) —
combine into an ensemble that honestly beats the best single model
(multimodal, 0.9724)?

## Method

- **Fixed holdout, same as the re-validation.** Own 725 rows from
  `candidates.jsonl.bak-20261114` (727 rows, 2 VERIFIED_REAL excluded),
  `stratified_split(own, 0.2, 42)` → train 580 / test **145 (124 pos /
  21 neg)**, majority baseline 0.8552. External 1,922 rows joined to
  TRAIN only (train total 2,502). Reconstruction identical to
  `feat/nn-reval-2026-11-14` (`NN-REVAL-2026-11-14.md`).
- **Members, two independent passes.**
  1. *Reval weights:* the weights the re-validation retrained on this
     exact split were rescored per test row (`scripts/score_v2.py`,
     `score_multi.py`, `score_hyper.py`). Provenance check: rescoring
     reproduces every member's reval numbers EXACTLY (see table) —
     acc, AUC and confusion identical to the reval report, so the
     weights are verified to come from the fixed-split training rows.
  2. *Fresh retrains:* all three members retrained from scratch on
     the same training rows (`scripts/run_retrain.sh`, detached,
     checkpoint every 20 epochs), rescored, and re-ensembled — see
     "Fresh-retrain confirmation" below.
- **Ensembles — fixed rules only, no fitting on the test set.**
  - `avg3`: equal mean of the three member probabilities, threshold 0.5.
  - `majority`: majority of the three member 0.5-threshold votes;
    its ranking score for AUC is the vote fraction (0, 1/3, 2/3, 1),
    not a 0/1 output — a 0/1 AUC would not be comparable to the
    continuous-score AUCs. Threshold 0.5 on the fraction is exactly
    ">= 2 of 3 votes", so accuracy/confusion are the plain majority.
  - Diagnostics (not contenders): pairwise means.
  - No learned stacking / meta-learner; no ensemble weight was fit
    on the test set (or anywhere — the means are unweighted).
- **Alignment gotcha, found and fixed:** the 5-field test-row key
  (chain, address, plugin, key, label) is NOT unique — 4 keys occur
  twice among the 145 rows. Dict-keying collapsed 145 rows to 141.
  The combiner aligns rows POSITIONALLY in split order after
  asserting the raw split-order key sequences are identical across
  all three score files (they are). The combined per-row file
  (`results/ensemble-combined.jsonl`) carries all three member
  scores plus the ensemble scores for every row.

## Results — reval weights (fixed 145-row own holdout, seed 42, threshold 0.5)

| Model / ensemble | Test acc | ROC AUC | tp / fp / fn / tn | WV recall | FP recall |
|---|---|---|---|---|---|
| v2 255-64-32-1 (recomputed) | 0.9103 | 0.9685 | 114 / 3 / 10 / 18 | 0.919 | 0.857 |
| hypergraph 255-16-16-1 (recomputed) | 0.9379 | 0.9823 | 117 / 2 / 7 / 19 | 0.944 | 0.905 |
| multimodal 290-64-32-1 (recomputed) | 0.9724 | 0.9850 | 122 / 2 / 2 / 19 | 0.984 | 0.905 |
| **ensemble avg3** | **0.9517** | **0.9873** | **119 / 2 / 5 / 19** | **0.960** | **0.905** |
| **ensemble majority vote** | **0.9586** | **0.9624** | **119 / 1 / 5 / 20** | **0.960** | **0.952** |
| diagnostic avg multimodal+hypergraph | 0.9517 | 0.9892 | 119 / 2 / 5 / 19 | 0.960 | 0.905 |
| diagnostic avg v2+multimodal | 0.9655 | 0.9820 | 121 / 2 / 3 / 19 | 0.976 | 0.905 |
| diagnostic avg v2+hypergraph | 0.9448 | 0.9816 | 117 / 1 / 7 / 20 | 0.944 | 0.952 |

Member recomputation is exact: every member row above is identical
to its reval number (acc, AUC, confusion). Baseline 0.8552.

## Verdict: NO — the ensemble does NOT beat the best single model

- **avg3 loses to multimodal by 3 rows** (138 vs 141 correct,
  0.9517 vs 0.9724). Its AUC is higher (0.9873 vs 0.9850), but on
  the metric that decides triage calls at threshold 0.5 it is worse.
- **Majority vote also loses, by 2 rows** (139 vs 141 correct,
  0.9586 vs 0.9724). It does fix one false positive multimodal makes
  (fp 1 vs 2, FP recall 0.952 vs 0.905) — but it loses three
  worth-validating rows multimodal gets right (fn 5 vs 2).
- The loss is concentrated in 4 rows where both ensembles flip
  multimodal's call (`results/ensemble-metrics.json`,
  `flips_vs_multimodal`): 3 are positives multimodal alone gets
  right (avg3 scores 0.4509, 0.3791, 0.4669 — the other two members
  drag the mean below 0.5), and 1 is a negative where majority is
  right and avg3 is wrong (avg3 0.5158). Multimodal is right where
  the other two are wrong 3 times; the reverse happens once.
  All three members agree on 131/145 rows (128 of them correct);
  3 rows are unanimously wrong — no ensemble of these three can fix
  those.
- The best pairwise diagnostic (v2+multimodal, 0.9655) still loses
  to multimodal alone by 1 row. Adding hypergraph hurts, not helps:
  avg3 (0.9517) < avg v2+multimodal (0.9655). The members' errors
  are too correlated, and multimodal's edge is in exactly the rows
  the weaker members get wrong.
- **What the ensemble does buy:** ranking quality. avg3 AUC 0.9873
  and avg multimodal+hypergraph AUC 0.9892 both beat multimodal's
  0.9850 — the averaged scores rank slightly better even though the
  0.5-threshold calls are worse. That is a real but narrow gain, and
  it does not change the verdict at the operating threshold.
- No model hits 100% anywhere. Train accuracies (multimodal 0.9952,
  hypergraph 0.9892) vs test accuracies remain memorisation gaps, as
  reported in the re-validation; the ensemble does not close them.

**Bottom line: ship multimodal alone for thresholded triage calls.
Do not replace it with the avg3 or majority ensemble.** If ranking
(AUC) ever matters more than the 0.5 call, avg multimodal+hypergraph
is the ranking-only alternative — but that is not the current use.

## Fresh-retrain confirmation

Chain: `scripts/run_retrain.sh` (23:24–00:10 UTC), interrupted by a
service restart that killed it mid-multimodal (epoch 60/120; the
checkpoint survived in the persistent workspace), then
`scripts/run_resume.sh` (00:11–00:49 UTC) resumed multimodal from
its epoch-60 checkpoint (`scripts/resume_multi.py`), ran hypergraph
fresh, and rescored + re-ensembled. Full logs:
`logs/retrain-all.log`, `logs/resume-all.log`.

| Model / ensemble (FRESH weights) | Test acc | ROC AUC | tp / fp / fn / tn | WV recall | FP recall |
|---|---|---|---|---|---|
| v2 255-64-32-1 (fresh, clean rerun) | 0.9103 | 0.9685 | 114 / 3 / 10 / 18 | 0.919 | 0.857 |
| hypergraph 255-16-16-1 (fresh, clean rerun) | 0.9379 | 0.9823 | 117 / 2 / 7 / 19 | 0.944 | 0.905 |
| multimodal 290-64-32-1 (fresh, RESUMED run) | 0.9586 | 0.9854 | 120 / 2 / 4 / 19 | 0.968 | 0.905 |
| **ensemble avg3 (fresh)** | **0.9586** | **0.9869** | **119 / 1 / 5 / 20** | **0.960** | **0.952** |
| **ensemble majority vote (fresh)** | **0.9586** | **0.9547** | **119 / 1 / 5 / 20** | **0.960** | **0.952** |
| diagnostic avg multimodal+hypergraph (fresh) | 0.9586 | 0.9892 | 119 / 1 / 5 / 20 | 0.960 | 0.952 |
| diagnostic avg v2+multimodal (fresh) | 0.9517 | 0.9827 | 120 / 3 / 4 / 18 | 0.968 | 0.857 |
| diagnostic avg v2+hypergraph (fresh) | 0.9448 | 0.9816 | 117 / 1 / 7 / 20 | 0.944 | 0.952 |

- **v2 and hypergraph reproduce EXACTLY as clean reruns** (every
  number identical to the reval pass, including the hypergraph
  no-edge ablation 0.924 / 0.967). Deterministic retraining confirmed.
- **Multimodal does NOT reproduce exactly — because of the resume,
  not because of the model.** `fit()` reseeds its shuffle RNG from
  seed 42 on every call, so the resumed 60 epochs replayed the
  epoch 0–59 shuffle sequence on top of epoch-60 weights. That is a
  different training trajectory on the same rows (documented in
  `scripts/resume_multi.py` and in the fresh viewer-data
  `resume_note`), and it lands 2 rows lower: 0.9586 (tp120/fn4)
  vs the reval 0.9724 (tp122/fn2), train acc 0.996 vs 0.9952. A clean
  multimodal rerun would be expected to reproduce 0.9724 exactly,
  as v2 and hypergraph did — that expectation is stated, not shown,
  and the resumed number must not be quoted as a clean second sample.
- **Verdict unchanged under the fresh weights: the ensemble does not
  beat the best single model.** With the resumed multimodal at
  0.9586, avg3 and majority both TIE it at 0.9586 (139 correct each)
  — never ahead. The fresh pass therefore confirms the reval-weight
  pass (where the ensembles lost by 2–3 rows): no version of this
  ensemble beats multimodal alone on the fixed holdout. The AUC
  story is the same too: avg multimodal+hypergraph 0.9892 beats
  multimodal's AUC (0.9854 fresh / 0.9850 reval) while tying/losing
  on accuracy.
- 5 rows are unanimously wrong in the fresh pass (vs 3 in the
  reval pass) — again, no ensemble of these three can fix those.

## How to reproduce

```bash
git worktree add ~/workspace/wt/nn-ensemble origin/master  # then checkout feat/nn-ensemble-2026-11-14
# rescore the reval weights + combine (fast, ~1 min):
nohup bash nn-ensemble-2026-11-14/scripts/run_ensemble.sh > nn-ensemble-2026-11-14/logs/score-all.log 2>&1 &
# fresh retrains from scratch + rescore + combine (~65 min, detached):
nohup bash nn-ensemble-2026-11-14/scripts/run_retrain.sh > nn-ensemble-2026-11-14/logs/retrain-all.log 2>&1 &
```

Scorers run from the reval worktrees (`~/workspace/wt/nn-reval-v2`,
`nn-reval-multi`, `nn-reval-hyper` backends) so each member is scored
by its own branch's feature code; the combiner
(`scripts/ensemble.py`) is pure stdlib and takes only the three
per-row score files. Weight paths can be overridden with
`ENSEMBLE_V2_CKPT`, `ENSEMBLE_MULTI_WEIGHTS`,
`ENSEMBLE_HYPER_WEIGHTS` (used by the fresh-retrain chain).

## Files in this branch (under `nn-ensemble-2026-11-14/`)

- `NN-ENSEMBLE-2026-11-14.md` — this report
- `scripts/score_v2.py`, `scripts/score_multi.py`,
  `scripts/score_hyper.py` — per-row rescoring of member weights
- `scripts/ensemble.py` — fixed-rule combiner (avg, majority, pairwise)
- `scripts/run_ensemble.sh`, `scripts/run_retrain.sh` — detached chains
- `results/{v2,hyper,multi}-scores.jsonl` — per-row member scores (reval weights)
- `results/ensemble-combined.jsonl` — per-row member + ensemble scores
- `results/ensemble-metrics.json` — full metrics + agreement + flips
- `results/fresh/` — fresh-retrain weights/logs (v2 exact, hypergraph
  exact, multimodal resumed from epoch 60 — see section above)
- `results/fresh-*-scores.jsonl`, `results/fresh-ensemble-*.json`
- `logs/score-all.log`, `logs/retrain-all.log`, `logs/resume-all.log`,
  per-scorer logs

## Limits (unchanged)

Triage only; zero verified-real positives in the data; no model or
ensemble predicts VERIFIED_REAL. Pure Python stdlib, no new
dependencies. Real data only — no simulated or synthetic rows
anywhere in training or evaluation.
