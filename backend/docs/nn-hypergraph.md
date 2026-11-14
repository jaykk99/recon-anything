# Hypergraph NN triage — `backend/app/nn/hypergraph.py`

A finding that spans several contracts at once (a proxy + its
implementation + the router that calls it, or several plugins firing
on the same target) is a **hyperedge**: one interaction connecting
many nodes, where a plain graph edge can only connect two. This
module builds those hyperedges from the findings data and runs
hypergraph message passing over them for triage scoring.

## What it is

- **Nodes** are findings, featurised with the existing v2 spec
  (`features.py`, 255 inputs: per-plugin blocks + key, bounty,
  recipient, chain, source, role, proxy/implementation flags).
- **Hyperedges** come from links already in the findings data,
  never invented:
  - `target` — all findings on the same (chain, address).
  - `implementation` — all findings sharing one
    `implementation_address` (different proxy targets sharing an
    implementation are one system).
  - `project` — external (audit) findings from the same
    `source.project_id`.
- **Message passing** (pure Python stdlib, no new dependencies):
  node -> hyperedge aggregation (mean of member embeddings) ->
  node update `tanh(W_self h + W_edge * mean incident hyperedges
  + b)`, 2 layers, then a sigmoid readout for the triage score.
  Backprop is hand-derived and gradient-checked (worst relative
  error ~1e-8 on a tiny graph; see `tests/test_nn_hypergraph.py`).
- **Training**: full-batch gradient descent, 255-16-16-1,
  ~5,100 parameters, lr 0.5, 200 epochs (sparse input layer,
  ~3.5s/epoch on this box). Train it with
  `python -m app.nn.train_hypergraph` from `backend/`. That driver also retrains the v2 MLP baseline
  (255-64-32-1) on the exact same split for an apples-to-apples
  comparison.

## Data and holdout

Own 723 findings (from `candidates.jsonl` + `batches.jsonl`) +
external 1,922 rows = 2,645 rows. The holdout is the **fixed
own-rows holdout**: the own findings split stratified, seed
42, test_frac 0.2 -> **144 test rows** (123 worth-validating / 21
likely-false-positive). The 1,922 external rows join the TRAIN
set only. Hypergraphs are built separately on the train rows and
on the test rows: an edge joining a train node to a test node
would leak test information into training.

Data note: the branch was built on 725 own rows / a 145-row
holdout (124 / 21). `candidates.jsonl` was re-adjudicated
upstream on 2026-11-14 08:53 UTC while the first training run
was in flight (4 rows removed, including the 2 VERIFIED_REAL
rows), so the shipped run trains on 723 own rows and tests on
144. The quoted v1/v2 numbers below were measured on the old
145-row holdout, so they are near but not exact comparators.
The retrained v2 baseline in the same run IS on the same
144-row split, so that head-to-head is exact.

## Honest numbers

Trained run 2026-11-14 09:52 UTC (`viewer-data.json`),
hypergraph 255-16-16-1, 200 epochs, lr schedule 0.5 / 0.15 /
0.05, seed 42. Test = fixed own-rows holdout, 144 rows
(123 worth-validating / 21 likely-false-positive):

| model | test acc | ROC AUC | WV recall | FP recall | confusion (tp/fp/fn/tn) |
|---|---|---|---|---|---|
| v1 MLP 81-32-16-1 (as reported, old 145-row holdout) | 0.8897 | 0.9781 | — | — | — |
| v2 MLP 255-64-32-1 (as reported, old 145-row holdout) | 0.9103 | 0.9697 | — | — | — |
| v2 MLP 255-64-32-1 (retrained, same 144-row split) | 0.8889 | 0.9559 | 0.992 | 0.286 | 122 / 15 / 1 / 6 |
| **hypergraph 255-16-16-1** | **0.9514** | **0.9907** | **0.984** | **0.762** | **121 / 5 / 2 / 16** |
| hypergraph, edges removed at eval (ablation) | 0.9306 | 0.9795 | 0.984 | 0.619 | 121 / 8 / 2 / 13 |

**Verdict: the hypergraph beats v2.** On the same 144-row
split it beats the retrained v2 MLP on accuracy (0.9514 vs
0.8889), ROC AUC (0.9907 vs 0.9559), and especially on
likely-false-positive recall (0.762 vs 0.286): the MLP
catches almost every worth-validating row (0.992) but only
6 of 21 false positives, while the hypergraph keeps WV
recall at 0.984 and catches 16 of 21 false positives. It
also beats the quoted v1 (0.8897 / 0.9781) and v2 (0.9103 /
0.9697) numbers, with the one-row holdout caveat above.
Train acc 0.9888, train AUC 0.9955 — no 100%, no overfit
flag. The retrained MLP's train AUC is 0.9991 against a
test AUC of 0.9559: it overfits more than the hypergraph
(train 0.9955 -> test 0.9907).

Where the edges help: the no-edge ablation scores 0.9306 /
0.9795, so the hyperedge context is worth +2.1 pts of
accuracy and +0.011 AUC. Test rows that sit in a hyperedge
(30 rows) score acc 0.9667, AUC 1.0, WV recall 1.0, FP
recall 0.875; singleton rows (114) score acc 0.9474, AUC
0.9871, WV recall 0.980, FP recall 0.692. The covered-slice
AUC of 1.0 is on 30 rows only — small-n, not a win claim.

Majority baseline on the 144-row holdout is 0.8542 (predict
worth-validating for everything). Accuracy near that means the
model learned nothing; judge by minority-class (likely-FP) recall
and ROC AUC. Any 100% is overfit, not a win — flag it.

## Hypergraph coverage (measured, train split)

- 68 hyperedges: 45 target, 1 implementation, 22 project.
- 272 / 2,501 train nodes sit in at least one hyperedge (~11%).
- Test split: 9 hyperedges, 30 / 144 nodes covered (~21%).
- 11 giant groups dropped (over the 16-member cap), including
  the two biggest shared implementations (384 and 68 targets):
  a hyperedge that big is a global average, not a signal.
- Most targets have exactly one finding, so most nodes score on
  the self path only and the model behaves like a small MLP there.
  The hyperedge context can only help where links exist.

## Limits

- **Triage only.** Never predicts VERIFIED_REAL (zero
  verified-real positives exist in the data). A high score means
  "worth a live probe", nothing more.
- **Detection only, read-only.** No transactions, no drains, no
  live probes from this module. crypto.com is never a target.
- **No call-graph hyperedges yet.** The own data has zero
  `cross_contract_call_graph` rows, so no related-contract links
  are available to build them from. When that plugin's findings
  carry related-contract addresses, add a `call_graph` edge type
  in `build_hypergraph`; the message passing already handles any
  edge list.
- **Thin coverage** (above): the hypergraph's contribution is
  bounded by how few multi-finding targets exist. If it does not
  beat v2, that is the first suspect, not the message passing.
- **Full-batch optimisation.** One gradient step per epoch (200
  steps total) vs the MLP's ~78 mini-batch steps per epoch.
  Learning rate matters more than usual here; see below.
- **External rows have no addresses** (`address` is empty), so
  they contribute only `project` hyperedges, never `target` or
  `implementation` ones.

## Learning rate

Full-batch GD takes one step per epoch, so the learning rate does
most of the work. Probes (6 epochs, same data, seed 42):

- lr 0.1: train loss 0.626 after 1 step, 0.443 after 5 steps.
- lr 0.5: train loss 0.430 after 1 step, 0.400 after 6 steps;
  test AUC 0.9178 after 6 epochs (accuracy still at the 0.8552
  majority baseline on the pre-change 145-row holdout: the
  ranking learns before the 0.5 threshold starts biting).
- lr 1.0: train loss 0.430 after 1 step (overshoots back to the
  same loss), 0.402 after 6 steps; test AUC 0.9063 after 6 epochs.

lr 0.5 wins, so the shipped run starts at lr 0.5 — but a flat
lr 0.5 does not survive 200 epochs: it escapes the majority
plateau fast (train loss 0.43 -> 0.13, acc 0.98 by epoch 30) and
then overshoots catastrophically (loss 0.50, acc back to the
0.8493 majority at epoch 35) and oscillates. The shipped run
therefore uses a step decay: 30 epochs at 0.5, 70 at 0.15, the
rest at 0.05. Because one full-batch step per epoch is so few
steps next to the MLP's ~78 mini-batch steps per epoch, the
shipped run uses 200 epochs (sparse input layer: ~3.5s/epoch)
instead of the MLP recipe's 60. Both budgets are stated in
`viewer-data.json` (`epochs`, `lr`).

## Wiring

- `pipeline.load_model()` loads both formats:
  `recon-nn-weights/1` (MLP) and `recon-nn-hypergraph/1`
  (this branch's `weights.json`).
- `pipeline.score_finding_dicts()` scores a run's findings as
  one batch for hypergraph models, so findings from the same run
  share context. `nn_top_features` for those scores is computed
  on the self path (it explains the finding's own features, not
  its neighbours).
- `api.py` `/api/nn/status` reports `"model": "hypergraph"` and
  the hypergraph layers.
- Scoring is flag-gated (`RECON_NN_SCORING=1`) and never breaks
  a scan: any failure leaves findings unscored.

## Files

- `backend/app/nn/hypergraph.py` — model + hyperedge builder +
  batch scoring helpers.
- `backend/app/nn/train_hypergraph.py` — training driver +
  MLP-v2 baseline retrain + viewer refresh.
- `backend/app/nn/hypergraph-weights.json` — trained weights
  (also copied to `weights.json`, the file the pipeline loads).
- `backend/app/nn/viewer-data.json` — metrics, hypergraph stats,
  baseline comparison.
- `backend/tests/test_nn_hypergraph.py` — 13 fast tests (edge
  construction, forward, gradient check, save/load) + 1 slow
  real-data holdout test (`-k "not slow"` skips it).
- `backend/docs/nn-hypergraph.md` — this file.
