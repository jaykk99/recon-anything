# Cross-modal / multimodal embeddings for NN triage

Branch: `feat/nn-multimodal`. Module: `backend/app/nn/multimodal.py`.
Wiring: `train.py` (`--multimodal`, `--holdout own`), `pipeline.py`
(k-NN / blend / neighbours on scored findings), `features.py`
(`top_features(..., extra=...)` so leave-one-out works with the
35 extra inputs). Tests: `backend/tests/test_nn_multimodal.py`
(12 tests, synthetic rows only).

## What it is

One shared embedding space combining three modalities per
contract/finding, pure Python stdlib, no new dependencies:

| modality | source in a row | tokens |
|---|---|---|
| (a) verified source text | `evidence["code"]` (Solidity excerpt) + contract name + function + selectors | identifier/word tokens (camel/snake split) |
| (b) deployed bytecode | `evidence["opcodes"]` (histogram dict, mnemonic string, or hex) + `evidence["bytecode*"]` hex | opcode unigrams + bigrams; hex byte bigrams as fallback |
| (c) finding text | plugin id + key + value + detail / check / remediation / function / risk | word tokens + key char-trigrams |

Method: hashed TF-IDF per modality (SHA-256 token -> fixed bucket,
IDF fit on TRAIN rows only), per-modality L2 normalisation, weighted
concatenation into one 640-dim shared space
(256 source + 128 bytecode + 256 finding), L2-normalised again.
Cosine similarity in that space is the neighbour metric. A fixed
seeded random projection (640 -> 32, rebuilt deterministically from
seed 1234, never stored) gives the dense block the triage MLP
consumes: 32 projected dims + 3 modality-presence flags = 35 extra
inputs on top of the 255 v2 features (290 total, layers
`[290, 64, 32, 1]`). A k-NN triage head over the projected train
index scores a finding by the similarity-weighted label mean of its
15 nearest train rows; the shipped blend is `0.7 * MLP + 0.3 * kNN`.

Missing modalities are normal: a missing modality contributes a
zero block and a 0.0 presence flag, and the vector is renormalised
over the modalities present. An all-empty row embeds to the zero
vector and the k-NN head falls back to the train positive rate.

## Modality coverage (measured, not assumed)

| modality | own train rows (580) | own test rows (145) | external rows (1,922) |
|---|---|---|---|
| source text (`code` excerpt) | 100% (580/580) | 100% (145/145) | 0% (no `code` field) |
| bytecode (`opcodes`/hex) | 0% | 0% | 0% |
| finding text | 100% | 100% | 100% |

(External rows do carry an extracted function name in 69% of
cases, which lands in the source block as a single identifier —
not source text in any meaningful sense. The `code` row above is
the honest measure.)

The bytecode modality is **empty on the whole training set**: none
of the 725 own rows carries opcodes, bytecode hex, selectors, or a
bytecode hash. The `opcodes` field that exists in `batches.jsonl`
is a histogram (`{"CALL": 2}`), not a sequence, and it never
survives into the candidate rows the model trains on. The bytecode
tokeniser is built and tested (histogram unigrams, mnemonic
sequences with bigrams, hex decoded to mnemonics via the EVM table
in `multimodal.py`), and it lights up on live scoring when a plugin
emits opcodes — but on this data it teaches the model nothing.
That is a data limitation, not a code limitation, and it is why the
bytecode block must not be credited with any of the measured gain.
The honest reading: this run measures source + finding embeddings,
with bytecode as a live-only path.

## Protocol (fixed holdout, seed 42)

- Own rows: 725 (620 worth-validating / 105 likely-FP) from
  `candidates.jsonl` + `batches.jsonl`, `build_dataset` as in v2.
- Fixed own-test holdout: `stratified_split(own, 0.2, 42)` -> 145
  rows (124 pos / 21 neg). Majority baseline accuracy 0.8552.
- Train set: remaining 580 own rows + all 1,922 external rows
  (1,629 pos / 293 neg) = 2,502 rows.
- Vocab, IDF, and the k-NN index are fit on TRAIN rows only. Test
  rows are never indexed and never touch IDF.
- Baselines on the same 145 rows: v1 recorded (81-32-16-1,
  own-only) and v2 recorded from the retrain sweep
  (255-64-32-1, 120 epochs, acc 0.9103, AUC 0.9697). The
  previously reported v2 combined-holdout numbers (acc 0.9811,
  AUC 0.9978 on 530 rows, in the copied `viewer-data.json`) are a
  different test set — do not compare them directly to the 145-row
  numbers below.

## Honest metrics (fixed 145-row own holdout, seed 42)

<!-- filled in from the training runs; see weights/viewer-data -->

| model | test acc | ROC AUC | WV precision / recall | FP precision / recall | confusion tp/fp/fn/tn |
|---|---|---|---|---|---|
| v1 (81-32-16-1, own-only, 60 ep, recorded) | 0.8897 | 0.9781 | ? / 0.871 | ? / 1.000 | 108/0/16/21 |
| v2 (255-64-32-1, 120 ep, recorded sweep) | 0.9103 | 0.9697 | ? / 0.919 | ? / 0.857 | 114/3/10/18 |
| v2 + multimodal MLP (290-64-32-1, 120 ep) | **0.9724** | **0.9850** | 0.984 / 0.984 | 0.905 / 0.905 | 122/2/2/19 |
| k-NN head only (k=15) | 0.9241 | 0.9731 | 0.952 / 0.960 | 0.750 / 0.714 | 119/6/5/15 |
| blend 0.7 MLP + 0.3 kNN | 0.9655 | **0.9881** | 0.968 / 0.984 | 0.895 / 0.810 | 121/2/3/19 |

Recorded v1/v2 rows are from `NN-V2-SWEEP-RECORD.md` in the
nn-scorer worktree (same fixed 145-row own holdout, seed 42, same
code/data); the v2 baseline was NOT re-run here — re-running the
identical 120-epoch config would only reproduce those numbers,
and the shared VM is CPU-starved. One test row is 0.7 pts of
accuracy, so a 1-2 pt gap is within noise; judge by AUC and
minority-class recall, not accuracy alone. The multimodal MLP and
blend rows come from the `--multimodal` run in this branch
(120 epochs, hidden 64,32, same protocol).

Reading: the multimodal MLP beats v2 by +6.2 pts accuracy and
+0.015 AUC, and beats v1 by +8.3 pts accuracy and +0.007 AUC.
The embeddings add real signal beyond the 255 v2 features:
permutation importance puts the `multimodal_embeddings` group 3rd
(AUC drop 0.0215, behind only `bounty_value` 0.197 and
`contract_role` 0.074). The blend trades a little accuracy for
the best AUC (0.9881). No 100% anywhere — not an overfit flag.
The one regression vs v1: FP recall 0.905 (19/21) vs v1's 1.000
(21/21) — the model trades 2 false positives for 14 fewer false
negatives (fn 16 -> 2). Train acc 0.995 vs test 0.972 is a
normal gap, not a memorisation flag.

Sensitivity check (144-row holdout): `candidates.jsonl` changed
under this task (727 -> 723 rows between the v2 sweep and this
run; the scanner rewrote it), so the first `--multimodal` run
landed on a 144-row holdout (123 pos / 21 neg) instead of the
fixed 145. Its numbers, for the record — MLP acc 0.9444,
AUC 0.9806, cm tp118/fp3/fn5/tn18, WV 0.975/0.959, FP 0.783/0.857;
k-NN-only acc 0.9028, AUC 0.9617, cm tp119/fp10/fn4/tn11;
blend acc 0.9583, AUC 0.9849, cm tp121/fp4/fn2/tn17;
retrieval P@5 0.9264, macro 0.7373, excl-dominant 0.7872. The
shipped numbers above come from a rerun against the
Nov 12 backup `candidates.jsonl.bak-20261114`, which reproduces
the original 725-row set and the exact fixed 145-row holdout.
The conclusion is the same on both holdouts: the multimodal
model beats v2 on accuracy and AUC.

Clustering check (same-plugin retrieval, top-5 train neighbours,
test rows only):

| metric | value |
|---|---|
| P@5 same-plugin (overall) | 0.9283 |
| P@5 macro (mean per-plugin) | 0.7004 |
| P@5 excl. dominant plugin (`unchecked_math_user_input`, 95/145 test rows) | 0.7920 |

Per-plugin P@5: `unchecked_math_user_input` 1.000,
`recipient_overdraw_withdraw` 1.000,
`recipient_sig_value_to_self` 1.000,
`uups_authorize_upgrade_missing` 0.943,
`contract_logic` 0.857, `recipient_mint_to_caller` 0.825,
`recipient_bridge_release_unproven` 0.800,
`bridge_withdrawer_identity_spoof` 0.680,
`cross_function_guard_sibling` 0.500,
`crypto_drain_scanner` 0.400, `eip712_separator_unbound` 0.400,
`hardcoded_hash_constant_mismatch` 0.000 (1 test row).
Measured on the fixed holdout with the train-only index.

144-row sensitivity check (see metrics table note): P@5 0.9264,
macro 0.7373, excl-dominant 0.7872.

Note the skew: 95 of the 145 test rows are
`unchecked_math_user_input`, so the overall P@5 is dominated by
that one plugin; the macro and excl-dominant numbers are the ones
that say whether retrieval works beyond it.

## How to train / score

```bash
# v2 baseline under the fixed own holdout (recorded numbers in
# NN-V2-SWEEP-RECORD.md; re-running reproduces them)
python -m app.nn.train --external app/nn/external_findings.jsonl \
    --holdout own --hidden 64,32 --epochs 120 --out /tmp/nn-baseline

# multimodal model (writes backend/app/nn/weights.json + viewer-data.json)
# NOTE: use the Nov 12 backup candidates file: the live
# candidates.jsonl lost 4 rows after the v2 sweep, and only the
# backup reproduces the exact fixed 145-row holdout.
python -m app.nn.train \
    --candidates ~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114 \
    --batches ~/workspace/recon-continuous/results/batches.jsonl \
    --external app/nn/external_findings.jsonl \
    --holdout own --hidden 64,32 --epochs 120 --multimodal

# score a target; findings gain nn_knn_score, nn_blend_score,
# nn_neighbours (top 3 train neighbours) when the weights carry
# the multimodal block. Old weights score exactly as before.
python -m app.nn.score --target bsc:0x...
```

`RECON_NN_SCORING=1` pipeline scoring attaches the same fields
via `attach_nn_scores` / `score_finding_dicts`.

## Limits

- Triage only. Embeddings rank findings by similarity to past
  findings. They never verify anything and never predict
  VERIFIED_REAL: there are zero verified-real positives in the
  training data.
- The embedding space is only as good as the text rows carry.
  External rows have no source-code excerpt (only a function name
  in 69% of cases); no training row has bytecode.
  Similar-source clustering is therefore measured on own rows only.
- Hashed TF-IDF has collisions by design (256/128/256 buckets);
  the random projection is lossy. k-NN runs in the 32-dim projected
  space; the 640-dim sparse space is used for the unit-test
  similarity checks and is stored only implicitly via the projection.
- `weights.json` grows by the k-NN index (2,502 x 32 floats plus
  plugin/key/label) — roughly 1 MB total.
- Detection only, read-only live probes, no transactions, no
  drains. crypto.com is never a target.
