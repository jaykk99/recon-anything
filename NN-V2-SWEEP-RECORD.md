# NN v2 + v3 sweep record (fixed own-test holdout, seed 42)

Own test = the original holdout (seed 42) from Jay's candidates.
All runs train on own-train + external rows. v1 baseline
(81-32-16-1, own-only, 60 ep): acc 0.8897, base 0.8552,
AUC 0.9781, cm tp=108 fp=0 fn=16 tn=21, FP recall 1.000,
WV recall 0.871.

## v2 (255 inputs, 725 own rows, 145-row test)

| Model | Test acc | Baseline | ROC AUC | FP recall | WV recall | Confusion |
|---|---|---|---|---|---|---|
| v2 255-32-16-1, std, 60 ep | 0.9034 | 0.8552 | 0.9712 | 0.857 | 0.911 | tp113 fp3 fn11 tn18 |
| v2 255-32-16-1, std, 120 ep | 0.8966 | 0.8552 | 0.9700 | 0.857 | 0.903 | tp112 fp3 fn12 tn18 |
| v2 255-64-32-1, std, 120 ep | 0.9103 | 0.8552 | 0.9697 | 0.857 | 0.919 | tp114 fp3 fn10 tn18 |
| v2 255-64-32-1, big, 120 ep | 0.9103 | 0.8552 | 0.9693 | 0.857 | 0.919 | tp114 fp3 fn10 tn18 |

Read: accuracy up (+2.1 pts best vs v1), ROC AUC marginally down in
every v2 config (0.970 vs 0.978), likely-FP recall 1.000 -> 0.857
(3 FPs where v1 had 0). Test set is 145 rows; one row is 0.7 pts.
More epochs at 32,16 did not help (0.9034 -> 0.8966). Wider at 120
epochs did (0.9103). Big external set (3,422 rows) changed nothing
on Jay's own test rows — identical confusion matrix — so the
standard 1,922-row set ships. No config hit 100% (overfit flag, not
a win). Best honest config, shipped: 255-64-32-1, 120 epochs,
standard external set.

## v2 reproduction (Nov 14, before v3)

- Combined split, shipped weights, re-implemented extraction
  (`backend/app/nn/verify_v2.py`): test n=530, acc 0.9811,
  AUC 0.9978, cm tp444 fp4 fn6 tn76. Matches nn-official-train.log
  and viewer-data.json exactly.
- Own-holdout RETRAIN, same script shape as the sweep
  (`train_v2_ownholdout.py`, 255-64-32-1, 120 ep): acc **0.9103**,
  AUC 0.9685 (sweep record said 0.9697), cm tp114 fp3 fn10 tn18,
  identical. The 0.0012 AUC gap is sparse-forward 1-ULP drift over
  120 epochs. Baseline 0.9103 is confirmed honest.
- The shipped weights.json is the combined-split artifact, not the
  own-holdout model. The own-holdout model (trained on more rows,
  2,502 vs 2,117) is preserved as nn-logs/v2-ownholdout-ckpt.json;
  repackaging it as the shipped weights is a small follow-up, not
  done here. Shipped weights stay the combined-split v2 artifact.

## Data drift (Nov 14): v2 vs v3 are NOT on identical data

`~/workspace/recon-continuous/results/candidates.jsonl` was
rewritten 2026-11-14 08:53:35 UTC by an adjudication job: deduped
4 duplicate rows (727 -> 723) and changed 1 verdict VERIFIED_REAL
-> FALSE_POSITIVE (MVK 0x3405ff98..., recipient_unbacked_claim).
Backup `candidates.jsonl.bak-20261114` (727 rows): old 620
UNVERIFIED / 94 FP / 11 TRIGGER_ONLY / 2 VERIFIED_REAL; new 617 /
95 / 11 / 0. The v2 sweep used the 725-row file (145-row test);
v3 uses the 723-row file (144-row test). **Treat v3-vs-v2
differences under ~1.4 pts (2 rows of 145) as within drift noise.**
The VERIFIED_REAL count is now 0 in the live file, so
`test_train_on_real_candidates` reads the count from the file
instead of hardcoding 2.

## v3: way more inputs (Jay, Nov 14) — 1,433 plugins + 41 context features

v3 spec: per-plugin inputs for ALL 1,433 registry plugins
(fired, confidence, severity, risk, count, gate, detector,
call-pattern = 8 each, 11,464) + 60 v2 non-plugin inputs + 41 new
context features (contract aggregates 15, bytecode/source 7,
call-graph 5, deployer 6, temporal 3, cross-contract 5) + 11
chains. Full dim **11,573**. Also built: a top-K + context variant
(301 inputs: v2's 24 plugin blocks + the 41 context features).
Training runs detached with nohup + log files and checkpoint
weights to disk every 20 epochs (crash-proofing: VM reboot #73
killed the first sweep launch; the resumed runs survived).

| Model | Test acc | Baseline | ROC AUC | FP recall | WV recall | Confusion |
|---|---|---|---|---|---|---|
| v3-A 11573-64-32-1, 120 ep | 0.882 | 0.854 | 0.955 | 0.476 | 0.951 | tp117 fp11 fn6 tn10 |
| v3-B 11573-32-16-1, 120 ep | 0.882 | 0.854 | 0.954 | 0.476 | 0.951 | tp117 fp11 fn6 tn10 |
| v3-C 301-64-32-1, 120 ep | 0.903 | 0.854 | 0.957 | 0.619 | 0.951 | tp117 fp8 fn6 tn13 |

(144-row test: one row is 0.7 pts. Train acc: A 0.993, B 0.994,
C 0.993 — all three memorised the training rows.)

Read: **way more inputs did NOT help.** The full-registry
expansion (A/B) is clearly worse than v2: -2.8 pts acc, AUC
-0.015, and likely-FP recall nearly halved (0.857 -> 0.476, 11
FPs vs 3). Narrower hidden layers did not rescue it (identical
confusion). The context families at v2 capacity (C) essentially
tie v2 on accuracy (0.903 vs 0.9103, a 1-row gap) but with worse
AUC (0.957 vs 0.9697) and worse FP recall (0.619 vs 0.857).
The new contract_aggregates family does show real signal
(permutation-importance AUC drop 0.041-0.047, 3rd-4th in A/B/C),
and the deployer/temporal families are dormant in training
(deployer joins 0: fresh-deploys covers Optimism/Scroll/Linea/
Avalanche only, no candidates exist on those chains; transition
joins 2 rows) but are live at scoring time on fresh chains.
**Shipped model stays v2 (255-64-32-1).** The v3 code ships
(sparse training, checkpoints, own-holdout eval, context
features); the full-registry spec is opt-in via an explicit
`--registry-ids` path, and the default train is the top-K +
context spec (301 inputs, config C shape).

## Crash-proofing (Jay, Nov 14: "fix it")

Long trains never run in a foreground exec any more. Every run
launches detached (`nohup python3 -m app.nn.train ... > log 2>&1
&`), the log is polled in short reads, and weights checkpoint to
disk every N epochs (atomic tmp + rename) plus at the last epoch.
A kill loses minutes, not hours: resume with `--resume <ckpt>`.
Checkpoint stores the lazy-L2 state (`last_touch` + `batch_ctr`)
so a resume is exact. Sparse first-layer training (touched
columns only + lazy L2 decay) cut the v3 fit from 156s CPU/epoch
to ~9s wall/epoch at 120 epochs on 2,502 rows; config A finished
in ~16 min wall. Equivalence: sparse vs dense reference weights
differ by at most 6.9e-08 after 5 epochs (summation-order drift),
tolerance 1e-6 in `test_nn_mlp_sparse.py`. All 24 NN tests pass.

Datasets:
- external standard: 1,922 rows = ScaBench 351 + xanoutas 450
  (caps, High/Medium) + defihack 378 + Sherlock-invalid 293 +
  audit-findings 450 (caps, Critical/High/Medium). Combined with
  own 725 = 2,647 rows, 2,249 pos / 398 neg (85.0% pos).
- external big: 3,422 rows (xanoutas + audit-findings caps 1,200).
  Same own-test result as standard; not shipped.

Notes:
- mlp.py optimization verified bit-identical weights vs old code
  (max weight diff 0.0, same seed/data); ~2.9x faster per epoch.
- First official train.py run used a worktree-relative --external
  path from backend/ CWD, which silently trained own-only (228
  features, acc 0.903). train.py now raises on a missing --external
  path. That run's weights were overwritten by the correct rerun.
- VM reboot #72 (~02:15 EST Nov 14) killed the first correct
  official train mid-run and wiped /tmp (sweep logs, raw source
  files, PR draft). Rebuilt from the surviving worktree files;
  sweep numbers above are from the pre-reboot logs.
- Raw source files (/tmp/scabench-curated.json, xanoutas-rows.jsonl,
  auditfindings-rows.jsonl, defihack.json, sherlock-invalid.jsonl)
  were lost in the reboot; the built dataset is committed at
  backend/app/nn/external_findings.jsonl. Rebuild from scratch
  needs re-fetching (commands in backend/docs/nn.md).
