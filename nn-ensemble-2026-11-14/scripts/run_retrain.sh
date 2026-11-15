#!/bin/bash
# Fresh-retrain confirmation chain (2026-11-14): retrain all three
# members from scratch on the SAME fixed-split training rows the
# re-validation used (own-train 580 + external 1,922 = 2,502, seed 42,
# Nov 12 backup candidates file), checkpointing every 20 epochs,
# then rescore the FRESH weights and re-run the ensemble combiner.
# The reval-weight ensemble (results/ensemble-metrics.json) is the
# first result; this chain checks it reproduces with fresh weights.
# All outputs land under nn-ensemble-2026-11-14/results/fresh/
# (persistent workspace), never /tmp.
# Launch detached: nohup bash scripts/run_retrain.sh > logs/retrain-all.log 2>&1 &
set -x
E=/home/hatch/workspace/wt/nn-ensemble/nn-ensemble-2026-11-14
CAND=~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114
BATCH=~/workspace/recon-continuous/results/batches.jsonl
mkdir -p "$E/results/fresh/v2" "$E/results/fresh/multi" "$E/results/fresh/hyper" "$E/logs"

echo "=== FRESH V2 START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-v2/backend && python3 -m app.nn.train_v2_ownholdout_reval > "$E/results/fresh/v2/train.log" 2>&1
echo "=== FRESH V2 EXIT $? $(date -u +%FT%TZ)"
cp /home/hatch/workspace/wt/nn-reval-v2/nn-logs/v2-ownholdout-ckpt.json "$E/results/fresh/v2/v2-ownholdout-ckpt.json"

echo "=== FRESH MULTI START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-multi/backend && python3 -m app.nn.train --candidates $CAND --batches $BATCH --external app/nn/external_findings.jsonl --holdout own --hidden 64,32 --epochs 120 --multimodal --out "$E/results/fresh/multi" > "$E/results/fresh/multi/train.log" 2>&1
echo "=== FRESH MULTI EXIT $? $(date -u +%FT%TZ)"

echo "=== FRESH HYPER START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-hyper/backend && python3 -m app.nn.train_hypergraph --candidates $CAND --batches $BATCH --out "$E/results/fresh/hyper" > "$E/results/fresh/hyper/train.log" 2>&1
echo "=== FRESH HYPER EXIT $? $(date -u +%FT%TZ)"

echo "=== FRESH RESCORE V2 START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-v2/backend && ENSEMBLE_V2_CKPT="$E/results/fresh/v2/v2-ownholdout-ckpt.json" python3 "$E/scripts/score_v2.py" "$E/results/fresh-v2-scores.jsonl" > "$E/logs/fresh-score-v2.log" 2>&1
echo "=== FRESH RESCORE V2 EXIT $? $(date -u +%FT%TZ)"

echo "=== FRESH RESCORE MULTI START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-multi/backend && ENSEMBLE_MULTI_WEIGHTS="$E/results/fresh/multi/weights.json" python3 "$E/scripts/score_multi.py" "$E/results/fresh-multi-scores.jsonl" > "$E/logs/fresh-score-multi.log" 2>&1
echo "=== FRESH RESCORE MULTI EXIT $? $(date -u +%FT%TZ)"

echo "=== FRESH RESCORE HYPER START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-hyper/backend && ENSEMBLE_HYPER_WEIGHTS="$E/results/fresh/hyper/hypergraph-weights.json" python3 "$E/scripts/score_hyper.py" "$E/results/fresh-hyper-scores.jsonl" > "$E/logs/fresh-score-hyper.log" 2>&1
echo "=== FRESH RESCORE HYPER EXIT $? $(date -u +%FT%TZ)"

echo "=== FRESH ENSEMBLE START $(date -u +%FT%TZ)"
cd "$E" && python3 scripts/ensemble.py results/fresh-v2-scores.jsonl results/fresh-hyper-scores.jsonl results/fresh-multi-scores.jsonl results/fresh-ensemble > "$E/logs/fresh-ensemble.log" 2>&1
echo "=== FRESH ENSEMBLE EXIT $? $(date -u +%FT%TZ)"
cat "$E/logs/fresh-ensemble.log"
echo "=== FRESH ALL DONE $(date -u +%FT%TZ)"
