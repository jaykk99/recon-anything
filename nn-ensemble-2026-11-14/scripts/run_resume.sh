#!/bin/bash
# Resume chain after the 2026-11-15 ~00:10 UTC service restart killed
# run_retrain.sh mid-multimodal (epoch 60/120; v2 already done).
# Resumes multimodal from its epoch-60 checkpoint, then runs the
# hypergraph fresh retrain, rescores all three FRESH weights and
# re-runs the ensemble combiner. All outputs under
# nn-ensemble-2026-11-14/results/fresh/ (persistent workspace),
# never /tmp.
# Launch detached: nohup bash scripts/run_resume.sh > logs/resume-all.log 2>&1 &
set -x
E=/home/hatch/workspace/wt/nn-ensemble/nn-ensemble-2026-11-14
CAND=~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114
BATCH=~/workspace/recon-continuous/results/batches.jsonl
mkdir -p "$E/results/fresh/v2" "$E/results/fresh/multi" "$E/results/fresh/hyper" "$E/logs"

echo "=== RESUME MULTI START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-multi/backend && python3 "$E/scripts/resume_multi.py" "$E/results/fresh/multi" > "$E/results/fresh/multi/train.log" 2>&1
echo "=== RESUME MULTI EXIT $? $(date -u +%FT%TZ)"

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
echo "=== RESUME ALL DONE $(date -u +%FT%TZ)"
