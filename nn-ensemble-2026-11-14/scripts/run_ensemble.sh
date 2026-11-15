#!/bin/bash
# Ensemble scoring chain (2026-11-14): rescore the three REVAL member
# weights on the fixed 145-row own holdout (seed 42), then combine
# with score-average and majority vote. All outputs land under
# nn-ensemble-2026-11-14/ (persistent workspace), never /tmp.
# Launch detached: nohup bash scripts/run_ensemble.sh > logs/score-all.log 2>&1 &
set -x
E=/home/hatch/workspace/wt/nn-ensemble/nn-ensemble-2026-11-14
R=/home/hatch/workspace/wt/nn-reval/nn-reval-2026-11-14
mkdir -p "$E/results" "$E/logs"

echo "=== ENSEMBLE SCORE V2 START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-v2/backend && python3 "$E/scripts/score_v2.py" "$E/results/v2-scores.jsonl" > "$E/logs/score-v2.log" 2>&1
echo "=== ENSEMBLE SCORE V2 EXIT $? $(date -u +%FT%TZ)"

echo "=== ENSEMBLE SCORE MULTI START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-multi/backend && python3 "$E/scripts/score_multi.py" "$E/results/multi-scores.jsonl" > "$E/logs/score-multi.log" 2>&1
echo "=== ENSEMBLE SCORE MULTI EXIT $? $(date -u +%FT%TZ)"

echo "=== ENSEMBLE SCORE HYPER START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-hyper/backend && python3 "$E/scripts/score_hyper.py" "$E/results/hyper-scores.jsonl" > "$E/logs/score-hyper.log" 2>&1
echo "=== ENSEMBLE SCORE HYPER EXIT $? $(date -u +%FT%TZ)"

echo "=== ENSEMBLE COMBINE START $(date -u +%FT%TZ)"
cd "$E" && python3 scripts/ensemble.py results/v2-scores.jsonl results/hyper-scores.jsonl results/multi-scores.jsonl results/ensemble > "$E/logs/ensemble.log" 2>&1
echo "=== ENSEMBLE COMBINE EXIT $? $(date -u +%FT%TZ)"
cat "$E/logs/ensemble.log"
echo "=== ENSEMBLE ALL DONE $(date -u +%FT%TZ)"
