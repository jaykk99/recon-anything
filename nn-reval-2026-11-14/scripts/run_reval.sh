#!/bin/bash
# NN re-validation chain (2026-11-14): fixed 145-row own holdout, seed 42.
# Rebuilds the split dumps, then retrains v2, multimodal and hypergraph
# from the Nov 12 backup candidates file, each with its own branch code.
# All outputs land under nn-reval-2026-11-14/ (persistent workspace),
# never /tmp: a VM reboot wiped /tmp mid-run once already.
# Launch detached: nohup bash scripts/run_reval.sh > logs/train-all.log 2>&1 &
set -x
R=/home/hatch/workspace/wt/nn-reval/nn-reval-2026-11-14
CAND=~/workspace/recon-continuous/results/candidates.jsonl.bak-20261114
BATCH=~/workspace/recon-continuous/results/batches.jsonl

echo "=== SPLIT DUMPS START $(date -u +%FT%TZ)"
python3 $R/scripts/dump_split.py /home/hatch/workspace/wt/nn-reval-v2/backend $R/evidence/split-v2.json
python3 $R/scripts/dump_split.py /home/hatch/workspace/wt/nn-reval-hyper/backend $R/evidence/split-hyper.json
python3 $R/scripts/dump_split.py /home/hatch/workspace/wt/nn-reval-multi/backend $R/evidence/split-multi.json
python3 -c "
import json
d = {n: json.load(open('$R/evidence/split-%s.json' % n)) for n in ['v2','hyper','multi']}
print('SPLIT-IDENTICAL:', d['v2']['test_keys'] == d['hyper']['test_keys'] == d['multi']['test_keys'])
print('counts:', {n: (v['n_own'], v['n_train'], v['n_test'], v['test_pos'], v['test_neg']) for n, v in d.items()})
"
echo "=== SPLIT DUMPS DONE $(date -u +%FT%TZ)"

echo "=== REVAL V2 START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-v2/backend && python3 -m app.nn.train_v2_ownholdout_reval > $R/results/v2/train.log 2>&1
echo "=== REVAL V2 EXIT $? $(date -u +%FT%TZ)"
cp /home/hatch/workspace/wt/nn-reval-v2/nn-logs/v2-ownholdout-ckpt.json $R/results/v2/v2-ownholdout-ckpt.json

echo "=== REVAL MULTI START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-multi/backend && python3 -m app.nn.train --candidates $CAND --batches $BATCH --external app/nn/external_findings.jsonl --holdout own --hidden 64,32 --epochs 120 --multimodal --out $R/results/multi > $R/results/multi/train.log 2>&1
echo "=== REVAL MULTI EXIT $? $(date -u +%FT%TZ)"

echo "=== REVAL HYPER START $(date -u +%FT%TZ)"
cd /home/hatch/workspace/wt/nn-reval-hyper/backend && python3 -m app.nn.train_hypergraph --candidates $CAND --batches $BATCH --out $R/results/hyper > $R/results/hyper/train.log 2>&1
echo "=== REVAL HYPER EXIT $? $(date -u +%FT%TZ)"

echo "=== REVAL ALL DONE $(date -u +%FT%TZ)"
