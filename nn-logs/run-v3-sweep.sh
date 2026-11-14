#!/bin/bash
# v3 sweep: way-more-inputs spec (11,573 inputs) on the honest
# own-holdout metric. Runs sequentially, detached, checkpointed
# every 20 epochs so a kill loses minutes, not hours.
# Run from backend/: nohup bash ../nn-logs/run-v3-sweep.sh > ../nn-logs/v3-sweep.log 2>&1 &
set -u
cd "$(dirname "$0")/../backend" || exit 1
EXT="app/nn/external_findings.jsonl"
COMMON="--external $EXT --eval own-holdout --lr 0.05 --seed 42 --checkpoint-every 20 --history-every 20"
run() {
  name="$1"; hidden="$2"; epochs="$3"
  echo "=== SWEEP $name hidden=$hidden epochs=$epochs $(date -u +%H:%M:%S) ==="
  # shellcheck disable=SC2086
  python3 -m app.nn.train $COMMON --hidden "$hidden" --epochs "$epochs" \
    --out "../nn-logs/$name" --checkpoint "../nn-logs/$name-ckpt.json"
  echo "=== DONE $name exit=$? $(date -u +%H:%M:%S) ==="
}
run v3-a-64-32-120 64,32 120
run v3-b-32-16-120 32,16 120
echo "=== SWEEP ALL DONE $(date -u +%H:%M:%S) ==="
