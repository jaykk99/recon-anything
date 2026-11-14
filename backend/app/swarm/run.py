"""Swarm CLI: run the five-role pipeline over a target queue.

    python -m app.swarm.run --queue targets.jsonl [--max-targets 1]
        [--chain scroll] [--fresh-only] [--concurrency 2]
        [--out-dir backend/docs/swarm-runs]

Queue rows are JSONL target dicts (chain, address, name, fresh_7d,
...). The run prints a JSONL event log to stdout (so the run is
capturable even where file writes are restricted) and writes one
evidence markdown + JSON per target plus a run-metrics JSON into
--out-dir. Exit code is 0 even when zero targets verify: 0 verified
is an honest result, not a failure.

Detection only, read-only live probes, no transactions. See
backend/docs/swarm.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# Allow running as `python -m app.swarm.run` from backend/, and as a
# script from anywhere (tests import the package instead).
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    from app.swarm.coordinator import Coordinator  # noqa: E402
    from app.swarm.triage import try_nn_ranker  # noqa: E402
else:
    from .coordinator import Coordinator  # noqa: E402
    from .triage import try_nn_ranker  # noqa: E402


def load_queue(path: str) -> list:
    targets = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                targets.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return targets


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="ReconAnything autonomous multi-agent swarm")
    parser.add_argument("--queue", required=True,
                        help="JSONL target queue (chain, address, ...)")
    parser.add_argument("--max-targets", type=int, default=0,
                        help="cap targets attempted (0 = all)")
    parser.add_argument("--chain", default=None,
                        help="only this chain (e.g. scroll)")
    parser.add_argument("--fresh-only", action="store_true",
                        help="only fresh_7d targets")
    parser.add_argument("--address", default=None,
                        help="only this exact contract address")
    parser.add_argument("--concurrency", type=int, default=2,
                        help="max parallel targets (default 2)")
    parser.add_argument("--chain-depth", type=int, default=1,
                        help="related-address chaining depth (default 1)")
    parser.add_argument("--out-dir", default=None,
                        help="evidence output directory")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--no-nn", action="store_true",
                        help="skip the NN triage ranker even if present")
    args = parser.parse_args(argv)

    targets = load_queue(args.queue)
    if args.chain:
        targets = [t for t in targets
                   if str(t.get("chain") or "").lower() == args.chain.lower()]
    if args.fresh_only:
        targets = [t for t in targets if t.get("fresh_7d")]
    if args.address:
        targets = [t for t in targets
                   if str(t.get("address") or "").lower() == args.address.lower()]
    if args.max_targets:
        targets = targets[:args.max_targets]

    nn_score_fn = None if args.no_nn else try_nn_ranker()
    coord = Coordinator(max_concurrent_targets=args.concurrency,
                        chain_depth=args.chain_depth,
                        out_dir=args.out_dir,
                        nn_score_fn=nn_score_fn)
    started = time.time()
    record = coord.run_queue(
        targets, run_id=args.run_id or f"swarm-{int(started)}")

    # JSONL event log to stdout: the run, replayable.
    board = record["board"]
    for event in board["events"]:
        print(json.dumps(event, default=str), flush=True)
    print(json.dumps({"kind": "run_metrics",
                      "metrics": record["metrics"]}, default=str), flush=True)
    if args.out_dir:
        try:
            os.makedirs(args.out_dir, exist_ok=True)
            metrics_path = os.path.join(
                args.out_dir,
                f"swarm-run-{record['metrics']['run_id']}.json")
            with open(metrics_path, "w", encoding="utf-8") as f:
                json.dump(record["metrics"], f, indent=2, default=str)
            print(json.dumps({"kind": "metrics_file",
                              "path": metrics_path}), flush=True)
        except Exception as e:  # noqa: BLE001 - stdout already has it
            print(json.dumps({"kind": "metrics_write_error",
                              "error": f"{type(e).__name__}: {e}"}), flush=True)
    print(f"swarm done: {record['metrics']['targets_completed']}/"
          f"{record['metrics']['targets_attempted']} targets, "
          f"{record['metrics']['findings_total']} findings, "
          f"{record['metrics']['candidates_total']} candidates, "
          f"{record['metrics']['verified_real']} verified real, "
          f"{record['metrics']['elapsed_s']}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
