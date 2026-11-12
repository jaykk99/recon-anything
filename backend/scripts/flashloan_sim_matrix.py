#!/usr/bin/env python3
"""Flash-loan simulation matrix runner.

LOCAL SIMULATION ONLY. Fork mode pins a local anvil fork of a public RPC
(state reads only); fixture mode uses a fresh local chain. Nothing is ever
broadcast to a live chain. Every output row is an UNVERIFIED candidate;
this tool never emits VERIFIED_REAL.

Usage:
  # fixture gate (vuln spot vault must fire, TWAP vault must not)
  python flashloan_sim_matrix.py --fixtures --out rows.jsonl

  # real candidates from a specs file (JSON list; see matrix.run_* docs)
  python flashloan_sim_matrix.py --candidates specs.json --out rows.jsonl

Spec fields: chain, address, function, mode ("fork" | "static"),
source_file (optional), source_origin (optional), fork_url (for fork mode),
price_view, quote_path {pairs, tokens, reference_in}, grid_usd,
usd_per_manip_unit, manip_hop.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.flashsim import matrix as mx  # noqa: E402
from app.flashsim.evm import Anvil  # noqa: E402

FIXTURE_SOL = os.path.join(os.path.dirname(__file__), "..", "app",
                           "flashsim", "fixtures", "FlashSimFixtures.sol")


def run_fixtures(port: int) -> list:
    with open(FIXTURE_SOL) as f:
        source = f.read()
    rows = []
    with Anvil(port) as rpc:
        deployer = rpc.accounts()[0]
        for kind in ("spot", "twap"):
            rows.append(mx.run_fixture_matrix(rpc, deployer, source, kind))
    return rows


def run_candidates(specs: list, port_base: int) -> list:
    rows = []
    for i, spec in enumerate(specs):
        if spec.get("source_file"):
            with open(spec["source_file"]) as f:
                spec["source"] = f.read()
        mode = spec.get("mode", "static")
        try:
            if mode == "fork":
                with Anvil(port_base + i, fork_url=spec["fork_url"]) as rpc:
                    spec["_fork_block"] = rpc.block_number()
                    row = mx.run_fork_candidate(rpc, spec)
                    row["fork_block"] = spec["_fork_block"]
            else:
                row = mx.run_static_candidate(spec)
        except Exception as e:  # noqa: BLE001
            row = {"chain": spec.get("chain"), "address": spec.get("address"),
                   "function": spec.get("function"),
                   "candidate_status": mx.CANDIDATE_STATUS,
                   "verdict": mx.SIM_ERROR, "error": f"runner failure: {e}"}
        rows.append(row)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", action="store_true")
    ap.add_argument("--candidates")
    ap.add_argument("--out", required=True)
    ap.add_argument("--port-base", type=int, default=18700)
    args = ap.parse_args()

    rows: list = []
    if args.fixtures:
        rows += run_fixtures(args.port_base)
    if args.candidates:
        with open(args.candidates) as f:
            specs = json.load(f)
        rows += run_candidates(specs, args.port_base + 10)

    with open(args.out, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    for row in rows:
        print(f"{row.get('chain')} {row.get('address')} "
              f"{row.get('function')} -> {row.get('verdict')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
