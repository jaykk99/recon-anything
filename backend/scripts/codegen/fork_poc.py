#!/usr/bin/env python3
"""Fork-only proof-of-concept runner for ReconAnything candidates.

Each candidate gets an executable test story: a concrete attack
hypothesis, a fork test that runs it, and the evidence it would need
to reach VERIFIED_REAL. FORK ONLY, NEVER LIVE BROADCAST: every
transaction goes to a local `anvil --fork-url` instance on
127.0.0.1. No live transaction is ever sent, no funds ever move on
any real chain, and a fork result is UNVERIFIED by design: it is a
lead for the live-probe lane, never proof (Jay's no-simulation rule).

The stranger is anvil's default funded test account 0
(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266) with its well-known
local test key; it exists only inside the throwaway fork.

Usage:
    python3 fork_poc.py --poc poc-1-agve-mintto.json
    python3 fork_poc.py --chain arbitrum --rpc-url https://... \\
        --address 0x... --steps '[{"sig": "mintTo(address,uint256)",
        "args": ["STRANGER", "1000000000000000000"]}]' \\
        --out /tmp/poc-out.json

A PoC definition file (JSON) carries: chain, rpc_url, address,
hypothesis, steps (cast-send calls as the stranger), reads (cast-call
balance/totalSupply probes taken before, between and after steps),
and what VERIFIED_REAL would still need.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time

STRANGER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
# Sends use --unlocked (anvil signs for its default accounts); no
# private key is handled anywhere in this script.
ANVIL = os.path.expanduser("~/.foundry/bin/anvil")
CAST = os.path.expanduser("~/.foundry/bin/cast")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(cmd, timeout=120):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def _cast_call(rpc, address, sig, args):
    return _run([CAST, "call", address, sig, *args, "--rpc-url", rpc])


def _cast_send(rpc, address, sig, args):
    # --unlocked: anvil's default accounts are unlocked, so anvil
    # signs. (cast's --private-key raw-tx path fails against this
    # anvil build with a spurious "Insufficient funds" error even
    # for a 1-wei transfer from a 10000-ETH account; the unlocked
    # path executes correctly. Fork-local only, never a live key.)
    return _run([CAST, "send", "--unlocked", "--from", STRANGER,
                 address, sig, *args, "--rpc-url", rpc])


def _cast_call_from(rpc, address, sig, args):
    """eth_call as the stranger: shows the revert reason a
    `cast send` hides behind a gas-estimation failure."""
    return _run([CAST, "call", address, sig, *args,
                 "--from", STRANGER, "--rpc-url", rpc])


def _resolve_args(args):
    return [STRANGER if a == "STRANGER" else str(a) for a in args]


def run_poc(poc: dict, out_path: str | None = None) -> dict:
    chain = poc["chain"]
    rpc_url = poc["rpc_url"]
    address = poc["address"]
    steps = poc.get("steps", [])
    reads = poc.get("reads", [])
    report: dict = {
        "poc_id": poc.get("poc_id", "fork-poc"),
        "hypothesis": poc.get("hypothesis", ""),
        "chain": chain, "address": address,
        "fork": "local anvil fork only; no live broadcast",
        "stranger": STRANGER,
        "steps": [], "reads": [],
        "verdict": "UNVERIFIED",
        "verdict_reason": ("fork/simulation is never proof; "
                           "VERIFIED_REAL needs a live-chain probe "
                           "from an unfunded stranger + live receipt "
                           "+ balance-delta evidence"),
        "still_needed_for_verified_real": poc.get(
            "still_needed_for_verified_real", []),
    }
    # Latest block, then fork 3 blocks back (stable, recent state).
    rc, latest, err = _run([CAST, "block-number", "--rpc-url", rpc_url],
                           timeout=60)
    if rc != 0:
        report["error"] = f"live RPC unreachable: {err[:200]}"
        return report
    fork_block = int(latest) - 3
    report["fork_block"] = fork_block
    report["live_block_at_fork"] = int(latest)
    port = _free_port()
    local_rpc = f"http://127.0.0.1:{port}"
    anvil = subprocess.Popen(
        [ANVIL, "--fork-url", rpc_url, "--fork-block-number",
         str(fork_block), "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 120
        up = False
        while time.time() < deadline:
            rc, _, _ = _run([CAST, "block-number", "--rpc-url", local_rpc],
                            timeout=10)
            if rc == 0:
                up = True
                break
            time.sleep(1)
        if not up:
            report["error"] = "anvil fork did not come up"
            return report

        def do_reads(tag):
            snap = {"tag": tag, "values": {}}
            for r in reads:
                rc, out, err = _cast_call(
                    local_rpc, address, r["sig"], _resolve_args(r.get("args", [])))
                snap["values"][r["sig"]] = {
                    "ok": rc == 0,
                    "value": out if rc == 0 else f"ERROR: {err[:200]}"}
            report["reads"].append(snap)
            return snap

        do_reads("before")
        for i, step in enumerate(steps):
            # Preview as an eth_call first: a send that reverts
            # fails gas estimation with no reason; the call shows it.
            prc, pout, perr = _cast_call_from(
                local_rpc, address, step["sig"],
                _resolve_args(step.get("args", [])))
            if step.get("call_only"):
                # Boundary probe: eth_call only, no state change.
                report["steps"].append({
                    "index": i, "sig": step["sig"],
                    "args": _resolve_args(step.get("args", [])),
                    "ok": prc == 0, "tx_hash": None,
                    "receipt": None,
                    "error": perr[:400] if prc != 0 else None,
                    "call_preview": {
                        "ok": prc == 0,
                        "return": pout[:400] if prc == 0 else None,
                        "error": perr[:400] if prc != 0 else None},
                    "call_only": True})
                do_reads(f"after_step_{i}")
                continue
            rc, out, err = _cast_send(
                local_rpc, address, step["sig"],
                _resolve_args(step.get("args", [])))
            tx_hash = None
            if rc == 0:
                for line in out.splitlines():
                    if "transactionHash" in line:
                        tx_hash = line.split()[-1]
            report["steps"].append({
                "index": i, "sig": step["sig"],
                "args": _resolve_args(step.get("args", [])),
                "ok": rc == 0, "tx_hash": tx_hash,
                "receipt": out[:600] if rc == 0 else None,
                "error": err[:400] if rc != 0 else None,
                "call_preview": {
                    "ok": prc == 0,
                    "return": pout[:400] if prc == 0 else None,
                    "error": perr[:400] if prc != 0 else None},
            })
            do_reads(f"after_step_{i}")
        # Deltas: before vs last snapshot, per read.
        first = report["reads"][0]["values"]
        last = report["reads"][-1]["values"]
        deltas = {}
        for sig in first:
            try:
                # cast call prints hex, or decimal with a " [1e18]"
                # suffix: take the first token either way.
                b = int(str(first[sig]["value"]).split()[0], 0)
                a = int(str(last[sig]["value"]).split()[0], 0)
                deltas[sig] = a - b
            except (ValueError, TypeError):
                deltas[sig] = None
        report["deltas"] = deltas
        report["fork_executed"] = any(s["ok"] for s in report["steps"])
        if report["fork_executed"]:
            report["fork_outcome"] = (
                "attack sequence executed on the fork; balance deltas "
                "above are fork-local evidence for the live-probe lane")
        else:
            report["fork_outcome"] = (
                "attack sequence did NOT execute on the fork "
                "(reverted); the live path is not reachable this way "
                "with these args")
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=10)
        except subprocess.TimeoutExpired:
            anvil.kill()
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w") as fh:
            json.dump(report, fh, indent=1)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--poc", help="PoC definition JSON file")
    ap.add_argument("--chain")
    ap.add_argument("--rpc-url")
    ap.add_argument("--address")
    ap.add_argument("--steps", help="JSON list of {sig, args}")
    ap.add_argument("--reads", help="JSON list of {sig, args}")
    ap.add_argument("--hypothesis", default="")
    ap.add_argument("--out")
    args = ap.parse_args()
    if args.poc:
        with open(args.poc) as fh:
            poc = json.load(fh)
    else:
        poc = {"poc_id": "cli", "chain": args.chain,
               "rpc_url": args.rpc_url, "address": args.address,
               "hypothesis": args.hypothesis,
               "steps": json.loads(args.steps or "[]"),
               "reads": json.loads(args.reads or "[]")}
    report = run_poc(poc, args.out)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
