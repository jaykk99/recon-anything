#!/usr/bin/env python3
"""Fork-hypothesis harness: test a detector finding against live
mainnet state on a LOCAL Anvil/Foundry fork.

Usage:
  fork_hypothesis.py --hypothesis hypothesis.json [--out result.json]
  fork_hypothesis.py --auto --chain bsc --address 0x... \
      --function "deposit(uint256,address)" [--block 12345]

A hypothesis is JSON:
  {"chain": "bsc", "address": "0x...", "function": "deposit(uint256,address)",
   "hypothesis": "depositing then withdrawing in one call moves the rate",
   "calls": [{"function": "deposit(uint256,address)", "args": [1000, "0x..."]},
             {"function": "withdraw(uint256,address)", "args": [1000, "0x..."]}]}

The harness builds a throwaway Foundry project in a temp dir,
forks the chain at the given block (latest if omitted) with
vm.createFork, runs the call sequence as a local forge test, and
writes a result JSON. It NEVER broadcasts a transaction and
never touches live state: forge test runs only against the
in-memory fork, and the script refuses any hypothesis that asks
for a broadcast / send / real transaction.

The verdict is ALWAYS "UNVERIFIED". A fork test is a local
candidate, never proof. The ONLY proof path is the live eth_call
probe from an unfunded stranger against the real contract in
its current state (Jay's no-simulation rule). A passing fork
test means "worth a live probe", nothing more.

Keyless: public RPCs from app.plugins.contract_chain (no API
key). Foundry is expected at ~/workspace/tools/audit/bin/
(or on PATH); if forge is not found the script exits non-zero
with an honest error and no fake result.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app import net  # noqa: E402

from app.plugins import contract_chain as cc  # noqa: E402

# Any of these in a hypothesis means "do it live" - refused.
FORBIDDEN = (
    "broadcast", "sendtransaction", "eth_send", "cast send",
    "forge script", "--broadcast", "send_transaction",
    "eth_sendtransaction", "eth_sendrawtransaction",
    "privatekey", "private_key",
)

FORGE_CANDIDATES = (
    os.path.expanduser("~/workspace/tools/audit/bin/forge"),
    shutil.which("forge") or "",
)

# Default argument for a Solidity type, for --auto mode.
_DEFAULT_ARG = {
    "uint": "0", "int": "0", "bool": "false",
    "address": "address(0)", "string": '""', "bytes": '""',
}


def find_forge() -> str:
    for cand in FORGE_CANDIDATES:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return ""


def check_forbidden(hyp: dict) -> str:
    blob = json.dumps(hyp).lower()
    for word in FORBIDDEN:
        if word in blob:
            return word
    return ""


def default_arg(sol_type: str) -> str:
    t = sol_type.strip()
    if t.endswith("[]"):
        return f"new {t}(0)"
    if re.match(r"^(uint|int)\d*$", t):
        return "0"
    if t == "address":
        return "address(0)"
    if t == "bool":
        return "false"
    if t == "string":
        return '""'
    if re.match(r"^bytes\d*$", t):
        return '""'
    return "0"


def parse_signature(sig: str):
    """'deposit(uint256,address)' -> ('deposit', ['uint256', 'address'])."""
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$", sig)
    if not m:
        raise ValueError(f"bad function signature: {sig!r}")
    params = [p.strip() for p in m.group(2).split(",") if p.strip()]
    return m.group(1), params


def sol_literal(value) -> str:
    """A JSON arg value -> a Solidity literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        if re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
            return value
        if re.fullmatch(r"0x[0-9a-fA-F]+", value):
            return value
        return json.dumps(value)
    raise ValueError(f"unsupported arg value: {value!r}")


def call_expr(target: str, func_sig: str, args, index: int) -> str:
    """A low-level call expression for one step of the sequence.

    Low-level .call is used deliberately: a revert in one step
    must not abort the whole test - the result (ok / revert) is
    recorded per step and reported, so the harness can tell a
    "sequence reverts" from a "sequence executes".
    """
    name, params = parse_signature(func_sig)
    if args is None:
        args = [default_arg(p) for p in params]
    else:
        if len(args) != len(params):
            raise ValueError(
                f"{func_sig}: {len(args)} args given, "
                f"{len(params)} expected")
        args = [sol_literal(a) for a in args]
    arg_list = ", ".join(args)
    sig = f"{name}({','.join(params)})"
    return (
        f'(bool ok{index}, bytes memory ret{index}) = '
        f'target.call('
        f'abi.encodeWithSignature("{sig}"'
        + (f", {arg_list}" if arg_list else "") + '));\n'
        f'        emit StepResult({index}, ok{index}, '
        f'ret{index});')


def build_test_contract(hyp: dict, rpc: str, block: int) -> str:
    address = hyp["address"]
    calls = hyp.get("calls") or []
    if not calls:
        func = hyp.get("function", "")
        if not func:
            raise ValueError(
                "hypothesis needs 'function' or a 'calls' list")
        calls = [{"function": func, "args": None}]
    steps = []
    for i, call in enumerate(calls):
        steps.append(call_expr(address, call["function"],
                               call.get("args"), i))
    steps_src = "\n".join(
        "        " + line for step in steps
        for line in step.split("\n"))
    return f"""// SPDX-License-Identifier: MIT
// Generated by fork_hypothesis.py - local fork only, never
// broadcasts. The verdict from this test is UNVERIFIED by
// construction; only a live eth_call stranger probe counts.
pragma solidity ^0.8.0;

interface Vm {{
    function createFork(string calldata url, uint256 blockNumber)
        external returns (uint256);
    function selectFork(uint256 forkId) external;
}}

contract HypothesisTest {{
    Vm constant vm = Vm(address(uint160(uint256(
        keccak256("hevm cheat code")))));
    address constant target = {address};

    event StepResult(uint256 indexed step, bool ok, bytes data);

    function setUp() public {{
        uint256 forkId = vm.createFork("{rpc}", {block});
        vm.selectFork(forkId);
    }}

    function test_hypothesis() public {{
{steps_src}
    }}
}}
"""


def latest_block(rpc: str) -> int:
    # httpx via app.net, not urllib: urllib reads come back
    # truncated through this VM's egress proxy while httpx
    # works, and app.net configures the proxy explicitly.
    payload = {"jsonrpc": "2.0", "id": 1,
               "method": "eth_blockNumber", "params": []}
    try:
        with net.sync_client(timeout=30) as client:
            resp = client.post(
                rpc, json=payload,
                headers={"Content-Type": "application/json"})
    except httpx.RequestError as exc:
        raise RuntimeError(f"latest block read failed: {exc}") \
            from exc
    data = resp.json()
    return int(data["result"], 16)


def run_forge_test(workdir: str, forge: str,
                   timeout_s: int = 300):
    # -vvvv (trace) so the per-step StepResult events appear in
    # the output; -vvv does not print them.
    proc = subprocess.run(
        [forge, "test", "-vvvv"], cwd=workdir,
        capture_output=True, text=True, timeout=timeout_s)
    return proc.returncode, proc.stdout + proc.stderr


def parse_forge_output(output: str) -> dict:
    passed = bool(re.search(r"\[PASS\]", output))
    failed = bool(re.search(r"\[FAIL", output))
    steps = []
    for m in re.finditer(
            r"StepResult\s*\(\s*step:\s*(\d+),\s*ok:\s*(true|false)",
            output):
        steps.append({"step": int(m.group(1)),
                      "ok": m.group(2) == "true"})
    # forge -vvv also prints the raw event args; fall back to
    # counting emitted StepResult lines if the decoded form
    # is not present.
    if not steps:
        for m in re.finditer(r"emit StepResult\(step: (\d+), "
                             r"ok: (true|false)", output):
            steps.append({"step": int(m.group(1)),
                          "ok": m.group(2) == "true"})
    return {"passed": passed and not failed,
            "failed": failed,
            "steps": steps,
            "raw": output}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Fork-test a detector hypothesis locally "
                    "(UNVERIFIED by construction).")
    ap.add_argument("--hypothesis",
                    help="hypothesis JSON file or JSON string")
    ap.add_argument("--auto", action="store_true",
                    help="build a probe from --function + defaults")
    ap.add_argument("--chain", default="bsc",
                    help="chain id (default: bsc)")
    ap.add_argument("--address",
                    help="target contract address")
    ap.add_argument("--function",
                    help='function signature, e.g. '
                         '"deposit(uint256,address)"')
    ap.add_argument("--block", type=int, default=0,
                    help="fork block (default: latest)")
    ap.add_argument("--rpc",
                    help="public RPC URL override")
    ap.add_argument("--out",
                    help="result JSON path (default: stdout)")
    ap.add_argument("--timeout", type=int, default=300,
                    help="forge test timeout in seconds")
    args = ap.parse_args(argv)

    forge = find_forge()
    if not forge:
        print("foundry not available: no forge binary at "
              "~/workspace/tools/audit/bin/forge or on PATH - "
              "no fork test was run and no result is claimed",
              file=sys.stderr)
        return 2

    if args.hypothesis:
        try:
            hyp = json.loads(args.hypothesis) \
                if args.hypothesis.strip().startswith("{") else \
                json.load(open(args.hypothesis))
        except (OSError, ValueError) as exc:
            print(f"bad hypothesis input: {exc}", file=sys.stderr)
            return 2
    elif args.auto:
        if not args.address or not args.function:
            print("--auto needs --address and --function",
                  file=sys.stderr)
            return 2
        hyp = {"chain": args.chain, "address": args.address,
               "function": args.function,
               "hypothesis": "auto probe: call the function on "
                             "a local fork and record the result"}
    else:
        print("give --hypothesis or --auto", file=sys.stderr)
        return 2

    bad = check_forbidden(hyp)
    if bad:
        print(f"refused: hypothesis asks for a live action "
              f"({bad!r}) - this harness never broadcasts or "
              f"sends a transaction", file=sys.stderr)
        return 2

    chain_id = hyp.get("chain") or args.chain
    chain = cc.CHAINS.get(chain_id)
    if chain is None:
        print(f"unknown chain: {chain_id}", file=sys.stderr)
        return 2
    rpc = args.rpc or chain.rpc_urls[0]
    address = hyp.get("address") or args.address
    if not address or not cc.ADDRESS_RE.match(address):
        print(f"bad address: {address}", file=sys.stderr)
        return 2
    hyp["chain"] = chain_id
    hyp["address"] = address

    block = args.block or hyp.get("block") or 0
    if not block:
        try:
            block = latest_block(rpc)
        except Exception as exc:
            print(f"could not read latest block from {rpc}: "
                  f"{exc}", file=sys.stderr)
            return 2

    try:
        test_src = build_test_contract(hyp, rpc, block)
    except ValueError as exc:
        print(f"bad hypothesis: {exc}", file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix="fork-hypothesis-")
    try:
        with open(os.path.join(workdir, "foundry.toml"), "w") as fh:
            fh.write('[profile.default]\nsrc = "src"\n'
                     'out = "out"\nlibs = ["lib"]\n')
        os.makedirs(os.path.join(workdir, "src"), exist_ok=True)
        with open(os.path.join(workdir, "src",
                               "Hypothesis.t.sol"), "w") as fh:
            fh.write(test_src)
        try:
            rc, output = run_forge_test(workdir, forge,
                                        args.timeout)
        except subprocess.TimeoutExpired:
            result = {"verdict": "UNVERIFIED",
                      "hypothesis": hyp.get("hypothesis", ""),
                      "chain": chain_id, "address": address,
                      "block": block, "rpc": rpc,
                      "forge": {"ran": False, "timeout": True},
                      "note": "forge test timed out - no result "
                              "claimed"}
            return _emit(result, args.out, 3)
        parsed = parse_forge_output(output)
        result = {
            "verdict": "UNVERIFIED",
            "hypothesis": hyp.get("hypothesis", ""),
            "chain": chain_id,
            "address": address,
            "block": block,
            "rpc": rpc,
            "fork": {"local_only": True, "broadcast": False,
                     "live_state_touched": False},
            "forge": {"ran": True, "exit_code": rc,
                      "passed": parsed["passed"],
                      "steps": parsed["steps"]},
            "note": "Local fork candidate only. A passing fork "
                    "test means the sequence executes on forked "
                    "state and is worth a live probe - it is NOT "
                    "proof. VERIFIED_REAL requires a live-chain "
                    "eth_call probe from an unfunded stranger "
                    "against the real contract in its current "
                    "state, plus live recipient/balance evidence.",
        }
        if not parsed["passed"]:
            result["forge"]["output_tail"] = output[-4000:]
        return _emit(result, args.out, 0 if parsed["passed"] else 3)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _emit(result: dict, out: str, code: int) -> int:
    text = json.dumps(result, indent=2)
    if out:
        with open(out, "w") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
