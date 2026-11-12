"""Local Anvil fork attack-path harness.

Takes a candidate + hypothesis (a function signature and args)
and runs the COMPLETE attack path on a local Anvil fork of the
live chain, measuring exactly what an unfunded stranger receives
before and after. The stranger is the protocol's own unfunded
caller (0x000...deaDBeef); the fork gives it a 0.01 ETH gas
reserve only, and every wei of gas the attack spends is
subtracted back out, so the reported receipt is the contract's
payout and nothing else.

Verdict is ALWAYS "UNVERIFIED". A fork payout is a candidate
for a live probe, never proof: VERIFIED_REAL still requires a
live-chain probe from an unfunded stranger plus live
receipt/balance evidence.

Hard refusals (this harness can never do these):
- any broadcast hypothesis (no --broadcast flag exists here,
  no private key is ever accepted, no mainnet RPC is ever
  contacted - the fork RPC is a public read-only endpoint and
  every transaction goes to the local Anvil instance only);
- any hypothesis carrying an external URL or a credential
  field (broadcast / rpc_url / private_key / mnemonic).

Read-only against the live chain (fork + eth_call). The only
writes happen on the throwaway local fork, which is killed when
the run ends. Needs foundry (anvil + cast) on the machine:
~/workspace/tools/audit/bin/ first, then PATH.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .plugins import contract_chain as cc

STRANGER = "0x00000000000000000000000000000000deaDBeef"  # == sim.FUZZ_CALLER
GAS_RESERVE_WEI = 10 ** 16  # 0.01 ETH, gas only, on the fork
MAX_UINT256 = 2 ** 256 - 1

_REFUSE_KEYS = frozenset({
    "broadcast", "rpc_url", "rpc-url", "private_key", "privatekey",
    "mnemonic", "key", "seed", "seed_phrase",
})
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def find_foundry_tool(name: str) -> str:
    """anvil/cast: the audit bin dir first, then PATH, else ''."""
    p = Path(os.path.expanduser("~/workspace/tools/audit/bin")) / name
    if p.exists():
        return str(p)
    return shutil.which(name) or ""


def _run_cmd(args: List[str], timeout: float) -> tuple:
    """subprocess.run wrapper (monkeypatch seam for tests).

    Returns (stdout+stderr text or None, error string or None)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), None
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def _spawn_anvil(args: List[str]):
    """subprocess.Popen wrapper (monkeypatch seam for tests)."""
    return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def _refuse(hypothesis: Any) -> Optional[str]:
    if not isinstance(hypothesis, dict):
        return "hypothesis must be an object with function + args"
    for k in hypothesis:
        if str(k).lower() in _REFUSE_KEYS:
            return (f"refused: hypothesis key {k!r} is a broadcast / "
                    "credential field; this harness only runs local "
                    "forks and never broadcasts")
    blob = json.dumps(hypothesis, default=str)
    if "http://" in blob or "https://" in blob:
        return ("refused: hypothesis carries an external URL; the "
                "harness picks its own fork RPC and only talks to "
                "the local Anvil instance")
    if "broadcast" in blob.lower():
        return "refused: broadcast is never allowed in this harness"
    fn = hypothesis.get("function", "")
    if not isinstance(fn, str) or "(" not in fn or ")" not in fn:
        return ("hypothesis.function must be a call signature like "
                "'mint(address,uint256)'")
    return None


def _resolve_arg(value: Any, address: str) -> str:
    if isinstance(value, str):
        if value == "STRANGER":
            return STRANGER
        if value == "SELF":
            return address
        if value == "MAX":
            return str(MAX_UINT256)
        if value == "ONE_ETH":
            return str(10 ** 18)
    return str(value)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _parse_int(out: Optional[str]) -> Optional[int]:
    if not out:
        return None
    s = out.strip().splitlines()
    if not s:
        return None
    first = s[0].strip()
    try:
        if first.startswith("0x"):
            return int(first, 16)
        return int(first)
    except Exception:  # noqa: BLE001
        return None


def run_fork_attack(chain: str, address: str, hypothesis: Dict[str, Any],
                    timeout_s: float = 300,
                    anvil_bin: Optional[str] = None,
                    cast_bin: Optional[str] = None,
                    fork_rpc: Optional[str] = None) -> Dict[str, Any]:
    """Run one attack hypothesis on a local Anvil fork.

    Returns a result dict with status (completed | degraded |
    refused), steps, stranger_received {native_wei, tokens}, and
    verdict ALWAYS "UNVERIFIED".
    """
    t0 = time.monotonic()
    base: Dict[str, Any] = {
        "chain": chain, "address": address,
        "hypothesis": hypothesis, "stranger": STRANGER,
        "verdict": "UNVERIFIED",
        "verdict_note": ("fork simulation only - never proof. "
                         "VERIFIED_REAL requires a live-chain probe "
                         "from an unfunded stranger plus live "
                         "receipt/balance evidence."),
    }
    if chain not in cc.CHAINS:
        return {**base, "status": "refused",
                "detail": f"unknown chain {chain}"}
    if not _ADDRESS_RE.match(address or ""):
        return {**base, "status": "refused",
                "detail": "address must be 0x + 40 hex characters"}
    refusal = _refuse(hypothesis)
    if refusal:
        return {**base, "status": "refused", "detail": refusal}

    anvil = anvil_bin or find_foundry_tool("anvil")
    cast = cast_bin or find_foundry_tool("cast")
    if not anvil or not cast:
        return {**base, "status": "degraded",
                "detail": ("anvil/cast not available on this machine "
                           "(looked in ~/workspace/tools/audit/bin "
                           "and PATH); fork testing needs foundry")}

    cfg = cc.CHAINS[chain]
    rpc = fork_rpc or (cfg.rpc_urls[0] if cfg.rpc_urls else "")
    if not rpc:
        return {**base, "status": "degraded",
                "detail": f"no public RPC configured for {chain}"}
    port = _free_port()
    local = f"http://127.0.0.1:{port}"
    steps: List[Dict[str, Any]] = []

    def remaining() -> float:
        return max(5.0, timeout_s - (time.monotonic() - t0))

    proc = None
    try:
        anvil_args = [anvil, "--fork-url", rpc, "--port", str(port),
                      "--no-rate-limit", "--silent"]
        if hypothesis.get("fork_block"):
            anvil_args += ["--fork-block-number",
                           str(hypothesis["fork_block"])]
        try:
            proc = _spawn_anvil(anvil_args)
        except Exception as e:  # noqa: BLE001
            return {**base, "status": "degraded",
                    "detail": f"could not start anvil: {e}"}
        # Wait for the fork to answer.
        ready = False
        for _ in range(60):
            if remaining() <= 5:
                break
            out, _err = _run_cmd(
                [cast, "block-number", "--rpc-url", local], 10)
            n = _parse_int(out)
            if n is not None:
                ready = True
                base["fork_block"] = n
                break
            time.sleep(1)
        if not ready:
            return {**base, "status": "degraded",
                    "detail": ("anvil fork did not answer within 60s "
                               f"(fork RPC {rpc}); the fork RPC may be "
                               "unreachable from this machine"),
                    "steps": steps}
        # Gas reserve for the stranger (gas only; subtracted back).
        _run_cmd([cast, "rpc", "anvil_setBalance", STRANGER,
                  hex(GAS_RESERVE_WEI), "--rpc-url", local], 15)

        tokens = hypothesis.get("tokens") or []

        def _native() -> Optional[int]:
            out, _e = _run_cmd(
                [cast, "balance", "--rpc-url", local, STRANGER], 15)
            return _parse_int(out)

        def _token_bal(token: str) -> Optional[int]:
            out, _e = _run_cmd(
                [cast, "call", "--from", STRANGER, "--rpc-url", local,
                 token, "balanceOf(address)(uint256)", STRANGER], 15)
            return _parse_int(out)

        before_native = _native()
        before_tokens = {t: _token_bal(t) for t in tokens}

        calls = hypothesis.get("steps") or [{
            "function": hypothesis["function"],
            "args": hypothesis.get("args") or
                    hypothesis.get("args_template") or [],
            "value_wei": hypothesis.get("value_wei", 0),
        }]
        gas_spent = 0
        for call in calls:
            fn = str(call.get("function", ""))
            args = [_resolve_arg(a, address)
                    for a in (call.get("args") or [])]
            value = int(call.get("value_wei", 0) or 0)
            send = [cast, "send", "--unlocked", "--from", STRANGER,
                    "--rpc-url", local, "--json"]
            if value:
                send += ["--value", str(value)]
            send += [address, fn, *args]
            out, err = _run_cmd(send, remaining())
            step: Dict[str, Any] = {"function": fn, "args": args,
                                    "value_wei": value}
            if out is None:
                step.update({"status": "transport_error",
                             "detail": (err or "cast send failed")[:300]})
                steps.append(step)
                continue
            try:
                receipt = json.loads(out)
                status = receipt.get("status")
                gas_used = int(receipt.get("gasUsed", 0) or 0)
                gas_price = int(
                    receipt.get("effectiveGasPrice", 0) or 0)
                gas_spent += gas_used * gas_price
                step.update({
                    "status": "success" if status in (
                        1, "0x1", "success") else "revert",
                    "gas_used": gas_used,
                    "gas_spent_wei": gas_used * gas_price,
                    "tx_hash": receipt.get("transactionHash", ""),
                })
            except Exception:  # noqa: BLE001
                low = out.lower()
                if "revert" in low or "error" in low:
                    step.update({"status": "revert",
                                 "detail": out.strip()[-300:]})
                else:
                    step.update({"status": "unknown",
                                 "detail": out.strip()[-300:]})
            steps.append(step)

        after_native = _native()
        after_tokens = {t: _token_bal(t) for t in tokens}
        received_tokens: Dict[str, Any] = {}
        for t in tokens:
            b, a = before_tokens.get(t), after_tokens.get(t)
            received_tokens[t] = (
                None if b is None or a is None else a - b)
        received_native: Optional[int] = None
        if before_native is not None and after_native is not None:
            # Add the gas back: the fork gave the stranger a gas
            # reserve, so the contract's payout is the native delta
            # plus what the attack spent on gas.
            received_native = (after_native - before_native) + gas_spent
        return {**base,
                "status": "completed",
                "fork_rpc_host": rpc.split("/")[2] if "://" in rpc
                else rpc,
                "steps": steps,
                "gas_spent_wei": gas_spent,
                "stranger_received": {
                    "native_wei": received_native,
                    "tokens": received_tokens,
                },
                "balances": {
                    "native_before_wei": before_native,
                    "native_after_wei": after_native,
                }}
    finally:
        if proc is not None:
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
            try:
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
