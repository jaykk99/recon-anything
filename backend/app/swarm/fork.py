"""ForkTester: test the story on a local fork (or its honest stand-in).

The fork step plans the stateful sequences (setup call, then the
sensitive call) that a single eth_call cannot test, and executes
them. Fork simulation is an analysis signal ONLY: every fork outcome
is recorded sim_derived and is NEVER fed to the validator as proof
and NEVER promotes a finding to VERIFIED_REAL.

Engines, in order:
1. ``anvil``   - real local fork (foundry anvil --fork-url), when the
                 binary is installed. Stateful: setup then target
                 runs against forked state.
2. ``ganache`` - real local fork (npx ganache --fork.url), same idea.
3. ``state_override`` - no local EVM is installed (this sandbox has
                 neither anvil nor ganache). Each planned step runs as
                 a live eth_call from the stranger against the public
                 RPC, with an optional balance override so the caller
                 is not broke. State does NOT carry between steps:
                 this is a per-step execution check, not a sequence
                 simulation, and the report says so. Real return /
                 revert data, nothing invented.
4. ``plan_only`` - nothing can execute; sequences planned only.

The report always names its engine and whether state carried over,
so a reader can tell exactly how much the fork step proved: which,
by the NO-SIMULATION rule, is never proof of a live vulnerability.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

from .rpc import RpcClient, selector
from .rules import STRANGER_ADDRESS

_FN_RE = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SENSITIVE_RE = re.compile(
    r"(withdraw|claim|rescue|sweep|drain|redeem|mint|transfer|"
    r"execute|call|delegate|upgrade|setOwner|renounce|selfdestruct)",
    re.I)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _local_plan(source: str) -> List[Dict[str, Any]]:
    """Fallback planner: pair state-changing setup fns with sensitive
    target fns found in the source. Max 8 sequences."""
    if not source:
        return []
    fns = list(dict.fromkeys(_FN_RE.findall(source)))
    sensitive = [f for f in fns if _SENSITIVE_RE.search(f)]
    setups = [f for f in fns if f not in sensitive]
    seqs: List[Dict[str, Any]] = []
    for target in sensitive[:8]:
        setup = setups[0] if setups else None
        seqs.append({"setup": setup, "target": target})
    return seqs


def plan_fork(source: str) -> List[Dict[str, Any]]:
    """Plan stateful probe sequences for one contract source.

    Prefers the repo's anvil_fork_probe planner; when it plans
    nothing (or is unavailable) the local source parser plans
    instead. An empty plan from the first planner is not an answer:
    it just means that planner had no opinion.
    """
    if not source:
        return []
    try:
        from ..plugins.anvil_fork_probe import plan_sequences  # type: ignore
        seqs = plan_sequences(source) or []
        mapped = [{"setup": (s.get("setup") or {}).get("name"),
                   "target": (s.get("target") or {}).get("name")}
                  for s in seqs]
        if mapped:
            return mapped
    except Exception:  # noqa: BLE001 - fall through to local planner
        pass
    return _local_plan(source)


def _calldata_for(fn_name: str, abi: Optional[List[Dict[str, Any]]],
                  address: str) -> Optional[str]:
    """Calldata for a call the swarm can safely make as a read-only
    eth_call: no-arg, or one zero-value argument (address=stranger,
    bool=false, uint256=0, bytes32=0, bytes/string=empty). Anything
    else returns None: the swarm never invents a meaningful argument
    for a state-changing call. A revert on the zero-value call is
    honest data (e.g. onlyGovernance rejecting a stranger).
    """
    if not fn_name:
        return None
    from .rpc import encode_address, encode_uint256
    if abi:
        for item in abi:
            if (isinstance(item, dict) and item.get("type") == "function"
                    and item.get("name") == fn_name):
                inputs = item.get("inputs") or []
                if len(inputs) == 0:
                    return "0x" + selector(f"{fn_name}()")
                if len(inputs) == 1:
                    typ = str(inputs[0].get("type") or "")
                    sig = f"{fn_name}({typ})"
                    if typ == "address":
                        return ("0x" + selector(sig)
                                + encode_address(STRANGER_ADDRESS))
                    if typ == "bool":
                        return "0x" + selector(sig) + encode_uint256(0)
                    if typ in ("uint256", "uint", "uint8", "uint96",
                               "uint128"):
                        return "0x" + selector(sig) + encode_uint256(0)
                    if typ == "bytes32":
                        return "0x" + selector(sig) + "00" * 32
                    if typ in ("bytes", "string"):
                        # empty dynamic arg: offset 0x20, length 0
                        return ("0x" + selector(sig)
                                + encode_uint256(32) + encode_uint256(0))
                return None
    # No ABI: try the no-arg form. A revert is honest data.
    return "0x" + selector(f"{fn_name}()")


class ForkTesterAgent:
    """Role agent: test the hypothesis on a fork (or stand-in)."""

    name = "forktester"

    def run(self, target: Dict[str, Any], hypothesis: Dict[str, Any],
            scout_report: Dict[str, Any], rpc: RpcClient,
            board: Any, source: str = "",
            abi: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        key = str(scout_report.get("key") or "")
        started = time.time()
        address = str(target.get("address") or "")
        seqs = plan_fork(source)
        # The hypothesis function goes first: the fork step tests the
        # story, not a random sensitive function.
        hyp_fn = str(hypothesis.get("function") or "")
        if hyp_fn and not any(s.get("target") == hyp_fn for s in seqs):
            seqs = [{"setup": None, "target": hyp_fn}] + seqs
        elif hyp_fn:
            seqs = sorted(seqs, key=lambda s: s.get("target") != hyp_fn)
        report: Dict[str, Any] = {
            "agent": self.name, "address": address, "key": key,
            "planned": seqs, "planned_count": len(seqs),
            "executed": False, "executed_count": 0,
            "outcomes": [], "sim_derived": True,
            "state_carried_between_steps": False,
            "engine": "plan_only",
        }
        if not seqs:
            report["note"] = ("no fork sequences planned "
                              "(no source, or no sensitive function found)")
            report["elapsed_s"] = round(time.time() - started, 3)
            board.post(self.name, key, "fork", report)
            return report

        engine = self._pick_engine()
        report["engine"] = engine
        try:
            if engine in ("anvil", "ganache"):
                outcomes = self._run_local_fork(
                    engine, target, seqs, rpc, abi, address)
                report["executed"] = True
                report["executed_count"] = len(outcomes)
                report["outcomes"] = outcomes
                report["state_carried_between_steps"] = True
                report["note"] = (
                    f"real local fork via {engine}; state carried "
                    "between setup and target calls")
            elif engine == "state_override":
                outcomes = self._run_state_override(
                    seqs, rpc, abi, address)
                report["executed"] = True
                report["executed_count"] = len(outcomes)
                report["outcomes"] = outcomes
                report["state_carried_between_steps"] = False
                report["note"] = (
                    "no local EVM installed; each step ran as a live "
                    "eth_call from the stranger against the public RPC "
                    "(balance override only). State did NOT carry "
                    "between steps: per-step execution check, not a "
                    "sequence simulation, and never proof.")
            else:
                report["note"] = (
                    "no fork engine available (no anvil, no ganache, "
                    "no state-override RPC); sequences planned only.")
        except Exception as e:  # noqa: BLE001 - fork failure is a report
            report["engine_error"] = f"{type(e).__name__}: {e}"
            report["note"] = f"fork engine {engine} failed: {e}"
        report["elapsed_s"] = round(time.time() - started, 3)
        board.post(self.name, key, "fork", report)
        return report

    @staticmethod
    def _pick_engine() -> str:
        # npx alone does not select ganache: starting it downloads
        # the package, which is slow and fails where npm writes are
        # blocked. Only a real ganache binary selects the fork engine.
        if shutil.which("anvil"):
            return "anvil"
        if shutil.which("ganache"):
            return "ganache"
        return "state_override"

    def _run_state_override(self, seqs: List[Dict[str, Any]],
                            rpc: RpcClient,
                            abi: Optional[List[Dict[str, Any]]],
                            address: str) -> List[Dict[str, Any]]:
        """Execute each planned step as a live eth_call from the
        stranger, with a 1 ETH balance override so the caller is not
        broke. Returns one outcome per step, with raw RPC output."""
        outcomes: List[Dict[str, Any]] = []
        override = {STRANGER_ADDRESS: {"balance": "0xde0b6b3a7640000"}}
        for seq in seqs:
            for role in ("setup", "target"):
                fn = seq.get(role)
                if not fn:
                    continue
                data = _calldata_for(str(fn), abi, address)
                if data is None:
                    outcomes.append({"sequence": seq, "role": role,
                                     "function": fn, "called": False,
                                     "reason": "arguments unknowable"})
                    continue
                try:
                    resp = rpc.eth_call(address, data,
                                        state_override=override)
                    outcomes.append({
                        "sequence": seq, "role": role, "function": fn,
                        "called": True, "calldata": data,
                        "result": resp.get("result"),
                        "error": (resp.get("error") or {}).get("message")
                        if resp.get("error") else None,
                        "raw": resp,
                    })
                except Exception as e:  # noqa: BLE001
                    outcomes.append({"sequence": seq, "role": role,
                                     "function": fn, "called": False,
                                     "reason": f"{type(e).__name__}: {e}"})
        return outcomes

    def _run_local_fork(self, engine: str, target: Dict[str, Any],
                        seqs: List[Dict[str, Any]], rpc: RpcClient,
                        abi: Optional[List[Dict[str, Any]]],
                        address: str) -> List[Dict[str, Any]]:
        """Real local fork: boot anvil/ganache forked at the live head,
        run setup->target eth_calls against it, tear it down."""
        port = _free_port()
        fork_url = (rpc.endpoints or [None])[0]
        if not fork_url:
            raise RuntimeError("no RPC endpoint to fork from")
        block = rpc.block_number()
        if engine == "anvil":
            cmd = ["anvil", "--fork-url", fork_url,
                   "--fork-block-number", str(max(block - 1, 0)),
                   "--port", str(port), "--silent"]
        else:
            cmd = ["npx", "-y", "ganache@7.9.2", "--fork.url", fork_url,
                   "--fork.blockNumber", str(max(block - 1, 0)),
                   "--port", str(port), "--logging.quiet"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        try:
            fork_rpc = RpcClient(target.get("chain") or "",
                                 endpoints=[f"http://127.0.0.1:{port}"])
            deadline = time.time() + 90
            ready = False
            while time.time() < deadline:
                try:
                    fork_rpc.block_number()
                    ready = True
                    break
                except Exception:  # noqa: BLE001 - not up yet
                    time.sleep(1)
            if not ready:
                raise RuntimeError(f"{engine} did not come up in 90s")
            outcomes: List[Dict[str, Any]] = []
            for seq in seqs:
                for role in ("setup", "target"):
                    fn = seq.get(role)
                    if not fn:
                        continue
                    data = _calldata_for(str(fn), abi, address)
                    if data is None:
                        outcomes.append({"sequence": seq, "role": role,
                                         "function": fn, "called": False,
                                         "reason": "arguments unknowable"})
                        continue
                    try:
                        resp = fork_rpc.eth_call(address, data)
                        outcomes.append({
                            "sequence": seq, "role": role, "function": fn,
                            "called": True, "calldata": data,
                            "result": resp.get("result"),
                            "error": (resp.get("error") or {}).get("message")
                            if resp.get("error") else None,
                            "raw": resp,
                        })
                    except Exception as e:  # noqa: BLE001
                        outcomes.append({"sequence": seq, "role": role,
                                         "function": fn, "called": False,
                                         "reason": f"{type(e).__name__}: {e}"})
            return outcomes
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                proc.kill()
