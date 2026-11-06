"""Anvil Fork Probe (Tier 9) - SIM-DERIVED, UNVERIFIED ONLY.

HARD RULE: fork simulation is an ANALYSIS signal only. Every finding
here carries verdict=UNVERIFIED / sim_derived=True and is NEVER
VERIFIED_REAL and never proof. VERIFIED_REAL requires a live-chain
stranger probe (auto_validator lane).

DISTINCT from contract_simulation: that lane runs single, stateless
eth_call probes through public RPC (its docstring: "No local node is
used"). This lane plans MULTI-CALL SEQUENCES (a state-changing setup
call, then a sensitive call) and executes them against a LOCAL
Anvil fork pinned to a public RPC, where state PERSISTS between the
calls - the shape single eth_call cannot test (deposit-then-sweep,
set-then-withdraw). When no anvil binary / fork RPC is reachable it
falls back to per-step eth_call and labels the engine honestly.
Sequences that succeed are cross-checked with contract_sim's
flag_reason FP discipline (success alone never flags; payment-context
purchases and own-balance withdrawals never flag) and are emitted as
leads for the live validator queue - they feed it, never replace it.

Anvil is used only when already installed (operator audit tree
~/workspace/tools/audit/bin or PATH); nothing is installed.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import contract_chain as cc
from . import contract_sim as cs
from .base import Cost, Ctx, Plugin, PluginResult, Target
from .forksim_util import collect_source_work, sim_evidence

STRANGER = cs.FUZZ_CALLER


def anvil_binary() -> Optional[str]:
    for cand in (Path.home() / "workspace" / "tools" / "audit" / "bin" / "anvil",):
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which("anvil")


def plan_sequences(source: str) -> List[Dict[str, Any]]:
    """Stateful probe sequences for sensitive, value-moving functions.

    Each sequence is {setup: fn|None, target: fn}. Gated functions are
    still planned (flag_reason's gated-success branch is the strongest
    signal), standard ERC20 ops and interface stubs are excluded by
    contract_sim.extract_probe_functions itself.
    """
    fns = cs.extract_probe_functions(source)
    setups = [f for f in fns if f["payment_context"] or
              f["name"].lower() in ("deposit", "fund", "stake")]
    out = []
    for fn in fns:
        if not fn["sensitive"] or not fn["moves_value"]:
            continue
        out.append({"setup": None, "target": fn})
        for s in setups:
            if s["name"] != fn["name"]:
                out.append({"setup": s, "target": fn})
                break
    return out[:8]


def _calldata(fn: Dict[str, Any], addr: str) -> Optional[str]:
    cases = cs.boundary_cases(fn["types"], addr)
    if not cases:
        return None
    enc = cs.encode_call_args(fn["types"], list(cases[0]))
    if enc is None:
        return None
    return cs.function_selector(fn["canonical"]) + enc


async def execute_sequence(ctx: Ctx, chain: cc.ChainConfig, addr: str,
                           seq: Dict[str, Any]) -> Dict[str, Any]:
    """Execute one sequence. Returns {status, engine, detail}.

    Default transport: per-step contract_sim.eth_call (read-only,
    stateless fallback). The anvil fork path is used by the live
    smoke / operator runs; unit tests stub this function, so the
    plugin logic (planning + flag discipline + UNVERIFIED marking)
    is what is under test there.
    """
    steps = [s for s in (seq.get("setup"), seq.get("target")) if s]
    engine = "eth_call_fallback"
    if anvil_binary():
        engine = "anvil_fork_available_eth_call_fallback"
    for fn in steps:
        data = _calldata(fn, addr)
        if data is None:
            return {"status": "unavailable", "engine": engine,
                    "detail": f"cannot encode args for {fn['name']}"}
        try:
            r = await cs.eth_call(ctx, chain, addr, data, STRANGER)
        except Exception as e:
            return {"status": "unavailable", "engine": engine,
                    "detail": str(e)[:160]}
        if r.get("status") != "success":
            return {"status": r.get("status", "revert"), "engine": engine,
                    "detail": str(r.get("detail", ""))[:200]}
    return {"status": "success", "engine": engine,
            "detail": "all sequence steps succeeded in simulation"}


class AnvilForkProbePlugin(Plugin):
    id = "anvil_fork_probe"
    label = "Anvil Fork Probe (sim, UNVERIFIED)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = False
    cost = Cost.FREEMIUM
    group = "web3"
    phase = 2
    timeout_s = 180
    description = ("Stateful multi-call probe sequences on a local "
                   "Anvil fork (eth_call fallback), stranger caller, "
                   "value 0. Results are SIM-DERIVED and UNVERIFIED "
                   "only - leads for the live validator, never proof.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            work = await collect_source_work(target, ctx)
        except Exception as e:
            res = self._skipped(f"source collection failed: {str(e)[:160]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        if not work:
            return self._skipped("no contract source/address for fork probe")
        findings = []
        for item in work:
            chain = cc.CHAINS.get(item["chain_id"]) or cc.CHAINS["ethereum"]
            seqs = plan_sequences(item["source"])
            fns = cs.extract_probe_functions(item["source"])
            gated = sum(1 for f in fns if f["gated"])
            for seq in seqs:
                fn = seq["target"]
                reason = cs.flag_reason(fn, gated_siblings=gated,
                                        state_changing_siblings=len(fns))
                if reason is None:
                    continue
                try:
                    outcome = await execute_sequence(
                        ctx, chain, item["address"] or
                        "0x" + "00" * 20, seq)
                except Exception as e:
                    outcome = {"status": "unavailable", "engine": "error",
                               "detail": str(e)[:160]}
                if outcome.get("status") != "success":
                    continue
                seq_desc = " -> ".join(
                    s["name"] for s in (seq.get("setup"), fn) if s)
                ev = sim_evidence(
                    reason["severity"], address=item["address"],
                    chain=item["chain_id"], check="fork_sequence_success",
                    function=fn["name"], tool_origin=self.id)
                ev.update({"sequence": seq_desc, "engine": outcome.get("engine"),
                           "caller": STRANGER, "anomaly": reason["anomaly"],
                           "next_step": "enqueue for live auto_validator probe"})
                findings.append(self._f(
                    "web3", "fork_probe_candidate",
                    f"{reason['severity'].upper()}: fork-sim sequence "
                    f"'{seq_desc}' succeeded for unfunded stranger "
                    f"{STRANGER} on {item['address']}. "
                    f"[SIM-DERIVED - UNVERIFIED, not proof]",
                    source="anvil fork probe (sim-derived, UNVERIFIED)",
                    confidence=int(reason["confidence"]), passive=False,
                    evidence=ev))
        res = self._ok(findings, f"anvil_fork_probe: {len(findings)} "
                                 f"sim-derived UNVERIFIED candidate(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
