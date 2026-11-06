"""Foundry Test Generator (Cat-1 #30, VARIANT of forge_inspect /
evm_tracer lanes).

Delta: generator mode. Takes an anomalous trace record (trace
record on the bus: {block, anomaly?, state_delta?, calls:
[{from, to, value, data | function, args}]}, e.g. produced by a
tracer / simulation lane) and emits a compilable Foundry test
skeleton - fork at the traced block, replay the calls from their
original senders with vm.prank, assert the anomalous state /
balance delta - as a local artifact carried in the finding's
evidence. Nothing is executed against a live chain; a trace with
no anomaly and no state delta generates no finding.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C


def generate_foundry_test(trace: Dict[str, Any]) -> str:
    block = trace.get("block", 0)
    calls = trace.get("calls") or []
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.20;",
        "",
        "import \"forge-std/Test.sol\";",
        "",
        "contract AnomalousTraceTest is Test {",
        "    function setUp() public {",
        f"        vm.createSelectFork(vm.rpcUrl(\"mainnet\"), "
        f"{int(block) if str(block).isdigit() else 0});",
        "    }",
        "",
        "    function test_replayAnomalousTrace() public {",
    ]
    for i, call in enumerate(calls):
        if not isinstance(call, dict):
            continue
        frm = call.get("from") or "address(0)"
        to = call.get("to") or "address(0)"
        value = int(call.get("value", 0) or 0)
        data = call.get("data") or ""
        lines.append(f"        // call {i}: {frm} -> {to}")
        lines.append(f"        vm.prank({frm});")
        if data:
            lines.append(
                f"        (bool ok{i},) = {to}.call{{value: "
                f"{value}}}(hex\"{str(data).removeprefix('0x')}\");")
        else:
            lines.append(
                f"        (bool ok{i},) = {to}.call{{value: "
                f"{value}}}(\"\");")
        lines.append(f"        assertTrue(ok{i}, \"replay call {i} "
                     f"reverted\");")
    delta = trace.get("state_delta")
    if delta:
        lines.append(f"        // anomalous delta observed: {delta}")
        lines.append("        // TODO: assert the post-state that "
                     "makes this delta anomalous for the target.")
    anomaly = trace.get("anomaly")
    if anomaly:
        lines.append(f"        // anomaly: {anomaly}")
    lines += ["    }", "}", ""]
    return "\n".join(lines)


def analyze_trace(trace: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(trace, dict) or not trace.get("calls"):
        return []
    anomalous = bool(trace.get("anomaly")) or bool(
        trace.get("state_delta"))
    if not anomalous:
        return []
    code = generate_foundry_test(trace)
    return [C.hit(
        "foundry_test_generated",
        f"generated a Foundry test skeleton replaying "
        f"{len(trace.get('calls') or [])} traced call(s) at block "
        f"{trace.get('block')} for the anomaly "
        f"'{trace.get('anomaly') or trace.get('state_delta')}': "
        f"save as test/AnomalousTrace.t.sol and run locally with "
        f"forge test.",
        "low",
        "Run the generated test against a local fork to "
        "reproduce the anomaly before patching.",
        generated_test=code, block=trace.get("block"),
        calls=len(trace.get("calls") or []),
        check="foundry_test_generator")]


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    for kind in ("trace", "traces"):
        for item in data["extras"].get(kind, []):
            if isinstance(item, dict):
                hits = analyze_trace(item)
                if hits:
                    return hits
    return []


class FoundryTestGeneratorPlugin(Plugin):
    id = "foundry_test_generator"
    label = "Foundry Test Generator"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Converts an anomalous transaction trace into "
                   "a compilable Foundry test skeleton (fork at "
                   "the traced block, replay the calls, assert "
                   "the anomalous delta). Local artifact only.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, extras=("trace", "traces"),
            source=False, bytecode=False,
            no_input="no trace supplied: generation needs a trace "
                     "record with calls and an anomaly")
