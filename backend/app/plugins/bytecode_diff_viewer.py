"""Bytecode Diff Viewer (Cat-1 #22, VARIANT of bytecode_deep_analysis).

Delta: two-input mode. Disassembles TWO bytecode blobs (old vs new
implementation, two addresses, one address at two blocks) and
emits the structural diff: added / removed function selectors,
and opcode-class changes (a SELFDESTRUCT or DELEGATECALL that
appears in the new code but not the old is the headline finding).
Identical code stays silent. Inputs arrive as a bytecode_pair
record {old, new} / bytecode_old + bytecode_new on the bus, or
two raw hex targets.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C
from . import contract_chain as cc

_WATCH = ("SELFDESTRUCT", "DELEGATECALL", "CALLCODE", "CREATE2")


def diff_bytecode(old_hex: str, new_hex: str) -> Dict[str, Any]:
    old_info = cc.analyze_bytecode(old_hex or "")
    new_info = cc.analyze_bytecode(new_hex or "")
    old_sels = {s["selector"] for s in old_info.get("selectors", [])}
    new_sels = {s["selector"] for s in new_info.get("selectors", [])}
    old_ops = {i["op"] for i in C.disasm(old_hex or "")}
    new_ops = {i["op"] for i in C.disasm(new_hex or "")}
    return {
        "added_selectors": sorted(new_sels - old_sels),
        "removed_selectors": sorted(old_sels - new_sels),
        "added_opcodes": sorted(new_ops - old_ops),
        "removed_opcodes": sorted(old_ops - new_ops),
        "old_size": old_info.get("size", 0),
        "new_size": new_info.get("size", 0),
        "identical": (old_hex or "").lower() == (new_hex or "").lower(),
    }


def analyze_diff(old_hex: str, new_hex: str) -> List[Dict[str, Any]]:
    if not C.code_bytes(old_hex) or not C.code_bytes(new_hex):
        return []
    d = diff_bytecode(old_hex, new_hex)
    if d["identical"]:
        return []
    hits: List[Dict[str, Any]] = []
    for op in _WATCH:
        if op in d["added_opcodes"]:
            hits.append(C.hit(
                "bytecode_diff_dangerous_opcode_added",
                f"bytecode diff: the NEW code introduces {op}, "
                f"which the old code did not contain "
                f"(size {d['old_size']} -> {d['new_size']} bytes).",
                "high",
                f"Audit why the upgrade adds {op} before trusting "
                f"the new implementation.",
                opcode=op, diff=d, check="bytecode_diff"))
    if d["added_selectors"]:
        hits.append(C.hit(
            "bytecode_diff_selectors_added",
            f"bytecode diff: {len(d['added_selectors'])} new "
            f"function selector(s) appear in the new code: "
            f"{', '.join(d['added_selectors'][:6])}.",
            "medium",
            "Identify every new entry point in the diff and "
            "check its access control.",
            diff=d, check="bytecode_diff"))
    if d["removed_selectors"]:
        hits.append(C.hit(
            "bytecode_diff_selectors_removed",
            f"bytecode diff: {len(d['removed_selectors'])} "
            f"function selector(s) disappeared in the new code: "
            f"{', '.join(d['removed_selectors'][:6])}; integrators "
            f"calling them will break.",
            "low",
            "Confirm the removed functions are intentionally "
            "retired and notify integrators.",
            diff=d, check="bytecode_diff"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    old = new = ""
    for item in data["extras"].get("bytecode_pair", []):
        if isinstance(item, dict):
            old = str(item.get("old") or item.get("a") or "")
            new = str(item.get("new") or item.get("b") or "")
    for kind, slot in (("bytecode_old", "old"), ("bytecode_new", "new")):
        for item in data["extras"].get(kind, []):
            if isinstance(item, str):
                if slot == "old":
                    old = item
                else:
                    new = item
            elif isinstance(item, dict):
                v = item.get("bytecode") or item.get("code") or ""
                if slot == "old":
                    old = str(v)
                else:
                    new = str(v)
    return analyze_diff(old, new)


class BytecodeDiffViewerPlugin(Plugin):
    id = "bytecode_diff_viewer"
    label = "Bytecode Diff Viewer"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Two-input structural bytecode diff: added / "
                   "removed selectors and opcode classes between "
                   "two blobs (old vs new implementation, two "
                   "blocks, two addresses).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze,
            extras=("bytecode_pair", "bytecode_old", "bytecode_new"),
            source=False, bytecode=False,
            no_input="no bytecode pair supplied: diffing needs "
                     "bytecode_pair {old, new}")
