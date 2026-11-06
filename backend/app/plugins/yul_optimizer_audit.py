"""Yul Optimizer Audit (Cat-1 #24, VARIANT of the assembly detectors).

Delta: a standalone Yul / inline-assembly audit beyond the three
named literal patterns the deep-audit detectors cover. It parses
assembly blocks (Solidity `assembly { ... }` or a raw Yul artifact)
and taint-tracks calldata / call results into memory and storage:

- calldataload-derived value reaching sstore / mstore with no
  bounds guard (revert / range check) earlier in the same block;
- returndatacopy sized by returndatasize() with no cap (unbounded
  copy into fixed memory);
- a `call` whose target or value comes straight from calldata;
- direct writes to the free-memory pointer slot 0x40 with a
  calldata-derived value.

Guarded flows (a range check + revert precedes the write) stay
silent.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_GUARD = re.compile(r"revert\s*\(|if\s+(?:gt|lt|eq|iszero)|"
                    r"switch|case\s", re.I)


def extract_yul_blocks(source: str) -> List[str]:
    src = source or ""
    blocks: List[str] = []
    for m in re.finditer(r"assembly\s*(?:\"[^\"]*\")?\s*\{", src):
        blocks.append(C._body_at(src, m.end() - 1))
    if not blocks and re.search(r"\bobject\s+\"|\bcode\s*\{|"
                                r"datacopy|calldataload", src):
        blocks.append(src)  # raw Yul artifact
    return blocks


def _tainted_vars(block: str) -> set:
    out = set()
    for m in re.finditer(
            r"let\s+(\w+)\s*:=.*?(calldataload|callvalue|caller\s*\()",
            block):
        out.add(m.group(1))
    return out


def audit_yul(source: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for block in extract_yul_blocks(source):
        tainted = _tainted_vars(block)
        # unbounded returndatacopy
        if re.search(r"returndatacopy\s*\([^)]*returndatasize\s*\(",
                     block):
            hits.append(C.hit(
                "yul_unbounded_returndatacopy",
                "assembly copies returndata with a "
                "returndatasize()-derived length and no cap: a "
                "callee can force an oversized copy over memory.",
                "medium",
                "Cap the copy length and check returndatasize "
                "against the destination buffer first.",
                pattern="returndatacopy", check="yul_audit"))
        # tainted flows into storage/memory writes
        for m in re.finditer(r"(sstore|mstore)\s*\(([^)]*)\)", block):
            args = m.group(2)
            used = [v for v in tainted
                    if re.search(rf"\b{re.escape(v)}\b", args)] \
                or (["calldataload"] if "calldataload" in args else [])
            if not used:
                continue
            before = block[max(0, m.start() - 600):m.start()]
            if _GUARD.search(before) and re.search(
                    r"(gt|lt|iszero|revert)", before):
                continue  # a guard precedes the write in this block
            hits.append(C.hit(
                "yul_calldata_taint_write",
                f"calldata-derived value ({', '.join(used)}) flows "
                f"into {m.group(1)} with no bounds guard earlier "
                f"in the assembly block: raw calldata controls a "
                f"{'storage' if m.group(1) == 'sstore' else 'memory'} "
                f"write.",
                "high" if m.group(1) == "sstore" else "medium",
                "Range-check calldata-derived values (and revert "
                "out of range) before any tainted sstore/mstore.",
                sink=m.group(1), tainted=used, check="yul_audit"))
        # call with calldata-derived target/value
        m = re.search(r"\bcall\s*\(([^)]*calldataload[^)]*)\)", block)
        if m:
            hits.append(C.hit(
                "yul_call_calldata_target",
                "assembly call() takes its target/value straight "
                "from calldata: an arbitrary-call primitive inside "
                "hand-written assembly.",
                "high",
                "Pin call targets in assembly and validate "
                "calldata-derived call parameters.",
                pattern="call_calldata", check="yul_audit"))
        if re.search(r"mstore\s*\(\s*0x40\s*,\s*calldataload", block):
            hits.append(C.hit(
                "yul_fmp_calldata_write",
                "free-memory pointer (0x40) is written from "
                "calldata: memory-layout corruption primitive.",
                "high",
                "Never derive the free-memory pointer from "
                "calldata.",
                pattern="fmp_calldata", check="yul_audit"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return audit_yul(data.get("source", ""))


class YulOptimizerAuditPlugin(Plugin):
    id = "yul_optimizer_audit"
    label = "Yul Optimizer Audit"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Standalone Yul / inline-assembly audit: "
                   "taint-tracks calldata and call results into "
                   "memory/storage writes and flags injection-"
                   "shaped flows and unbounded returndatacopy.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, bytecode=False,
            no_input="no source with assembly / Yul blocks to audit")
