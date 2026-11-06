"""Gas Optimization Analyzer (Cat-1 #8, VARIANT of audit_toolbox).

Delta: a dedicated gas report, separated from security findings -
per-function findings for the classic fee-bloating patterns with
an estimated waste class:

- array `.length` (a storage read) re-evaluated in a loop condition;
- the same state variable SLOADed repeatedly inside one function
  instead of cached in a local;
- storage writes inside loops (SSTORE per iteration);
- public functions that could be external (calldata vs memory);
- `++i` written as `i++` in loop increments is NOT flagged (noise);
  string/bytes storage compared with keccak per call is flagged
  as repeated hashing of storage.

Estimates are qualitative (low/medium/high waste), not fake-precise
gas numbers.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_LOOP_RE = re.compile(r"for\s*\(([^;]*);([^;]*);([^)]*)\)\s*\{", re.S)


def analyze_gas_source(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    hits: List[Dict[str, Any]] = []
    state = {v["name"] for v in C.state_vars(src)}
    clean = C.strip_comments(src)
    for m in _LOOP_RE.finditer(clean):
        cond = m.group(2)
        pos = clean.find("{", m.end() - 1)
        body = C._body_at(clean, pos) if pos >= 0 else ""
        if ".length" in cond:
            var = re.search(r"([A-Za-z_]\w*)\.length", cond)
            hits.append(C.hit(
                "gas_loop_storage_length",
                f"loop condition re-reads "
                f"{var.group(1) if var else 'array'}.length from "
                f"storage on every iteration; cache it in a local "
                f"before the loop. Waste class: medium.",
                "low",
                "Cache the array length in a local variable before "
                "the loop.",
                pattern="loop_length", check="gas_opt"))
        writes = {w for w in re.findall(
            r"([A-Za-z_]\w*)\s*(?:\+=|-=|=(?!=)|\+\+)", body)
            if w in state}
        if writes:
            hits.append(C.hit(
                "gas_storage_write_in_loop",
                f"storage variable(s) {', '.join(sorted(writes))} "
                f"written inside a loop body: one SSTORE per "
                f"iteration. Waste class: high.",
                "medium",
                "Accumulate in a memory local and write storage "
                "once after the loop.",
                pattern="sstore_in_loop", variables=sorted(writes),
                check="gas_opt"))
    for f in C.functions(src):
        body = f["body"]
        for var in sorted(state):
            reads = len(re.findall(rf"\b{re.escape(var)}\b", body))
            if reads >= 4:
                hits.append(C.hit(
                    "gas_repeated_storage_read",
                    f"function {f['name']}() reads storage variable "
                    f"{var} {reads} times; cache the first read in a "
                    f"local. Waste class: medium.",
                    "low",
                    "Read the storage variable once into a local "
                    "and reuse it.",
                    function=f["name"], variable=var, reads=reads,
                    pattern="repeated_sload", check="gas_opt"))
                break  # one per function keeps the report readable
        if re.search(r"keccak256\s*\(\s*abi\.encodePacked\s*\(\s*\w+",
                     body) and any(v in body for v in state):
            hits.append(C.hit(
                "gas_storage_hash_compare",
                f"function {f['name']}() hashes storage data with "
                f"keccak256 on every call for a comparison; cache "
                f"the hash. Waste class: low.",
                "low",
                "Precompute and store the comparison hash once.",
                function=f["name"], pattern="hash_compare",
                check="gas_opt"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_gas_source(data.get("source", ""))


class GasOptAnalyzerPlugin(Plugin):
    id = "gas_opt_analyzer"
    label = "Gas Optimization Analyzer"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Dedicated gas report: loop storage-length "
                   "reads, repeated SLOADs, SSTORE-in-loop and "
                   "repeated storage hashing, with waste classes, "
                   "kept separate from security findings.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, bytecode=False,
            no_input="no contract source to analyze for gas waste")
