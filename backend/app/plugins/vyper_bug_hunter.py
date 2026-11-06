"""Vyper Bug Hunter (300-expansion Cat-1 #20, SHIP).

First Vyper coverage in the registry: every other contract lane is
Solidity-only. Consumes Vyper source (Sourcify supports Vyper, or a
local .vy artifact supplied on the discovery bus / as the target)
plus the compiler version from the `# @version` pragma and flags:

- the Vyper reentrancy-lock compiler bug: versions 0.2.15, 0.2.16
  and 0.3.0-0.3.7 miscompiled the @nonreentrant lock (CVE-2023-46219
  class), so a contract in that range USING @nonreentrant is
  reported high;
- unsafe raw_call with a caller-controlled target;
- value-moving external functions with no @nonreentrant coverage
  that make external calls;
- blockhash / block.timestamp dependence for value decisions.

Keyless, pure-Python static analysis, no chain writes.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_VULN_LOCK_RANGES = [((0, 2, 15), (0, 2, 16)), ((0, 3, 0), (0, 3, 7))]
_REM = ("Upgrade the Vyper compiler past the affected range and "
        "redeploy; the deployed bytecode carries the miscompiled "
        "reentrancy lock and cannot be patched in place.")


def vyper_version(source: str) -> tuple:
    m = re.search(r"@version\s+(\d+)\.(\d+)\.(\d+)", source or "")
    if not m:
        m = re.search(r"pragma\s+vyper\s+(\d+)\.(\d+)\.(\d+)", source or "")
    return tuple(int(x) for x in m.groups()) if m else ()


def analyze_vyper_source(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    hits: List[Dict[str, Any]] = []
    ver = vyper_version(src)
    ver_s = ".".join(map(str, ver)) if ver else "unknown"
    uses_lock = "@nonreentrant" in src
    if ver and uses_lock and any(lo <= ver <= hi for lo, hi in
                                 _VULN_LOCK_RANGES):
        hits.append(C.hit(
            "vyper_reentrancy_lock_compiler_bug",
            f"Vyper {ver_s} is in the compiler range whose "
            f"@nonreentrant lock was miscompiled (0.2.15/0.2.16, "
            f"0.3.0-0.3.7); the lock does not actually block "
            f"re-entry on the affected key, so functions relying "
            f"on it can be re-entered.",
            "high", _REM, vyper_version=ver_s, check="vyper_lock_bug"))
    # raw_call with caller-controlled target
    for m in re.finditer(r"raw_call\s*\(\s*([A-Za-z_][\w\.]*)", src):
        tgt = m.group(1)
        window = src[max(0, m.start() - 400):m.start()]
        if tgt in ("msg.sender",) or re.search(
                rf"def\s+\w+\([^)]*\b{re.escape(tgt)}\b", window + src[:m.start()]):
            hits.append(C.hit(
                "vyper_raw_call_user_target",
                f"raw_call target '{tgt}' is caller-controlled; an "
                f"attacker can point the call at any contract with "
                f"the contract's value/context.",
                "high",
                "Never raw_call a caller-supplied address with value; "
                "pin targets in storage set by governance.",
                check="vyper_raw_call"))
    if "raw_call(" in src and not hits:
        # raw_call carrying value at all deserves a look when target
        # is an argument of the enclosing function
        if re.search(r"raw_call\([^)]*value\s*=", src, re.S):
            hits.append(C.hit(
                "vyper_raw_call_value",
                "raw_call forwards value; verify the target is not "
                "reachable from calldata and the call is reentrancy-"
                "guarded.",
                "medium",
                "Restrict raw_call targets and add @nonreentrant.",
                check="vyper_raw_call"))
    # value-moving externals without lock that call out
    for m in re.finditer(
            r"@external[^\n]*\n(?:@payable[^\n]*\n|@nonreentrant[^\n]*\n)*"
            r"def\s+(\w+)\s*\(([^)]*)\)[^:]*:(.*?)(?=\n@|\nclass |\Z)",
            src, re.S):
        name, body = m.group(1), m.group(3)
        seg_start = src.rfind("@external", 0, m.end())
        seg = src[seg_start:m.end()] if seg_start >= 0 else ""
        calls_out = ("raw_call(" in body or ".transfer(" in body
                     or "send(" in body)
        moves_value = "@payable" in seg or "msg.value" in body \
            or "value=" in body
        if calls_out and moves_value and "@nonreentrant" not in seg:
            hits.append(C.hit(
                "vyper_unguarded_value_call",
                f"external function {name}() moves value / calls out "
                f"with no @nonreentrant lock.",
                "medium",
                "Add @nonreentrant to value-moving externals that "
                "make external calls.",
                function=name, check="vyper_nonreentrant_coverage"))
    if re.search(r"block\.timestamp|blockhash\s*\(", src) and re.search(
            r"(rand|winner|lottery|seed|%|>)", src):
        hits.append(C.hit(
            "vyper_block_value_dependence",
            "Value/outcome logic depends on block.timestamp or "
            "blockhash, which validators can influence.",
            "medium",
            "Do not derive value decisions from block values; use "
            "a commit-reveal or VRF design.",
            check="vyper_block_dependence"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_vyper_source(data.get("source", ""))


class VyperBugHunterPlugin(Plugin):
    id = "vyper_bug_hunter"
    label = "Vyper Bug Hunter"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Vyper source analysis: the 0.2.15/0.2.16 and "
                   "0.3.0-0.3.7 @nonreentrant compiler bug, unsafe "
                   "raw_call targets, unguarded value-moving "
                   "externals, and block-value dependence.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True,
            no_input="no Vyper source to analyze: supply Vyper "
                     "source or a contract with verified Vyper source")
