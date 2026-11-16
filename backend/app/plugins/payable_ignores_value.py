"""Payable function ignoring msg.value / ETH with no withdrawal path
(r100 wave 1).

Solodit finding class: a `payable` function that never reads
`msg.value` lets a caller send ETH that the function silently ignores
- the ETH sits in the contract with no accounting for it. The
companion check flags contracts that can receive ETH (receive /
payable fallback) but have no code path that ever sends ETH out, so
anything received is locked forever.

CWE-404 (Improper Resource Shutdown or Release). Static source
detector; findings are candidates for triage, never VERIFIED_REAL
on their own.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_ETH_OUT_RE = re.compile(
    r"\.call\s*\{\s*value\s*:|\.transfer\s*\(|\.send\s*\(")


def find_payable_ignores_value(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    hits: List[Dict[str, Any]] = []
    for fn in C.functions(src):
        name = fn["name"]
        if name in ("constructor", "receive", "fallback"):
            continue
        mods = fn.get("mods") or ""
        if "payable" not in mods:
            continue
        body = fn.get("body") or ""
        if not body.strip():
            continue  # interface declaration, no body to judge
        if "msg.value" in body:
            continue
        hits.append(C.hit(
            "payable_ignores_msg_value",
            f"payable function {name}() never reads `msg.value` - a "
            f"caller can send ETH that the function silently ignores, "
            f"leaving the ETH unaccounted for in the contract.",
            "medium",
            "Either read `msg.value` (credit it, price against it) "
            "or drop `payable` so accidental ETH transfers revert "
            "instead of locking funds.",
            cwe="CWE-404", check="payable_ignores_msg_value",
            function=name))
    # Companion: can receive ETH but nothing ever sends it out.
    can_receive = bool(re.search(
        r"\breceive\s*\(\s*\)\s*external\s+payable\b", src)
        or re.search(r"\bfallback\s*\(\s*\)\s*external\s+payable\b", src))
    if can_receive and not _ETH_OUT_RE.search(src):
        hits.append(C.hit(
            "eth_no_withdrawal_path",
            "contract can receive ETH (payable receive/fallback) but "
            "no code path ever sends ETH out - anything received is "
            "locked in the contract with no way to recover it.",
            "medium",
            "Add an owner/guardian withdrawal path for received ETH, "
            "or remove the payable receive/fallback so ETH cannot "
            "arrive in the first place.",
            cwe="CWE-404", check="payable_ignores_msg_value"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return find_payable_ignores_value(data.get("source", ""))


class PayableIgnoresValuePlugin(Plugin):
    id = "payable_ignores_msg_value"
    label = "Payable Ignores msg.value"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Flags payable functions that never read msg.value "
                   "and contracts that can receive ETH with no "
                   "withdrawal path (CWE-404).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, stamp=False,
            bytecode=False,
            no_input="no contract source to check for ignored ETH")
