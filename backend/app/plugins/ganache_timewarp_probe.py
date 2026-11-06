"""Ganache Time-Warp Probe (Tier 9) - SIM-DERIVED, UNVERIFIED ONLY.

HARD RULE: simulation analysis only. Every finding carries
verdict=UNVERIFIED / sim_derived=True; never VERIFIED_REAL, never
proof. VERIFIED_REAL requires live-chain probes.

Coverage decision: a generic Ganache instant-chain plugin would be
a DUPLICATE of anvil_fork_probe (both spin a local EVM). The distinct
Ganache remainder is its signature simulation primitive set -
``evm_increaseTime`` / ``evm_snapshot`` / instant mining - i.e.
TIME AND BLOCK manipulation. This plugin analyzes the shape those
primitives exploit:

- a value release gated on ``block.timestamp >= <anchor>`` (or
  block.number) where <anchor> is a storage variable that a PUBLIC,
  UNGATED function can set - on any local chain (and via miner
  timestamp drift, within limits, live) a stranger warps time or
  moves the anchor and releases early;
- a value release gated on a timestamp anchor that is never
  assigned anywhere except its declaration default (0) - the gate
  is already open.

Gated setters, constructor-only anchors and releases that pay only
the caller's own recorded balance do not flag.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from . import contract_chain as cc
from .base import Cost, Plugin, PluginResult, Target, Ctx
from .forksim_util import is_gated, run_analyzer_plugin


def analyze_timewarp_source(source: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    clean = cc._strip_comments(source)
    fns = cc.extract_functions(clean)
    # storage anchors referenced in a time/block gate
    anchors: Dict[str, Dict[str, Any]] = {}
    for fn in fns:
        for m in re.finditer(
                r"(?:block\.timestamp|block\.number|now)\s*>=?\s*"
                r"([A-Za-z_][A-Za-z0-9_]*)", fn["text"]):
            anchors.setdefault(m.group(1), {"gated_fn": fn})
        for m in re.finditer(
                r"require\s*\(\s*(?:block\.timestamp|block\.number)"
                r"\s*>?=?\s*([A-Za-z_][A-Za-z0-9_]*)", fn["text"]):
            anchors.setdefault(m.group(1), {"gated_fn": fn})
    if not anchors:
        return hits
    # does the gated function move value to the caller?
    for anchor, info in anchors.items():
        gated_fn = info["gated_fn"]
        moves = bool(re.search(r"\.transfer\(|\.call\{value|payable\(",
                               gated_fn["text"]))
        own_only = bool(re.search(r"\[\s*msg\.sender\s*\]", gated_fn["text"])) \
            and "address(this).balance" not in gated_fn["text"]
        if not moves or own_only:
            continue
        # who can write the anchor?
        ungated_setter = None
        assigned = False
        for fn in fns:
            if fn["name"] == "constructor":
                if re.search(rf"\b{re.escape(anchor)}\s*=", fn["text"]):
                    assigned = True
                continue
            if re.search(rf"\b{re.escape(anchor)}\s*(\+?=|=\s)", fn["text"]) \
                    and re.search(rf"\b{re.escape(anchor)}\b", fn["text"]):
                if re.search(rf"\b{re.escape(anchor)}\s*[+\-*/]?=", fn["text"]):
                    assigned = True
                    if not is_gated(fn["text"], fn["signature"]) and \
                            re.search(r"\b(public|external)\b", fn["signature"]):
                        ungated_setter = fn["name"]
        if ungated_setter:
            hits.append({
                "key": "ganache_timewarp_anchor_settable",
                "severity": "high", "check": "time_anchor_public_setter",
                "function": gated_fn["name"],
                "detail": (f"Time-warp shape: '{gated_fn['name']}' "
                           f"releases value when block time passes "
                           f"'{anchor}', but '{ungated_setter}' sets "
                           f"'{anchor}' with no access gate. In "
                           f"Ganache/Anvil simulation (evm_increaseTime "
                           f"/ anchor move) a stranger releases early; "
                           f"live impact still needs live validation."),
                "confidence": 68})
        elif not assigned:
            hits.append({
                "key": "ganache_timewarp_anchor_unset",
                "severity": "medium", "check": "time_anchor_never_set",
                "function": gated_fn["name"],
                "detail": (f"Time-warp shape: '{gated_fn['name']}' "
                           f"releases value gated on '{anchor}', but "
                           f"'{anchor}' is never assigned in the "
                           f"source (defaults to 0), so the time gate "
                           f"is open from deployment."),
                "confidence": 62})
    return hits


class GanacheTimewarpProbePlugin(Plugin):
    id = "ganache_timewarp_probe"
    label = "Ganache Time-Warp Probe (sim, UNVERIFIED)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Ganache-style time/block manipulation analysis "
                   "(evm_increaseTime class): value releases whose "
                   "time anchor is publicly settable or never set. "
                   "SIM-DERIVED, UNVERIFIED only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_analyzer_plugin(self, target, ctx,
                                         analyze_timewarp_source)
