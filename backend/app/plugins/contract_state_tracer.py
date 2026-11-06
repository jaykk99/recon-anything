"""Contract State Tracer (Cat-1 #3, VARIANT of storage_state_analysis).

Delta: the historic dimension. Given slot samples - the same
storage slot read with eth_getStorageAt at several blocks (supplied
on the discovery bus as storage_samples / state_trace records of
{block, slot, value, label?}, e.g. collected by an upstream lane) -
it diffs each slot across the block range and reports changes,
with privileged slots (owner / implementation / admin labelled, or
the EIP-1967 slots) raised to high. Single-point reads are the
covering plugin's job; this one only speaks when a value actually
changed over time. Degrades honestly: no samples, no claim.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_EIP1967_IMPL = ("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a"
                 "920a3ca505d382bbc")
_PRIV_WORDS = ("owner", "implementation", "admin", "beacon")


def _norm(v: Any) -> str:
    return str(v or "").strip().lower()


def trace_slot_changes(samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_slot: Dict[str, List[Dict[str, Any]]] = {}
    for s in samples or []:
        if not isinstance(s, dict):
            continue
        slot = _norm(s.get("slot") or s.get("key") or "")
        if not slot:
            continue
        by_slot.setdefault(slot, []).append(s)
    hits: List[Dict[str, Any]] = []
    for slot, rows in by_slot.items():
        rows = sorted(rows, key=lambda r: int(r.get("block", 0) or 0))
        values = [_norm(r.get("value")) for r in rows]
        distinct = []
        for v in values:
            if not distinct or distinct[-1] != v:
                distinct.append(v)
        if len(distinct) < 2:
            continue
        label = str(rows[0].get("label") or "")
        priv = any(p in label.lower() for p in _PRIV_WORDS) or \
            slot.replace("0x", "").endswith(_EIP1967_IMPL[-16:])
        hits.append(C.hit(
            "contract_state_slot_changed",
            f"storage slot {slot[:18]}... ({label or 'unlabelled'}) "
            f"changed {len(distinct) - 1} time(s) between block "
            f"{rows[0].get('block')} and {rows[-1].get('block')}: "
            f"{distinct[0][:20]}... -> {distinct[-1][:20]}...",
            "high" if priv else "medium",
            "Review who authorized this state change; privileged "
            "slot changes over time are the on-chain footprint of "
            "ownership / implementation rotation and must match "
            "governance records.",
            slot=slot, label=label, blocks=[r.get("block") for r in rows],
            distinct_values=len(distinct), check="state_tracer"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    samples: List[Dict[str, Any]] = []
    for kind in ("storage_samples", "state_trace"):
        for item in data["extras"].get(kind, []):
            if isinstance(item, dict) and isinstance(item.get("samples"), list):
                samples.extend(item["samples"])
            elif isinstance(item, dict):
                samples.append(item)
            elif isinstance(item, list):
                samples.extend(x for x in item if isinstance(x, dict))
    return trace_slot_changes(samples)


class ContractStateTracerPlugin(Plugin):
    id = "contract_state_tracer"
    label = "Contract State Tracer"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Historic storage tracing: diffs the same "
                   "storage slots across a block range and reports "
                   "slot changes over time, privileged slots first.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze,
            extras=("storage_samples", "state_trace"),
            source=False, bytecode=False,
            no_input="no multi-block storage samples supplied: "
                     "historic tracing needs slot samples at 2+ blocks")
