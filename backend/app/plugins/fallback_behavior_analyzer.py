"""Fallback Behavior Analyzer (Cat-1 #28, VARIANT of
fallback_state_write_extended).

Delta: a behavioral MAP of the fallback / receive path - what
happens on unstructured or unknown calldata - combining source
analysis with supplied read-only eth_call probe results
(fallback_probes records {selector, reverted, returned_bytes,
value_accepted}, gathered value-0 from an unfunded caller by the
contract_simulation lane):

- fallback delegatecalls onward (proxy-style catch-all) with no
  admin routing -> high;
- fallback/receive writes state beyond a plain payable credit;
- fallback silently accepts value with no event / accounting;
- probes show an unknown selector returning success + data
  (catch-all forwarder behaviour confirmed at read-only level).

A receive() that only emits an event, and a fallback that simply
reverts, stay silent.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_WRITE = re.compile(r"([A-Za-z_]\w*)\s*(?:\+=|-=|=(?!=)|\+\+|--)")


def analyze_fallback(source: str,
                     probes: Optional[List[Dict[str, Any]]] = None
                     ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    src = source or ""
    state = {v["name"] for v in C.state_vars(src)} if src else set()
    for f in C.functions(src):
        if f["name"] not in ("fallback", "receive"):
            continue
        body = f["body"]
        if "delegatecall" in body:
            hits.append(C.hit(
                "fallback_delegatecall_catchall",
                f"{f['name']}() delegatecalls onward: any unknown "
                f"calldata is executed by foreign code in this "
                f"contract's context - the fallback IS the "
                f"dispatch for everything unlisted.",
                "high",
                "Route the fallback explicitly, gate admin "
                "functions, and pin the delegate target.",
                function=f["name"], check="fallback_behavior"))
        writes = {w for w in _WRITE.findall(body) if w in state}
        if writes:
            hits.append(C.hit(
                "fallback_state_write_map",
                f"{f['name']}() writes state "
                f"({', '.join(sorted(writes))}) on unstructured "
                f"calldata: plain ETH transfers or junk calls "
                f"mutate contract state.",
                "medium",
                "Keep receive/fallback free of state writes "
                "beyond a simple payable credit, or gate them.",
                function=f["name"], writes=sorted(writes),
                check="fallback_behavior"))
        payable = "payable" in f["mods"] or "payable" in f["header"]
        if payable and "emit " not in body and not writes \
                and "delegatecall" not in body and len(body.strip()) < 8:
            hits.append(C.hit(
                "fallback_silent_value_accept",
                f"{f['name']}() silently accepts ETH value with "
                f"no event and no accounting: funds sent here are "
                f"invisible to off-chain bookkeeping.",
                "low",
                "Emit an event (or record a credit) on every "
                "value-accepting fallback/receive.",
                function=f["name"], check="fallback_behavior"))
    for p in probes or []:
        if not isinstance(p, dict):
            continue
        if not p.get("reverted") and int(p.get("returned_bytes", 0)
                                         or 0) > 0:
            hits.append(C.hit(
                "fallback_probe_catchall_success",
                f"read-only probe with unknown selector "
                f"{p.get('selector', '?')} returned success with "
                f"{p.get('returned_bytes')} bytes: the fallback "
                f"acts as a catch-all forwarder (probe was "
                f"value-0, unfunded caller).",
                "medium",
                "Confirm the catch-all behaviour is intended and "
                "its target is pinned.",
                selector=str(p.get("selector", "")),
                check="fallback_behavior"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    probes: List[Dict[str, Any]] = []
    for item in data["extras"].get("fallback_probes", []):
        if isinstance(item, dict) and isinstance(item.get("probes"), list):
            probes.extend(item["probes"])
        elif isinstance(item, dict):
            probes.append(item)
    return analyze_fallback(data.get("source", ""), probes)


class FallbackBehaviorAnalyzerPlugin(Plugin):
    id = "fallback_behavior_analyzer"
    label = "Fallback Behavior Analyzer"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Behavioral map of fallback/receive: "
                   "delegatecall catch-alls, state writes on "
                   "unstructured calldata, silent value acceptance, "
                   "plus read-only unknown-selector probe results.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze,
            extras=("fallback_probes",), fetch=True, bytecode=False,
            no_input="no source or fallback probe results to map")
