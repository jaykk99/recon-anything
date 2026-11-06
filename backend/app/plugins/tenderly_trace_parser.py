"""Tenderly trace parser (Cat-4 SHIP).

Parses a Tenderly simulation/trace export (operator-supplied trace
JSON, or a public simulation payload referenced by the target) into
an action report: revert reason, the failing call frame, gas
hotspots, and state diffs - flagging the security-relevant outcomes:
reverts with informative reasons, state diffs that grant approvals or
move balances, and single calls burning outsized gas.

Keyless: supplied/public trace JSON parsed locally. No Tenderly
account, no simulation is executed by this plugin.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import artifact_dicts, parse_json_maybe, all_texts
from .base import Cost, Ctx, Plugin, PluginResult, Target

GAS_HOTSPOT_SHARE = 0.6


def _walk_calls(node: Any, out: List[Dict[str, Any]], depth: int = 0):
    if depth > 12 or len(out) > 400:
        return
    if isinstance(node, dict):
        if "call_type" in node or "function_selector" in node or \
                ("from" in node and "to" in node and "gas_used" in node):
            out.append(node)
        for v in node.values():
            _walk_calls(v, out, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _walk_calls(v, out, depth + 1)


def parse_trace(trace: Any) -> List[Dict[str, Any]]:
    """Pure: trace JSON (dict or JSON string) -> action-report hits."""
    hits: List[Dict[str, Any]] = []
    if isinstance(trace, str):
        trace = parse_json_maybe(trace)
    if not isinstance(trace, dict):
        return hits
    # Revert / error surfacing (several export shapes)
    err = (trace.get("error") or trace.get("revert_reason")
           or trace.get("revertReason"))
    status = str(trace.get("status") or "").lower()
    if err or status in ("false", "failed", "error", "reverted"):
        hits.append({"kind": "trace_reverted",
                     "revert_reason": str(err)[:200] if err else
                     "transaction reverted (no reason string)"})
    calls: List[Dict[str, Any]] = []
    _walk_calls(trace.get("call_trace") or trace.get("calls")
                or trace, calls)
    total_gas = 0
    for c in calls:
        try:
            total_gas += int(c.get("gas_used") or c.get("gasUsed") or 0)
        except (TypeError, ValueError):
            continue
    for c in calls:
        if c.get("error"):
            hits.append({"kind": "failing_call_frame",
                         "to": c.get("to"), "from": c.get("from"),
                         "error": str(c.get("error"))[:160],
                         "selector": c.get("function_selector")})
        try:
            g = int(c.get("gas_used") or c.get("gasUsed") or 0)
        except (TypeError, ValueError):
            g = 0
        if total_gas and g / total_gas >= GAS_HOTSPOT_SHARE and \
                len(calls) > 1:
            hits.append({"kind": "gas_hotspot",
                         "to": c.get("to"), "gas_used": g,
                         "share_pct": round(g / total_gas * 100, 1)})
    # State diffs: approvals / balance moves are the security signal.
    diffs = trace.get("state_diff") or trace.get("stateDiff") or []
    if isinstance(diffs, list):
        for d in diffs:
            if not isinstance(d, dict):
                continue
            raw = str(d).lower()
            if "allowance" in raw or "approve" in raw:
                hits.append({"kind": "state_diff_approval",
                             "contract": d.get("address")
                             or d.get("contract")})
            elif "balance" in raw:
                hits.append({"kind": "state_diff_balance_move",
                             "contract": d.get("address")
                             or d.get("contract")})
    return hits


class TenderlyTraceParserPlugin(Plugin):
    id = "tenderly_trace_parser"
    label = "Tenderly Trace Parser"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Parse supplied Tenderly trace JSON into revert "
                   "reasons, failing frames, gas hotspots and state "
                   "diffs (approvals / balance moves).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            traces: List[Any] = []
            for d in artifact_dicts(ctx):
                for key in ("trace", "tenderly_trace"):
                    if key in d:
                        traces.append(d[key])
                for tr in d.get("traces") or []:
                    traces.append(tr)
            for _w, text, _u in await all_texts(ctx, target):
                parsed = parse_json_maybe(text)
                if isinstance(parsed, dict) and (
                        "call_trace" in parsed or "state_diff" in parsed
                        or "revert_reason" in parsed):
                    traces.append(parsed)
            parsed_count = 0
            for trace in traces[:5]:
                hits = parse_trace(trace)
                if hits:
                    parsed_count += 1
                for hit in hits:
                    sev = {"trace_reverted": "medium",
                           "failing_call_frame": "medium",
                           "state_diff_approval": "high",
                           "state_diff_balance_move": "medium",
                           "gas_hotspot": "low"}.get(hit["kind"], "low")
                    findings.append(self._f(
                        "web3", f"tenderly_{hit['kind']}",
                        f"Tenderly trace: {hit['kind'].replace('_', ' ')}"
                        f" - {hit.get('revert_reason') or hit.get('error') or ''}"
                        f" {('contract ' + str(hit.get('contract'))) if hit.get('contract') else ''}"
                        .strip(),
                        source="tenderly trace parser", confidence=85,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Review the decoded trace "
                            "before relying on the simulated flow; "
                            "approval-granting state diffs in a "
                            "'read-only' simulation are a red flag."}))
            res = self._ok(findings,
                           f"{len(traces)} traces parsed"
                           if not findings else
                           f"{len(findings)} trace signals")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
