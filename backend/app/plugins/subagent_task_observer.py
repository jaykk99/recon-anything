"""Subagent task observer (over supplied run telemetry).

Analyzes SUPPLIED plugin/subagent execution records (status, duration,
degraded reasons, lane). It does not run or spawn anything. Emits an
observer report as findings: repeatedly degraded workers, timed-out
or stalled tasks, and expected lanes that produced no records at all
(silent lanes). Pure logic over run data, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

STALL_MS = 55000


def analyze_observer(records: Any, expected_lanes: Any = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(records, list):
        records = []
    by_plugin: Dict[str, List[Dict[str, Any]]] = {}
    lanes_seen = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        pid = str(r.get("plugin_id") or r.get("id") or "?")
        by_plugin.setdefault(pid, []).append(r)
        if r.get("lane"):
            lanes_seen.add(str(r["lane"]))
        st = str(r.get("status", "")).lower()
        dur = r.get("duration_ms")
        if isinstance(dur, (int, float)) and dur >= STALL_MS:
            rows.append({"key": "worker_stalled",
                         "value": f"Worker '{pid}' ran {int(dur)}ms "
                                  f"(>= {STALL_MS}ms stall threshold)",
                         "severity": "medium", "evidence": {"plugin_id": pid}})
        if st in ("timeout", "timed_out"):
            rows.append({"key": "worker_timeout",
                         "value": f"Worker '{pid}' timed out: its surface "
                                  f"has no verified result this run",
                         "severity": "medium", "evidence": {"plugin_id": pid}})
    for pid, recs in by_plugin.items():
        bad = [r for r in recs if str(r.get("status", "")).lower()
               in ("degraded", "error", "failed", "timeout", "timed_out")]
        if len(recs) >= 2 and len(bad) >= 2:
            rows.append({"key": "worker_repeatedly_degraded",
                         "value": f"Worker '{pid}' degraded/failed {len(bad)} "
                                  f"of {len(recs)} executions: a repeating "
                                  f"failure, not a one-off",
                         "severity": "high", "evidence": {"plugin_id": pid,
                                                           "failures": len(bad)}})
    if isinstance(expected_lanes, list):
        for lane in expected_lanes:
            if str(lane) not in lanes_seen:
                rows.append({"key": "lane_silent",
                             "value": f"Lane '{lane}' produced no execution "
                                      f"records: an unobserved/silent lane",
                             "severity": "medium", "evidence": {"lane": str(lane)}})
    return rows


class SubagentTaskObserverPlugin(Plugin):
    id = "subagent_task_observer"
    label = "Subagent Task Observer"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Observe supplied worker execution records: flag stalled, "
                   "timed-out, repeatedly degraded workers and silent lanes.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_observer(ctx.consume("plugin_statuses"),
                                    ctx.consume("expected_lanes") or None)
        except Exception as exc:
            return self._degraded(f"observer failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Task observer",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Investigate the named worker/lane "
                                             "and add checkpointing so partial "
                                             "progress survives a stall.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"observer rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
