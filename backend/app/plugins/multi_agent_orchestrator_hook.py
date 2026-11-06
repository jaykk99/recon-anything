"""Multi-agent orchestrator hook (analysis of supplied configs/logs).

Does NOT run subagents. It analyzes a SUPPLIED orchestration config
(routes from finding classes to agent lanes) and/or dispatch log and
flags: finding classes with no route (routing gaps), routes pointing
at unknown lane/plugin ids, self-routing loops, routes missing their
required inputs, and expected lanes that never received a task
(unobserved loops). Pure routing analysis, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def analyze_orchestration(config: Any, findings: Any = None,
                          known_lanes: Any = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(config, dict):
        return rows
    routes = config.get("routes") if isinstance(config.get("routes"), dict) else {}
    lanes = config.get("lanes") if isinstance(config.get("lanes"), list) else []
    lane_ids = {str(x.get("id") if isinstance(x, dict) else x) for x in lanes}
    if isinstance(known_lanes, list):
        lane_ids |= {str(x) for x in known_lanes}
    required_inputs = config.get("required_inputs") if isinstance(
        config.get("required_inputs"), dict) else {}
    provided = config.get("provided_inputs") if isinstance(
        config.get("provided_inputs"), list) else []
    for cls, lane in routes.items():
        lane = str(lane)
        if lane == str(cls):
            rows.append({"key": "orchestration_self_loop",
                         "value": f"Route for class '{cls}' points at itself: "
                                  f"an unobserved infinite dispatch loop",
                         "severity": "high",
                         "evidence": {"class": str(cls), "lane": lane}})
        elif lane_ids and lane not in lane_ids:
            rows.append({"key": "orchestration_unknown_lane",
                         "value": f"Route for class '{cls}' targets unknown "
                                  f"lane/plugin '{lane}': tasks would be "
                                  f"dispatched into the void",
                         "severity": "high",
                         "evidence": {"class": str(cls), "lane": lane}})
        for need in required_inputs.get(cls, []) or []:
            if need not in provided:
                rows.append({"key": "orchestration_missing_input",
                             "value": f"Route for class '{cls}' requires input "
                                      f"'{need}' which the plan does not provide",
                             "severity": "medium",
                             "evidence": {"class": str(cls), "input": str(need)}})
    if isinstance(findings, list):
        classes = set()
        for f in findings:
            if isinstance(f, dict):
                classes.add(str(f.get("category") or f.get("key") or ""))
        for cls in sorted(c for c in classes if c and c not in routes):
            rows.append({"key": "orchestration_routing_gap",
                         "value": f"Finding class '{cls}' has no route in the "
                                  f"orchestration config: no specialist will "
                                  f"ever pick it up",
                         "severity": "medium", "evidence": {"class": cls}})
    dispatched = config.get("dispatched_lanes")
    if isinstance(dispatched, list):
        for lane in lane_ids:
            if lane and lane not in [str(d) for d in dispatched]:
                rows.append({"key": "orchestration_lane_never_dispatched",
                             "value": f"Lane '{lane}' is declared but never "
                                      f"received a task in the supplied log",
                             "severity": "low", "evidence": {"lane": lane}})
    return rows


class MultiAgentOrchestratorHookPlugin(Plugin):
    id = "multi_agent_orchestrator_hook"
    label = "Multi-Agent Orchestrator Hook"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Audit a supplied orchestration config/log: routing gaps, "
                   "unknown lanes, self-loops, missing inputs, idle lanes.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            cfg = ctx.consume("orchestration_config")
            rows = analyze_orchestration(cfg[0] if cfg else None,
                                         ctx.consume("findings"))
        except Exception as exc:
            return self._degraded(f"orchestration audit failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Orchestrator audit",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Fix the route/lane/input named "
                                             "in the finding, then re-audit "
                                             "the config.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"orchestration rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
