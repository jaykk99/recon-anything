"""Purpleteam-style builder-focused test orchestration (Tier-5).

Purpleteam runs security tests the way a builder thinks about an
app: grouped by LAYER (frontend / API / infrastructure), executed as
a test plan, and reported as a per-layer posture - pass, warn or
fail - that a developer can act on without reading raw scanner
output.

This plugin executes a layer-grouped plan of EXISTING plugins
through the shared orchestration engine and grades each layer from
the composed findings' severities: FAIL when a layer produced a
high-severity finding, WARN on medium/low findings, PASS when the
layer's checks ran and found nothing. The plan is configurable via
ctx.shared["purpleteam_plan"] ({layer: [plugin_id, ...]}); the
default plan uses only keyless plugins already on master.

Only layers with something to say produce findings (the posture
report itself is emitted when any layer warns or fails) - a fully
passing plan is silent, so a clean target gets no report noise.
Distinct from a vuln scanner: no new checks live here, the value is
the layering, the grading and the builder-readable report.
"""
from __future__ import annotations

import time
from typing import Dict, List

from ..classifier import domain_from_target
from ._orchestration import collect_findings, override_for, \
    run_downstream, severity_of
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DEFAULT_PLAN: Dict[str, List[str]] = {
    "frontend": ["headers", "clickjack"],
    "api": ["cors"],
    "infra": ["tls"],
}

_GRADE_ORDER = {"pass": 0, "warn": 1, "fail": 2}


class PurpleteamTestPlanPlugin(Plugin):
    id = "purpleteam_test_plan"
    label = "Purpleteam Layered Test Plan"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    phase = 2
    timeout_s = 120
    description = ("Runs a test plan of existing checks grouped by "
                   "app layer (frontend/API/infra) and emits a "
                   "pass/warn/fail posture report per layer.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        raw_plan = override_for(ctx, "purpleteam_plan")
        plan: Dict[str, List[str]] = {}
        if isinstance(raw_plan, dict) and raw_plan:
            for layer, ids in raw_plan.items():
                if isinstance(ids, (list, tuple)) and ids:
                    plan[str(layer)] = [str(i) for i in ids]
        if not plan:
            plan = dict(DEFAULT_PLAN)

        findings: List[Finding] = []
        posture: Dict[str, Dict] = {}
        worst = "pass"
        for layer, ids in plan.items():
            records = await run_downstream(ctx, target, ids, cap=6)
            found = collect_findings(records)
            findings.extend(found)
            grade = "pass"
            for f in found:
                sev = severity_of(f)
                if sev == "high":
                    grade = "fail"
                elif grade == "pass":
                    grade = "warn"
            posture[layer] = {
                "grade": grade, "checks": ids,
                "statuses": {r["id"]: r["status"] for r in records},
                "findings": len(found),
                "high": sum(1 for f in found if severity_of(f) == "high"),
            }
            if _GRADE_ORDER[grade] > _GRADE_ORDER[worst]:
                worst = grade
            self._checkpoint(findings)
        if worst == "pass":
            res = self._ok([], "purpleteam plan: all layers pass")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        for layer, info in posture.items():
            if info["grade"] == "pass":
                continue
            findings.append(self._f(
                "web", "layer_posture",
                f"Layer '{layer}' posture: {info['grade'].upper()} - "
                f"{info['findings']} findings "
                f"({info['high']} high) from checks "
                f"{', '.join(info['checks'])}",
                source="purpleteam_test_plan", confidence=90,
                evidence={"severity": "high" if info["grade"] == "fail"
                                      else "medium",
                          "layer": layer, "grade": info["grade"],
                          "checks": info["checks"],
                          "finding_count": info["findings"],
                          "remediation": "Fix this layer's findings "
                                         "first, then re-run the plan; "
                                         "the layer grade only clears "
                                         "when its checks come back "
                                         "clean."}))
        findings.append(self._f(
            "web", "purpleteam_posture_report",
            f"Purpleteam posture for {domain}: overall "
            f"{worst.upper()} - "
            + ", ".join(f"{k}={v['grade']}" for k, v in posture.items()),
            source="purpleteam_test_plan", confidence=90,
            evidence={"severity": "high" if worst == "fail" else "medium",
                      "posture": posture, "overall": worst,
                      "remediation": "Treat FAIL layers as release "
                                     "blockers and WARN layers as "
                                     "tracked debt; re-run the plan "
                                     "after fixes."}))
        res = self._ok(findings, f"purpleteam posture: {worst} "
                                 f"({len(findings)} findings)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
