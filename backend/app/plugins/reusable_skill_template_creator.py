"""Reusable skill template creator (over supplied run history).

Converts supplied completed scan runs that produced verified findings
into reusable parameterized templates: named stages, the plugin
sequence, parameters (target placeholder, never a hardcoded real
target), and expected finding classes. The template artifact rides in
the finding's evidence. Pure local generation, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def build_template(run: Dict[str, Any]) -> Dict[str, Any] | None:
    if not isinstance(run, dict):
        return None
    verified = run.get("verified_findings")
    if not isinstance(verified, list) or not verified:
        return None
    stages = run.get("stages") or run.get("plugin_sequence") or []
    if not isinstance(stages, list) or not stages:
        return None
    classes = sorted({str(f.get("key") or f.get("category"))
                      for f in verified if isinstance(f, dict)})
    return {"name": str(run.get("name") or "scan-template"),
            "parameters": {"target": "{{target}}",
                           "mode": str(run.get("mode") or "passive")},
            "stages": [str(s) for s in stages],
            "expected_finding_classes": classes,
            "source_verified_count": len(verified)}


def analyze_templates(runs: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(runs, list):
        return rows
    for run in runs:
        tpl = build_template(run)
        if tpl is None:
            continue
        rows.append({"key": "skill_template_created",
                     "value": f"Reusable template '{tpl['name']}' created "
                              f"from a verified run: {len(tpl['stages'])} "
                              f"stages, expects {len(tpl['expected_finding_classes'])} "
                              f"finding classes (artifact in evidence)",
                     "severity": "low", "evidence": {"template": tpl}})
    return rows


class ReusableSkillTemplateCreatorPlugin(Plugin):
    id = "reusable_skill_template_creator"
    label = "Reusable Skill Template Creator"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Turn supplied verified scan runs into reusable "
                   "parameterized templates (stages, params, expected "
                   "finding classes).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_templates(ctx.consume("completed_runs"))
        except Exception as exc:
            return self._degraded(f"template creator failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Template creator",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Store the template with the "
                                             "run-plan templates so future "
                                             "runs can reuse it.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"templates: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
