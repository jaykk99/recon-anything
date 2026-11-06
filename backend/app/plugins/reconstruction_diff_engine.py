"""Reconstruction diff engine (variant of app diff.py/delta.py).

Run-vs-run finding diffing already exists at app level. This plugin's
delta: component-vs-clean-build functional diff. It compares a supplied
clean reference (per-component expected behaviors) against the current
observed component state and reports matched / drifted / missing
behaviors per component, plus behaviors present in the current build
that the reference does not declare. Pure analysis, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _behaviors(comp: Any) -> set:
    if not isinstance(comp, dict):
        return set()
    b = comp.get("behaviors") or comp.get("functions") or []
    return {str(x).strip() for x in b if str(x).strip()} if isinstance(b, list) else set()


def analyze_reconstruction(reference: Any, current: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(reference, list) or not isinstance(current, list):
        return rows
    cur = {str(c.get("name")): c for c in current if isinstance(c, dict) and c.get("name")}
    for ref in reference:
        if not isinstance(ref, dict) or not ref.get("name"):
            continue
        name = str(ref["name"])
        if name not in cur:
            rows.append({"key": "component_missing",
                         "value": f"Component '{name}' exists in the clean "
                                  f"reference but is missing from the current build",
                         "severity": "high", "evidence": {"component": name}})
            continue
        want, have = _behaviors(ref), _behaviors(cur[name])
        for b in sorted(want - have):
            rows.append({"key": "behavior_missing",
                         "value": f"Component '{name}' lost behavior '{b}' "
                                  f"vs the clean reference (functional drift)",
                         "severity": "medium",
                         "evidence": {"component": name, "behavior": b}})
        for b in sorted(have - want):
            rows.append({"key": "behavior_undeclared",
                         "value": f"Component '{name}' has behavior '{b}' "
                                  f"that the clean reference does not declare",
                         "severity": "medium",
                         "evidence": {"component": name, "behavior": b}})
    return rows


class ReconstructionDiffEnginePlugin(Plugin):
    id = "reconstruction_diff_engine"
    label = "Reconstruction Diff Engine"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Component-vs-clean-build functional diff: per-component "
                   "matched/drifted/missing behavior deltas.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            ref = ctx.consume("reference_components")
            cur = ctx.consume("current_components")
            rows = analyze_reconstruction(ref, cur)
        except Exception as exc:
            return self._degraded(f"reconstruction diff failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Reconstruction diff",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Reconcile the component with "
                                             "the clean reference: restore "
                                             "missing behavior or document "
                                             "the intentional change.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"reconstruction deltas: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
