"""Step-by-step walkthrough builder (report-formatting plugin).

Consumes supplied findings and builds a per-finding walkthrough:
numbered steps (1 confirm the issue, 2 apply the fix from the
finding's remediation, 3 re-run the named plugin to verify), ordered
by severity. The walkthrough rides in the finding's evidence. A
finding with no remediation gets a gap finding instead, naming what
is missing. Pure local generation, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_SEV_RANK = {"high": 0, "critical": 0, "medium": 1, "low": 2}


def build_walkthrough(f: Dict[str, Any]) -> List[str]:
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    pid = str(f.get("plugin_id") or "the detecting plugin")
    fix = str(ev.get("remediation") or "")
    return [f"1. Confirm: reproduce the finding '{f.get('key', 'issue')}' "
            f"on the target.",
            f"2. Fix: {fix}",
            f"3. Verify: re-run plugin '{pid}' and confirm the finding "
            f"no longer fires."]


def analyze_walkthroughs(findings: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(findings, list):
        return rows
    items = [f for f in findings if isinstance(f, dict)]

    def _rank(f: Dict[str, Any]) -> int:
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        sev = str(ev.get("severity") or f.get("severity") or "low").lower()
        return _SEV_RANK.get(sev, 2)

    items.sort(key=_rank)
    for f in items:
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        if not ev.get("remediation"):
            rows.append({"key": "walkthrough_missing_remediation",
                         "value": f"Finding '{f.get('key', '?')}' has no "
                                  f"remediation, so no fix walkthrough can "
                                  f"be built for it",
                         "severity": "medium",
                         "evidence": {"finding_key": str(f.get("key", ""))}})
        else:
            rows.append({"key": "fix_walkthrough",
                         "value": f"Walkthrough for '{f.get('key', '?')}': "
                                  f"confirm, fix, re-run "
                                  f"'{f.get('plugin_id', '?')}' to verify",
                         "severity": "low",
                         "evidence": {"finding_key": str(f.get("key", "")),
                                      "steps": build_walkthrough(f)}})
    return rows


class StepByStepWalkthroughBuilderPlugin(Plugin):
    id = "step_by_step_walkthrough_builder"
    label = "Step-by-Step Walkthrough Builder"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Build per-finding fix walkthroughs (confirm, fix, "
                   "re-run the named plugin to verify), severity ordered.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_walkthroughs(ctx.consume("findings"))
        except Exception as exc:
            return self._degraded(f"walkthrough build failed: {exc}")
        findings: List[Finding] = [
            self._f("web", r["key"], r["value"], source="Walkthrough builder",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Follow the steps in order; "
                                             "the verify step names the "
                                             "plugin to re-run.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"walkthrough rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
