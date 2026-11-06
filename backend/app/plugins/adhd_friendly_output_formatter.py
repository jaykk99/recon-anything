"""ADHD-friendly output formatter (report-formatting plugin).

Audits a supplied findings set for overload: more findings than a
top-action list can hold (7), or a high-severity finding buried below
low-severity noise in presentation order. When overloaded it emits the
condensed format as a finding: top actions first, one line each
(asset, problem, fix), the rest collapsed into a counted tail. Counts
always reconcile with the full set; nothing is silently dropped.
Pure local formatting, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

TOP_N = 7
_SEV_RANK = {"high": 0, "critical": 0, "medium": 1, "low": 2}


def _sev(f: Dict[str, Any]) -> str:
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    return str(f.get("severity") or ev.get("severity") or "low").lower()


def format_actions(findings: List[Dict[str, Any]]) -> List[str]:
    ordered = sorted((f for f in findings if isinstance(f, dict)),
                     key=lambda f: _SEV_RANK.get(_sev(f), 2))
    lines = []
    for f in ordered[:TOP_N]:
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        fix = str(ev.get("remediation") or "review and fix")[:60]
        lines.append(f"{f.get('value', f.get('key', 'finding'))} -> {fix}")
    return lines


def analyze_output_load(findings: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(findings, list):
        return rows
    items = [f for f in findings if isinstance(f, dict)]
    if len(items) <= TOP_N and all(
            _SEV_RANK.get(_sev(items[i]), 2) <= _SEV_RANK.get(_sev(items[i + 1]), 2)
            for i in range(len(items) - 1)):
        return rows  # small and already severity-ordered: nothing to fix
    actions = format_actions(items)
    buried = [str(f.get("key")) for i, f in enumerate(items)
              if _sev(f) == "high" and i >= TOP_N]
    rows.append({"key": "output_condensed_format",
                 "value": f"Report has {len(items)} findings: condensed to "
                          f"{len(actions)} top actions + a counted tail of "
                          f"{max(0, len(items) - len(actions))} (counts "
                          f"reconcile, nothing dropped)",
                 "severity": "medium" if buried else "low",
                 "evidence": {"top_actions": actions,
                              "total_findings": len(items),
                              "tail_count": max(0, len(items) - len(actions)),
                              "buried_high": buried}})
    return rows


class AdhdFriendlyOutputFormatterPlugin(Plugin):
    id = "adhd_friendly_output_formatter"
    label = "ADHD-Friendly Output Formatter"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Condense overloaded findings sets: top-7 actions first, "
                   "one line each, counted tail; flag buried high severity.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_output_load(ctx.consume("findings"))
        except Exception as exc:
            return self._degraded(f"formatter failed: {exc}")
        findings: List[Finding] = [
            self._f("web", r["key"], r["value"], source="Output formatter",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Present the condensed top "
                                             "actions first; keep the full "
                                             "report behind the counted tail.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"formatter rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
