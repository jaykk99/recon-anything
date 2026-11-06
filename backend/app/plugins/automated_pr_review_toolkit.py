"""Automated PR review toolkit.

Reviews a SUPPLIED PR diff (it never pushes or comments). Findings:
registry-count pins that disagree with each other inside the diff,
new plugin files added without a matching test file, plugin style
deviations (missing description/label/group in added code), and
secret-shaped strings in the diff (evidence masked). Local diff
parsing, keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_SECRET_RX = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN (RSA |EC )?PRIVATE KEY-----|password\s*=\s*['\"][^'\"]{8,}['\"])", re.I)
_PIN_RX = re.compile(r"len\((?:discover\(\)|reg)\)\s*==\s*(\d+)")
_NEW_PLUGIN_RX = re.compile(r"^\+\+\+ b/(?:.*/)?plugins/([\w\-]+\.py)", re.M)
_NEW_TEST_RX = re.compile(r"^\+\+\+ b/(?:.*/)?tests/(test_[\w\-]+\.py)", re.M)


def _mask(s: str) -> str:
    return (s[:4] + "***") if len(s) > 4 else "***"


def analyze_pr_diff(diff: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(diff, str) or not diff.strip():
        return rows
    pins = sorted({int(n) for n in _PIN_RX.findall(diff)})
    if len(pins) > 1:
        rows.append({"key": "pr_registry_pin_mismatch",
                     "value": f"Diff contains conflicting registry-count "
                              f"pins {pins}: the registry total cannot be "
                              f"all of these at once",
                     "severity": "high", "evidence": {"pins": pins}})
    new_plugins = set(_NEW_PLUGIN_RX.findall(diff))
    new_tests = " ".join(_NEW_TEST_RX.findall(diff))
    for pf in sorted(new_plugins):
        stem = pf[:-3].replace("-", "_")
        short = "_".join(stem.split("_")[:2])
        if stem not in new_tests and short not in new_tests and not new_tests:
            rows.append({"key": "pr_new_plugin_without_tests",
                         "value": f"Diff adds plugin file '{pf}' but adds no "
                                  f"test file: new plugins need fixture tests",
                         "severity": "medium", "evidence": {"file": pf}})
    added = "\n".join(l[1:] for l in diff.splitlines() if l.startswith("+"))
    if new_plugins:
        for field in ("description", "label", "group"):
            if f"{field} =" not in added and f"{field}=" not in added:
                rows.append({"key": "pr_plugin_style_deviation",
                             "value": f"Added plugin code does not set "
                                      f"'{field}': registry style requires "
                                      f"label/description/group on every plugin",
                             "severity": "low", "evidence": {"field": field}})
    for m in _SECRET_RX.finditer(diff):
        rows.append({"key": "pr_secret_in_diff",
                     "value": f"Secret-shaped string in diff (masked): "
                              f"{_mask(m.group(0))}: remove it and rotate "
                              f"the credential",
                     "severity": "high",
                     "evidence": {"masked": _mask(m.group(0))}})
    return rows


class AutomatedPrReviewToolkitPlugin(Plugin):
    id = "automated_pr_review_toolkit"
    label = "Automated PR Review Toolkit"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Review a supplied PR diff: pin mismatches, untested new "
                   "plugins, style deviations, secrets (masked).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            diffs = ctx.consume("pr_diff")
            diff = diffs[0] if diffs and isinstance(diffs[0], str) else ""
            rows = analyze_pr_diff(diff)
        except Exception as exc:
            return self._degraded(f"PR review failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="PR review",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Fix the named issue in the "
                                             "diff before merge.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"review rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
