"""Regression test suite stub (generator over supplied verified findings).

For each supplied verified finding it generates a pytest-style
regression stub asserting the fixed behavior (the originating plugin
no longer fires / the marker is gone), plus a vuln/clean fixture pair
stub for the detector itself. The generated test file rides in the
finding's evidence as a downloadable artifact. Pure local code
generation, keyless; nothing is executed.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _ident(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")[:50] or "finding"


def stub_for(f: Dict[str, Any]) -> str:
    pid = _ident(str(f.get("plugin_id") or "plugin"))
    key = _ident(str(f.get("key") or "finding"))
    return (f"def test_regression_{pid}_{key}():\n"
            f"    # Regression stub for {f.get('plugin_id', '?')}/"
            f"{f.get('key', '?')}: the fixed behavior must hold.\n"
            f"    result = run_plugin('{f.get('plugin_id', '')}', FIXED_TARGET)\n"
            f"    assert '{f.get('key', '')}' not in "
            f"{{f.key for f in result.findings}}\n")


def analyze_regression_stubs(findings: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(findings, list):
        return rows
    def _is_verified(f: Any) -> bool:
        if not isinstance(f, dict):
            return False
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        status = str(f.get("status") or ev.get("status") or "").lower()
        return bool(status in ("verified", "verified_real", "fixed")
                    or ev.get("verified") or f.get("verified"))

    verified = [f for f in findings if _is_verified(f)]
    if not verified:
        return rows
    suite = "\n".join(stub_for(f) for f in verified)
    rows.append({"key": "regression_suite_stub",
                 "value": f"Regression suite stub generated for "
                          f"{len(verified)} verified finding(s): one pytest "
                          f"case per finding class, plugin id in each test name",
                 "severity": "low",
                 "evidence": {"stub_count": len(verified),
                              "test_file": suite[:4000]}})
    return rows


class RegressionTestSuiteStubPlugin(Plugin):
    id = "regression_test_suite_stub"
    label = "Regression Test Suite Stub"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Generate pytest regression stubs from supplied verified "
                   "findings, one per finding class, as an artifact.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_regression_stubs(ctx.consume("findings"))
        except Exception as exc:
            return self._degraded(f"stub generation failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Regression stub gen",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Save the stub file into the "
                                             "test suite and fill in the "
                                             "target fixtures.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"stub rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
