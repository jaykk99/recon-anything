"""Seen / inferred / unknown classifier.

Tags run results by epistemic class: SEEN (direct probe evidence),
INFERRED (derived or correlation-boosted from another finding), and
UNKNOWN (surfaces no plugin covered: degraded, timed out, skipped or
errored workers). Emits blind-spot findings for UNKNOWN coverage and a
note for INFERRED results that rest on derivation rather than a direct
probe. Pure logic over supplied run data, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_BAD_STATUS = ("degraded", "timeout", "timed_out", "skipped", "error", "failed")


def classify(findings: Any, statuses: Any) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"seen": [], "inferred": [], "unknown": []}
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            label = str(f.get("key") or f.get("value") or "?")
            ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
            cls = str(f.get("epistemic_class") or ev.get("epistemic_class") or "").lower()
            derived = bool(f.get("derived") or ev.get("derived")
                           or ev.get("correlation") or ev.get("dedup_boosted"))
            if cls in out:
                out[cls].append(label)
            elif derived:
                out["inferred"].append(label)
            else:
                out["seen"].append(label)
    if isinstance(statuses, list):
        for s in statuses:
            if not isinstance(s, dict):
                continue
            st = str(s.get("status", "")).lower()
            if any(b in st for b in _BAD_STATUS):
                out["unknown"].append(str(s.get("plugin_id") or s.get("id") or "?"))
    return out


def analyze_classification(findings: Any, statuses: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    c = classify(findings, statuses)
    for pid in c["unknown"]:
        rows.append({"key": "coverage_blind_spot",
                     "value": f"Blind spot: plugin '{pid}' did not complete "
                              f"(degraded/timeout/skipped), so its surface is "
                              f"UNKNOWN in this run, not clean",
                     "severity": "medium", "evidence": {"plugin_id": pid}})
    if c["inferred"]:
        rows.append({"key": "inferred_results_present",
                     "value": f"{len(c['inferred'])} result(s) are INFERRED "
                              f"(derived/correlated, not directly probed): "
                              + ", ".join(c["inferred"][:10]),
                     "severity": "low",
                     "evidence": {"inferred": c["inferred"][:20],
                                  "seen_count": len(c["seen"])}})
    return rows


class SeenInferredUnknownClassifierPlugin(Plugin):
    id = "seen_inferred_unknown_classifier"
    label = "Seen/Inferred/Unknown Classifier"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Classify run results SEEN vs INFERRED vs UNKNOWN and "
                   "enumerate coverage blind spots from degraded plugins.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_classification(ctx.consume("findings"),
                                          ctx.consume("plugin_statuses"))
        except Exception as exc:
            return self._degraded(f"classification failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Epistemic classifier",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Re-run the named plugins or "
                                             "probe the surface directly "
                                             "before treating it as clean.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"classification rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
