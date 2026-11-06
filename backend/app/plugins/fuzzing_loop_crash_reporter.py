"""Fuzzing-loop crash reporter (variant of zeroday detectors).

zeroday_differential / zeroday_error_miner DETECT crash candidates;
they do not format reports. This plugin's delta: consume supplied
crash candidates, deduplicate them by crash signature (endpoint +
error fingerprint), and format each unique crash as a structured bug
report: repro request shape, sanitized stack excerpt (secrets masked),
affected parameter, severity suggestion. Pure formatting, keyless.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_SECRET_RX = re.compile(r"([A-Za-z0-9_\-]{4})[A-Za-z0-9_\-]{12,}")


def crash_signature(c: Dict[str, Any]) -> str:
    ep = str(c.get("endpoint") or c.get("url") or "")
    err = str(c.get("error") or c.get("error_type") or c.get("body") or "")
    fp = re.sub(r"[^a-z]", "", err.lower())[:40]
    return hashlib.sha256(f"{ep}|{fp}".encode()).hexdigest()[:12]


def _sanitize(text: str, limit: int = 240) -> str:
    s = _SECRET_RX.sub(r"\1***", str(text or ""))
    return re.sub(r"\s+", " ", s)[:limit]


def analyze_crashes(candidates: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(candidates, list):
        return rows
    groups: Dict[str, Dict[str, Any]] = {}
    for c in candidates:
        if not isinstance(c, dict):
            continue
        status = c.get("status") or c.get("status_code")
        err = str(c.get("error") or c.get("body") or "")
        if not (status and int(status) >= 500 if isinstance(status, (int, float))
                else False) and not err:
            continue
        sig = crash_signature(c)
        slot = groups.setdefault(sig, {"crash": c, "count": 0})
        slot["count"] += 1
    for sig, slot in groups.items():
        c = slot["crash"]
        ep = str(c.get("endpoint") or c.get("url") or "?")
        param = str(c.get("param") or c.get("parameter") or "?")
        report = (f"BUG REPORT crash-{sig}: endpoint={ep} param={param} "
                  f"occurrences={slot['count']} repro='mutate {param} on {ep}' "
                  f"stack='{_sanitize(str(c.get('stack') or c.get('error') or c.get('body') or ''))}'")
        rows.append({"key": "crash_bug_report",
                     "value": f"Unique crash at {ep} (param {param}) seen "
                              f"{slot['count']} time(s), signature {sig}: "
                              f"structured bug report in evidence",
                     "severity": "high" if slot["count"] >= 3 else "medium",
                     "evidence": {"signature": sig, "endpoint": ep,
                                  "param": param, "occurrences": slot["count"],
                                  "bug_report": report}})
    return rows


class FuzzingLoopCrashReporterPlugin(Plugin):
    id = "fuzzing_loop_crash_reporter"
    label = "Fuzzing Loop Crash Reporter"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Dedupe supplied crash candidates by signature and "
                   "format each unique crash as a structured bug report.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            cands = ctx.consume("crash_candidates") or ctx.consume("findings")
            rows = analyze_crashes(cands)
        except Exception as exc:
            return self._degraded(f"crash reporter failed: {exc}")
        findings: List[Finding] = [
            self._f("web", r["key"], r["value"], source="Crash reporter",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "File the bug report, fix the "
                                             "crash path, and re-fuzz the "
                                             "endpoint to verify.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"crash reports: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
