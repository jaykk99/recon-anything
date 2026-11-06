"""Runtime state snapshot verify (variant of amass_asset_tracker).

The tracker only diffs enumeration membership (subdomains/IPs). This
plugin's delta: source-vs-runtime parity across the full observable
state: endpoint statuses, response headers, TLS posture, open port set
and finding set, baseline run vs current run, with a per-surface
parity pass/drift finding for every drift. Pure comparison, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _map(state: Any, key: str) -> Dict[str, Any]:
    if isinstance(state, dict) and isinstance(state.get(key), dict):
        return {str(k): v for k, v in state[key].items()}
    return {}


def analyze_parity(baseline: Any, current: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        return rows
    for surface in ("endpoints", "headers", "tls", "ports"):
        b, c = _map(baseline, surface), _map(current, surface)
        for k in sorted(set(b) | set(c)):
            if k not in c:
                rows.append({"key": "parity_surface_missing",
                             "value": f"Parity drift: {surface} '{k}' was "
                                      f"present in the baseline snapshot but "
                                      f"is absent at runtime now",
                             "severity": "medium",
                             "evidence": {"surface": surface, "item": k}})
            elif k not in b:
                rows.append({"key": "parity_surface_added",
                             "value": f"Parity drift: {surface} '{k}' appears "
                                      f"at runtime but was not in the baseline "
                                      f"snapshot (undeclared state)",
                             "severity": "medium",
                             "evidence": {"surface": surface, "item": k}})
            elif str(b[k]) != str(c[k]):
                rows.append({"key": "parity_value_drift",
                             "value": f"Parity drift: {surface} '{k}' changed "
                                      f"from '{str(b[k])[:60]}' (baseline) to "
                                      f"'{str(c[k])[:60]}' (runtime)",
                             "severity": "medium" if surface in ("tls", "ports") else "low",
                             "evidence": {"surface": surface, "item": k}})
    bf = baseline.get("findings") if isinstance(baseline.get("findings"), list) else []
    cf = current.get("findings") if isinstance(current.get("findings"), list) else []
    bkeys = {str(f.get("key")) for f in bf if isinstance(f, dict)}
    ckeys = {str(f.get("key")) for f in cf if isinstance(f, dict)}
    for k in sorted(ckeys - bkeys):
        rows.append({"key": "parity_new_finding_class",
                     "value": f"Parity drift: finding class '{k}' appears at "
                              f"runtime but not in the baseline snapshot",
                     "severity": "medium", "evidence": {"finding_key": k}})
    return rows


class RuntimeStateSnapshotVerifyPlugin(Plugin):
    id = "runtime_state_snapshot_verify"
    label = "Runtime State Snapshot Verify"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Baseline-vs-runtime parity check across endpoints, "
                   "headers, TLS, ports and finding set; report drift.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            base = ctx.consume("baseline_state")
            cur = ctx.consume("current_state")
            rows = analyze_parity(base[0] if base else None,
                                  cur[0] if cur else None)
        except Exception as exc:
            return self._degraded(f"parity check failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Snapshot parity",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Decide whether the drift is an "
                                             "intended change; if not, restore "
                                             "the baseline state and re-verify.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"parity drift rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
