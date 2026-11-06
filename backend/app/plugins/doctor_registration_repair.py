"""Doctor: registration repair (framework diagnostic, read-only).

Runs registry health checks over supplied registry entries (or the
live registry in the wrapper): discover() count vs an expected pin,
duplicate plugin ids, missing label/description/group fields, groups
outside the valid set, and phase/lane mis-declarations. Emits one
repair finding per defect naming the plugin id and the concrete fix.
It diagnoses and reports; it never edits code. Keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import PLUGIN_GROUPS, Cost, Ctx, Finding, Plugin, PluginResult, Target

_VALID_LANES = ("fast", "heavy")


def analyze_registry(entries: Any, expected_count: Any = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(entries, list):
        return rows
    ids = [str(e.get("id")) for e in entries if isinstance(e, dict) and e.get("id")]
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        rows.append({"key": "doctor_duplicate_plugin_id",
                     "value": f"Plugin id '{dup}' is registered more than "
                              f"once: later registrations silently shadow "
                              f"earlier ones. Rename one module's id",
                     "severity": "high", "evidence": {"plugin_id": dup}})
    if isinstance(expected_count, int) and len(entries) != expected_count:
        rows.append({"key": "doctor_registry_count_mismatch",
                     "value": f"Registry holds {len(entries)} plugins but the "
                              f"pin expects {expected_count}: a module failed "
                              f"to import or a pin was not updated",
                     "severity": "high",
                     "evidence": {"actual": len(entries), "expected": expected_count}})
    for e in entries:
        if not isinstance(e, dict):
            continue
        pid = str(e.get("id") or "?")
        for fieldname in ("label", "description", "group"):
            if not str(e.get(fieldname) or "").strip():
                rows.append({"key": "doctor_missing_field",
                             "value": f"Plugin '{pid}' is missing its "
                                      f"'{fieldname}' field: set it in the "
                                      f"plugin class",
                             "severity": "medium",
                             "evidence": {"plugin_id": pid, "field": fieldname}})
        g = str(e.get("group") or "")
        if g and g not in PLUGIN_GROUPS:
            rows.append({"key": "doctor_invalid_group",
                         "value": f"Plugin '{pid}' declares group '{g}', "
                                  f"outside the valid set {list(PLUGIN_GROUPS)}",
                         "severity": "medium",
                         "evidence": {"plugin_id": pid, "group": g}})
        lane = str(e.get("lane") or "fast")
        if lane not in _VALID_LANES:
            rows.append({"key": "doctor_invalid_lane",
                         "value": f"Plugin '{pid}' declares lane '{lane}', "
                                  f"expected one of {_VALID_LANES}",
                         "severity": "low",
                         "evidence": {"plugin_id": pid, "lane": lane}})
        phase = e.get("phase", 1)
        if phase not in (1, 2, 3):  # 3 = confirmation lane (candidate queue)
            rows.append({"key": "doctor_invalid_phase",
                         "value": f"Plugin '{pid}' declares phase {phase!r}, "
                                  f"expected 1, 2 or 3",
                         "severity": "low", "evidence": {"plugin_id": pid}})
    return rows


def live_registry_entries() -> List[Dict[str, Any]]:
    from .registry import discover
    out = []
    for pid, cls in discover().items():
        out.append({"id": pid, "label": getattr(cls, "label", ""),
                    "description": getattr(cls, "description", ""),
                    "group": getattr(cls, "group", ""),
                    "lane": getattr(cls, "lane", "fast"),
                    "phase": getattr(cls, "phase", 1)})
    return out


class DoctorRegistrationRepairPlugin(Plugin):
    id = "doctor_registration_repair"
    label = "Doctor Registration Repair"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Registry health doctor: duplicate ids, count-pin "
                   "mismatch, missing fields, invalid group/lane/phase, "
                   "with the concrete fix per defect.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            supplied = ctx.consume("registry_entries")
            expected = ctx.consume("expected_plugin_count")
            entries = supplied if supplied else live_registry_entries()
            rows = analyze_registry(entries,
                                    expected[0] if expected and isinstance(expected[0], int) else None)
        except Exception as exc:
            return self._degraded(f"doctor failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Registry doctor",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Apply the concrete fix named "
                                             "in the finding.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"doctor rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
