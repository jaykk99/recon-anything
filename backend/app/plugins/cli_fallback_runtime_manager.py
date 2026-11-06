"""CLI fallback runtime manager (framework utility).

Consumes supplied plugin results. For every check that degraded
because a preferred external tool/binary was absent, it emits a
fallback plan finding naming the native or CLI route that covers the
same check, so blocked work reroutes instead of dying silently. Pure
routing logic over supplied results, keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_MISSING_RX = re.compile(
    r"(not found|not installed|missing|no such file|binary|executable|command)", re.I)

# degraded plugin/tool keyword -> (native fallback route, note)
FALLBACKS = [
    (r"nuclei", "nuclei_templates (native template checks)", "native"),
    (r"nmap|masscan", "port_audit (native socket sweep)", "native"),
    (r"amass|subfinder", "subdomains + assetfinder (native enum)", "native"),
    (r"httpx", "headers + banners (native HTTP probes)", "native"),
    (r"ffuf|wfuzz|gobuster", "content_discovery + param_fuzzer (native)", "native"),
    (r"sqlmap", "sqli (native injection probes)", "native"),
    (r"nikto", "nikto_scan native checks via misconfig_sweep", "native"),
    (r"whatweb|wappalyzer", "fingerprint + webtech (native)", "native"),
]


def fallback_for(text: str) -> str | None:
    for pat, route, _kind in FALLBACKS:
        if re.search(pat, text or "", re.I):
            return route
    return None


def analyze_fallbacks(results: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(results, list):
        return rows
    for r in results:
        if not isinstance(r, dict):
            continue
        st = str(r.get("status", "")).lower()
        reason = str(r.get("reason") or r.get("message") or "")
        hay = f"{r.get('plugin_id', '')} {reason}"
        if st in ("degraded", "skipped", "error") and _MISSING_RX.search(reason):
            route = fallback_for(hay) or "native plugin covering the same check class"
            rows.append({"key": "fallback_route_available",
                         "value": f"'{r.get('plugin_id', '?')}' degraded "
                                  f"(missing tool) but the check is covered "
                                  f"by: {route}. Reroute instead of dropping "
                                  f"the check",
                         "severity": "medium",
                         "evidence": {"plugin_id": str(r.get("plugin_id", "")),
                                      "fallback": route}})
    return rows


class CliFallbackRuntimeManagerPlugin(Plugin):
    id = "cli_fallback_runtime_manager"
    label = "CLI Fallback Runtime Manager"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("For checks degraded by a missing tool/binary, emit the "
                   "native fallback route that covers the same check.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_fallbacks(ctx.consume("plugin_statuses"))
        except Exception as exc:
            return self._degraded(f"fallback manager failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Fallback manager",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Enable the named native "
                                             "fallback route for this check.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"fallback rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
