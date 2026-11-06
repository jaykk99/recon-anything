"""Unrequested scope blocker (variant: per-finding scope audit).

Scope is enforced up front at target level elsewhere. This plugin's
delta: a post-hoc, per-finding audit. It consumes supplied findings /
bus assets plus the run's declared scope (hosts + path prefixes) and
flags every item whose host or path falls outside that scope, naming
the producing plugin, so scope creep is visible and blockable before
reporting. Pure analysis, keyless.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _host_of(item: Dict[str, Any]) -> str:
    for k in ("host", "hostname", "target"):
        if item.get(k):
            return str(item[k]).lower()
    for k in ("source_url", "url", "value"):
        v = str(item.get(k) or "")
        if "://" in v:
            return (urlparse(v).hostname or "").lower()
    return ""


def analyze_scope(items: Any, scope: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(scope, dict) or not isinstance(items, list):
        return rows
    hosts = {str(h).lower() for h in scope.get("hosts") or []}
    prefixes = [str(p) for p in scope.get("path_prefixes") or []]
    if not hosts and not prefixes:
        return rows
    for item in items:
        if not isinstance(item, dict):
            continue
        host = _host_of(item)
        label = str(item.get("key") or item.get("value") or "item")[:60]
        producer = str(item.get("plugin_id") or "?")
        if host and hosts:
            in_scope = any(host == h or host.endswith("." + h) for h in hosts)
            if not in_scope:
                rows.append({"key": "finding_out_of_scope",
                             "value": f"Out-of-scope item '{label}' on host "
                                      f"'{host}' produced by plugin "
                                      f"'{producer}': outside the declared "
                                      f"scope {sorted(hosts)}",
                             "severity": "high",
                             "evidence": {"host": host, "plugin_id": producer}})
                continue
        url = str(item.get("source_url") or item.get("url") or "")
        if prefixes and url:
            path = urlparse(url).path or "/"
            if not any(path.startswith(p) for p in prefixes):
                rows.append({"key": "finding_path_out_of_scope",
                             "value": f"Item '{label}' path '{path}' is "
                                      f"outside the declared path prefixes "
                                      f"{prefixes} (plugin '{producer}')",
                             "severity": "medium",
                             "evidence": {"path": path, "plugin_id": producer}})
    return rows


class UnrequestedScopeBlockerPlugin(Plugin):
    id = "unrequested_scope_blocker"
    label = "Unrequested Scope Blocker"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Per-finding scope audit: flag findings/assets whose "
                   "host or path is outside the run's declared scope.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            scope = ctx.consume("declared_scope")
            items = ctx.consume("findings")
            rows = analyze_scope(items, scope[0] if scope else None)
        except Exception as exc:
            return self._degraded(f"scope audit failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Scope audit",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Drop the out-of-scope item "
                                             "from the report and fix the "
                                             "producing plugin's scope guard.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"scope rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
