"""CLAUDE.md management syncer (repo-state drift, read-only).

Diffs facts stated in supplied instruction files (CLAUDE.md / AGENTS.md
style text: plugin counts, live URLs, tool names) against actual repo
state supplied alongside (or the live registry count), and emits one
drift finding per stale line. It reads and reports; it never edits an
instruction file. Keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_COUNT_RX = re.compile(r"(\d{2,5})\s+(?:plugins|detectors|modules)\b", re.I)
_URL_RX = re.compile(r"https?://[^\s)'\"<>]+")


def analyze_instruction_drift(texts: Any, actual: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(actual, dict):
        actual = {}
    actual_count = actual.get("plugin_count")
    actual_urls = {str(u).rstrip("/") for u in actual.get("urls") or []}
    actual_tools = {str(t).lower() for t in actual.get("tools") or []}
    items: List[Dict[str, str]] = []
    if isinstance(texts, list):
        for t in texts:
            if isinstance(t, str):
                items.append({"name": "instructions", "text": t})
            elif isinstance(t, dict):
                items.append({"name": str(t.get("name") or "instructions"),
                              "text": str(t.get("text") or t.get("content") or "")})
    elif isinstance(texts, str):
        items = [{"name": "instructions", "text": texts}]
    for item in items:
        for m in _COUNT_RX.finditer(item["text"]):
            stated = int(m.group(1))
            if isinstance(actual_count, int) and stated != actual_count:
                rows.append({"key": "instruction_count_drift",
                             "value": f"'{item['name']}' states {stated} "
                                      f"plugins/modules but the actual "
                                      f"registry has {actual_count}: stale "
                                      f"instruction line",
                             "severity": "medium",
                             "evidence": {"file": item["name"], "stated": stated,
                                          "actual": actual_count}})
        if actual_urls:
            for m in _URL_RX.finditer(item["text"]):
                url = m.group(0).rstrip("/.,")
                if url.rstrip("/") not in actual_urls:
                    rows.append({"key": "instruction_stale_url",
                                 "value": f"'{item['name']}' references URL "
                                          f"{url} which is not in the current "
                                          f"live-URL set",
                                 "severity": "low",
                                 "evidence": {"file": item["name"], "url": url}})
        if actual_tools:
            for tool in re.findall(r"`([a-z][a-z0-9_\-]{2,})`", item["text"]):
                if tool.lower() not in actual_tools and "_" in tool:
                    rows.append({"key": "instruction_unknown_tool",
                                 "value": f"'{item['name']}' names tool "
                                          f"'{tool}' which does not exist in "
                                          f"the current registry/tool set",
                                 "severity": "low",
                                 "evidence": {"file": item["name"], "tool": tool}})
    return rows


class ClaudemdManagementSyncerPlugin(Plugin):
    id = "claudemd_management_syncer"
    label = "CLAUDE.md Management Syncer"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Diff stated facts in supplied instruction files "
                   "(counts, URLs, tool names) against actual repo state; "
                   "report drift, read-only.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            state = ctx.consume("repo_state")
            actual = state[0] if state and isinstance(state[0], dict) else {}
            if "plugin_count" not in actual:
                try:
                    from .registry import discover
                    actual = {**actual, "plugin_count": len(discover())}
                except Exception:
                    pass
            texts = ctx.consume("instruction_files") or ctx.consume("artifacts")
            rows = analyze_instruction_drift(texts, actual)
        except Exception as exc:
            return self._degraded(f"instruction sync failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Instruction syncer",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Update the named instruction "
                                             "line to the actual value.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"drift rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
