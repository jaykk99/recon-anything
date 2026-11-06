"""MCP tool schema aligner.

Consumes an operator-supplied MCP tools/list payload (from any MCP
server) and flags schema drift: tools with missing or thin
descriptions, the same concept exposed under inconsistent parameter
names or types across tools, and required-field mismatches for the
same parameter. Emits a normalized alignment report as findings.
Local parsing only, keyless; nothing is executed.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# concept -> acceptable parameter spellings (normalized)
_CONCEPTS = {
    "url": {"url", "target_url", "targeturl", "uri", "target"},
    "host": {"host", "hostname", "target_host", "domain"},
    "path": {"path", "file_path", "filepath", "file"},
    "query": {"query", "q", "search", "search_query"},
    "id": {"id", "item_id", "itemid", "uid"},
}


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _params(tool: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return {}
    required = set(schema.get("required") or [])
    return {str(k): {"type": str((v or {}).get("type", "")) if isinstance(v, dict) else "",
                     "required": str(k) in required}
            for k, v in props.items()}


def analyze_mcp_tools(tools: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if isinstance(tools, dict):
        tools = tools.get("tools") or tools.get("result", {}).get("tools") or []
    if not isinstance(tools, list):
        return rows
    concept_seen: Dict[str, Dict[str, str]] = {}
    param_seen: Dict[str, Dict[str, Any]] = {}
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name") or "?")
        desc = str(t.get("description") or "").strip()
        if len(desc) < 20:
            rows.append({"key": "mcp_thin_description",
                         "value": f"MCP tool '{name}' has a missing/thin "
                                  f"description ({len(desc)} chars): agents "
                                  f"cannot select it reliably",
                         "severity": "medium", "evidence": {"tool": name}})
        for pname, meta in _params(t).items():
            np = _norm(pname)
            for concept, spellings in _CONCEPTS.items():
                if np in {_norm(s) for s in spellings}:
                    prev = concept_seen.setdefault(concept, {})
                    if prev and np not in prev:
                        rows.append({"key": "mcp_param_name_drift",
                                     "value": f"Concept '{concept}' is named "
                                              f"'{pname}' in tool '{name}' but "
                                              f"'{next(iter(prev))}' in tool "
                                              f"'{prev[next(iter(prev))]}': "
                                              f"inconsistent parameter naming",
                                     "severity": "medium",
                                     "evidence": {"tool": name, "concept": concept}})
                    prev[np] = name
            prior = param_seen.get(np)
            if prior and prior["type"] and meta["type"] and prior["type"] != meta["type"]:
                rows.append({"key": "mcp_param_type_mismatch",
                             "value": f"Parameter '{pname}' is type "
                                      f"'{prior['type']}' in tool '{prior['tool']}' "
                                      f"but type '{meta['type']}' in tool '{name}'",
                             "severity": "medium",
                             "evidence": {"tool": name, "parameter": pname}})
            if prior and prior["required"] != meta["required"]:
                rows.append({"key": "mcp_required_mismatch",
                             "value": f"Parameter '{pname}' is required in tool "
                                      f"'{prior['tool']}' but optional in '{name}' "
                                      f"(or vice versa)",
                             "severity": "low",
                             "evidence": {"tool": name, "parameter": pname}})
            param_seen.setdefault(np, {**meta, "tool": name})
    return rows


class McpToolSchemaAlignerPlugin(Plugin):
    id = "mcp_tool_schema_aligner"
    label = "MCP Tool Schema Aligner"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "api"
    description = ("Align a supplied MCP tools/list schema set: flag thin "
                   "descriptions, parameter name/type drift, required "
                   "mismatches.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            tools: Any = ctx.consume("mcp_tools")
            if tools and len(tools) == 1 and isinstance(tools[0], (dict, list)):
                tools = tools[0]
            rows = analyze_mcp_tools(tools)
        except Exception as exc:
            return self._degraded(f"schema alignment failed: {exc}")
        findings: List[Finding] = [
            self._f("api", r["key"], r["value"], source="MCP schema aligner",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Rename/retype the parameter "
                                             "consistently across tools and "
                                             "write a full description.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"schema drift rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
