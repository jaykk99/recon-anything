"""Prompt injection shield (detector only).

Scans supplied text artifacts (llms.txt/.md docs, README/config text,
recorded tool outputs) for prompt-injection patterns aimed at an
agent: instruction overrides, role/delimiter escapes, tool-call
coercion and exfiltration requests. It FLAGS the passage as a finding
with masked evidence. It never executes, follows or obeys any content
it scans. Pure pattern analysis, keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_PATTERNS = [
    ("injection_override", "high",
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I)),
    ("injection_override", "high",
     re.compile(r"disregard\s+(your|the)\s+(instructions|rules|system\s+prompt)", re.I)),
    ("injection_new_identity", "high",
     re.compile(r"you\s+are\s+now\s+(a|an|in)\b.{0,40}(mode|assistant|agent)", re.I)),
    ("injection_role_escape", "high",
     re.compile(r"(<\|im_start\|>|\[INST\]|###\s*system\b|<system>)", re.I)),
    ("injection_tool_coercion", "high",
     re.compile(r"(call|invoke|run|execute)\s+(the\s+)?(tool|function|command)\b.{0,60}(now|immediately)", re.I)),
    ("injection_exfiltration", "high",
     re.compile(r"(send|post|upload|exfiltrate)\s+.{0,40}(api\s*key|password|secret|token|credentials|system\s+prompt)\b", re.I)),
    ("injection_exfiltration", "medium",
     re.compile(r"reveal\s+(your\s+)?(system\s+prompt|instructions|hidden\s+prompt)", re.I)),
    ("injection_coercion", "medium",
     re.compile(r"do\s+not\s+tell\s+the\s+user", re.I)),
]


def _mask(snippet: str) -> str:
    s = re.sub(r"\s+", " ", snippet or "").strip()
    return (s[:37] + "***") if len(s) > 40 else s


def analyze_injection(texts: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    items: List[Dict[str, Any]] = []
    if isinstance(texts, str):
        items = [{"name": "text", "text": texts}]
    elif isinstance(texts, list):
        for t in texts:
            if isinstance(t, str):
                items.append({"name": "artifact", "text": t})
            elif isinstance(t, dict):
                items.append({"name": str(t.get("name") or "artifact"),
                              "text": str(t.get("text") or t.get("content") or "")})
    seen = set()
    for item in items:
        for key, sev, rx in _PATTERNS:
            m = rx.search(item["text"])
            if m and (item["name"], key, m.group(0)[:40]) not in seen:
                seen.add((item["name"], key, m.group(0)[:40]))
                start = max(0, m.start() - 20)
                rows.append({"key": key,
                             "value": f"Prompt-injection pattern in supplied "
                                      f"artifact '{item['name']}': passage is "
                                      f"flagged and quarantined, never obeyed",
                             "severity": sev,
                             "evidence": {"artifact": item["name"],
                                          "masked_snippet": _mask(item["text"][start:m.end() + 20])}})
    return rows


class PromptInjectionShieldMcpPlugin(Plugin):
    id = "prompt_injection_shield_mcp"
    label = "Prompt Injection Shield (MCP)"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "api"
    description = ("Detect prompt-injection patterns in supplied text "
                   "artifacts/tool outputs; flag and quarantine, never obey.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            texts = ctx.consume("artifacts") or ctx.consume("tool_outputs")
            rows = analyze_injection(texts)
        except Exception as exc:
            return self._degraded(f"injection scan failed: {exc}")
        findings: List[Finding] = [
            self._f("api", r["key"], r["value"], source="Injection shield",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Quarantine this passage: do not "
                                             "let it reach a model context as "
                                             "instructions; treat the source "
                                             "as untrusted data.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"injection rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
