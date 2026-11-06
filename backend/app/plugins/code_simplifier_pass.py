"""Code simplifier pass (analysis only, never rewrites).

Analyzes supplied source (served JS, contract source, supplied files)
for simplification candidates: duplicated code blocks, dead functions
defined but never referenced, and pass-through wrapper functions whose
whole body forwards to another call. One candidate finding per site
with size metrics. Keyless static parsing.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_FUNC_RX = re.compile(r"(?:function\s+(\w+)|def\s+(\w+)|const\s+(\w+)\s*=\s*(?:\(|function))")
_WRAPPER_RX = re.compile(
    r"(?:function\s+(\w+)\s*\([^)]*\)\s*\{\s*return\s+(\w+)\s*\([^)]*\)\s*;?\s*\}|"
    r"def\s+(\w+)\s*\([^)]*\)\s*:\s*\n\s+return\s+(\w+)\s*\([^)]*\)\s*$)", re.M)


def _files(data: Any) -> List[Dict[str, str]]:
    out = []
    if isinstance(data, list):
        for f in data:
            if isinstance(f, dict):
                out.append({"name": str(f.get("name") or f.get("path") or "file"),
                            "text": str(f.get("text") or f.get("content") or "")})
            elif isinstance(f, str):
                out.append({"name": "file", "text": f})
    return out


def analyze_simplification(data: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    files = _files(data)
    all_text = "\n".join(f["text"] for f in files)
    for f in files:
        text = f["text"]
        # duplicated blocks: same normalized 5-line window twice in one file
        lines = [re.sub(r"\s+", " ", l).strip() for l in text.splitlines()]
        seen: Dict[str, int] = {}
        dup = 0
        for i in range(max(0, len(lines) - 4)):
            window = "\n".join(lines[i:i + 5])
            if len(window) < 60:
                continue
            if window in seen:
                dup += 1
            seen[window] = i
        if dup:
            rows.append({"key": "simplify_duplicated_block",
                         "value": f"'{f['name']}' repeats the same 5-line "
                                  f"block {dup + 1}+ times: extract a helper",
                         "severity": "low",
                         "evidence": {"file": f["name"], "duplicates": dup}})
        for m in _WRAPPER_RX.finditer(text):
            name = m.group(1) or m.group(3)
            callee = m.group(2) or m.group(4)
            if name and callee and name != callee:
                rows.append({"key": "simplify_passthrough_wrapper",
                             "value": f"'{name}' in '{f['name']}' is a "
                                      f"pass-through wrapper around '{callee}': "
                                      f"call '{callee}' directly",
                             "severity": "low",
                             "evidence": {"file": f["name"], "function": name}})
    # dead functions: defined once, never referenced anywhere else
    for f in files:
        for m in _FUNC_RX.finditer(f["text"]):
            name = m.group(1) or m.group(2) or m.group(3)
            if not name or len(name) < 3 or name in ("main", "run", "init"):
                continue
            refs = len(re.findall(rf"\b{re.escape(name)}\s*\(", all_text))
            defs = len(re.findall(rf"(?:function\s+|def\s+|const\s+){re.escape(name)}\b", all_text))
            if refs <= defs:
                rows.append({"key": "simplify_dead_function",
                             "value": f"Function '{name}' in '{f['name']}' is "
                                      f"defined but never called in the "
                                      f"supplied set (dead code)",
                             "severity": "low",
                             "evidence": {"file": f["name"], "function": name}})
    return rows


class CodeSimplifierPassPlugin(Plugin):
    id = "code_simplifier_pass"
    label = "Code Simplifier Pass"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Flag simplification candidates in supplied source: "
                   "duplicated blocks, dead functions, pass-through wrappers.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            files = ctx.consume("source_files") or ctx.consume("artifacts")
            rows = analyze_simplification(files)
        except Exception as exc:
            return self._degraded(f"simplifier failed: {exc}")
        findings: List[Finding] = [
            self._f("web", r["key"], r["value"], source="Simplifier pass",
                    confidence=75,
                    evidence={"severity": r["severity"],
                              "remediation": "Apply the named simplification "
                                             "in the source repo, then re-test.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"simplification rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
