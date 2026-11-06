"""Token / context quota guard (report-data utility).

Consumes the run's report sections / finding summaries and flags
context waste: near-duplicate summaries (high word overlap) and
oversized evidence blobs that blow a per-section character budget.
Emits a context-budget report: duplicates to trim, estimated tokens
saved, quota warnings. Pure local text processing, keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SECTION_BUDGET_CHARS = 8000
DUP_THRESHOLD = 0.8


def _words(text: str) -> set:
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


def _sections(data: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if isinstance(data, list):
        for i, s in enumerate(data):
            if isinstance(s, str):
                out.append({"name": f"section-{i}", "text": s})
            elif isinstance(s, dict):
                txt = s.get("text") or s.get("value") or s.get("summary") or ""
                out.append({"name": str(s.get("name") or s.get("key") or f"section-{i}"),
                            "text": str(txt)})
    elif isinstance(data, str):
        out = [{"name": "report", "text": data}]
    return out


def analyze_quota(data: Any, budget: int = SECTION_BUDGET_CHARS) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    secs = _sections(data)
    for s in secs:
        if len(s["text"]) > budget:
            rows.append({"key": "context_quota_exceeded",
                         "value": f"Report section '{s['name']}' is "
                                  f"{len(s['text'])} chars, over the {budget}-char "
                                  f"context budget (~{len(s['text']) // 4} est. tokens)",
                         "severity": "medium",
                         "evidence": {"section": s["name"],
                                      "chars": len(s["text"]), "budget": budget}})
    wordsets = [(s["name"], _words(s["text"])) for s in secs]
    for i in range(len(wordsets)):
        for j in range(i + 1, len(wordsets)):
            a, b = wordsets[i][1], wordsets[j][1]
            if not a or not b:
                continue
            sim = len(a & b) / max(1, len(a | b))
            if sim >= DUP_THRESHOLD:
                saved = min(len(secs[i]["text"]), len(secs[j]["text"])) // 4
                rows.append({"key": "context_near_duplicate",
                             "value": f"Sections '{wordsets[i][0]}' and "
                                      f"'{wordsets[j][0]}' are near-duplicates "
                                      f"(overlap {sim:.0%}): trim one, saving "
                                      f"~{saved} est. tokens",
                             "severity": "low",
                             "evidence": {"sections": [wordsets[i][0], wordsets[j][0]],
                                          "est_tokens_saved": saved}})
    return rows


class TokenContextQuotaGuardPlugin(Plugin):
    id = "token_context_quota_guard"
    label = "Token Context Quota Guard"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Guard the context budget: flag near-duplicate report "
                   "summaries and oversized evidence sections.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            data = ctx.consume("report_sections") or ctx.consume("findings")
            rows = analyze_quota(data)
        except Exception as exc:
            return self._degraded(f"quota guard failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Quota guard",
                    confidence=80,
                    evidence={"severity": r["severity"],
                              "remediation": "Trim the duplicate/oversized "
                                             "section before the report enters "
                                             "a model context.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"quota rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
