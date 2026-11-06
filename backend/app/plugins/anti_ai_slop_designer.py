"""Anti-AI-slop designer (code/report quality).

Scans supplied text/code (report drafts, served JS, reconstructed
source) for boilerplate and slop patterns: stock AI filler phrases,
generic comment blocks, placeholder TODO filler, and paragraphs
repeated verbatim across the document. One cleanup finding per site
with the pattern and a size metric. Pure local pattern analysis,
keyless.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SLOP_PHRASES = [
    "in today's fast-paced world", "delve into", "it's important to note",
    "furthermore", "moreover", "in conclusion, it is worth noting",
    "when it comes to", "at the end of the day", "ever-evolving landscape",
    "unlock the power", "harness the power", "game-changer",
    "cutting-edge solution", "robust and scalable", "seamlessly integrate",
]
_PLACEHOLDER_RX = re.compile(r"\b(TODO|FIXME|XXX)[:\s].{0,40}(placeholder|coming soon|implement (this|later)|lorem)", re.I)
_GENERIC_COMMENT_RX = re.compile(r"(//|#|\*)\s*(this (function|method|class) (does|is)|here we|in this (section|part) we)\b", re.I)


def analyze_slop(texts: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    items: List[Dict[str, str]] = []
    if isinstance(texts, list):
        for t in texts:
            if isinstance(t, str):
                items.append({"name": "artifact", "text": t})
            elif isinstance(t, dict):
                items.append({"name": str(t.get("name") or "artifact"),
                              "text": str(t.get("text") or t.get("content") or "")})
    elif isinstance(texts, str):
        items = [{"name": "artifact", "text": texts}]
    for item in items:
        text = item["text"]
        low = text.lower()
        hits = [p for p in SLOP_PHRASES if p in low]
        if len(hits) >= 2:
            rows.append({"key": "slop_filler_phrases",
                         "value": f"'{item['name']}' contains {len(hits)} "
                                  f"stock filler phrases ({', '.join(hits[:4])}): "
                                  f"rewrite with concrete content",
                         "severity": "low",
                         "evidence": {"artifact": item["name"], "phrases": hits}})
        ph = _PLACEHOLDER_RX.findall(text)
        if ph:
            rows.append({"key": "slop_placeholder_filler",
                         "value": f"'{item['name']}' has {len(ph)} placeholder "
                                  f"TODO filler site(s): dead scaffold text",
                         "severity": "medium",
                         "evidence": {"artifact": item["name"], "count": len(ph)}})
        gc = _GENERIC_COMMENT_RX.findall(text)
        if len(gc) >= 3:
            rows.append({"key": "slop_generic_comments",
                         "value": f"'{item['name']}' has {len(gc)} generic "
                                  f"boilerplate comment blocks that restate "
                                  f"the code instead of explaining it",
                         "severity": "low",
                         "evidence": {"artifact": item["name"], "count": len(gc)}})
        paras = [re.sub(r"\s+", " ", p).strip().lower()
                 for p in re.split(r"\n\s*\n", text) if len(p.strip()) >= 120]
        seen: Dict[str, int] = {}
        for p in paras:
            seen[p] = seen.get(p, 0) + 1
        dups = [p for p, n in seen.items() if n > 1]
        if dups:
            rows.append({"key": "slop_repeated_paragraph",
                         "value": f"'{item['name']}' repeats the same "
                                  f"paragraph verbatim {len(dups)} time(s) "
                                  f"(template filler, ~{len(dups[0])} chars each)",
                         "severity": "medium",
                         "evidence": {"artifact": item["name"],
                                      "repeated": len(dups)}})
    return rows


class AntiAiSlopDesignerPlugin(Plugin):
    id = "anti_ai_slop_designer"
    label = "Anti-AI-Slop Designer"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Flag boilerplate/slop in supplied text and code: filler "
                   "phrases, placeholder TODOs, generic comments, repeated "
                   "paragraphs.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            texts = ctx.consume("artifacts") or ctx.consume("report_texts")
            rows = analyze_slop(texts)
        except Exception as exc:
            return self._degraded(f"slop scan failed: {exc}")
        findings: List[Finding] = [
            self._f("web", r["key"], r["value"], source="Slop scan",
                    confidence=80,
                    evidence={"severity": r["severity"],
                              "remediation": "Replace the flagged filler "
                                             "with concrete, specific content "
                                             "or delete it.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"slop rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
