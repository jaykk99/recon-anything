"""Text humanizer (report-formatting plugin).

Analyzes supplied report/finding text for jargon density and
corporate filler that hides the actual action, and emits a quality
finding whose evidence carries a plain-language rendition built from a
template glossary (remediation kept verbatim in its own field, so no
technical content is lost). Pure local transformation, keyless, no
external model call.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

GLOSSARY = {
    "utilize": "use", "leverage": "use", "in order to": "to",
    "facilitate": "help", "commence": "start", "terminate": "end",
    "approximately": "about", "sufficient": "enough",
    "in the event that": "if", "prior to": "before",
    "subsequent to": "after", "ascertain": "find out",
    "endeavor": "try", "methodology": "method",
}
JARGON_THRESHOLD = 3


def humanize_text(text: str) -> str:
    out = text or ""
    for phrase, plain in sorted(GLOSSARY.items(), key=lambda kv: -len(kv[0])):
        out = re.sub(rf"\b{re.escape(phrase)}\b", plain, out, flags=re.I)
    out = re.sub(r"\s+", " ", out).strip()
    return out


def analyze_humanizer(texts: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    items: List[Dict[str, str]] = []
    if isinstance(texts, list):
        for t in texts:
            if isinstance(t, str):
                items.append({"name": "text", "text": t})
            elif isinstance(t, dict):
                items.append({"name": str(t.get("name") or t.get("key") or "finding"),
                              "text": str(t.get("text") or t.get("value") or "")})
    elif isinstance(texts, str):
        items = [{"name": "text", "text": texts}]
    for item in items:
        hits = [p for p in GLOSSARY
                if re.search(rf"\b{re.escape(p)}\b", item["text"], re.I)]
        if len(hits) >= JARGON_THRESHOLD:
            rows.append({"key": "text_needs_humanizing",
                         "value": f"'{item['name']}' uses {len(hits)} "
                                  f"jargon/filler phrases ({', '.join(hits[:5])}): "
                                  f"plain-language rendition is in evidence",
                         "severity": "low",
                         "evidence": {"item": item["name"], "jargon": hits,
                                      "humanized": humanize_text(item["text"])[:500]}})
    return rows


class TextHumanizerSkillPlugin(Plugin):
    id = "text_humanizer_skill"
    label = "Text Humanizer Skill"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Flag jargon-heavy report text and emit a plain-language "
                   "rendition in evidence; remediation kept verbatim.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            texts = ctx.consume("report_texts") or ctx.consume("findings")
            rows = analyze_humanizer(texts)
        except Exception as exc:
            return self._degraded(f"humanizer failed: {exc}")
        findings: List[Finding] = [
            self._f("web", r["key"], r["value"], source="Text humanizer",
                    confidence=80,
                    evidence={"severity": r["severity"],
                              "remediation": "Publish the humanized "
                                             "rendition alongside the "
                                             "technical finding.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"humanizer rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
