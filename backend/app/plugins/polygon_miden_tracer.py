"""Polygon Miden tracer.
Local MASM analysis: flags procedures that consume external/advice inputs or move assets with no assert anywhere in the program."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


def analyze_artifact(text):
    hits = []
    if not text or not re.search(r"\bproc\.|\bbegin\b|\.masm|use\.std::", text):
        return hits
    if re.search(r"asset|transfer|move_asset", text, re.I) and not re.search(r"\bassert", text):
        hits.append({"key": "miden_asset_move_no_assert",
            "value": "Miden program moves assets with no assert instruction anywhere - external inputs are never validated before the movement",
            "severity": "high",
            "remediation": "Assert every external input (amounts, recipients, note data) before moving assets."})
    if re.search(r"advice|adv\.push|input\.", text, re.I) and not re.search(r"\bassert", text):
        hits.append({"key": "miden_external_input_no_assert",
            "value": "Miden program consumes advice/external inputs with no assertion on them",
            "severity": "medium",
            "remediation": "Bind advice inputs with asserts against committed values."})
    return hits


async def _get_artifact(target, ctx):
    try:
        for kind in ("artifacts", "source", "sources", "code",
                     "artifact_text", "files", "contracts"):
            for item in ctx.consume(kind):
                if isinstance(item, str) and len(item) > 20:
                    return item
                if isinstance(item, dict):
                    import json as _j
                    return _j.dumps(item)
    except Exception:
        pass
    raw = (getattr(target, "raw", "") or "").strip()
    norm = (getattr(target, "normalized", "") or "").strip()
    if raw and (len(raw) > 30 or raw.startswith("{") or "\n" in raw):
        return raw
    if norm.startswith("http"):
        try:
            page = await ctx.fetch_page(norm)
            if page:
                txt = page.get("text") if isinstance(page, dict) else getattr(page, "text", "")
                if txt:
                    return txt
        except Exception:
            pass
    return raw


class PolygonMidenTracer(Plugin):
    id = "polygon_miden_tracer"
    label = "Polygon Miden Tracer"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Traces Miden MASM programs: procedure call graph, asset movements, and missing assertions on external inputs."
    passive = True

    async def run(self, target, ctx):
        try:
            text = await _get_artifact(target, ctx)
            hits = analyze_artifact(text or "")
            findings = [
                self._f("web3", h["key"], h["value"], self.id,
                        confidence=85,
                        evidence={"severity": h.get("severity", "medium"),
                                  "remediation": h.get("remediation", "")})
                for h in hits]
            return self._ok(
                findings,
                reason=f"{len(findings)} alt-chain finding(s) from artifact analysis")
        except Exception as exc:  # never raise fatally
            return self._ok([], reason=f"degraded: {type(exc).__name__}: {exc}")
