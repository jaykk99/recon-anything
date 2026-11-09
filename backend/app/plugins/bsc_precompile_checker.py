"""BSC precompile checker (variant, BSC detector family).
Delta: calls to BNB Chain precompile addresses (0x64-0x6a range: double-sign, cometBFT/light-client, BLS, native staking helpers) whose success/return value is never checked before a value or security decision."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('0x00000000000000000000000000000000000000(64|65|66|67|68|69|6a)\\b[\s\S]{0,200}?\.call\s*\(', 'require\s*\(\s*success|if\s*\(\s*!success|\(\s*bool\s+success', 'bsc_precompile_unchecked_result', 'high', 'BNB Chain precompile is called and its success flag is never checked - a failed precompile call silently flows into a value/security decision', 'Capture and require the precompile call success flag and validate decoded output.'), ('(doubleSign|cometBFT|nativeStaking|blsPrecompile)[\s\S]{0,150}?\.call\s*\(', 'require\s*\(\s*success|if\s*\(\s*!success', 'bsc_named_precompile_unchecked', 'medium', 'Named BNB precompile helper is called without checking call success', 'Check the success flag on every precompile call.')]
RULES = [tuple(x.replace(chr(8), chr(92) + chr(98)) if isinstance(x, str) else x for x in r) for r in RULES]  # normalise word-boundary escapes

def analyze_artifact(text):
    """Pure analysis: returns list of hit dicts. No I/O, never raises."""
    hits = []
    if not text or not isinstance(text, str):
        return hits
    for pattern, guard, key, severity, value, remediation in RULES:
        try:
            if not re.search(pattern, text, re.I | re.S):
                continue
            if guard and re.search(guard, text, re.I | re.S):
                continue
        except re.error:
            continue
        hits.append({"key": key, "value": value, "severity": severity,
                     "remediation": remediation})
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


class BscPrecompileChecker(Plugin):
    id = "bsc_precompile_checker"
    label = "BSC Precompile Checker"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Variant of the BSC detector family: flags BNB Chain precompile calls whose return value / success is not checked."
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
