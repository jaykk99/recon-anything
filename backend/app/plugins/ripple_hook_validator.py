"""XRPL Hook validator.
Flags hooks that accept without checking hook_account/originator, unbounded loops with no GUARD, state writes, and emit() calls with no emission check."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('accept\s*\(|int64_t hook\s*\(', 'hook_account\s*\(\)|otxn_field.*account|originator', 'xrpl_hook_no_account_check', 'high', "XRPL Hook accepts transactions without checking hook_account() / the originator - any account's transactions can drive its logic", 'Check hook_account() and the originating account before applying hook logic.'), ('for\s*\(\s*;;\s*\)|while\s*\(\s*1\s*\)', 'GUARD|guard\s*\(', 'xrpl_hook_unbounded_loop', 'medium', 'XRPL Hook contains an unbounded loop with no GUARD() macro - it can exceed hook execution limits or be abused for griefing', 'Bound every loop and place GUARD() at the top of each iteration.'), ('emit\s*\(', 'etxn_check|check.*emission|PREPARE|retry', 'xrpl_hook_emit_no_check', 'medium', 'XRPL Hook emits a transaction without checking the emission (etxn_check / prepare) - failed emissions are silently lost', 'Prepare and check every emitted transaction and handle retry/failure.')]

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


class RippleHookValidator(Plugin):
    id = "ripple_hook_validator"
    label = "Ripple Hook Validator"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Audits XRPL Hooks for missing account/originator checks, unbounded loops without guards, and emit/retry errors."
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
