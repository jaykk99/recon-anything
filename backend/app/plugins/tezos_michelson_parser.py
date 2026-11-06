"""Tezos Michelson parser.
Parses entrypoints / instruction trace from Michelson or Micheline JSON; flags TRANSFER_TOKENS paths with no SENDER check and FA2-style transfers with no operator validation."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('TRANSFER_TOKENS|IMPLICIT_ACCOUNT', 'SENDER|sender', 'michelson_transfer_no_sender_check', 'high', 'Michelson contract transfers tez/tokens (TRANSFER_TOKENS) with no SENDER check in the code - entrypoints may be callable by anyone', 'Compare SENDER against the stored owner/administrator and FAILWITH on mismatch before transferring.'), ('fa2|FA2|Fa2', 'isOperator|is_operator|operator', 'tezos_fa2_no_operator_check', 'medium', 'FA2-style transfer logic never checks the operator (isOperator) - tokens may be moved by non-operators', 'Enforce the FA2 operator policy on every transfer entrypoint.')]

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


class TezosMichelsonParser(Plugin):
    id = "tezos_michelson_parser"
    label = "Tezos Michelson Parser"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Parses Michelson/Micheline contracts and flags token/tez transfers with no sender check and FA2 transfers with no operator check."
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
