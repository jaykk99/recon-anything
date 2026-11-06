"""Arbitrum Stylus evaluation (variant of contract_recon).
Delta: Stylus/Wasm branch - instead of EVM opcode analysis, flag Stylus host-call risks: external calls with no sender check and value functions with no owner gating."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('delegate_call|raw_call|call_contract|StaticCall', 'msg_sender|only_owner|check_owner', 'stylus_unchecked_external_call', 'high', 'Stylus contract makes an external / delegate-style call with no msg_sender or owner check in the contract', 'Verify the caller (msg_sender) before any external call that can move value.'), ('pub fn (transfer|withdraw|mint)\b', 'msg_sender|only_owner|owner', 'stylus_unguarded_value_function', 'high', 'Stylus value-moving function (transfer/withdraw/mint) has no owner/sender gating anywhere in the contract', 'Gate value-moving Stylus entrypoints on the contract owner.')]

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


class ArbitrumStylusEval(Plugin):
    id = "arbitrum_stylus_eval"
    label = "Arbitrum Stylus Eval"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Variant of contract_recon: Stylus (Wasm) branch - flags unchecked external calls and unguarded value functions in Stylus contracts."
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
