"""Solana sysvar audit.
Flags Clock/Rent/Instructions passed as raw AccountInfo without the typed Sysvar wrapper, instruction introspection without program checks, and clock-derived randomness."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('(Clock|Rent|Instructions)\\s*:\\s*(AccountInfo|UncheckedAccount)|clock\\s*:\\s*AccountInfo|rent\\s*:\\s*AccountInfo', 'Sysvar\\s*<', 'solana_sysvar_unverified_account', 'high', 'Solana program accepts a sysvar (Clock/Rent/Instructions) as a raw caller-supplied account without verifying its key equals the real sysvar ID', "Use the typed Sysvar<'info, Clock> wrapper or compare the account key against the sysvar program ID."), ('load_instruction_at|load_current_index_checked|get_instruction_relative', 'ed25519|secp256k1|check_program_id|verify_instruction', 'solana_instruction_introspection_misuse', 'medium', "Instruction introspection is used without verifying the introspected instruction's program (ed25519/secp256k1) - a caller can spoof the inspected instruction", 'Verify the program ID and instruction index of every introspected instruction.'), ('(unix_timestamp|clock\\.slot)[\\s\\S]{0,120}(rand|random|winner|lottery|seed)', None, 'solana_clock_randomness', 'medium', 'Security decision / randomness derives from Clock sysvar values (unix_timestamp/slot), which validators can influence', 'Do not use clock/sysvar values as randomness or sole security inputs.')]

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


class SolanaSysvarAudit(Plugin):
    id = "solana_sysvar_audit"
    label = "Solana Sysvar Audit"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Flags sysvar accounts accepted without verifying the sysvar ID, and instruction-introspection / clock misuse."
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
