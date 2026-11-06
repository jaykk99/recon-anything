"""PDA seed validator.
Flags create_program_address (non-canonical bump), seeds taken directly from caller input, and PDA accounts accepted without a seeds constraint / re-derivation."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('create_program_address', 'find_program_address', 'pda_noncanonical_bump', 'high', 'PDA derived with create_program_address, which accepts any bump - the canonical bump is not enforced, so multiple valid PDAs exist for the same seeds', 'Derive PDAs with find_program_address and store / enforce the canonical bump.'), ('seeds\s*=\s*&?\[?\s*(user_seed|caller_seed|seed_param|args\.seed|input\.seed)', None, 'pda_caller_supplied_seed', 'high', 'PDA seeds are taken directly from caller-supplied input, so an attacker can derive / target PDAs for other users', 'Bind seeds to validated account keys and program constants, never raw caller bytes.'), ('pda_account\s*:|pda\s*:\s*Account', 'seeds\s*=', 'pda_not_rederived', 'medium', 'A PDA account is accepted without a seeds constraint, so it is never re-derived against the program ID', 'Add a seeds + bump constraint so the PDA is re-derived on every use.')]

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


class PdaSeedValidator(Plugin):
    id = "pda_seed_validator"
    label = "PDA Seed Validator"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Traces PDA derivations: non-canonical bumps, caller-supplied seeds, PDAs accepted without re-derivation."
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
