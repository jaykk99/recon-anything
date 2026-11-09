"""zkSync bootloader / system contract audit.
Flags single-key system upgrade authority, default-account validation that never increments the nonce, and system functions callable by anyone (no bootloader check)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('upgrade_authority\s*[:=]\s*0x[0-9a-fA-F]{40}|upgrade\s*\([^)]*0x[0-9a-fA-F]{40}', 'timelock|multisig|governance', 'zksync_system_upgrade_single_key', 'high', 'zkSync system contract upgrade authority is a single address with no timelock / multisig / governance in the artifact', 'Put system upgrade authority behind a timelock and multisig.'), ('validate_transaction|fn validate\\b', 'increment_nonce|increase_nonce|nonce\s*\+=\s*1|nonce\s*=\s*nonce\s*\+', 'zksync_validation_no_nonce_increment', 'high', 'zkSync account validation never increments the nonce - validated transactions can be replayed', 'Increment the account nonce during validation, per the Era default-account rules.'), ('SystemContext|system_contract|fn system_', 'ensure_bootloader|only_bootloader|bootloader_address|BOOTLOADER', 'zksync_system_fn_no_bootloader_check', 'medium', 'A zkSync system function has no bootloader-only check, so it may be callable by arbitrary accounts', 'Restrict system functions to the bootloader formal address.')]
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


class ZksyncBootloaderSpy(Plugin):
    id = "zksync_bootloader_spy"
    label = "zkSync Bootloader Spy"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Audits zkSync system-contract / bootloader behaviour: single-key upgrade authority, account validation without nonce increment, system functions without bootloader check."
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
