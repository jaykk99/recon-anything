"""Move resource tracer.
Builds resource-mutation signals from Move source/disassembly: move_from / borrow_global_mut on a non-signer address, and destroy/burn entrypoints with no signer parameter."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('move_from\s*<\s*\w+\s*>\s*\(\s*(addr|address|account_addr|target)\b', 'address_of\s*\(\s*&?signer\)\s*==|assert!\([^)]*signer', 'move_resource_move_from_other', 'high', "Move entrypoint calls move_from on an address parameter that is not proven to be the signer's address - it can remove another account's resource", 'Derive the address from the signer (address_of(&signer)) and assert equality with any supplied address.'), ('borrow_global_mut\s*<[^>]+>\s*\(\s*(addr|account_addr|target)\b', None, 'move_resource_borrow_mut_other', 'medium', 'Move entrypoint mutably borrows a global resource at a caller-supplied address', "Borrow only at the signer's own address or verify ownership first."), ('(entry\s+)?fun\s+\w*(destroy|burn|take)\w*\s*\(\s*[a-z_]+\s*:', 'signer', 'move_resource_destroy_no_signer', 'high', 'A destroy/burn/take entrypoint takes no signer argument, so anyone can invoke it on resources it can reach', "Require the owner's signer on every resource-destroying entrypoint.")]
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


class MoveResourceTracer(Plugin):
    id = "move_resource_tracer"
    label = "Move Resource Tracer"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Maps per-entrypoint Move resource mutations and flags entrypoints that move/destroy other accounts' resources or lack signer checks."
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
