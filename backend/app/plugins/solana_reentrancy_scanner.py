"""Solana reentrancy (CPI) scanner.
Flags a cross-program invocation that happens before local state is written/finalized, and the same mutable account passed twice into one instruction."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


def analyze_artifact(text):
    hits = []
    if not text:
        return hits
    cpi = re.search(r"invoke\s*\(|invoke_signed\s*\(|CpiContext::new|transfer_checked|\.cpi\s*\(", text)
    writes = [m.start() for m in re.finditer(r"\.save\s*\(\)|state\.\w+\s*=[^=]|account\.\w+\s*=[^=]|\.reload\s*\(", text)]
    if cpi and writes and cpi.start() < max(writes) and not re.search(r"\.reload\s*\(", text):
        hits.append({"key": "solana_cpi_before_state_finalized",
            "value": "Cross-program invocation occurs before local state is finalized/written, so a callback into this program can observe and exploit stale state (Solana CPI re-entry shape)",
            "severity": "high",
            "remediation": "Finalize local state before the CPI (checks-effects-interactions) and reload accounts after the CPI."})
    m = re.search(r"accounts\.(\w+)[\s\S]{0,100}accounts\.\1\b", text)
    if m:
        hits.append({"key": "solana_duplicate_mutable_account",
            "value": f"The same mutable account '{m.group(1)}' is passed twice into one instruction / CPI, enabling aliasing and double-spend style accounting errors",
            "severity": "medium",
            "remediation": "Reject duplicate mutable accounts or alias-check them before the CPI."})
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


class SolanaReentrancyScanner(Plugin):
    id = "solana_reentrancy_scanner"
    label = "Solana Reentrancy Scanner"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Maps Solana CPIs and flags re-entry shapes: CPI before state finalization, duplicate mutable accounts."
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
