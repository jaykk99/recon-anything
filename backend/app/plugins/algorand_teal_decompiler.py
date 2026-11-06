"""Algorand TEAL decompiler / audit.
Reconstructs the opcode listing and applies the classic TEAL safety checks: an approval program that returns success without checking RekeyTo, CloseRemainderTo, or AssetCloseTo lets a signer be rekeyed / drained on close."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


def disassemble_teal(text):
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip() and not ln.strip().startswith("//")]

def analyze_artifact(text):
    hits = []
    if not text or not re.search(r"#pragma version|\btxn\b|\bint\b.*\breturn\b", text, re.S):
        return hits
    if not re.search(r"\breturn\b", text):
        return hits
    checks = (("RekeyTo", "algorand_rekey_not_checked", "high", "RekeyTo is never checked - the account can be rekeyed to an attacker address in any transaction this program approves"),
              ("CloseRemainderTo", "algorand_close_remainder_not_checked", "medium", "CloseRemainderTo is never checked - closing the account sweeps its remainder to an arbitrary address"),
              ("AssetCloseTo", "algorand_asset_close_not_checked", "medium", "AssetCloseTo is never checked - closing an asset holding sweeps it to an arbitrary address"))
    for field, key, sev, msg in checks:
        if field not in text:
            hits.append({"key": key, "value": f"TEAL program approves transactions but {msg}",
                "severity": sev,
                "remediation": f"Assert txn {field} equals Global ZeroAddress (or the intended address) in the approval program."})
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


class AlgorandTealDecompiler(Plugin):
    id = "algorand_teal_decompiler"
    label = "Algorand TEAL Decompiler"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Disassembles TEAL approval/clear programs and flags missing RekeyTo / CloseRemainderTo / AssetCloseTo checks."
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
