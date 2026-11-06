"""Anchor IDL decoder (variant of solana_contract).
Delta: IDL input mode - parse IDL JSON, render instructions/accounts, flag sensitive instructions with no signer account or authority accounts not marked isSigner. Pure local analysis."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


SENSITIVE = re.compile(r"withdraw|transfer|mint|burn|close|redeem|claim|burn|drain", re.I)
AUTH_NAMES = ("authority", "owner", "admin", "signer", "payer")

def analyze_artifact(text):
    hits = []
    if not text:
        return hits
    try:
        data = json.loads(text)
    except Exception:
        return hits
    if not isinstance(data, dict):
        return hits
    for ix in data.get("instructions") or []:
        if not isinstance(ix, dict):
            continue
        name = str(ix.get("name") or "")
        accounts = [a for a in (ix.get("accounts") or []) if isinstance(a, dict)]
        has_signer = any(a.get("isSigner") for a in accounts)
        for a in accounts:
            an = str(a.get("name") or "").lower()
            if an in AUTH_NAMES and not a.get("isSigner"):
                hits.append({"key": "anchor_authority_not_signer",
                    "value": f"Anchor IDL instruction '{name}': account '{a.get('name')}' is an authority account but isSigner is false, so the program cannot rely on it having signed",
                    "severity": "high",
                    "remediation": "Mark authority accounts as signers in the IDL and enforce signer checks in the handler."})
        if SENSITIVE.search(name) and not has_signer:
            hits.append({"key": "anchor_sensitive_instruction_no_signer",
                "value": f"Anchor IDL instruction '{name}' moves value but declares no signer account at all",
                "severity": "high",
                "remediation": "Require a signer account for every value-moving instruction and check it against stored authority."})
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


class SolanaAnchorDecoder(Plugin):
    id = "solana_anchor_decoder"
    label = "Solana Anchor IDL Decoder"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Variant of solana_contract: parses an Anchor IDL and flags instructions whose sensitive actions lack a signer account."
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
