"""Avalanche subnet verifier.
Flags Warp message receivers that never check the signer quorum / BLS threshold, and Teleporter receivers with no relayer/source verification."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('getVerifiedWarpMessage|receiveWarpMessage|WarpMessage', 'quorum|signer|BLS|bls|threshold', 'avalanche_warp_no_quorum_check', 'high', 'Contract receives Warp messages without checking the validator signer quorum / BLS threshold - forged cross-subnet messages may be accepted', 'Verify the Warp message against the subnet validator set and required quorum.'), ('receiveCrossChainMessage|TeleporterMessage|ITeleporterReceiver', 'relayer|verify.*source|check.*origin|source.*subnet', 'avalanche_teleporter_relayer_trust', 'medium', 'Teleporter receiver trusts delivered messages with no relayer / source-subnet verification in the contract', 'Verify the source blockchain/subnet and authorised relayer for every Teleporter message.')]

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


class AvalancheSubnetVerifier(Plugin):
    id = "avalanche_subnet_verifier"
    label = "Avalanche Subnet Verifier"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Verifies cross-subnet messaging hooks: Warp message quorum checks and Teleporter relayer trust in receiving contracts."
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
