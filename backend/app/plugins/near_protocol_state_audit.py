"""NEAR protocol state audit.
Flags callbacks not marked #[private], promise results consumed without a Failed check, and attached_deposit used without an assertion."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('fn\s+\w*callback\w*\s*\(', '#\[private\]', 'near_callback_not_private', 'high', 'NEAR callback function is not marked #[private] - anyone can call it directly and spoof a cross-contract result', 'Annotate every callback with #[private].'), ('PromiseResult|promise_result', 'Failed|NotReady', 'near_promise_result_unchecked', 'high', 'NEAR promise result is consumed without handling the Failed case - state is finalized on a possibly-failed cross-contract call', 'Match on PromiseResult and only finalize state on Successful; handle Failed/NotReady.'), ('attached_deposit', 'assert!|require!|assert_eq!', 'near_deposit_unchecked', 'medium', 'attached_deposit is read without any assertion - underpayment / deposit handling errors across shards', 'Assert the attached deposit covers the required amount before proceeding.')]

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


class NearProtocolStateAudit(Plugin):
    id = "near_protocol_state_audit"
    label = "NEAR Protocol State Audit"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Audits NEAR contracts for non-private callbacks, unchecked promise results, and deposit/gas handling errors."
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
