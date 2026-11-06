"""Flow Cadence analyzer.
Flags account capabilities linked at a public path that borrow privileged resources, and privileged resource functions with no entitlement / restricted access."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('\.link\s*<[^>]+>\s*\(\s*/public/|save\s*\([^)]*/public/', '/private/|PrivatePath', 'cadence_public_capability_privileged', 'high', "Cadence capability is linked at a /public/ path, so anyone can borrow it and reach the linked resource's functions", 'Link privileged capabilities at /private/ paths and issue them only to trusted accounts.'), ('pub\s+fun\s+(withdraw|transfer|mint|destroy)\w*\s*\(', 'entitlement|access\(self\)|access\(Contract\)|auth\(', 'cadence_privileged_fn_no_entitlement', 'high', 'Cadence privileged resource function (withdraw/transfer/mint/destroy) is declared pub with no entitlement or restricted access', 'Declare privileged functions with entitlements (access(Entitlement)) or access(self).')]

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


class FlowCadenceAnalyzer(Plugin):
    id = "flow_cadence_analyzer"
    label = "Flow Cadence Analyzer"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Analyzes Cadence contracts for public capabilities reaching privileged functions and missing entitlements."
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
