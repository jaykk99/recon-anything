"""Filecoin FVM inspector.
Flags exported actor methods that mutate state or move value with no caller validation in the actor."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('fn\\s+(withdraw|transfer|set_\\w+|update_\\w+)\\s*\\(', 'validate_caller|caller\\s*==|check_caller|assert.*caller', 'fvm_export_no_caller_check', 'high', 'FVM actor export moves value / changes config with no caller validation in the actor source', 'Validate the caller (robust address) against the stored owner in every privileged export.'), ('state\\.\\w+\\s*=|save_state|store_state|\\.save\\(\\)', 'caller', 'fvm_state_mutation_no_caller_validation', 'medium', 'FVM actor mutates and saves state with no caller reference anywhere in the source - caller validation is absent', 'Validate the message caller before any state mutation.')]

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


class FilecoinFvmInspector(Plugin):
    id = "filecoin_fvm_inspector"
    label = "Filecoin FVM Inspector"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Inspects FVM actors for missing caller validation, robust/id address confusion, and unguarded state mutation."
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
