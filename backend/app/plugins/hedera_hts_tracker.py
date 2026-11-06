"""Hedera HTS tracker.
Parses mirror-node token-info JSON: flags wipe/freeze/supply/KYC/fee-schedule keys held by a plain account (not a key list / threshold key)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


KEYS = (("wipe_key", "high", "wipe holder balances"), ("supply_key", "high", "mint/burn supply"), ("freeze_key", "medium", "freeze accounts"), ("kyc_key", "medium", "grant/revoke KYC"), ("fee_schedule_key", "medium", "change custom fees"), ("pause_key", "medium", "pause all transfers"))

def _is_single_account(keyval):
    if keyval is None:
        return False
    if isinstance(keyval, str):
        return True
    if isinstance(keyval, dict):
        t = str(keyval.get("_type") or keyval.get("type") or "")
        if "KeyList" in t or "ThresholdKey" in t:
            return False
        return True
    return True

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
    for k, sev, power in KEYS:
        if k in data and _is_single_account(data.get(k)):
            hits.append({"key": f"hts_{k}_single_holder",
                "value": f"Hedera HTS token holds a live {k} with a single-account key - that key can {power}",
                "severity": sev,
                "remediation": f"Replace the {k} with a threshold/key-list key or remove it if the power is not needed."})
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


class HederaHtsTracker(Plugin):
    id = "hedera_hts_tracker"
    label = "Hedera HTS Tracker"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Tracks Hedera HTS token configuration: supply/freeze/wipe/KYC/fee keys, who holds them, and treasury centralization."
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
