"""Optimism Bedrock differ (variant lane).
Consumes an L1/L2 state snapshot JSON ({l1:{...}, l2:{...}}) and reports config mismatches and relayed block-number/timestamp lag."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


CONFIG_KEYS = ("sequencer", "sequencer_address", "batch_inbox", "batchInbox", "gas_limit", "gasLimit", "base_fee_scalar", "blob_base_fee_scalar")

def analyze_artifact(text):
    hits = []
    if not text:
        return hits
    try:
        data = json.loads(text)
    except Exception:
        return hits
    if not isinstance(data, dict) or "l1" not in data or "l2" not in data:
        return hits
    l1, l2 = data.get("l1") or {}, data.get("l2") or {}
    for k in CONFIG_KEYS:
        if k in l1 and k in l2 and str(l1[k]).lower() != str(l2[k]).lower():
            hits.append({"key": "bedrock_config_mismatch",
                "value": f"Optimism Bedrock config mismatch for '{k}': L1 reports {l1[k]} but L2 reports {l2[k]}",
                "severity": "high",
                "remediation": "Reconcile the SystemConfig value on L1 with the value relayed to L2; investigate sequencer/batcher config drift."})
    try:
        lag = abs(int(l1.get("block_number", l1.get("blockNumber", 0))) - int(l2.get("block_number", l2.get("blockNumber", 0))))
        if lag > 50:
            hits.append({"key": "bedrock_relayed_block_lag",
                "value": f"L1 block relayed to L2 lags by {lag} blocks - L2 is operating on stale L1 state",
                "severity": "medium",
                "remediation": "Check the L1Block relay / sequencer: L2 should track L1 within a few blocks."})
    except Exception:
        pass
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


class OptimismBedrockDiffer(Plugin):
    id = "optimism_bedrock_differ"
    label = "Optimism Bedrock Differ"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Variant: Optimism Bedrock L1/L2 cross-layer diff - reports config discrepancies and relayed-block lag between L1 system contracts and L2."
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
