"""Cardano Plutus evaluation.
Anchor-gated missing-check analysis: a validator that never finds its own input (double satisfaction), never checks the datum, or never verifies value paid out."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


def analyze_artifact(text):
    hits = []
    if not text or not re.search(r"validator|minting_policy|Plutus|aiken|fn\s+spend", text, re.I):
        return hits
    if not re.search(r"findOwnInput|find_own_input|own_input", text):
        hits.append({"key": "plutus_double_satisfaction_risk",
            "value": "Plutus validator never identifies its own input (findOwnInput) - one satisfying input can validate spending of multiple UTXOs (double satisfaction)",
            "severity": "high",
            "remediation": "Find the own input and bind all checks to that specific UTXO."})
    if not re.search(r"datum|Datum", text):
        hits.append({"key": "plutus_datum_not_validated",
            "value": "Plutus validator never inspects the datum - state carried in the UTXO is unvalidated",
            "severity": "medium",
            "remediation": "Decode and validate the datum in every spend path."})
    if not re.search(r"valuePaidTo|value_paid_to|lovelaceValueOf|quantity_of|assetClassValueOf", text):
        hits.append({"key": "plutus_value_preservation_missing",
            "value": "Plutus validator never checks value paid to an address / value preservation - inputs can be drained while the script still validates",
            "severity": "high",
            "remediation": "Assert the required value is paid to the script / beneficiary in every spend."})
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


class CardanoPlutusEval(Plugin):
    id = "cardano_plutus_eval"
    label = "Cardano Plutus Eval"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Evaluates Plutus/Aiken validators for datum/redeemer gaps, double-satisfaction shapes, and missing value-preservation checks."
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
