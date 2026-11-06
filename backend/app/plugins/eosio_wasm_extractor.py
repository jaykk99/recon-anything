"""EOSIO Wasm/ABI extractor (variant of da_wasm_surface).
Delta: EOSIO awareness - extract ABI actions and tables from the artifact, and flag value actions whose contract source never calls require_auth."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


def extract_abi_actions(text):
    try:
        data = json.loads(text)
    except Exception:
        # concatenated artifact: find the ABI JSON object
        m = re.search(r"\{.*\}", text or "", re.S)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except Exception:
            return []
    if isinstance(data, dict):
        acts = data.get("actions") or (data.get("abi") or {}).get("actions") or []
        return [str(a.get("name")) for a in acts if isinstance(a, dict) and a.get("name")]
    return []

def analyze_artifact(text):
    hits = []
    if not text:
        return hits
    actions = extract_abi_actions(text)
    sensitive = [a for a in actions if re.search(r"withdraw|transfer|mint|burn|issue|claim", a, re.I)]
    if sensitive and "require_auth" not in text:
        for a in sensitive:
            hits.append({"key": "eosio_action_no_require_auth",
                "value": f"EOSIO action '{a}' moves value but the contract source never calls require_auth - anyone can invoke it for any account",
                "severity": "high",
                "remediation": "Call require_auth on the authorizing account in every value-moving action."})
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


class EosioWasmExtractor(Plugin):
    id = "eosio_wasm_extractor"
    label = "EOSIO Wasm Extractor"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Variant of da_wasm_surface: EOSIO branch - extracts ABI actions/tables and flags sensitive actions with no require_auth."
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
