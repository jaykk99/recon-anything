"""Starknet Cairo disassembly / audit.
Flags CASM-only deployments (no Sierra available for audit), and Cairo external entrypoints that move value or write storage with no caller check."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


def analyze_artifact(text):
    hits = []
    if not text:
        return hits
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if isinstance(data, dict) and ("casm" in data or "sierra" in data):
        if data.get("casm") and not data.get("sierra"):
            hits.append({"key": "starknet_casm_only_no_sierra",
                "value": "Starknet class is deployed as CASM only with no Sierra program available - the deployed code cannot be audited at the Sierra level",
                "severity": "medium",
                "remediation": "Publish / verify the Sierra class so the deployment can be audited."})
        return hits
    if re.search(r"(withdraw|transfer|mint)\s*\(", text) and not re.search(r"get_caller_address|caller.*assert|assert.*caller", text, re.I):
        hits.append({"key": "cairo_unguarded_value_entrypoint",
            "value": "Cairo external entrypoint moves value (withdraw/transfer/mint) with no get_caller_address check in the contract",
            "severity": "high",
            "remediation": "Assert get_caller_address() equals the stored owner/authorized caller in every value entrypoint."})
    if re.search(r"\.write\s*\(", text) and not re.search(r"get_caller_address|assert", text, re.I):
        hits.append({"key": "cairo_storage_write_no_auth",
            "value": "Cairo contract writes storage with no caller assertion anywhere in the source",
            "severity": "medium",
            "remediation": "Gate storage writes on a caller/owner assertion."})
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


class StarknetCairoDisasm(Plugin):
    id = "starknet_cairo_disasm"
    label = "Starknet Cairo Disassembler"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Decodes Starknet Sierra/CASM artifacts and flags CASM-only deployments and unguarded Cairo entrypoints."
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
