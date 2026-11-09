"""Sui programmable transaction block audit.
Parses a PTB JSON artifact: flags DEX/router MoveCalls with no slippage or deadline argument, and mutable shared objects reused across commands."""
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
        return hits
    cmds = []
    if isinstance(data, list):
        cmds = data
    elif isinstance(data, dict):
        cmds = data.get("commands") or data.get("transactions") or []
    shared_mutable = {}
    for i, c in enumerate(cmds):
        if not isinstance(c, dict):
            continue
        kind = str(c.get("kind") or c.get("type") or "")
        target = str(c.get("target") or "")
        blob = json.dumps(c).lower()
        if ("movecall" in kind.lower() or "swap" in target.lower() or "router" in blob or "::dex::" in blob or "swap" in blob):
            if not any(k in blob for k in ("min_out", "min_amount", "slippage", "deadline", "min_return")):
                hits.append({"key": "sui_ptb_swap_no_slippage",
                    "value": f"Sui PTB command {i} calls a DEX/swap path ({target or kind}) with no slippage (min_out) or deadline argument - sandwich / value-leak exposure",
                    "severity": "high",
                    "remediation": "Pass an explicit minimum-output and deadline to every swap command in a PTB."})
        for m in re.finditer(r'"sharedObjectId"\s*:\s*"([^"]+)"', json.dumps(c)):
            if '"mutable"\\s*:\\s*true' in json.dumps(c) or '"mutable": true' in json.dumps(c):
                shared_mutable.setdefault(m.group(1), []).append(i)
    for oid, idxs in shared_mutable.items():
        if len(idxs) > 1:
            hits.append({"key": "sui_ptb_shared_object_contention",
                "value": f"Shared object {oid} is mutably used by {len(idxs)} PTB commands - contention / ordering abuse surface",
                "severity": "medium",
                "remediation": "Minimise mutable shared-object use per PTB or sequence commands so ordering cannot be abused."})
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


class SuiProgrammableTxAudit(Plugin):
    id = "sui_programmable_tx_audit"
    label = "Sui Programmable Tx Audit"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Audits Sui programmable transaction blocks for DEX calls without slippage/deadline and shared-object contention."
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
