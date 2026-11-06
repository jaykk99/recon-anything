"""CosmWasm actor analyzer.
Flags reply handlers that swallow submessage results, ReplyOn::Never on value submessages, unwrap on instantiate/migrate results, and IBC entrypoints with no admin/auth check."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('fn reply[\s\S]{0,500}?Ok\s*\(\s*Response::new\(\)\s*\)', None, 'cosmwasm_reply_error_swallowed', 'high', 'CosmWasm reply handler returns Ok(Response::new()) regardless of the submessage result - failed submessages are silently swallowed', 'Match on the reply result and propagate or record failures before finalizing state.'), ('reply_on\s*:\s*ReplyOn::Never', None, 'cosmwasm_submsg_no_reply', 'medium', 'SubMsg is dispatched with ReplyOn::Never, so its failure can never be observed by this contract', 'Use ReplyOn::Error / Always for value-moving submessages and handle the reply.'), ('(instantiate|migrate)[\s\S]{0,250}?\.unwrap\(\)', None, 'cosmwasm_unchecked_instantiate_result', 'medium', 'Instantiate/migrate result is unwrapped - a failed sub-instantiation panics or is mishandled instead of being checked', 'Check instantiate/migrate results explicitly and handle errors.'), ('fn ibc_\w+', 'ensure|check_admin|assert|admin', 'cosmwasm_ibc_entrypoint_exposed', 'medium', 'IBC entrypoint is exposed with no admin / channel authorization check in the contract', 'Gate IBC entrypoints on the expected channel/port and caller.')]

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


class CosmwasmActorAnalyzer(Plugin):
    id = "cosmwasm_actor_analyzer"
    label = "CosmWasm Actor Analyzer"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Analyzes CosmWasm instantiate/execute/reply entrypoints: swallowed submessage errors, unchecked instantiate, exposed IBC entrypoints."
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
