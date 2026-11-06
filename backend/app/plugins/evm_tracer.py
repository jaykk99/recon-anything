"""EVM call tracer (Tier-10, Geth debug_traceTransaction, ANALYSIS).

Requests a callTracer trace for a confirmed tx hash and parses the
call tree locally: call counts by type, DELEGATECALLs, calls into
known contracts, reverted subcalls and moved value are reported as
structured findings. Public RPCs gate debug_ methods on many plans;
when the method is unavailable the plugin degrades cleanly WITH the
RPC error as evidence instead of failing. Trace PARSING only — no
transaction is ever sent.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import _tier10_common as C
from .base import Cost, Ctx, Plugin, PluginResult, Target


def parse_trace(node: Any, depth: int = 0, out: Dict[str, Any] = None
                ) -> Dict[str, Any]:
    """Flatten a callTracer tree into counts (pure function)."""
    if out is None:
        out = {"total": 0, "by_type": {}, "delegatecalls": [],
               "known": [], "reverted": 0, "value_wei": 0}
    if not isinstance(node, dict) or depth > 40:
        return out
    out["total"] += 1
    ctype = str(node.get("type") or "CALL")
    out["by_type"][ctype] = out["by_type"].get(ctype, 0) + 1
    to = (node.get("to") or "").lower()
    if ctype == "DELEGATECALL":
        out["delegatecalls"].append(to)
    if to in C.WATCHED_CONTRACTS:
        out["known"].append({"to": to, "name": C.WATCHED_CONTRACTS[to],
                             "type": ctype})
    if node.get("error"):
        out["reverted"] += 1
    try:
        out["value_wei"] += int(node.get("value") or "0x0", 16)
    except (TypeError, ValueError):
        pass
    for child in node.get("calls") or []:
        parse_trace(child, depth + 1, out)
    return out


class EvmTracerPlugin(Plugin):
    id = "evm_tracer"
    label = "EVM Tracer (callTracer Parser)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Parses debug_traceTransaction callTracer output "
                   "for a tx hash into call-tree findings (delegatecalls, "
                   "known-contract calls, reverts, value). Degrades "
                   "cleanly when the RPC gates debug_ methods. "
                   "Parsing only.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        txhash = C.target_hash(target)
        if not txhash:
            shared = ctx.consume("tx_hashes") if hasattr(ctx, "consume") \
                else []
            txhash = shared[0] if shared else None
        if not txhash:
            return self._skipped("needs a transaction hash to trace")
        trace, err = await C.rpc(
            ctx, "debug_traceTransaction",
            [txhash, {"tracer": "callTracer"}])
        if not isinstance(trace, dict):
            return self._degraded(
                f"debug_traceTransaction unavailable on public RPCs: "
                f"{err}")
        parsed = parse_trace(trace)
        findings = [self._f(
            "web3", "evm_trace_summary",
            f"Trace {txhash}: {parsed['total']} calls "
            f"{parsed['by_type']}, {parsed['reverted']} reverted, "
            f"value moved {parsed['value_wei'] / 1e18:.4f} ETH",
            "EvmTracer", confidence=90,
            evidence={"severity": "low", "tx": txhash,
                      "total_calls": parsed["total"],
                      "by_type": parsed["by_type"],
                      "reverted": parsed["reverted"],
                      "value_wei": parsed["value_wei"],
                      "remediation": "Call-tree shape for exploit / "
                                     "MEV path analysis."})]
        for dc in parsed["delegatecalls"][:5]:
            findings.append(self._f(
                "web3", "evm_trace_delegatecall",
                f"DELEGATECALL into {dc} in tx {txhash}",
                "EvmTracer", confidence=85,
                evidence={"severity": "medium", "tx": txhash, "to": dc,
                          "remediation": "Delegatecall targets execute "
                                         "in caller storage context; "
                                         "verify the target is trusted "
                                         "and immutable or governed."}))
        for k in parsed["known"][:5]:
            findings.append(self._f(
                "web3", "evm_trace_known_contract",
                f"{k['type']} into known contract {k['name']} "
                f"({k['to']})", "EvmTracer", confidence=80,
                evidence={"severity": "low", "tx": txhash, **k,
                          "remediation": "Known-protocol interaction "
                                         "inside the traced execution "
                                         "path."}))
        return self._ok(findings, f"{len(findings)} trace findings")
