"""Mempool sniffer (Tier-10 core plugin, MONITORING ONLY).

Polls the pending block over HTTPS JSON-RPC (eth_getBlockByNumber
"pending", with a txpool_content fallback where the node exposes it),
classifies a bounded sample of pending transactions (swaps, approvals
- including unlimited approvals - large transfers, calls to watched
contracts such as DEX routers / Aave / Permit2, and anything touching
a target address), and emits findings for the notable classes.

Read-only observation only: it never builds, signs, broadcasts or
front-runs anything. WebSocket subscription is deliberately not used;
HTTP polling works keyless through ordinary HTTPS egress.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import _tier10_common as C
from .base import Cost, Ctx, Plugin, PluginResult, Target

SAMPLE = 200


def parse_pending(result: Any) -> List[Dict[str, Any]]:
    """Extract a tx list from a pending-block or txpool_content result."""
    if isinstance(result, dict):
        txs = result.get("transactions")
        if isinstance(txs, list):
            return [t for t in txs if isinstance(t, dict)]
        pending = result.get("pending")
        if isinstance(pending, dict):  # txpool_content shape
            out = []
            for by_nonce in pending.values():
                if isinstance(by_nonce, dict):
                    out.extend(t for t in by_nonce.values()
                               if isinstance(t, dict))
            return out
    return []


class MempoolSnifferPlugin(Plugin):
    id = "mempool_sniffer"
    label = "Mempool Sniffer (Pending-Tx Monitor)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Polls the Ethereum pending block over HTTPS RPC, "
                   "classifies a bounded sample of pending txs (swaps, "
                   "approvals, large transfers, watched-contract calls, "
                   "target-address touches) and reports notable classes. "
                   "Read-only monitoring; no broadcasting.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        watch = C.target_address(target)
        result, err = await C.rpc(ctx, "eth_getBlockByNumber",
                                  ["pending", True])
        source = "eth_getBlockByNumber(pending)"
        if result is None:
            result, err = await C.rpc(ctx, "txpool_content", [])
            source = "txpool_content"
        txs = parse_pending(result)
        if result is None:
            return self._degraded(f"pending pool unreadable: {err}")
        if not txs:
            return self._ok([], "pending pool empty in this sample")
        findings = []
        counts: Dict[str, int] = {}
        for tx in txs[:SAMPLE]:
            info = C.classify_tx(tx)
            counts[info["class"]] = counts.get(info["class"], 0) + 1
            frm = (tx.get("from") or "").lower()
            to = (tx.get("to") or "").lower()
            touches = watch and watch.lower() in (frm, to)
            if info["unlimited_approval"]:
                findings.append(self._f(
                    "web3", "mempool_unlimited_approval_pending",
                    f"Pending UNLIMITED approval to {info['spender']} "
                    f"(tx {tx.get('hash', '?')})", "MempoolSniffer",
                    confidence=85,
                    evidence={"severity": "high", "tx": tx.get("hash"),
                              "spender": info["spender"],
                              "remediation": "An unlimited approval is "
                                             "about to go live; the owner "
                                             "should revoke or reduce it "
                                             "unless the spender is fully "
                                             "trusted."}))
            if touches:
                findings.append(self._f(
                    "web3", "mempool_target_tx_pending",
                    f"Pending {info['class']} tx touches target address "
                    f"{watch} (tx {tx.get('hash', '?')})",
                    "MempoolSniffer", confidence=90,
                    evidence={"severity": "medium", "tx": tx.get("hash"),
                              "class": info["class"],
                              "remediation": "Target address has live "
                                             "mempool activity; review "
                                             "before it confirms."}))
            if info["value_wei"] >= C.LARGE_VALUE_WEI:
                findings.append(self._f(
                    "web3", "mempool_large_value_pending",
                    f"Pending transfer of "
                    f"{info['value_wei'] / 1e18:.2f} ETH "
                    f"(tx {tx.get('hash', '?')})", "MempoolSniffer",
                    confidence=80,
                    evidence={"severity": "medium", "tx": tx.get("hash"),
                              "value_wei": info["value_wei"],
                              "remediation": "Large pending value move; "
                                             "monitoring observation only."}))
            if info["watched"] and info["class"] == "swap":
                findings.append(self._f(
                    "web3", "mempool_watched_swap_pending",
                    f"Pending swap via {info['watched']} "
                    f"(tx {tx.get('hash', '?')})", "MempoolSniffer",
                    confidence=70,
                    evidence={"severity": "low", "tx": tx.get("hash"),
                              "contract": info["watched"],
                              "remediation": "Mempool flow observation "
                                             "for MEV exposure analysis."}))
        findings.append(self._f(
            "web3", "mempool_sample_summary",
            f"Pending sample via {source}: {len(txs[:SAMPLE])} txs, "
            f"classes {counts}", "MempoolSniffer", confidence=75,
            evidence={"severity": "low", "source_method": source,
                      "sampled": len(txs[:SAMPLE]), "counts": counts,
                      "remediation": "Baseline mempool composition for "
                                     "this scan window."}))
        return self._ok(findings, f"{len(findings)} mempool findings")
