"""MEV / swap transaction parser (Tier-10, EigenPhi-style, ANALYSIS).

Parses a CONFIRMED transaction (by hash, from the target or the
shared bus) from its receipt logs: ERC20 Transfer flows and DEX swap
events are extracted into structured findings, and per-address net
token flows are summarized so profit-shaped patterns (one address
receiving multiple distinct assets while sending one) are visible.
This is historical ANALYSIS of an already-mined transaction: nothing
is submitted, copied or executed.
"""
from __future__ import annotations

from typing import Any, Dict

from . import _tier10_common as C
from .base import Cost, Ctx, Plugin, PluginResult, Target


def parse_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Pure parser: receipt dict -> transfers / swaps / net flows."""
    transfers = []
    swaps = 0
    flows: Dict[str, Dict[str, int]] = {}
    logs = receipt.get("logs") if isinstance(receipt, dict) else None
    for log in logs or []:
        if not isinstance(log, dict):
            continue
        topics = log.get("topics") or []
        if not topics:
            continue
        t0 = str(topics[0]).lower()
        token = (log.get("address") or "").lower()
        if t0 == C.TRANSFER_TOPIC and len(topics) >= 3:
            frm = "0x" + str(topics[1])[-40:]
            to = "0x" + str(topics[2])[-40:]
            try:
                value = int(log.get("data") or "0x0", 16)
            except ValueError:
                value = 0
            transfers.append({"token": token, "from": frm, "to": to,
                              "value": value})
            flows.setdefault(frm, {})
            flows.setdefault(to, {})
            flows[frm][token] = flows[frm].get(token, 0) - value
            flows[to][token] = flows[to].get(token, 0) + value
        elif t0 in (C.SWAP_V3_TOPIC, C.SYNC_TOPIC):
            swaps += 1
    return {"transfers": transfers, "swaps": swaps, "flows": flows}


class MevTxParserPlugin(Plugin):
    id = "mev_tx_parser"
    label = "MEV Transaction Parser (EigenPhi-style)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Parses a confirmed tx by hash (receipt logs) into "
                   "swap sequences, token transfers and per-address net "
                   "value flows for MEV analysis. Historical analysis "
                   "only; nothing is executed or copied.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        txhash = C.target_hash(target)
        if not txhash:
            shared = ctx.consume("tx_hashes") if hasattr(ctx, "consume") \
                else []
            txhash = shared[0] if shared else None
        if not txhash:
            return self._skipped(
                "needs a transaction hash in the target to parse")
        receipt, err = await C.rpc(
            ctx, "eth_getTransactionReceipt", [txhash])
        if not isinstance(receipt, dict):
            return self._degraded(f"receipt unreadable: {err}")
        parsed = parse_receipt(receipt)
        findings = []
        tx_obj, _ = await C.rpc(ctx, "eth_getTransactionByHash", [txhash])
        to = (tx_obj or {}).get("to") if isinstance(tx_obj, dict) else None
        findings.append(self._f(
            "web3", "mev_tx_summary",
            f"Tx {txhash}: {len(parsed['transfers'])} token transfers, "
            f"{parsed['swaps']} swap/sync events, to={to}",
            "MevTxParser", confidence=90,
            evidence={"severity": "low", "tx": txhash, "to": to,
                      "transfer_count": len(parsed["transfers"]),
                      "swap_events": parsed["swaps"],
                      "status": receipt.get("status"),
                      "remediation": "Analysis of a confirmed tx; use "
                                     "the flow summary to classify "
                                     "sandwich / arbitrage / ordinary "
                                     "swap behavior."}))
        for t in parsed["transfers"][:10]:
            findings.append(self._f(
                "web3", "mev_tx_transfer",
                f"Transfer {t['value']} of {t['token']} "
                f"{t['from']} -> {t['to']}", "MevTxParser", confidence=85,
                evidence={"severity": "low", "tx": txhash, **t,
                          "remediation": "Component flow of the parsed "
                                         "transaction."}))
        # Profit-shaped: one address net-receives >= 2 distinct tokens
        # and net-sends at most 1.
        for addr, by_token in parsed["flows"].items():
            received = [k for k, v in by_token.items() if v > 0]
            sent = [k for k, v in by_token.items() if v < 0]
            if len(received) >= 2 and len(sent) <= 1:
                findings.append(self._f(
                    "web3", "mev_profit_shaped_flow",
                    f"Profit-shaped flow: {addr} net-received "
                    f"{len(received)} distinct tokens, net-sent "
                    f"{len(sent)}", "MevTxParser", confidence=75,
                    evidence={"severity": "medium", "tx": txhash,
                              "address": addr,
                              "received_tokens": received,
                              "sent_tokens": sent,
                              "remediation": "Pattern matches extractor "
                                             "behavior; label the "
                                             "address in monitoring, "
                                             "analysis only."}))
        return self._ok(findings, f"{len(findings)} tx-parse findings")
