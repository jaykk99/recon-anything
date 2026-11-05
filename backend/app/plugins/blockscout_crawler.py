"""Blockscout API crawler for an address (Tier-7).

No Blockscout coverage exists on master (dee4763, grep: zero hits).
chain_osint enriches via Blockchair + Etherscan only. Blockscout's
open v2 API (keyless, self-hostable instances) exposes transactions,
token transfers and internal transactions in one crawl; this plugin
summarizes that activity as findings: dormant-vs-active posture,
internal-call surface, and token-transfer breadth. Read-only.
"""
from __future__ import annotations

import re
from typing import List

from .base import Cost, Ctx, Plugin, PluginResult, Target

ADDR_RX = re.compile(r"0x[a-fA-F0-9]{40}")
INSTANCES = ["https://eth.blockscout.com",
             "https://base.blockscout.com",
             "https://gnosis.blockscout.com"]


def extract_addresses(target: Target, ctx: Ctx) -> List[str]:
    out: List[str] = []
    for cand in [target.raw or "", target.normalized or ""]:
        out += ADDR_RX.findall(cand)
    for item in ctx.consume("contract_addresses"):
        s = item if isinstance(item, str) else str(
            item.get("address", "") if isinstance(item, dict) else item)
        out += ADDR_RX.findall(s)
    seen, uniq = set(), []
    for a in out:
        if a.lower() not in seen:
            seen.add(a.lower())
            uniq.append(a)
    return uniq[:4]


class BlockscoutCrawlerPlugin(Plugin):
    id = "blockscout_crawler"
    label = "Blockscout Crawler"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = ("Crawls a Blockscout v2 instance for an address: "
                   "transaction, token-transfer and internal-tx "
                   "summaries as findings. Keyless.")
    phase = 2
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        addrs = extract_addresses(target, ctx)
        if not addrs:
            return self._skipped("no EVM address in target or bus")
        findings = []
        reached = False
        for addr in addrs:
            for base in INSTANCES:
                try:
                    info = await self._get(ctx, f"{base}/api/v2/addresses/{addr}")
                except Exception:
                    info = None
                if info is None:
                    continue
                reached = True
                findings += await self._crawl(ctx, base, addr, info)
                break
        if not findings:
            if not reached:
                return self._degraded("Blockscout instances unreachable "
                                       "from this host")
            return self._ok([], "address known but no activity summary")
        return self._ok(findings, f"{len(findings)} blockscout findings")

    async def _get(self, ctx, url):
        resp = await ctx.http.get(url, timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None

    async def _crawl(self, ctx, base, addr, info):
        out = []
        counters = {}
        try:
            c = await self._get(ctx, f"{base}/api/v2/addresses/{addr}/counters")
            counters = c or {}
        except Exception:
            counters = {}
        tx_count = counters.get("transactions_count")
        if tx_count is not None:
            out.append(self._f(
                "web3", "blockscout_tx_summary",
                f"{addr}: {tx_count} transactions, "
                f"{counters.get('token_transfers_count', 0)} token "
                f"transfers, {counters.get('internal_transactions_count', 0)} "
                "internal txs",
                "Blockscout", confidence=85,
                evidence={"severity": "low", "address": addr,
                          "instance": base, "counters": counters,
                          "remediation": "Review internal-transaction "
                                         "volume: heavy internal-call "
                                         "surface warrants a call-graph "
                                         "audit of the contract."}))
        internal = counters.get("internal_transactions_count") or 0
        try:
            internal = int(internal)
        except Exception:
            internal = 0
        if internal > 1000:
            out.append(self._f(
                "web3", "blockscout_heavy_internal_calls",
                f"{addr}: {internal} internal transactions",
                "Blockscout", confidence=80,
                evidence={"severity": "medium", "address": addr,
                          "internal_transactions": internal,
                          "remediation": "Map the internal call graph; "
                                         "delegatecall-heavy flows are a "
                                         "common upgrade-risk surface."}))
        if info.get("is_contract"):
            out.append(self._f(
                "web3", "blockscout_contract_identity",
                f"{addr}: contract {info.get('name') or '(unnamed)'} "
                f"verified={bool(info.get('is_verified'))}",
                "Blockscout", confidence=85,
                evidence={"severity": "low", "address": addr,
                          "name": info.get("name"),
                          "verified": bool(info.get("is_verified")),
                          "remediation": "Unverified contracts on "
                                         "Blockscout should be verified "
                                         "for user trust."}))
        return out
