"""Chainlink data-feed listener (Tier-7, keyless live read).

Distinct remainder vs master: contract_audit/defi_risk flag
latestRoundData() in SOURCE CODE with no staleness check, and
chainlink_price_unbounded checks source patterns. Nobody reads the
LIVE feeds. This plugin eth_calls latestRoundData() on the canonical
mainnet aggregators via public RPC and reports the live price plus
staleness (now - updatedAt): a stale feed is the on-chain condition
that breaks lending/liquidation logic downstream. Read-only.
"""
from __future__ import annotations

import time

from .base import Cost, Ctx, Plugin, PluginResult, Target

RPC = "https://ethereum-rpc.publicnode.com"
SELECTOR = "0xfeaf968c"  # latestRoundData()
FEEDS = {
    "ETH/USD": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
    "BTC/USD": "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c",
    "LINK/USD": "0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c",
}
STALE_S = 3600


def decode_round(data_hex: str):
    """Decode (roundId, answer, startedAt, updatedAt, answeredInRound)."""
    h = data_hex[2:] if data_hex.startswith("0x") else data_hex
    if len(h) < 64 * 5:
        return None
    words = [int(h[i * 64:(i + 1) * 64], 16) for i in range(5)]
    answer = words[1] - (1 << 256) if words[1] >= (1 << 255) else words[1]
    return {"round_id": words[0], "answer": answer,
            "updated_at": words[3]}


class ChainlinkFeedsPlugin(Plugin):
    id = "chainlink_feeds"
    label = "Chainlink Data Feeds Listener"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = ("Reads live Chainlink aggregator feeds "
                   "(latestRoundData via public RPC) for ETH/USD, "
                   "BTC/USD and LINK/USD on Ethereum mainnet and "
                   "reports price plus staleness. Keyless, read-only.")
    phase = 1
    timeout_s = 60

    async def _read(self, ctx, feed):
        resp = await ctx.http.post(RPC, json={
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{"to": feed, "data": SELECTOR}, "latest"]},
            timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        result = data.get("result") if isinstance(data, dict) else None
        if not result or result == "0x":
            return None
        return decode_round(result)

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings = []
        reached = False
        now = int(time.time())
        for pair, feed in FEEDS.items():
            try:
                r = await self._read(ctx, feed)
            except Exception:
                r = None
            if not r:
                continue
            reached = True
            age = max(0, now - r["updated_at"])
            price = r["answer"] / 1e8
            findings.append(self._f(
                "web3", "chainlink_feed_price",
                f"{pair} = {price:.2f} (round {r['round_id']}, "
                f"age {age}s)", "ChainlinkFeed", confidence=90,
                evidence={"severity": "low", "pair": pair, "feed": feed,
                          "price": price, "age_s": age,
                          "round_id": r["round_id"],
                          "remediation": "Consumers must check "
                                         "updatedAt staleness and "
                                         "answeredInRound >= roundId "
                                         "before trusting this price."}))
            if age > STALE_S:
                findings.append(self._f(
                    "web3", "chainlink_stale_feed",
                    f"{pair} feed stale: updated {age}s ago",
                    "ChainlinkFeed", confidence=90,
                    evidence={"severity": "high", "pair": pair,
                              "feed": feed, "age_s": age,
                              "remediation": "Stale feed: downstream "
                                             "protocols pricing off it "
                                             "can be drained via "
                                             "mispriced liquidations. "
                                             "Pause consumers until the "
                                             "feed updates."}))
        if not reached:
            return self._degraded("public RPC did not answer feed reads")
        return self._ok(findings, f"{len(findings)} feed findings")
