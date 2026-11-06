"""MEV-Share / Flashbots bundle-inclusion monitor (Tier-10, READER).

Reads the public Flashbots blocks API (blocks.flashbots.net) for the
most recent blocks produced through the Flashbots relay: bundle
counts, transactions per block and miner/coinbase value are turned
into inclusion statistics. This is the MEV-Share era relay-health
view: monitoring only — no bundles are built, simulated for
submission, or sent, and no MEV-Share events are subscribed to on the
user's behalf. If the public API is gone, the plugin degrades cleanly
with the HTTP evidence.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target

BLOCKS_API = "https://blocks.flashbots.net/v1/blocks"


def parse_blocks(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        blocks = payload.get("blocks")
        if isinstance(blocks, list):
            return [b for b in blocks if isinstance(b, dict)]
    if isinstance(payload, list):
        return [b for b in payload if isinstance(b, dict)]
    return []


class MevShareStatusPlugin(Plugin):
    id = "mev_share_status"
    label = "MEV-Share / Relay Inclusion Monitor"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Read-only reader of recent Flashbots relay block / "
                   "bundle inclusion stats (public blocks API) for "
                   "MEV-Share era relay health monitoring. No bundle "
                   "submission.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            resp = await ctx.http.get(
                BLOCKS_API, params={"limit": "5"}, timeout=15)
        except Exception as e:
            return self._degraded(
                f"Flashbots blocks API unreachable: {type(e).__name__}")
        if resp.status_code != 200:
            return self._degraded(
                f"Flashbots blocks API HTTP {resp.status_code} "
                f"(public endpoint may be retired)")
        try:
            payload = resp.json()
        except Exception:
            return self._degraded("Flashbots blocks API non-JSON")
        blocks = parse_blocks(payload)
        if not blocks:
            return self._degraded("Flashbots blocks API returned no blocks")
        total_bundles = 0
        total_txs = 0
        for b in blocks:
            try:
                total_bundles += int(b.get("num_bundles") or
                                     len(b.get("bundles") or []))
            except (TypeError, ValueError):
                pass
            try:
                total_txs += int(b.get("num_txs") or
                                 len(b.get("transactions") or []))
            except (TypeError, ValueError):
                pass
        latest = blocks[0]
        findings = [self._f(
            "web3", "mev_share_inclusion_stats",
            f"Flashbots relay: last {len(blocks)} blocks carried "
            f"{total_bundles} bundles / {total_txs} txs; latest block "
            f"{latest.get('block_number')}", "FlashbotsBlocks",
            confidence=85,
            evidence={"severity": "low",
                      "blocks_sampled": len(blocks),
                      "total_bundles": total_bundles,
                      "total_txs": total_txs,
                      "latest_block": latest.get("block_number"),
                      "remediation": "Inclusion-rate monitoring only; "
                                     "a drop to zero signals relay / "
                                     "MEV-Share pipeline trouble."})]
        if total_bundles == 0:
            findings.append(self._f(
                "web3", "mev_share_no_bundles",
                "No bundles in the recent Flashbots block sample",
                "FlashbotsBlocks", confidence=70,
                evidence={"severity": "medium",
                          "blocks_sampled": len(blocks),
                          "remediation": "Zero bundle inclusion is "
                                         "abnormal for the relay; check "
                                         "relay health before relying "
                                         "on private routing."}))
        return self._ok(findings, f"{len(findings)} MEV-Share findings")
