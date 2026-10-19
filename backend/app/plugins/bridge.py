"""Cross-chain bridge vulnerability checker.

Detects bridge integrations and flags common bridge attack surfaces:
validator sets, relayer trust, wrapped asset custody. Read-only.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

BRIDGE_PATTERNS = [
    (r"multichain|anyswap", "Multichain/AnySwap bridge integration", "medium"),
    (r"wormhole", "Wormhole bridge integration", "medium"),
    (r"layerzero|stargate", "LayerZero/Stargate bridge", "medium"),
    (r"polygon.*bridge|arbitrum.*bridge|optimism.*bridge", "L2 native bridge", "low"),
    (r"lockAndMint|burnAndMint|deposit.*withdraw", "lock/mint bridge pattern", "medium"),
    (r"relayer", "relayer component (trust assumption)", "medium"),
    (r"validator.*set|guardian", "validator/guardian set (centralization risk)", "medium"),
    # --- Expanded bridge coverage ---
    (r"across\.to|across bridge", "Across bridge integration", "medium"),
    (r"hop\.exchange|hop bridge", "Hop Protocol bridge", "medium"),
    (r"synapse.*bridge|synapseprotocol", "Synapse bridge", "medium"),
    (r"cbridge|celer", "Celer cBridge", "medium"),
    (r"connext|nxTP", "Connext bridge", "medium"),
    (r"debridge", "deBridge", "medium"),
    (r"meson\.fi|meson bridge", "Meson bridge", "medium"),
    (r"orbiter\.finance", "Orbiter Finance bridge", "medium"),
    (r"rhino\.fi", "Rhino.fi bridge", "medium"),
    (r"portalbridge|portal\.wormhole", "Wormhole Portal bridge", "medium"),
    (r"allbridge", "Allbridge", "medium"),
    (r"thorchain|rune", "THORChain", "medium"),
    (r"axelar", "Axelar bridge", "medium"),
    (r"hyperlane", "Hyperlane bridge", "medium"),
    (r"ccip|chainlink.*ccip", "Chainlink CCIP bridge", "medium"),
    # --- Bridge risk patterns ---
    (r"wrapped (btc|eth|usdc)|wbtc|weth", "wrapped asset usage (custody risk)", "low"),
    (r"mint\(.*\)|_mint\(", "unrestricted mint function pattern", "medium"),
    (r"pause\(\)|pausable|emergency.*(stop|halt|pause)", "pausable bridge (admin key risk)", "medium"),
    (r"multisig|multi-sig", "multisig custody (check signer threshold)", "low"),
    (r"rate.?limit|daily.?limit|volume.?cap", "bridge rate limiting present", "low"),
    (r"liquidity.?pool.*bridge|bridge.*liquidity", "liquidity-pool bridge model", "low"),
    (r"atomic.?swap|htlc|hash.?time.?lock", "atomic swap / HTLC pattern", "low"),
    (r"optimistic.*bridge|fraud.?proof", "optimistic bridge (fraud-proof window)", "low"),
    (r"zk.?bridge|zero.?knowledge.*bridge", "ZK bridge", "low"),
]

REMEDIATION = ("Prefer bridges with strong validator decentralization, "
               "rate limits, and monitoring. Verify wrapped asset backing.")


class BridgePlugin(Plugin):
    id = "bridge"
    label = "Bridge Security Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Detect bridge integrations and trust assumptions."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:400000]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        seen = set()
        for pat, label, sev in BRIDGE_PATTERNS:
            for m in re.finditer(pat, html, re.I):
                if label in seen:
                    continue
                seen.add(label)
                findings.append(self._f(
                    "web3", "bridge_pattern",
                    f"Bridge integration: {label}. Review validator "
                    f"decentralization and rate limits.",
                    source="Bridge scan", source_url=page_url,
                    confidence=60, passive=passive,
                    evidence={"severity": sev,
                              "remediation": REMEDIATION,
                              "scope_note": "Read-only. Authorized testing only."}))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} bridge patterns")
        res.duration_ms = dur
        return res
