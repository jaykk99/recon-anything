"""DEX liquidity depth calculator (Cat-4 variant).

Computes actual pool depth for a token's DEX pairs - the +-2% depth
(how much value can trade before price moves 2%), reserve ratios,
and depth history - from keyless DEX API data or supplied pool
artifacts. Flags shallow depth relative to market cap and sudden
depth collapse, the classic rug-pull staging pattern (liquidity
quietly drained before the exit).

Keyless read-only data (DexScreener-shaped artifacts / API). No
trading, no simulation of trades against live pools.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ._cat4_common import artifact_dicts, fetch_json
from .base import Cost, Ctx, Plugin, PluginResult, Target

DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens/{addr}"
COLLAPSE_PCT = 50.0
SHALLOW_RATIO = 0.02     # depth < 2% of (implied) market value
MIN_DEPTH_USD = 5000.0


def depth_from_reserves(reserve_usd: float) -> float:
    """+-2% depth approximation for a constant-product pool: the
    trade size that moves price ~2% is ~10% of one side's reserves,
    i.e. ~5% of total pool USD value (both sides)."""
    try:
        return float(reserve_usd) * 0.05
    except (TypeError, ValueError):
        return 0.0


def analyse_pool(pool: Any) -> List[Dict[str, Any]]:
    """Pure: pool record -> depth hits.

    Shape: {"pair","liquidity_usd","market_cap_usd",
            "history":[{"ts","liquidity_usd"}]} (history oldest first).
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(pool, dict):
        return hits
    try:
        liq = float(pool.get("liquidity_usd") or 0)
    except (TypeError, ValueError):
        return hits
    depth = depth_from_reserves(liq)
    base = {"pair": pool.get("pair") or pool.get("pair_address"),
            "liquidity_usd": liq, "depth_2pct_usd": round(depth, 2)}
    mcap = pool.get("market_cap_usd") or pool.get("fdv_usd")
    try:
        mcap_f = float(mcap) if mcap is not None else 0.0
    except (TypeError, ValueError):
        mcap_f = 0.0
    if liq > 0 and depth < MIN_DEPTH_USD:
        hits.append({**base, "kind": "shallow_absolute_depth"})
    if mcap_f > 0 and liq / mcap_f < SHALLOW_RATIO:
        hits.append({**base, "kind": "shallow_relative_depth",
                     "liquidity_to_mcap_pct": round(liq / mcap_f * 100, 2)})
    hist = [h for h in pool.get("history") or [] if isinstance(h, dict)]
    if len(hist) >= 2:
        try:
            first = float(hist[0].get("liquidity_usd") or 0)
            last = float(hist[-1].get("liquidity_usd") or 0)
            if first > 0 and last < first * (1 - COLLAPSE_PCT / 100.0):
                hits.append({**base, "kind": "liquidity_collapse",
                             "from_usd": first, "to_usd": last,
                             "drop_pct": round((1 - last / first) * 100, 1)})
        except (TypeError, ValueError):
            pass
    return hits


class DexLiquidityDepthCalcPlugin(Plugin):
    id = "dex_liquidity_depth_calc"
    label = "DEX Liquidity Depth Calculator"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Compute +-2% pool depth and reserve ratios for a "
                   "token's DEX pairs keylessly; flag shallow depth "
                   "and sudden liquidity collapse (rug staging).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            pools: List[Dict[str, Any]] = []
            for d in artifact_dicts(ctx):
                for p in d.get("pools") or []:
                    if isinstance(p, dict):
                        pools.append(p)
            if not pools:
                norm = (target.normalized or "").strip()
                if norm.startswith("0x") and len(norm) == 42:
                    data = await fetch_json(
                        ctx, DEXSCREENER.format(addr=norm))
                    if isinstance(data, dict):
                        for pair in (data.get("pairs") or [])[:3]:
                            if not isinstance(pair, dict):
                                continue
                            liq = (pair.get("liquidity") or {}).get("usd")
                            pools.append({
                                "pair": pair.get("pairAddress"),
                                "liquidity_usd": liq,
                                "market_cap_usd": pair.get("marketCap")
                                or pair.get("fdv")})
            sev_map = {"liquidity_collapse": "high",
                       "shallow_relative_depth": "medium",
                       "shallow_absolute_depth": "medium"}
            for pool in pools[:8]:
                for hit in analyse_pool(pool):
                    findings.append(self._f(
                        "web3", f"dex_{hit['kind']}",
                        f"DEX pool {hit.get('pair')}: "
                        f"{hit['kind'].replace('_', ' ')} - liquidity "
                        f"${hit['liquidity_usd']:,.0f}, +-2% depth "
                        f"~${hit['depth_2pct_usd']:,.0f}",
                        source="dex liquidity depth calc",
                        confidence=85,
                        evidence={
                            "severity": sev_map.get(hit["kind"], "low"),
                            "hit": hit,
                            "remediation": "Do not size positions "
                            "beyond the +-2% depth; a collapsing pool "
                            "is a rug in progress - exit first, "
                            "investigate after."}))
            res = self._ok(findings,
                           f"{len(pools)} pools analysed"
                           if not findings else
                           f"{len(findings)} depth risks")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
