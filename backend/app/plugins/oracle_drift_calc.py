"""Oracle Drift Calculator (Cat-1 #12, VARIANT of chainlink_feeds /
uniswap_quoter lanes).

Delta: quantitative drift measurement. The existing lanes check
HOW a contract consumes a feed statically; this one measures -
given paired samples of a DEX spot price and the Chainlink feed
answer for the same asset (supplied on the bus as oracle_samples
records {asset, spot, oracle, timestamp?}, e.g. collected by the
quoter / feed lanes) - the divergence in basis points, and flags
SUSTAINED drift beyond threshold (default 100 bps across 2+
samples, or any single sample beyond 500 bps). One noisy tick is
not a finding; sustained divergence is.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

SUSTAINED_BPS = 100
SINGLE_BPS = 500


def drift_bps(spot: float, oracle: float) -> float:
    if not oracle:
        return 0.0
    return abs(spot - oracle) / abs(oracle) * 10000.0


def calc_oracle_drift(samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_asset: Dict[str, List[float]] = {}
    for s in samples or []:
        if not isinstance(s, dict):
            continue
        try:
            spot = float(s.get("spot", s.get("spot_price", 0)))
            oracle = float(s.get("oracle", s.get("feed", 0)))
        except Exception:
            continue
        if spot <= 0 or oracle <= 0:
            continue
        asset = str(s.get("asset") or s.get("pair") or "asset")
        by_asset.setdefault(asset, []).append(drift_bps(spot, oracle))
    hits: List[Dict[str, Any]] = []
    for asset, drifts in by_asset.items():
        worst = max(drifts)
        sustained = sum(1 for d in drifts if d >= SUSTAINED_BPS)
        if worst >= SINGLE_BPS or sustained >= 2:
            hits.append(C.hit(
                "oracle_spot_drift",
                f"{asset}: DEX spot vs Chainlink feed drift peaks "
                f"at {worst:.0f} bps with {sustained} sample(s) "
                f"above {SUSTAINED_BPS} bps - sustained oracle "
                f"drift; contracts settling on the stale side can "
                f"be traded against.",
                "high" if worst >= SINGLE_BPS else "medium",
                "Add a drift/deviation circuit-breaker: reject or "
                "pause settlement when spot and feed diverge past "
                "a set band, and prefer the fresher source.",
                asset=asset, peak_bps=round(worst, 1),
                sustained_samples=sustained, samples=len(drifts),
                check="oracle_drift"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    samples: List[Dict[str, Any]] = []
    for kind in ("oracle_samples", "oracle_prices"):
        for item in data["extras"].get(kind, []):
            if isinstance(item, dict) and isinstance(
                    item.get("samples"), list):
                samples.extend(item["samples"])
            elif isinstance(item, dict):
                samples.append(item)
            elif isinstance(item, list):
                samples.extend(x for x in item if isinstance(x, dict))
    return calc_oracle_drift(samples)


class OracleDriftCalcPlugin(Plugin):
    id = "oracle_drift_calc"
    label = "Oracle Drift Calculator"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Measures DEX spot vs Chainlink feed divergence "
                   "in basis points over paired samples and flags "
                   "sustained drift beyond threshold.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze,
            extras=("oracle_samples", "oracle_prices"),
            source=False, bytecode=False,
            no_input="no paired spot/oracle samples supplied: "
                     "drift needs spot + feed samples for an asset")
