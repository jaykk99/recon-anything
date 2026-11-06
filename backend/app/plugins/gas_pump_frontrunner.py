"""Gas-pump frontrunner profiler (Cat-4 variant, mempool lane).

Bonding-curve / launchpad watcher-profiler: analyses OBSERVED public
mempool activity around known launchpad contracts - sniper timing
(how fast wallets pile into a launch), fee-bidding escalation (the
gas-pump pattern of rival bots outbidding each other), and repeat
actors - and reports the PATTERNS only.

BOUNDARY - MONITORING/ANALYSIS ONLY: this module observes and
profiles activity that is already public. It contains no transaction
construction, no signing, and no relay or submission capability of
any kind; a fixture test greps this file to prove the absence of any
such surface.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import artifact_dicts
from .base import Cost, Ctx, Plugin, PluginResult, Target

# Known launchpad / bonding-curve contracts (lowercase). Observation
# targets only.
LAUNCHPADS = {
    "0x4e6b6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5",  # placeholder-shape guard
}
FEE_PREMIUM_X = 3.0
BID_WAR_MIN_BIDDERS = 3


def _fee(tx: Dict[str, Any]) -> float:
    for key in ("gas_price_gwei", "max_fee_gwei", "fee_gwei"):
        try:
            return float(tx.get(key) or 0)
        except (TypeError, ValueError):
            continue
    return 0.0


def profile_launch_activity(txs: Any, launchpads: Any = None
                            ) -> List[Dict[str, Any]]:
    """Pure: observed mempool txs -> frontrun-pattern hits.

    Tx shape: {"hash","from","to","method","block","fee_gwei"/
    "gas_price_gwei","seconds_after_launch"}.
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(txs, list):
        return hits
    pads = {str(p).lower() for p in (launchpads or LAUNCHPADS)}
    watched = [t for t in txs if isinstance(t, dict)
               and str(t.get("to") or "").lower() in pads]
    if not watched:
        return hits
    fees = sorted(_fee(t) for t in watched if _fee(t) > 0)
    median_fee = fees[len(fees) // 2] if fees else 0.0
    # Sniper timing: very early arrivals paying a large fee premium.
    for t in watched:
        secs = t.get("seconds_after_launch")
        fee = _fee(t)
        if isinstance(secs, (int, float)) and secs <= 30 \
                and median_fee and fee >= FEE_PREMIUM_X * median_fee:
            hits.append({"kind": "launch_sniper_fee_premium",
                         "actor": t.get("from"), "hash": t.get("hash"),
                         "seconds_after_launch": secs,
                         "fee_gwei": fee, "median_fee_gwei": median_fee})
    # Fee-bidding war: several distinct actors, same block, same pad,
    # escalating fees (the gas-pump signature).
    by_block: Dict[Any, List[Dict[str, Any]]] = {}
    for t in watched:
        by_block.setdefault(t.get("block"), []).append(t)
    for block, group in by_block.items():
        actors = {str(t.get("from")) for t in group}
        gfees = sorted(_fee(t) for t in group)
        if len(actors) >= BID_WAR_MIN_BIDDERS and len(gfees) >= 2 \
                and gfees[-1] >= 2 * max(gfees[0], 0.01):
            hits.append({"kind": "fee_bidding_war", "block": block,
                         "bidders": len(actors),
                         "fee_range_gwei": [gfees[0], gfees[-1]],
                         "target": group[0].get("to")})
    return hits


class GasPumpFrontrunnerPlugin(Plugin):
    id = "gas_pump_frontrunner"
    label = "Gas-Pump Frontrun Profiler (monitoring only)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Monitoring/analysis only: profile observed "
                   "mempool activity at launchpad contracts for "
                   "sniper timing and fee-bidding (gas-pump) wars. "
                   "No transaction capability of any kind.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            datasets: List[Any] = []
            pads = None
            for d in artifact_dicts(ctx):
                if isinstance(d.get("mempool_txs"), list):
                    datasets.append(d["mempool_txs"])
                if isinstance(d.get("launchpads"), list):
                    pads = d["launchpads"]
            for txs in datasets[:5]:
                for hit in profile_launch_activity(txs, pads):
                    sev = ("high" if hit["kind"] ==
                           "launch_sniper_fee_premium" else "medium")
                    findings.append(self._f(
                        "web3", f"frontrun_{hit['kind']}",
                        f"Launchpad frontrun pattern: "
                        f"{hit['kind'].replace('_', ' ')} - {hit}",
                        source="gas-pump frontrun profiler",
                        confidence=80,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Launch with anti-sniper "
                            "measures (staggered enable, per-wallet "
                            "caps, private launch flow) and warn users "
                            "that early blocks are bot-dominated."}))
            res = self._ok(findings,
                           "no launchpad mempool data supplied"
                           if not datasets else
                           f"{len(findings)} frontrun patterns")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
