"""Token holder cluster (Cat-4 variant of token_rugcheck).

Beyond concentration percentages: cluster a token's holders by
SHARED FUNDING SOURCE (and first-transfer origin) to expose
coordinated wallet networks hiding behind apparent distribution -
ten 'independent' wallets that were all funded by one wallet in the
same hour are one holder wearing ten hats.

Keyless explorer/RPC-derived holder+funding data (or supplied
artifacts). Read-only analysis. Detection only.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import artifact_dicts
from .base import Cost, Ctx, Plugin, PluginResult, Target

MIN_CLUSTER_WALLETS = 3
CLUSTER_SHARE_MEDIUM = 0.15
CLUSTER_SHARE_HIGH = 0.30
KNOWN_FUNDERS = ("exchange", "bridge", "cex", "binance", "coinbase",
                 "kraken", "okx", "bybit", "faucet", "disperse")


def cluster_holders(holders: Any) -> List[Dict[str, Any]]:
    """Pure: holder records -> coordinated-cluster hits.

    Holder shape: {"address","balance_pct","funder",
                   "funder_label"} - balance_pct as a fraction (0.42)
    or percentage (42) - both handled.
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(holders, list):
        return hits
    clusters: Dict[str, Dict[str, Any]] = {}
    for h in holders:
        if not isinstance(h, dict):
            continue
        funder = str(h.get("funder") or "").lower()
        label = str(h.get("funder_label") or "").lower()
        if not funder or any(k in label for k in KNOWN_FUNDERS):
            continue
        try:
            pct = float(h.get("balance_pct") or 0)
        except (TypeError, ValueError):
            continue
        if pct > 1.0:
            pct = pct / 100.0
        c = clusters.setdefault(funder, {"wallets": [], "share": 0.0})
        c["wallets"].append(h.get("address"))
        c["share"] += pct
    for funder, c in clusters.items():
        if len(c["wallets"]) >= MIN_CLUSTER_WALLETS \
                and c["share"] >= CLUSTER_SHARE_MEDIUM:
            hits.append({"kind": "coordinated_holder_cluster",
                         "funder": funder,
                         "wallets": len(c["wallets"]),
                         "combined_share_pct": round(c["share"] * 100, 1),
                         "sample_wallets": c["wallets"][:4]})
    return hits


class TokenHolderClusterPlugin(Plugin):
    id = "token_holder_cluster"
    label = "Token Holder Cluster Analysis"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Cluster token holders by shared funding source "
                   "to expose coordinated wallet networks behind "
                   "apparent distribution.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            datasets: List[Any] = []
            for d in artifact_dicts(ctx):
                if isinstance(d.get("holders"), list):
                    datasets.append(d["holders"])
            for holders in datasets[:5]:
                for hit in cluster_holders(holders):
                    sev = ("high" if hit["combined_share_pct"] / 100.0
                           >= CLUSTER_SHARE_HIGH else "medium")
                    findings.append(self._f(
                        "web3", "coordinated_holder_cluster",
                        f"{hit['wallets']} holder wallets funded by "
                        f"the same source {hit['funder']} jointly "
                        f"hold {hit['combined_share_pct']}% of supply "
                        f"- distribution is coordinated, not organic",
                        source="token holder cluster", confidence=85,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Treat the cluster as ONE "
                            "holder for risk purposes; coordinated "
                            "clusters can dump in unison."}))
            res = self._ok(findings,
                           "no holder/funding data supplied"
                           if not datasets else
                           f"{len(findings)} coordinated clusters")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
