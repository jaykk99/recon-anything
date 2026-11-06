"""Sandwich attack profiler (Cat-4 variant).

Historic on-chain profiler: scans a token/victim's past swap
activity (keyless explorer/RPC-derived records, or supplied
artifacts) for the front-run / victim / back-run triple - the same
actor swapping immediately before AND after a victim's swap in the
same block - and attributes repeat MEV bots across blocks.

Read-only historic analysis. No transactions are constructed or
submitted; this profiles attacks that already happened.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import artifact_dicts
from .base import Cost, Ctx, Plugin, PluginResult, Target

SWAP_METHODS = {"swap", "swapExactTokensForTokens",
                "swapExactETHForTokens", "swapExactTokensForETH",
                "swapETHForExactTokens", "swapTokensForExactTokens",
                "swapTokensForExactETH"}
REPEAT_BOT_MIN = 3


def _is_swap(tx: Dict[str, Any]) -> bool:
    method = str(tx.get("method") or tx.get("function") or "")
    if method in SWAP_METHODS:
        return True
    sel = str(tx.get("selector") or "").replace("0x", "").lower()
    return sel in ("38ed1739", "7ff36ab5", "18cbafe5", "022c0d9f",
                   "5c11d795", "fb3bdb41")


def profile_sandwiches(txs: Any) -> List[Dict[str, Any]]:
    """Pure: ordered tx records -> sandwich-triple hits.

    Tx shape: {"block","index","from","method"/"selector","pool"}.
    Records are grouped by block+pool and scanned in index order.
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(txs, list):
        return hits
    swaps = [t for t in txs if isinstance(t, dict) and _is_swap(t)]
    groups: Dict[Any, List[Dict[str, Any]]] = {}
    for t in swaps:
        groups.setdefault((t.get("block"), t.get("pool")), []).append(t)
    bot_counts: Dict[str, int] = {}
    for (block, pool), group in groups.items():
        group.sort(key=lambda t: t.get("index") or 0)
        for i in range(len(group) - 2):
            a, victim, b = group[i], group[i + 1], group[i + 2]
            attacker = str(a.get("from") or "")
            if attacker and attacker == str(b.get("from") or "") \
                    and attacker != str(victim.get("from") or ""):
                hits.append({"kind": "sandwich_triple",
                             "block": block, "pool": pool,
                             "attacker": attacker,
                             "victim": victim.get("from")})
                bot_counts[attacker] = bot_counts.get(attacker, 0) + 1
    for bot, count in bot_counts.items():
        if count >= REPEAT_BOT_MIN:
            hits.append({"kind": "repeat_sandwich_bot",
                         "attacker": bot, "sandwiches": count})
    return hits


class SandwichAttackProfilerPlugin(Plugin):
    id = "sandwich_attack_profiler"
    label = "Sandwich Attack Profiler"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Historic profiler: detect front-run/victim/"
                   "back-run sandwich triples in past swap activity "
                   "and attribute repeat MEV bots. Read-only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            datasets: List[Any] = []
            for d in artifact_dicts(ctx):
                if isinstance(d.get("swap_txs"), list):
                    datasets.append(d["swap_txs"])
            for txs in datasets[:5]:
                for hit in profile_sandwiches(txs):
                    sev = ("high" if hit["kind"] ==
                           "repeat_sandwich_bot" else "medium")
                    findings.append(self._f(
                        "web3", f"mev_{hit['kind']}",
                        f"Sandwich profile: "
                        f"{hit['kind'].replace('_', ' ')} - attacker "
                        f"{hit.get('attacker')}"
                        + (f" victimised {hit.get('victim')} in block "
                           f"{hit.get('block')}"
                           if hit["kind"] == "sandwich_triple" else
                           f" ({hit.get('sandwiches')} confirmed "
                           f"sandwiches)"),
                        source="sandwich attack profiler",
                        confidence=90,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Route swaps through private "
                            "mempool protection and set tight slippage; "
                            "repeat bots target this pool's flow "
                            "specifically."}))
            res = self._ok(findings,
                           "no swap history supplied"
                           if not datasets else
                           f"{len(findings)} sandwich signals")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
