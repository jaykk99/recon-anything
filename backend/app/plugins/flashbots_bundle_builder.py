"""Flashbots bundle-inclusion analyser (Cat-4 variant).

Despite the historic list name, this is an ANALYSER, not a builder:
for supplied transaction hashes / inclusion records it determines -
from keyless public relay/block data or supplied artifacts - whether
privately-routed transactions stayed private, which block producer
included them, and how inclusion timing compares with public-mempool
routing. Privacy leaks (privately-routed transactions that appeared
in the public mempool first) and producer centralisation are the
findings.

BOUNDARY - MONITORING/ANALYSIS ONLY: no bundle construction, no
signing, and no submission capability exists in this module; a
fixture test greps this file to prove the absence of any such
surface.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import artifact_dicts
from .base import Cost, Ctx, Plugin, PluginResult, Target

CENTRALISATION_SHARE = 0.7
CENTRALISATION_MIN = 5


def analyse_inclusion(records: Any) -> List[Dict[str, Any]]:
    """Pure: inclusion records -> privacy/centralisation hits.

    Record shape: {"tx_hash","route" ("private"|"public"),
    "seen_public_before_inclusion" (bool), "included_block",
    "builder","delay_blocks"}.
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(records, list):
        return hits
    recs = [r for r in records if isinstance(r, dict)]
    for r in recs:
        if str(r.get("route") or "").lower() in ("private", "protect",
                                                 "flashbots") \
                and r.get("seen_public_before_inclusion"):
            hits.append({"kind": "private_tx_leaked_to_mempool",
                         "tx_hash": r.get("tx_hash"),
                         "included_block": r.get("included_block"),
                         "builder": r.get("builder")})
    builders: Dict[str, int] = {}
    for r in recs:
        b = str(r.get("builder") or "")
        if b:
            builders[b] = builders.get(b, 0) + 1
    if len(recs) >= CENTRALISATION_MIN and builders:
        top, count = max(builders.items(), key=lambda kv: kv[1])
        share = count / len(recs)
        if share >= CENTRALISATION_SHARE:
            hits.append({"kind": "builder_centralisation",
                         "builder": top, "share_pct": round(share * 100, 1),
                         "records": len(recs)})
    return hits


class FlashbotsBundleBuilderPlugin(Plugin):
    id = "flashbots_bundle_builder"
    label = "Flashbots Bundle-Inclusion Analyser (monitoring only)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Monitoring/analysis only: analyse bundle/tx "
                   "inclusion from public data - privacy leaks of "
                   "privately-routed txs and builder centralisation. "
                   "No construction or submission capability.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            datasets: List[Any] = []
            for d in artifact_dicts(ctx):
                for key in ("inclusion_records", "bundle_records"):
                    if isinstance(d.get(key), list):
                        datasets.append(d[key])
            for records in datasets[:5]:
                for hit in analyse_inclusion(records):
                    sev = ("high" if hit["kind"] ==
                           "private_tx_leaked_to_mempool" else "medium")
                    findings.append(self._f(
                        "web3", f"bundle_{hit['kind']}",
                        f"Bundle inclusion analysis: "
                        f"{hit['kind'].replace('_', ' ')} - {hit}",
                        source="flashbots bundle-inclusion analyser",
                        confidence=85,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Route sensitive flow only "
                            "through relays you trust, and monitor "
                            "inclusion: a privately-routed transaction "
                            "seen publicly first was leaked or sold."}))
            res = self._ok(findings,
                           "no inclusion records supplied"
                           if not datasets else
                           f"{len(findings)} inclusion signals")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
