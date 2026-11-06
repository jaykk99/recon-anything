"""The Graph subgraph health query (Tier-7).

No The Graph coverage on master. Subgraph health is the ingestion
risk: a subgraph with indexing errors or a large block lag serves
wrong data to every dapp reading it. This plugin queries a
subgraph's _meta block + indexing status (keyless hosted endpoint
where it still answers; THEGRAPH_API_KEY gateway path behind env
when set) and reports lag / hasIndexingErrors. Without any
answering endpoint it degrades/skips cleanly - never fabricates.
"""
from __future__ import annotations

import os

from .base import Cost, Ctx, Plugin, PluginResult, Target

HOSTED = "https://api.thegraph.com/subgraphs/name/graphprotocol/graph-network"
GATEWAY = "https://gateway.thegraph.com/api/{key}/subgraphs/id/{sid}"
DEFAULT_SID = "5zvR82QoaXuFyDEKLZ9t6v9adgnptxYpKpSbxtgVENFV"
META_QUERY = {"query": "{ _meta { block { number } "
                       "hasIndexingErrors deployment } }"}
LAG_BLOCKS = 100


class TheGraphSubgraphsPlugin(Plugin):
    id = "thegraph_subgraphs"
    label = "The Graph Subgraphs (Health)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = ("Queries a The Graph subgraph's _meta health "
                   "(indexed block, hasIndexingErrors) keylessly via "
                   "the hosted network subgraph, or via the gateway "
                   "when THEGRAPH_API_KEY is set.")
    phase = 1
    timeout_s = 60

    async def _meta(self, ctx, url):
        resp = await ctx.http.post(url, json=META_QUERY, timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        meta = ((data or {}).get("data") or {}).get("_meta")
        return meta if isinstance(meta, dict) else None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        key = ctx.keys.get("thegraph") or os.environ.get(
            "THEGRAPH_API_KEY")
        urls = []
        if key:
            urls.append(GATEWAY.format(key=key, sid=DEFAULT_SID))
        urls.append(HOSTED)
        meta = None
        used = ""
        for url in urls:
            try:
                meta = await self._meta(ctx, url)
            except Exception:
                meta = None
            if meta:
                used = url
                break
        if not meta:
            if not key:
                return self._skipped(
                    "needs THEGRAPH_API_KEY: hosted endpoint did not "
                    "answer and the gateway is key-only")
            return self._degraded("The Graph endpoints did not answer")
        block = ((meta.get("block") or {}).get("number"))
        errors = bool(meta.get("hasIndexingErrors"))
        findings = []
        if errors:
            findings.append(self._f(
                "web3", "subgraph_indexing_errors",
                f"subgraph {meta.get('deployment')}: "
                "hasIndexingErrors=true", "TheGraph", confidence=90,
                evidence={"severity": "high", "block": block,
                          "endpoint": used,
                          "remediation": "Consumers of this subgraph "
                                         "are reading incomplete data; "
                                         "fail over to a healthy "
                                         "deployment."}))
        findings.append(self._f(
            "web3", "subgraph_health",
            f"subgraph indexed to block {block}, errors={errors}",
            "TheGraph", confidence=85,
            evidence={"severity": "low", "block": block,
                      "has_indexing_errors": errors, "endpoint": used,
                      "remediation": "Track subgraph lag in monitoring; "
                                     "alert when it exceeds your "
                                     "freshness budget."}))
        return self._ok(findings, "subgraph health read")
