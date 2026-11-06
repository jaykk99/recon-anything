"""Subsquid archive/indexer discovery (Tier-7, keyless).

No Subsquid coverage on master. Subsquid archives expose a public
per-network status surface (current indexed height); indexers and
dapps built on a lagging archive serve stale chain data. This
plugin probes the archive height for major networks and reports
availability + height as findings (and a lag finding when a
network's archive trails the Ethereum head source by a wide
margin is out of scope - heights are reported per network as
inventory). Keyless public endpoints, read-only.
"""
from __future__ import annotations

from .base import Cost, Ctx, Plugin, PluginResult, Target

NETWORKS = {
    "ethereum-mainnet": "https://v2.archive.subsquid.io/network/ethereum-mainnet/height",
    "binance-mainnet": "https://v2.archive.subsquid.io/network/binance-mainnet/height",
    "polygon-mainnet": "https://v2.archive.subsquid.io/network/polygon-mainnet/height",
    "arbitrum-one": "https://v2.archive.subsquid.io/network/arbitrum-one/height",
    "base-mainnet": "https://v2.archive.subsquid.io/network/base-mainnet/height",
}


class SubsquidDiscoveryPlugin(Plugin):
    id = "subsquid_discovery"
    label = "Subsquid Indexer Discovery"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = ("Discovers Subsquid archive datasets for major "
                   "networks (keyless archive height endpoints) and "
                   "reports indexed height per network.")
    phase = 1
    timeout_s = 60

    async def _height(self, ctx, url):
        resp = await ctx.http.get(url, timeout=15)
        if resp.status_code != 200:
            return None
        text = (resp.text or "").strip()
        try:
            return int(text)
        except Exception:
            try:
                data = resp.json()
                return int(data.get("height")) if isinstance(data, dict) else None
            except Exception:
                return None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings = []
        reached = 0
        for net, url in NETWORKS.items():
            try:
                h = await self._height(ctx, url)
            except Exception:
                h = None
            if h is None:
                continue
            reached += 1
            findings.append(self._f(
                "web3", "subsquid_archive_available",
                f"{net}: archive height {h}", "SubsquidArchive",
                confidence=85,
                evidence={"severity": "low", "network": net,
                          "height": h, "endpoint": url,
                          "remediation": "Indexers on this archive "
                                         "serve data up to this "
                                         "height only; confirm lag "
                                         "before trusting fresh reads."}))
        if not reached:
            return self._degraded("Subsquid archive endpoints "
                                  "unreachable from this host")
        return self._ok(findings, f"{reached} archives discovered")
