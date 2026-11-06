"""Helios-style light-client consistency check (Tier-7, keyless).

No light-client / cross-endpoint consensus check exists on master.
A light client (Helios) trusts a sync-committee-signed head instead
of one RPC; the detection-grade equivalent available keylessly is a
consensus-lite cross-check: fetch the latest block header from two
independent public RPC endpoints and compare number + hash. A
divergence means one endpoint is lying, lagging, or intercepted -
exactly the failure a light client protects against. Read-only
eth_getBlockByNumber only.
"""
from __future__ import annotations

from .base import Cost, Ctx, Plugin, PluginResult, Target

RPC_A = "https://ethereum-rpc.publicnode.com"
# eth.llamarpc.com returned HTTP 525 live on 2026-11-05; dRPC's free
# endpoint answered correctly, so it is the second endpoint.
RPC_B = "https://eth.drpc.org"
LAG_BLOCKS = 5


class HeliosConsistencyPlugin(Plugin):
    id = "helios_consistency"
    label = "Helios Light-Client Consistency Check"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = ("Cross-checks the latest Ethereum block header "
                   "(number + hash) across two independent public RPC "
                   "endpoints; divergence or heavy lag is a finding. "
                   "Light-client style verification, keyless.")
    phase = 1
    timeout_s = 60

    async def _head(self, ctx, rpc):
        resp = await ctx.http.post(rpc, json={
            "jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
            "params": ["latest", False]}, timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, dict):
            return None
        try:
            return {"number": int(result.get("number", "0x0"), 16),
                    "hash": result.get("hash", ""),
                    "timestamp": int(result.get("timestamp", "0x0"), 16)}
        except Exception:
            return None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            a = await self._head(ctx, RPC_A)
            b = await self._head(ctx, RPC_B)
        except Exception as e:
            return self._degraded(f"RPC cross-check error: {e}")
        if not a or not b:
            return self._degraded("one or both public RPC endpoints "
                                  "unreachable")
        findings = []
        if a["number"] == b["number"] and a["hash"] != b["hash"]:
            findings.append(self._f(
                "web3", "rpc_head_hash_mismatch",
                f"block {a['number']}: hash differs across endpoints "
                f"({a['hash'][:18]}... vs {b['hash'][:18]}...)",
                "HeliosCheck", confidence=90,
                evidence={"severity": "high", "block": a["number"],
                          "hash_a": a["hash"], "hash_b": b["hash"],
                          "remediation": "Same-height hash divergence "
                                         "means an endpoint is serving "
                                         "a fork or bad data: do not "
                                         "trust either for value "
                                         "decisions; use a light client "
                                         "(Helios) or a third endpoint."}))
        lag = abs(a["number"] - b["number"])
        if lag > LAG_BLOCKS:
            findings.append(self._f(
                "web3", "rpc_head_lag",
                f"endpoint heads differ by {lag} blocks "
                f"({a['number']} vs {b['number']})",
                "HeliosCheck", confidence=85,
                evidence={"severity": "medium", "lag_blocks": lag,
                          "head_a": a["number"], "head_b": b["number"],
                          "remediation": "A lagging endpoint serves "
                                         "stale state: price and balance "
                                         "reads from it can be exploited "
                                         "or wrong."}))
        return self._ok(findings,
                        "heads agree" if not findings else
                        f"{len(findings)} consistency findings")
