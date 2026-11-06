"""Flashbots Protect / relay status reader (Tier-10, MONITORING ONLY).

Distinct remainder vs master: the flash_loan_* / mev_* plugins are
SOURCE-pattern detectors on contract code. Nobody reads the live
Flashbots infrastructure. This plugin is a READER only: it checks the
public Flashbots relay health endpoint and the Flashbots Protect RPC
endpoint (eth_chainId read) and reports their status. It does NOT
build, sign or submit bundles, and it never calls any bundle or
private-transaction submission method.
"""
from __future__ import annotations

from .base import Cost, Ctx, Plugin, PluginResult, Target

RELAY_HEALTH = "https://relay.flashbots.net/health"
PROTECT_RPC = "https://rpc.flashbots.net"


class FlashbotsProtectStatusPlugin(Plugin):
    id = "flashbots_protect_status"
    label = "Flashbots Protect Status Reader"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Read-only status reader for Flashbots Protect and "
                   "the Flashbots relay (public health + eth_chainId). "
                   "Monitoring only: no bundle building or submission.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings = []
        reached = False
        # 1. Relay health (public GET).
        try:
            resp = await ctx.http.get(RELAY_HEALTH, timeout=15)
            if resp.status_code == 200:
                reached = True
                body = (resp.text or "")[:200]
                findings.append(self._f(
                    "web3", "flashbots_relay_health",
                    f"Flashbots relay health endpoint OK: {body!r}",
                    "FlashbotsRelay", confidence=85,
                    evidence={"severity": "low", "endpoint": RELAY_HEALTH,
                              "http_status": 200,
                              "remediation": "Monitoring only. A relay "
                                             "outage means Protect users "
                                             "fall back to the public "
                                             "mempool; watch status before "
                                             "relying on private routing."}))
            else:
                findings.append(self._f(
                    "web3", "flashbots_relay_health_degraded",
                    f"Flashbots relay health endpoint HTTP "
                    f"{resp.status_code}", "FlashbotsRelay", confidence=70,
                    evidence={"severity": "medium",
                              "endpoint": RELAY_HEALTH,
                              "http_status": resp.status_code,
                              "remediation": "Relay degraded: private-tx "
                                             "users may be exposed to the "
                                             "public mempool until it "
                                             "recovers."}))
        except Exception:
            pass
        # 2. Protect RPC endpoint: eth_chainId is a pure read.
        try:
            resp = await ctx.http.post(PROTECT_RPC, json={
                "jsonrpc": "2.0", "id": 1, "method": "eth_chainId",
                "params": []}, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                chain = data.get("result") if isinstance(data, dict) \
                    else None
                if chain:
                    reached = True
                    findings.append(self._f(
                        "web3", "flashbots_protect_endpoint",
                        f"Flashbots Protect RPC live, chainId {chain}",
                        "FlashbotsProtect", confidence=85,
                        evidence={"severity": "low",
                                  "endpoint": PROTECT_RPC,
                                  "chain_id": chain,
                                  "remediation": "Monitoring only; this "
                                                 "reader never submits "
                                                 "private transactions."}))
        except Exception:
            pass
        if not reached and not findings:
            return self._degraded(
                "Flashbots relay/Protect endpoints unreachable via egress")
        return self._ok(findings, f"{len(findings)} Flashbots status findings")
