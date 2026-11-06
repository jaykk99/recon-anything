"""Token allowance auditor (Tier-10, Revoke.cash-style, READ-ONLY).

Distinct remainder vs master: tokenapproval scans web PAGE SOURCE for
approval-shaped code patterns. Nobody reads the LIVE on-chain
allowances of an address. This plugin eth_calls ERC20 allowance() for
a target address across major tokens x known spender contracts
(Uniswap routers, Permit2, Aave Pool, Seaport) and flags unlimited
(max-uint) and large standing approvals. Read-only: it never submits
a revoke transaction.
"""
from __future__ import annotations

from . import _tier10_common as C
from .base import Cost, Ctx, Plugin, PluginResult, Target


class RevokeWatcherPlugin(Plugin):
    id = "revoke_watcher"
    label = "Revoke Watcher (Live Allowance Audit)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Live ERC20 allowance audit for a target address: "
                   "allowance() eth_call reads for major tokens against "
                   "known spenders, flagging unlimited approvals. "
                   "Read-only; never revokes on-chain.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        owner = C.target_address(target)
        if not owner:
            return self._skipped(
                "needs an Ethereum address target to audit allowances")
        findings = []
        reached = False
        checked = 0
        for tname, token in C.TOKENS.items():
            for spender, sname in C.SPENDERS.items():
                data, _ = await C.eth_call(
                    ctx, token, "0x" + C.SEL["allowance"]
                    + C.pad_addr(owner) + C.pad_addr(spender))
                if not data:
                    continue
                reached = True
                checked += 1
                amount = C.decode_uint(data)
                if amount is None or amount == 0:
                    continue
                if amount >= C.MAX_UINT - 1000:
                    findings.append(self._f(
                        "web3", "unlimited_allowance_live",
                        f"UNLIMITED {tname} allowance for {sname} "
                        f"({spender}) by {owner}", "RevokeWatcher",
                        confidence=95,
                        evidence={"severity": "high", "token": token,
                                  "token_name": tname, "owner": owner,
                                  "spender": spender,
                                  "spender_name": sname,
                                  "allowance": str(amount),
                                  "remediation": "Revoke or reduce this "
                                                 "unlimited approval at "
                                                 "a revoke UI unless the "
                                                 "spender is fully "
                                                 "trusted; a compromised "
                                                 "spender can drain the "
                                                 "full balance."}))
                else:
                    dec = C.TOKEN_DECIMALS.get(token, 18)
                    findings.append(self._f(
                        "web3", "standing_allowance_live",
                        f"Standing {tname} allowance for {sname}: "
                        f"{amount / 10 ** dec:.4f} tokens",
                        "RevokeWatcher", confidence=85,
                        evidence={"severity": "low", "token": token,
                                  "token_name": tname, "owner": owner,
                                  "spender": spender,
                                  "spender_name": sname,
                                  "allowance": str(amount),
                                  "remediation": "Bounded approval; "
                                                 "review whether the "
                                                 "spender still needs "
                                                 "it."}))
        if not reached:
            return self._degraded("allowance reads failed on all RPCs")
        return self._ok(
            findings,
            f"{len(findings)} allowance findings over {checked} reads")
