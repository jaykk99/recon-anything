"""Aave V3 pool STATE READER (Tier-10, READ-ONLY — NOT a builder).

This plugin replaces the requested "flashloan builder" slot with the
monitoring deliverable the boundary allows: it READS live Aave V3 Pool
state on Ethereum mainnet via eth_call — the reserves list, and for
WETH the reserve data plus the aToken-held available liquidity — and
reports it as analysis findings.

Execution is OUT OF SCOPE: this plugin does NOT build flash-loan
transactions, does NOT encode execution calldata for submission, and
never broadcasts anything. The flash-loan premium is reported only
where it can be derived from read state; no loan is taken or simulated
against a live pool.
"""
from __future__ import annotations

from . import _tier10_common as C
from .base import Cost, Ctx, Plugin, PluginResult, Target

POOL = C.AAVE_V3_POOL


def decode_reserves_list(data_hex: str):
    """Decode an ABI address[] return: offset, length, then words."""
    if not isinstance(data_hex, str) or not data_hex.startswith("0x"):
        return []
    h = data_hex[2:]
    if len(h) < 128:
        return []
    try:
        n = int(h[64:128], 16)
    except ValueError:
        return []
    out = []
    for i in range(min(n, 200)):
        addr = C.decode_addr(data_hex, 2 + i)
        if addr:
            out.append(addr)
    return out


class AaveV3StatePlugin(Plugin):
    id = "aave_v3_state"
    label = "Aave V3 Pool State Reader (Read-Only)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("READ-ONLY Aave V3 state reader: reserves list and "
                   "WETH reserve/liquidity state via eth_call on the "
                   "mainnet Pool. Explicitly NOT a flash-loan builder; "
                   "no execution, no broadcasting.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings = []
        data, err = await C.eth_call(
            ctx, POOL, "0x" + C.SEL["getReservesList"])
        if not data:
            return self._degraded(f"Aave Pool getReservesList failed: {err}")
        reserves = decode_reserves_list(data)
        findings.append(self._f(
            "web3", "aave_v3_reserves",
            f"Aave V3 Pool lists {len(reserves)} reserves",
            "AaveV3Pool", confidence=90,
            evidence={"severity": "low", "pool": POOL,
                      "reserve_count": len(reserves),
                      "reserves": reserves[:20],
                      "remediation": "State observation only; reserve "
                                     "count changes signal listings / "
                                     "freezes to review."}))
        # WETH reserve data + available liquidity (aToken balance of
        # the underlying token is the pool's lendable liquidity).
        rd, _ = await C.eth_call(
            ctx, POOL, "0x" + C.SEL["getReserveData"] + C.pad_addr(C.WETH))
        if rd:
            liq_rate = C.decode_uint(rd, 2)
            var_rate = C.decode_uint(rd, 4)
            a_token = C.decode_addr(rd, 8)
            findings.append(self._f(
                "web3", "aave_v3_weth_reserve",
                f"Aave V3 WETH reserve: liquidity rate {liq_rate}, "
                f"variable borrow rate {var_rate}, aToken {a_token}",
                "AaveV3Pool", confidence=90,
                evidence={"severity": "low", "pool": POOL,
                          "asset": C.WETH, "a_token": a_token,
                          "current_liquidity_rate": liq_rate,
                          "current_variable_borrow_rate": var_rate,
                          "remediation": "Rate observation for "
                                         "utilization monitoring."}))
            if a_token:
                bal, _ = await C.eth_call(
                    ctx, C.WETH,
                    "0x" + C.SEL["balanceOf"] + C.pad_addr(a_token))
                avail = C.decode_uint(bal) if bal else None
                if avail is not None:
                    findings.append(self._f(
                        "web3", "aave_v3_weth_liquidity",
                        f"Aave V3 WETH available liquidity: "
                        f"{avail / 1e18:.2f} WETH (held by aToken)",
                        "AaveV3Pool", confidence=90,
                        evidence={"severity": "low", "pool": POOL,
                                  "asset": C.WETH, "a_token": a_token,
                                  "available_liquidity_wei": avail,
                                  "remediation": "Liquidity observation "
                                                 "only; this reader "
                                                 "takes no flash loan "
                                                 "and builds nothing."}))
        return self._ok(findings, f"{len(findings)} Aave state findings")
