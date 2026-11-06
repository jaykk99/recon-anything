"""Cross-venue price STATE READER (Tier-10, ANALYSIS ONLY).

This plugin occupies the requested "arbitrage state overrider" slot
with the monitoring deliverable the boundary allows: it READS the
same pair's quoted state on two venues (Uniswap V3 via the read-only
quoter, Uniswap V2 via Router.getAmountsOut — both eth_call reads)
and reports the spread as a NON-ACTIONABLE ANALYSIS finding.

It does NOT override any state, does NOT build or execute arbitrage,
and never broadcasts a transaction. The word "analysis" is in every
finding so downstream consumers cannot mistake the observation for a
trade instruction.
"""
from __future__ import annotations

from . import _tier10_common as C
from .base import Cost, Ctx, Plugin, PluginResult, Target
from .uniswap_quoter import quote as v3_quote

PAIRS = [("WETH/USDT", C.WETH, C.USDT, 10**18),
         ("WETH/USDC", C.WETH, C.USDC, 10**18)]


def encode_get_amounts_out(amount_in: int, path) -> str:
    """Router.getAmountsOut(uint256,address[]) calldata (read)."""
    # head: amountIn, offset(0x40); tail: length, then addresses.
    return ("0x" + C.SEL["getAmountsOut"] + C.pad_uint(amount_in)
            + C.pad_uint(64) + C.pad_uint(len(path))
            + "".join(C.pad_addr(a) for a in path))


def decode_amounts_out(data_hex: str):
    """Decode a uint256[] return; last element is the final amount."""
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
    for i in range(min(n, 20)):
        v = C.decode_uint(data_hex, 2 + i)
        if v is not None:
            out.append(v)
    return out


class ArbStateReaderPlugin(Plugin):
    id = "arb_state_reader"
    label = "Arbitrage State Reader (Analysis Only)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("READ-ONLY cross-venue price state reader: quotes "
                   "the same pair on Uniswap V3 and V2 via eth_call "
                   "and reports spread observations as non-actionable "
                   "ANALYSIS. No state overriding, no execution.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings = []
        last_err = ""
        for label, tin, tout, amount in PAIRS:
            v3_out, _quoter, last_err = await v3_quote(
                ctx, tin, tout, 500, amount)
            v2_data, err2 = await C.eth_call(
                ctx, C.UNI_V2_ROUTER,
                encode_get_amounts_out(amount, [tin, tout]))
            amounts = decode_amounts_out(v2_data) if v2_data else []
            v2_out = amounts[-1] if amounts else None
            if v2_out is None:
                last_err = last_err or err2
            if v3_out is None or v2_out is None:
                continue
            dec = C.TOKEN_DECIMALS.get(tout, 18)
            p3, p2 = v3_out / 10**dec, v2_out / 10**dec
            spread_bps = (abs(p3 - p2) / max(p2, 1e-9)) * 10000
            findings.append(self._f(
                "web3", "arb_spread_observation_analysis",
                f"ANALYSIS (non-actionable): {label} V3 quote {p3:.4f} "
                f"vs V2 quote {p2:.4f} -> spread {spread_bps:.1f} bps",
                "ArbStateReader", confidence=85,
                evidence={"severity": "low", "pair": label,
                          "v3_price": p3, "v2_price": p2,
                          "spread_bps": spread_bps,
                          "analysis_only": True,
                          "non_actionable": True,
                          "remediation": "Spread observation for "
                                         "market-state monitoring only. "
                                         "This reader executes "
                                         "nothing; spreads usually "
                                         "reflect fees / liquidity depth, "
                                         "not free profit."}))
            if spread_bps >= 50:
                findings.append(self._f(
                    "web3", "arb_wide_spread_analysis",
                    f"ANALYSIS (non-actionable): wide {label} cross-"
                    f"venue spread {spread_bps:.1f} bps (>= 50 bps)",
                    "ArbStateReader", confidence=80,
                    evidence={"severity": "medium", "pair": label,
                              "spread_bps": spread_bps,
                              "analysis_only": True,
                              "non_actionable": True,
                              "remediation": "Wide quoted spreads flag "
                                             "thin or stressed liquidity "
                                             "for monitoring; not an "
                                             "execution signal."}))
        if not findings:
            return self._degraded(
                f"cross-venue quote reads failed: {last_err}")
        return self._ok(findings, f"{len(findings)} arb-state findings")
