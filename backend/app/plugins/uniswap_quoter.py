"""Uniswap V3 quoter READER (Tier-10, READ-ONLY quote analysis).

Calls QuoterV2.quoteExactInputSingle via eth_call for major pairs and
reports the quoted out-amount and implied price. This is price /
impact ANALYSIS only: quote functions are view-style reads, no swap
is executed, no transaction is built for submission or broadcast.
"""
from __future__ import annotations

from typing import Optional, Tuple

from . import _tier10_common as C
from .base import Cost, Ctx, Plugin, PluginResult, Target

QUOTER = C.UNI_V3_QUOTER_V2
# (label, tokenIn, tokenOut, fee, amountIn)
QUOTES = [
    ("WETH->USDT fee3000", C.WETH, C.USDT, 3000, 10**18),
    ("WETH->USDT fee500", C.WETH, C.USDT, 500, 10**18),
    ("WETH->USDC fee500", C.WETH, C.USDC, 500, 10**18),
]


def encode_quote_v1(token_in: str, token_out: str, fee: int,
                    amount_in: int) -> str:
    """Quoter (v1 interface) quoteExactInputSingle calldata.

    QuoterV2 deployments accept the same read through the struct
    interface; the v1 flat encoding is what the canonical Quoter at
    0xb273... answers, and eth_call against QuoterV2's struct entry
    uses the tuple encoding built in encode_quote_v2.
    """
    return ("0x" + C.SEL["quoteExactInputSingleV1"]
            + C.pad_addr(token_in) + C.pad_addr(token_out)
            + C.pad_uint(fee) + C.pad_uint(amount_in) + C.pad_uint(0))


def encode_quote_v2(token_in: str, token_out: str, fee: int,
                    amount_in: int) -> str:
    # QuoterV2 QuoteExactInputSingleParams struct order:
    # (tokenIn, tokenOut, amountIn, fee, sqrtPriceLimitX96); the
    # tuple is static, so it is encoded inline in that order.
    return ("0xc6a5026a"
            + C.pad_addr(token_in) + C.pad_addr(token_out)
            + C.pad_uint(amount_in) + C.pad_uint(fee) + C.pad_uint(0))


async def quote(ctx, token_in: str, token_out: str, fee: int,
                amount_in: int) -> Tuple[Optional[int], str, str]:
    """One read-only quote: (amount_out, quoter_label, error).

    The canonical Quoter (0xb273...) is tried first (verified live);
    QuoterV2's struct entry is the fallback. Both are pure eth_call
    reads.
    """
    out, err = await C.eth_call(
        ctx, C.UNI_V3_QUOTER_V1,
        encode_quote_v1(token_in, token_out, fee, amount_in))
    if out:
        v = C.decode_uint(out, 0)
        if v:
            return v, "UniswapQuoterV1", ""
    out, err = await C.eth_call(
        ctx, C.UNI_V3_QUOTER_V2,
        encode_quote_v2(token_in, token_out, fee, amount_in))
    if out:
        v = C.decode_uint(out, 0)
        if v:
            return v, "UniswapQuoterV2", ""
    return None, "", err or "quote reverted on both quoters"


class UniswapQuoterPlugin(Plugin):
    id = "uniswap_quoter"
    label = "Uniswap V3 Quoter (Read-Only)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Read-only Uniswap V3 QuoterV2 quoteExactInputSingle "
                   "eth_call reads for major pairs (price/impact "
                   "analysis). No swap execution.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings = []
        prices = {}
        last_err = ""
        for label, tin, tout, fee, amount in QUOTES:
            out, quoter, last_err = await quote(
                ctx, tin, tout, fee, amount)
            if out is None:
                continue
            dec = C.TOKEN_DECIMALS.get(tout, 18)
            price = out / (10 ** dec)
            prices[label] = price
            findings.append(self._f(
                "web3", "uniswap_v3_quote",
                f"{label}: 1 unit in -> {price:.4f} out (quoted)",
                quoter, confidence=90,
                evidence={"severity": "low", "pair": label,
                          "quoter": quoter,
                          "token_in": tin, "token_out": tout,
                          "fee": fee, "amount_in": amount,
                          "amount_out": out, "implied_price": price,
                          "remediation": "Quote is analysis only; "
                                         "execution is out of scope for "
                                         "this reader."}))
        if not findings:
            return self._degraded(f"quoter reads failed: {last_err}")
        p500 = prices.get("WETH->USDT fee500")
        p3000 = prices.get("WETH->USDT fee3000")
        if p500 and p3000:
            spread_bps = abs(p500 - p3000) / p3000 * 10000
            findings.append(self._f(
                "web3", "uniswap_fee_tier_spread",
                f"WETH/USDT fee-tier quote spread: {spread_bps:.1f} bps "
                f"(500 vs 3000)", "UniswapQuoter", confidence=85,
                evidence={"severity": "low", "spread_bps": spread_bps,
                          "remediation": "Tier spread is a liquidity "
                                         "observation, not a trade "
                                         "signal from this plugin."}))
        return self._ok(findings, f"{len(findings)} quoter findings")
