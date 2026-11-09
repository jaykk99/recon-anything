"""Pure Uniswap-V2-style AMM math for the flash-loan simulation matrix.

Everything here is integer math identical to what a V2 pair/router does
on-chain (997/1000 fee), so a *modeled* displacement or payout can be
hand-checked against *executed* fixture runs. The pytest gate does exactly
that cross-check.

No chain access, no keys, no state. Functions raise ValueError on nonsense
input instead of silently returning a number.
"""
from __future__ import annotations

from typing import List, Sequence, Tuple

FEE_NUM = 997
FEE_DEN = 1000


def get_amount_out(amount_in: int, reserve_in: int, reserve_out: int) -> int:
    """V2 getAmountOut: out = in*997*reserve_out / (reserve_in*1000 + in*997)."""
    if amount_in < 0 or reserve_in <= 0 or reserve_out <= 0:
        raise ValueError("bad swap inputs")
    if amount_in == 0:
        return 0
    amount_in_with_fee = amount_in * FEE_NUM
    numerator = amount_in_with_fee * reserve_out
    denominator = reserve_in * FEE_DEN + amount_in_with_fee
    return numerator // denominator


def get_amounts_out(amount_in: int, hops: Sequence[Tuple[int, int]]) -> List[int]:
    """Multi-hop quote. hops = [(reserve_in, reserve_out), ...] per hop."""
    amounts = [amount_in]
    for reserve_in, reserve_out in hops:
        amounts.append(get_amount_out(amounts[-1], reserve_in, reserve_out))
    return amounts


def reserves_after_swap(amount_in: int, reserve_in: int, reserve_out: int) -> Tuple[int, int, int]:
    """Return (amount_out, new_reserve_in, new_reserve_out) for one swap."""
    amount_out = get_amount_out(amount_in, reserve_in, reserve_out)
    return amount_out, reserve_in + amount_in, reserve_out - amount_out


def unit_price(amount_reference: int, hops: Sequence[Tuple[int, int]]) -> int:
    """Spot unit price of the input asset in output-asset units, quoted for a
    fixed reference amount (e.g. 1e18). This is the number a naive oracle
    reads via router.getAmountsOut(reference, path)[-1] - and the number a
    DUEL-style convert function multiplies by the caller's amount."""
    return get_amounts_out(amount_reference, hops)[-1]


def flash_repay_amount(borrowed: int) -> int:
    """Minimum same-token repayment for a V2 flash swap of `borrowed`:
    ceil(borrowed * 1000 / 997)."""
    if borrowed < 0:
        raise ValueError("bad loan")
    return -(-borrowed * FEE_DEN // FEE_NUM)


def displaced_reserves(
    swap_in: int, reserve_in: int, reserve_out: int
) -> Tuple[Tuple[int, int], int]:
    """Reserves after a hypothetical manipulation swap of `swap_in` units of
    the in-asset into the pool. Returns ((new_rin, new_rout), amount_out)."""
    out, rin, rout = reserves_after_swap(swap_in, reserve_in, reserve_out)
    return (rin, rout), out


def displacement_pct(quote_before: int, quote_after: int) -> float:
    """Signed % move of a quote. 0.0 when the quote does not move."""
    if quote_before <= 0:
        raise ValueError("quote_before must be positive")
    return (quote_after - quote_before) * 100.0 / quote_before
