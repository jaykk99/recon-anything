"""Realizable-value estimation for triage: tell a real $100k contract from
one that nominally "has 100k" but holds dust.

The distinction that matters is *realizable* value, not nominal. A contract
can report, or appear to hold, a large token balance whose pool is empty -
infinite mintable supply with no liquidity, a token priced off a stale or
fake quote. None of that is money anyone can actually move. So:

- Native balance (ETH/BNB/SOL/...) is fully liquid - counted at face value.
- A token position is worth at most what its pool can absorb, so it is
  bounded by that pool's real USD liquidity. A position with no pool, or a
  pool below the dust floor, is worth ~0 regardless of nominal size.

This is a conservative UPPER bound on what's realizable (it ignores slippage,
which only lowers it further), and that's the right bias for triage: it will
never hide a genuinely valuable contract, and it strips the dust that wastes a
reviewer's time. Nothing here fetches anything - the live scanner supplies the
native balance and each position's pool liquidity (e.g. from DexScreener); this
module just does the honest arithmetic.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# A token pool below this USD liquidity is treated as having no realizable
# value - you cannot get meaningful money out of it.
DUST_POOL_FLOOR_USD = 500.0


def realizable_value_usd(native_usd: Optional[float],
                         token_positions: Optional[List[Dict[str, Any]]] = None,
                         dust_pool_floor: float = DUST_POOL_FLOOR_USD
                         ) -> float:
    """Conservative USD value a contract actually controls.

    native_usd: USD value of the native-coin balance (fully liquid).
    token_positions: list of {nominal_usd, liquidity_usd} per token held.
      nominal_usd  - position size at quoted price (may be illusory).
      liquidity_usd- the token's real pool liquidity (None/0 = no pool).
    A position is valued at min(nominal, liquidity); no/low pool -> 0.
    """
    total = max(float(native_usd or 0.0), 0.0)
    for pos in token_positions or []:
        nominal = float(pos.get("nominal_usd") or 0.0)
        liq = pos.get("liquidity_usd")
        liq = float(liq) if liq not in (None, "") else 0.0
        if liq < dust_pool_floor or nominal <= 0:
            continue  # no realizable value - dust
        total += min(nominal, liq)
    return total


def is_dust(value_usd: Optional[float], threshold_usd: float) -> bool:
    """True if a contract's realizable value is below the worth-reviewing
    threshold. A missing/None value is NOT dust - we can't assess it, so it
    is never filtered out on value grounds."""
    if value_usd is None:
        return False
    return float(value_usd) < float(threshold_usd)


def value_band(value_usd: Optional[float]) -> str:
    """Coarse label for display/sorting: unknown / dust / low / mid / high."""
    if value_usd is None:
        return "unknown"
    v = float(value_usd)
    if v < DUST_POOL_FLOOR_USD:
        return "dust"
    if v < 100_000:
        return "low"
    if v < 1_000_000:
        return "mid"
    return "high"
