"""Quant math layer: pure, deterministic arithmetic over LIVE
read values (storage / eth_call returns), never pattern matching.

Every function takes plain integers (token amounts in the token's
smallest unit, reserves likewise) and returns plain values so the
results are unit-testable on hand-computed vectors and
re-derivable from the inputs a plugin stamps into evidence
(provenance: which reads produced the inputs, observed_at).

Scope of the math:
- ERC-4626-style vault/share math, including the virtual-shares
  (+1 asset / +10**offset shares) inflation-attack defence and a
  first-depositor inflation profitability computation.
- Fee-on-transfer: expected received vs nominal shortfall.
- Constant-product AMM (x*y=k): spot price with decimals,
  amount_out under the 0.3% fee formula, price impact, and the
  max movable value statement (draining one side toward zero
  costs unbounded input; the practical bound reported is the
  output at a given input plus the reserve ceiling).
- Supply/mint math: remaining mintable under a cap, and claim
  arithmetic (balance vs allowance).

No I/O, no chain access: plugins make the reads (eth_call /
storage) and stamp the figures this module computes.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Vault / share math (ERC-4626)
# ---------------------------------------------------------------------------

def shares_out(deposit: int, total_assets: int, total_supply: int,
               decimals_offset: int = 0, virtual: bool = True) -> int:
    """Shares minted for `deposit` assets under the ERC-4626
    virtual-offset formula:

        shares = deposit * (total_supply + 10**offset)
                 / (total_assets + 1)          (floor division)

    With offset 0 and an empty vault (assets=supply=0) this is the
    plain 1:1 first-deposit shape: shares = deposit * 1 / 1.
    virtual=False models the VULNERABLE pre-4626 vault shape with
    no virtual shares/assets at all (plain supply/assets ratio,
    1:1 on an empty vault) - the shape the inflation attack
    actually drains.
    """
    if deposit < 0 or total_assets < 0 or total_supply < 0:
        raise ValueError("negative vault input")
    if not virtual:
        if total_supply == 0 or total_assets == 0:
            return deposit
        return deposit * total_supply // total_assets
    virtual_shares = 10 ** decimals_offset
    return deposit * (total_supply + virtual_shares) // (total_assets + 1)


def assets_out(shares: int, total_assets: int, total_supply: int,
               decimals_offset: int = 0, virtual: bool = True) -> int:
    """Assets returned for redeeming `shares` (inverse of
    shares_out, rounding down in the vault's favour):

        assets = shares * (total_assets + 1)
                 / (total_supply + 10**offset)
    """
    if shares < 0 or total_assets < 0 or total_supply < 0:
        raise ValueError("negative vault input")
    if not virtual:
        if total_supply == 0:
            return 0
        return shares * total_assets // total_supply
    virtual_shares = 10 ** decimals_offset
    return shares * (total_assets + 1) // (total_supply + virtual_shares)


def inflation_attack(first_deposit: int, donation: int,
                     victim_deposit: int,
                     decimals_offset: int = 0,
                     virtual: bool = True) -> Dict[str, Any]:
    """First-depositor inflation attack, computed end to end.

    Sequence: the attacker is the first depositor (deposit
    `first_deposit`, receiving shares_out over the empty vault),
    then DONATES `donation` assets directly to the vault (raising
    total_assets without minting shares), then the victim deposits
    `victim_deposit`. If the victim's deposit rounds down to few
    or zero shares, the attacker redeems everything and profits.

    Returns the full ledger so a finding can show its working:
    attacker/victim shares, the attacker's redemption value, the
    attacker's total spend, and the net profit (can be negative:
    with a sufficient decimals offset the donation is spread over
    the virtual shares and the attack loses money).
    """
    a_shares = shares_out(first_deposit, 0, 0, decimals_offset, virtual)
    assets_after = first_deposit + donation
    supply_after = a_shares
    v_shares = shares_out(victim_deposit, assets_after, supply_after,
                          decimals_offset, virtual)
    total_assets = assets_after + victim_deposit
    total_supply = supply_after + v_shares
    attacker_redeem = assets_out(a_shares, total_assets, total_supply,
                                 decimals_offset, virtual) if a_shares else 0
    spend = first_deposit + donation
    profit = attacker_redeem - spend
    return {
        "attacker_shares": a_shares,
        "victim_shares": v_shares,
        "victim_share_of_supply_ppm": (
            v_shares * 1_000_000 // total_supply if total_supply else 0),
        "attacker_redeem": attacker_redeem,
        "attacker_spend": spend,
        "attacker_profit": profit,
        "profitable": profit > 0,
        "decimals_offset": decimals_offset,
        "virtual_shares": virtual,
    }


# ---------------------------------------------------------------------------
# Fee-on-transfer
# ---------------------------------------------------------------------------

def expected_received(nominal: int, fee_bps: Optional[int] = None,
                      fee_fraction: Optional[float] = None) -> Dict[str, int]:
    """What a recipient actually gets from a `nominal` transfer
    under a fee. Exactly one of fee_bps (basis points, integer
    math) or fee_fraction (0.0-1.0 float, converted to bps) must
    be given. Returns {received, fee_amount, shortfall} where
    shortfall == nominal - received."""
    if fee_bps is None:
        if fee_fraction is None:
            raise ValueError("fee_bps or fee_fraction required")
        fee_bps = int(round(fee_fraction * 10_000))
    if not (0 <= fee_bps <= 10_000):
        raise ValueError("fee_bps out of range")
    fee_amount = nominal * fee_bps // 10_000
    return {"received": nominal - fee_amount,
            "fee_amount": fee_amount,
            "shortfall": fee_amount,
            "fee_bps": fee_bps}


# ---------------------------------------------------------------------------
# Constant-product AMM (x*y=k, Uniswap-V2 shape)
# ---------------------------------------------------------------------------

def amm_spot_price(reserve_a: int, reserve_b: int,
                   decimals_a: int = 18, decimals_b: int = 18) -> float:
    """Spot price of A denominated in B, decimal-adjusted:
    (reserve_b / 10**dec_b) / (reserve_a / 10**dec_a)."""
    if reserve_a <= 0 or reserve_b < 0:
        raise ValueError("reserves must be positive")
    return (reserve_b / 10 ** decimals_b) / (reserve_a / 10 ** decimals_a)


def amm_amount_out(amount_in: int, reserve_in: int, reserve_out: int,
                   fee_bps: int = 30) -> int:
    """Output for `amount_in` under the x*y=k formula with the
    fee taken on the input (default 0.3% = 30 bps, the
    Uniswap-V2 / PancakeSwap-V2 shape):

        in_after_fee = amount_in * (10000 - fee_bps) / 10000
        out = in_after_fee * reserve_out / (reserve_in + in_after_fee)
    """
    if amount_in < 0 or reserve_in <= 0 or reserve_out <= 0:
        raise ValueError("bad AMM input")
    if not (0 <= fee_bps < 10_000):
        raise ValueError("fee_bps out of range")
    in_after_fee = amount_in * (10_000 - fee_bps)
    numerator = in_after_fee * reserve_out
    denominator = reserve_in * 10_000 + in_after_fee
    return numerator // denominator


def amm_price_impact_bps(amount_in: int, reserve_in: int,
                         reserve_out: int, fee_bps: int = 30) -> int:
    """Price impact of a trade in basis points: how far the
    execution price sits below the spot price, fee excluded from
    the impact figure (impact is the slippage component)."""
    out = amm_amount_out(amount_in, reserve_in, reserve_out, fee_bps)
    if amount_in <= 0 or reserve_in <= 0:
        raise ValueError("bad AMM input")
    # spot out at zero impact, using the fee-free rate
    spot_out = amount_in * reserve_out / reserve_in
    if spot_out <= 0:
        return 0
    return int((1 - out / spot_out) * 10_000)


def amm_max_movable(reserve_in: int, reserve_out: int,
                    fee_bps: int = 30) -> Dict[str, Any]:
    """The movable-value statement for a pair at current reserves:
    the output side can never pay out more than `reserve_out`
    (the asymptote of x*y=k), and moving HALF the output reserve
    requires an input of ~reserve_in (exactly: solving out =
    reserve_out/2 gives in_after_fee = reserve_in, so
    amount_in = reserve_in * 10000 / (10000 - fee_bps))."""
    if reserve_in <= 0 or reserve_out <= 0:
        raise ValueError("bad reserves")
    half_out = reserve_out // 2
    in_for_half = reserve_in * 10_000 // (10_000 - fee_bps)
    return {
        "reserve_in": reserve_in,
        "reserve_out": reserve_out,
        "max_out_ceiling": reserve_out,
        "out_for_half_reserve": half_out,
        "in_required_for_half_reserve": in_for_half,
        "fee_bps": fee_bps,
    }


# ---------------------------------------------------------------------------
# Supply / mint / claim math
# ---------------------------------------------------------------------------

def remaining_mintable(cap: Optional[int], total_supply: int) -> Optional[int]:
    """cap - total_supply. None when the token has no cap
    (cap is None or 0, the common uncapped encoding): minting is
    then bounded by access control, not arithmetic."""
    if cap is None or cap <= 0:
        return None
    return max(0, cap - total_supply)


def claimable(balance: int, allowance: Optional[int] = None) -> int:
    """What a claim/transferFrom path can actually move: the
    balance, bounded by the allowance when one applies."""
    if balance < 0:
        raise ValueError("negative balance")
    if allowance is None:
        return balance
    return min(balance, max(0, allowance))


def stamped(figures: Dict[str, Any], inputs: Dict[str, Any],
            observed_at: str) -> Dict[str, Any]:
    """Attach input provenance to computed figures for evidence:
    {figures, inputs, observed_at}. Plugins pass the reads the
    figures were derived from (slot / eth_call / source line)."""
    return {"figures": figures, "inputs": inputs,
            "observed_at": observed_at}
