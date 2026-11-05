"""BSC detectors: PancakeSwap & AMM integration (10 plugins).

Dedupe map (outcome per ID, also in the PR body):
- pancake_v2_v3_router_misdirection: (b) BSC variant - router
  identity is a PancakeSwap-specific allowlist question (custom
  check: unknown router literal bound while Pancake swap
  interfaces are used, or an ungated router setter).
- pancake_pool_skimming_vulnerability: (a) NEW - pair skim()
  exposed to strangers (nothing else looks at skim).
- pancake_price_oracle_manipulation: (b) BSC variant - Pancake
  pair getReserves() spot price consumed as an oracle without a
  TWAP (the generic stale-oracle detector covers Chainlink).
- pancake_add_liquidity_dust_leak: (a) NEW - addLiquidity called
  with zero minimums (custom call-argument check).
- pancake_remove_liquidity_frontrun: (a) NEW - removeLiquidity
  with zero minimums (custom call-argument check).
- pancake_swap_exact_tokens_underflow: (c) shared overflow
  routine restricted to the swap-amount derivation site
  (custom check).
- pancake_lp_token_burn_logic: (a) NEW - pair burn() paying a
  caller-chosen recipient, ungated.
- pancake_flash_swap_reentrancy: (b) BSC variant - the
  pancakeCall flash-swap callback missing its pair/caller
  validation (reentrancy family, callback-specific pattern).
- pancake_insufficient_slippage_protection: (a) NEW -
  swapExact* called with a zero minimum-out (custom
  call-argument check; distinct from the MEV lane, which flags
  victim contracts whose own swap API offers no slippage
  parameter at all).
- pancake_k_value_invariant_violation: (b) BSC variant -
  pair-shaped reserve accounting with no K invariant check.
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "pancake"

SPECS = [
    S("pancake_v2_v3_router_misdirection", FAMILY, severity="high",
      outcome="b", custom="router_misdirection",
      detail="Router misdirection: swap calls are routed through "
             "a router address that is not a known PancakeSwap "
             "router (or the router address can be rewritten by "
             "an ungated setter), so swaps can be silently "
             "redirected to an attacker-controlled contract that "
             "keeps the input tokens."),
    S("pancake_pool_skimming_vulnerability", FAMILY,
      severity="medium", outcome="a",
      need=(r"\.skim\s*\(",), gated_suppresses=True,
      recipient=True,
      detail="Pool skimming: a PancakeSwap pair's skim() is "
             "invoked from an ungated function, so anyone can "
             "sweep the pair's excess tokens (the amount above "
             "the reserves) out of the pool instead of the "
             "protocol recovering them."),
    S("pancake_price_oracle_manipulation", FAMILY, severity="high",
      outcome="b",
      need=(r"getReserves\s*\(",),
      need_any=(r"_mint|mint\s*\(|borrow|swap|price|valueOf",),
      forbid=(r"consult|twap|TWAP|observe\s*\(|priceCumulative",),
      contract_forbid=(r"PancakeOracle|TWAP",),
      detail="Spot-price oracle manipulation: a PancakeSwap "
             "pair's getReserves() spot price is consumed "
             "directly to price a mint / borrow / swap / "
             "valuation, with no TWAP (no cumulative-price "
             "consult) anywhere. Spot reserves are movable "
             "inside one transaction (flash swaps), so every "
             "decision priced off them is manipulable at "
             "near-zero cost."),
    S("pancake_add_liquidity_dust_leak", FAMILY, severity="medium",
      outcome="a", custom="call_args_zero",
      custom_data={"calls": {"addLiquidity": (4, 5),
                             "addLiquidityETH": (2, 3)}},
      detail="Add-liquidity dust leak: addLiquidity is called "
             "with BOTH minimum amounts set to 0, so the pool "
             "can take the full desired amounts at any ratio "
             "the market dictates at execution time and the "
             "unpaired remainder ('dust') is stranded in the "
             "pool for skimmers instead of being bounded by "
             "the caller's intent."),
    S("pancake_remove_liquidity_frontrun", FAMILY,
      severity="medium", outcome="a", custom="call_args_zero",
      custom_data={"calls": {"removeLiquidity": (3, 4),
                             "removeLiquidityETH": (2, 3),
                             "removeLiquidityWithPermit": (3, 4)}},
      detail="Remove-liquidity frontrunning: removeLiquidity is "
             "called with BOTH minimum amounts set to 0, so a "
             "frontrunner who moves the pool price first makes "
             "the victim's withdrawal settle at the manipulated "
             "ratio - the withdrawal has no floor."),
    S("pancake_swap_exact_tokens_underflow", FAMILY,
      severity="medium", outcome="c",
      custom="swap_amount_underflow",
      detail="Swap amount underflow: the amount fed into a "
             "PancakeSwap swap is derived by raw subtraction "
             "(balance minus a reserve/fee term) in pre-0.8 or "
             "unchecked arithmetic with no bound checked first, "
             "so a state where the subtrahend exceeds the "
             "balance wraps the swap amount to a huge number "
             "instead of reverting."),
    S("pancake_lp_token_burn_logic", FAMILY, severity="medium",
      outcome="a",
      need=(r"\.burn\s*\(",),
      need_any=(r"msg\.sender", r"\bto\b", r"recipient"),
      gated_suppresses=True, recipient=True,
      detail="LP burn logic: a PancakeSwap pair's burn() (which "
             "redeems the underlying tokens to the chosen "
             "recipient) is exposed through an ungated function "
             "with a caller-chosen recipient, so LP tokens held "
             "by this contract can be redeemed by anyone, to "
             "themselves."),
    S("pancake_flash_swap_reentrancy", FAMILY, severity="high",
      outcome="b", fn_re=r"pancakeCall|uniswapV2Call|Call$",
      need_any=(r"\.transfer\s*\(", r"\.call\s*\{",
                r"\]\s*(\+|-)?="),
      forbid=(r"msg\.sender\s*==|require\s*\([^)]*msg\.sender",
              r"factory\s*==|pair\s*=="),
      detail="Flash-swap callback without caller validation: "
             "the pancakeCall/uniswapV2Call callback moves value "
             "or writes state without first verifying that "
             "msg.sender is the genuine pair (and that the call "
             "was initiated by this contract). Anyone can invoke "
             "the callback directly, impersonating a flash swap, "
             "and drive the contract's logic with attacker "
             "inputs."),
    S("pancake_insufficient_slippage_protection", FAMILY,
      severity="high", outcome="a", custom="call_args_zero",
      custom_data={"calls": {
          "swapExactTokensForTokens": (1,),
          "swapExactTokensForTokensSupportingFeeOnTransferTokens":
              (1,),
          "swapExactETHForTokens": (0,),
          "swapExactTokensForETH": (1,),
          "swapExactTokensForETHSupportingFeeOnTransferTokens":
              (1,)}},
      detail="Insufficient slippage protection: a PancakeSwap "
             "swapExact* call passes amountOutMin = 0 (directly "
             "or via a variable assigned 0), accepting ANY "
             "output amount - the textbook sandwich-attack "
             "surface on BNB Chain."),
    S("pancake_k_value_invariant_violation", FAMILY,
      severity="high", outcome="b", fn_re=r"swap|mint|burn",
      contract_need=(r"reserve\w*\s*(=|;)",),
      need=(r"reserve\w*\s*(\+|-)?=",),
      contract_forbid=(
          r"reserve\w*\W{0,3}\*\W{0,3}reserve\w*",
          r"_kLast|kLast", r">=\s*_?k\b"),
      detail="K invariant violation: this pair-shaped contract "
             "rewrites its reserves in a swap/mint/burn path but "
             "nowhere checks the constant-product invariant "
             "(reserve0 * reserve1 >= K), so trades can settle "
             "at ratios that drain one side of the pool - the "
             "check PancakeSwap pairs exist to enforce."),
]

register_family(globals(), SPECS)
