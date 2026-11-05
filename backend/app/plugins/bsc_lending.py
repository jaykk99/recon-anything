"""BSC detectors: flash loans & lending protocols (10 plugins).

Dedupe map (outcome per ID, also in the PR body):
- flash_loan_spot_balance_check: (a) NEW - repayment assurance
  by spot balance comparison only.
- flash_loan_callback_auth_bypass: (b) BSC/DeFi variant of the
  callback-validation family (sibling of the PancakeSwap
  callback detector, restricted to flash-loan receiver
  callbacks: onFlashLoan / executeOperation shapes).
- flash_loan_repayment_underflow: (c) shared overflow routine
  restricted to flash-loan repayment math.
- flash_loan_governance_takeover: (a) NEW - spot-balance voting
  power (governance family member; the governance-module
  sibling covers the propose() threshold site, this one the
  vote-weight site).
- flash_loan_reward_dilution: (a) NEW - spot-balance reward
  claims with no time weighting.
- venus_comptroller_state_sync: (b) BSC variant - Venus is
  BSC's Compound fork; the check is the comptroller hook
  (mintAllowed/borrowAllowed) by name.
- venus_accrue_interest_omission: (b) BSC variant - Venus
  vToken *Stored reads without accrueInterest().
- venus_mint_rate_assumption: (b) BSC variant - vToken mint
  crediting the underlying amount 1:1, ignoring the exchange
  rate.
- lending_pool_liquidation_incentive_overflow: (c) shared
  overflow routine restricted to liquidation incentive math.
- lending_pool_collateral_seizure_gap: (a) NEW - seizure with
  no health/shortfall check anywhere in the function.
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "lending"

SPECS = [
    S("flash_loan_spot_balance_check", FAMILY, severity="medium",
      outcome="a", fn_re=r"flashLoan",
      need=(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",),
      forbid=(r"transferFrom\s*\(",
              r"debt\w*\s*\[\s*msg\.sender\s*\]\s*="),
      detail="Flash-loan spot balance check: the lender verifies "
             "repayment only by comparing its own spot token "
             "balance before/after the callback. A balance can "
             "be inflated without repaying (direct donation, a "
             "second loanee's funds, fee-on-transfer games), so "
             "the check does not prove THIS borrower repaid. "
             "Lenders that pull repayment via transferFrom or "
             "track an initiator-bound debt record do not flag."),
    S("flash_loan_callback_auth_bypass", FAMILY, severity="high",
      outcome="b",
      fn_re=r"onFlashLoan|executeOperation|receiveFlashLoan|"
            r"onFlashloan",
      need_any=(r"\.transfer\s*\(", r"\.call\s*\{",
                r"approve\s*\(", r"\]\s*(\+|-)?="),
      forbid=(r"msg\.sender\s*==|initiator\s*==|"
              r"require\s*\([^)]*msg\.sender"),
      detail="Flash-loan callback auth bypass: the receiver "
             "callback (onFlashLoan / executeOperation shape) "
             "acts on the funds without verifying the caller is "
             "the lender or that the initiator is this contract, "
             "so anyone can call the callback directly and make "
             "the contract move or approve its own assets as if "
             "a flash loan were in flight."),
    S("flash_loan_repayment_underflow", FAMILY, severity="medium",
      outcome="c", fn_re=r"flash|repay",
      version_gate="pre080_or_unchecked",
      need_any=(r"=\s*[^;]*balanceOf\s*\([^)]*\)\s*-",
                r"=\s*[^;]*-\s*\w*[Bb]alance\w*"),
      forbid=(r"require\s*\([^)]*(>=|>)",),
      detail="Flash-loan repayment underflow: repayment/fee math "
             "subtracts balance snapshots (after minus before) "
             "in pre-0.8 or unchecked arithmetic, so a callback "
             "that leaves the balance LOWER than the snapshot "
             "wraps the 'fee' to a huge number instead of "
             "reverting, corrupting the repayment accounting."),
    S("flash_loan_governance_takeover", FAMILY, severity="high",
      outcome="a", fn_re=r"vote|castVote",
      need_any=(r"balanceOf\s*\(", r"getVotes\s*\("),
      forbid=(r"getPastVotes|getPriorVotes|snapshot|checkpoint",),
      contract_forbid=(r"getPastVotes|getPriorVotes",),
      detail="Flash-loan governance takeover: voting weight is "
             "read from the CURRENT token balance (balanceOf / "
             "current getVotes) at vote time, with no past-block "
             "snapshot. An attacker can flash-borrow the "
             "governance token, vote with borrowed weight, and "
             "return it in the same transaction - voting power "
             "that costs nothing to hold."),
    S("flash_loan_reward_dilution", FAMILY, severity="medium",
      outcome="a", fn_re=r"claim|harvest|getReward|collect",
      need_any=(r"balanceOf\s*\(\s*msg\.sender",
                r"shares\s*\[\s*msg\.sender",
                r"staked\s*\[\s*msg\.sender"),
      forbid=(r"depositTime|lockUntil|stakeTime|lastDeposit|"
              r"startTime\s*\[|timeWeighted|block\.number\s*-",),
      detail="Flash-loan reward dilution: the reward claim is "
             "computed from the caller's CURRENT balance / share "
             "position with no deposit-time or lock weighting, "
             "so a flash-borrowed position can be held for "
             "exactly the claim transaction and dilute every "
             "honest staker's rewards."),
    S("venus_comptroller_state_sync", FAMILY, severity="high",
      outcome="b", fn_re=r"^mint|^borrow|mintFresh|borrowFresh",
      contract_need_any=(r"comptroller|Comptroller",
                         r"totalBorrows", r"accountBorrows",
                         r"borrowBalance"),
      need_any=(r"_mint\s*\(", r"totalBorrows\w*\s*\+=",
                r"accountBorrows\w*\s*(\+)?=",
                r"borrowBalance\w*\s*\+="),
      forbid=(r"comptroller\.\w+", r"mintAllowed|borrowAllowed",
              r"isListed|getHypotheticalAccountLiquidity|"
              r"accountAssets"),
      detail="Venus comptroller desync: this Venus/Compound-"
             "style market mints or lends WITHOUT consulting "
             "the comptroller (no mintAllowed/borrowAllowed, no "
             "membership/liquidity check), so the comptroller's "
             "account-liquidity state never learns about the "
             "position - collateral factors, listing status and "
             "shortfall checks are all bypassed on BNB Chain's "
             "main lending design."),
    S("venus_accrue_interest_omission", FAMILY, severity="medium",
      outcome="b",
      need_any=(r"exchangeRateStored|borrowBalanceStored",
                r"getCash\s*\("),
      forbid=(r"accrueInterest\s*\(",),
      detail="Venus accrue-interest omission: the function "
             "reads stored (stale) exchange-rate / borrow-balance "
             "values without calling accrueInterest() first, so "
             "it acts on rates that lag real time - redemptions "
             "and liquidations settle at yesterday's price "
             "while the market's true state has moved."),
    S("venus_mint_rate_assumption", FAMILY, severity="medium",
      outcome="b", fn_re=r"mint",
      contract_need=(r"totalBorrows|comptroller|exchangeRate",),
      need=(r"mintAmount|_amount|amount",),
      need_any=(r"_mint\s*\(\s*msg\.sender\s*,\s*\w*[Aa]mount",
                r"totalSupply\w*\s*\+=\s*\w*[Aa]mount"),
      forbid=(r"exchangeRate",),
      detail="Venus mint-rate assumption: the market credits "
             "vTokens 1:1 with the underlying amount deposited, "
             "never dividing by the exchange rate. As the rate "
             "drifts from 1.0 (it only grows in Venus markets), "
             "new minters are over-credited and existing "
             "holders are diluted."),
    S("lending_pool_liquidation_incentive_overflow", FAMILY,
      severity="high", outcome="c", fn_re=r"liquidat",
      version_gate="pre080_or_unchecked",
      need=(r"\*",),
      need_any=(r"incentive|bonus|seize|collateral",),
      forbid=(r"\.mul\s*\(", r"SafeMath"),
      detail="Liquidation incentive overflow: the collateral-"
             "seizure amount is computed with raw multiplication "
             "(debt x incentive) in pre-0.8 or unchecked "
             "arithmetic, so a large liquidation wraps the "
             "seizure amount - either stealing far more "
             "collateral than the incentive allows or zeroing "
             "it and breaking liquidation entirely."),
    S("lending_pool_collateral_seizure_gap", FAMILY,
      severity="high", outcome="a", fn_re=r"liquidat|seize",
      need_any=(r"seize\w*\s*\(", r"transfer\w*\s*\([^)]*collateral",
                r"_seize|liquidateCalculateSeize"),
      forbid=(r"getAccountLiquidity|healthFactor|shortfall|"
              r"liquidateBorrowAllowed|liquidateAllowed|"
              r"isLiquidatable|checkLiquidation"),
      detail="Collateral seizure gap: the liquidation path "
             "seizes a borrower's collateral without ever "
             "checking the account is actually underwater (no "
             "liquidity / shortfall / health-factor check in "
             "the function). If reachable on healthy accounts, "
             "anyone can force-seize collateral at the "
             "liquidation discount."),
]

register_family(globals(), SPECS)
