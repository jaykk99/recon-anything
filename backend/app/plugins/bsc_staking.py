"""BSC detectors: staking & MasterChef farming (10 plugins).

Dedupe map (outcome per ID, also in the PR body):
- masterchef_pool_length_oob: (a) NEW - pid indexing without a
  pool-length bound (MasterChef-specific state shape).
- masterchef_pending_reward_overflow: (c) shared overflow
  routine restricted to the accRewardPerShare pending math.
- masterchef_emergency_withdraw_lock: (a) NEW - emergency
  withdraw that does not zero BOTH user amount and rewardDebt
  before paying out (double-claim lock-in).
- masterchef_reward_token_depletion: (a) NEW - pending paid
  without updatePool() accruing first (stale-accrual payout).
  Distinct state from the rewardDebt detector: accrual vs debt.
- masterchef_duplicate_pool_registration: (b) BSC variant -
  MasterChef add() with no lpToken uniqueness scan (the
  canonical BSC chef flaw).
- masterchef_deposit_fee_skimming: (a) NEW - chef credits the
  full deposit while skimming a fee out of it (the BEP-20
  sibling detector covers the same shape inside a TOKEN's
  transfer; this one is the chef's deposit accounting).
- staking_lockup_duration_bypass: (a) NEW - declared lock that
  the withdraw path never reads.
- staking_reward_compounding_reentrancy: (c) shared reentrancy
  (CEI) routine restricted to compound/claim sites.
- staking_total_shares_mismatch: (a) NEW - shares credited from
  the requested amount instead of the received balance delta
  (fee-on-transfer desync).
- staking_zero_deposit_harvest: (a) NEW - reward paid in a
  deposit/claim path that never writes rewardDebt, so the same
  pending can be claimed repeatedly (deposit(0) harvest loop).
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "staking"

SPECS = [
    S("masterchef_pool_length_oob", FAMILY, severity="medium",
      outcome="a",
      need=(r"poolInfo\s*\[\s*\w*[Pp]id\s*\]",),
      forbid=(r"poolInfo\.length",),
      detail="MasterChef pool index out of bounds: the function "
             "indexes poolInfo[pid] with a caller-supplied pool "
             "id and never bounds it against poolInfo.length. "
             "Out-of-range pids revert every call (a permanent "
             "DoS for that path in integrations that pass user "
             "pids through) and, in variants that catch the "
             "revert, fall through with a zeroed pool struct."),
    S("masterchef_pending_reward_overflow", FAMILY,
      severity="medium", outcome="c", include_view=True,
      version_gate="pre080_or_unchecked",
      need=(r"acc\w*PerShare",),
      need_any=(r"\*",),
      forbid=(r"\.mul\s*\(", r"SafeMath"),
      detail="MasterChef pending-reward overflow: the pending "
             "reward is computed as amount x accRewardPerShare "
             "with raw pre-0.8 / unchecked multiplication. "
             "accRewardPerShare is a large scaled accumulator, "
             "so big positions wrap the product and the pending "
             "figure (and every payout based on it) is wrong."),
    S("masterchef_emergency_withdraw_lock", FAMILY,
      severity="high", outcome="a", fn_re=r"emergencyWithdraw",
      need_any=(r"safeTransfer", r"\.transfer\s*\("),
      forbid_all=(r"\.amount\s*=\s*0", r"rewardDebt\s*=\s*0"),
      detail="Emergency-withdraw lock: emergencyWithdraw pays "
             "the LP out but does not zero BOTH the user's "
             "amount and rewardDebt. The surviving accounting "
             "lets the user deposit the same LP again and claim "
             "the pending rewards a second time (or leaves "
             "rewardDebt pointing at a position that no longer "
             "exists). Zeroing both before the transfer is the "
             "canonical MasterChef shape and does not flag."),
    S("masterchef_reward_token_depletion", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"withdraw|deposit|harvest",
      need=(r"pending", r"rewardDebt\s*="),
      need_any=(r"safeTransfer|safeRewardTransfer|\.transfer\s*\("),
      forbid=(r"updatePool\s*\(",),
      detail="Reward depletion by stale accrual: this payout "
             "path transfers pending rewards WITHOUT calling "
             "updatePool() first, so rewards are settled against "
             "a stale accRewardPerShare while the pool keeps "
             "accruing off-book. Early claimers are paid from "
             "the shared reward balance at the wrong rate and "
             "the chef's reward token drains ahead of schedule."),
    S("masterchef_duplicate_pool_registration", FAMILY,
      severity="medium", outcome="b", fn_re=r"^add$|addPool",
      need_any=(r"poolInfo\.push\s*\(", r"poolInfo\s*\["),
      forbid=(r"poolInfo\s*\[\s*i\s*\]\s*\.lpToken",
              r"lpToken\s*==|==\s*_lpToken|already|exists"),
      detail="Duplicate pool registration: MasterChef add() "
             "registers a pool without scanning existing pools "
             "for the same lpToken. The same LP ends up in two "
             "pools, its balanceOf(this) backs BOTH pools' "
             "accounting, and rewards are allocated (and "
             "claimable) twice against one deposit base - the "
             "canonical BSC chef misconfiguration."),
    S("masterchef_deposit_fee_skimming", FAMILY, severity="medium",
      outcome="a", fn_re=r"deposit",
      need=(r"\.amount\s*\+=\s*_?\w*[Aa]mount",
            r"fee"),
      need_any=(r"safeTransfer\w*\s*\([^)]*fee",
                r"transfer\w*\s*\([^)]*fee"),
      forbid=(r"amount\s*-\s*fee|_amount\s*-\s*fee|"
              r"balanceBefore|receivedAmount"),
      detail="MasterChef deposit-fee skimming mismatch: the "
             "chef takes a deposit fee OUT of the transfer but "
             "credits the user's amount with the FULL pre-fee "
             "figure. The credited position exceeds the LP "
             "actually held for the user, so withdrawals and "
             "reward shares are computed on phantom balance."),
    S("staking_lockup_duration_bypass", FAMILY, severity="medium",
      outcome="a", fn_re=r"withdraw|unstake|redeem",
      contract_need=(r"lock\w*\s*(=|;)|unlockTime|lockPeriod|"
                     r"lockDuration",),
      need_any=(r"safeTransfer", r"\.transfer\s*\(",
                r"call\{value"),
      forbid=(r"unlockTime|lockUntil|depositTime|stakeTime|"
              r"lockPeriod|lockDuration|block\.timestamp"),
      detail="Lockup bypass: the staking contract declares a "
             "lock (lockPeriod / unlockTime state) but the "
             "withdraw path never reads any lock or timestamp "
             "state - the advertised lockup is unenforced and "
             "stakers can exit at any time, defeating the "
             "lock's purpose (and any reward priced for it)."),
    S("staking_reward_compounding_reentrancy", FAMILY,
      severity="high", outcome="c",
      fn_re=r"compound|claim|harvest|getReward|restake",
      need_any=(r"\.transfer\s*\(", r"\.call\s*\{",
                r"safeTransfer"),
      forbid=(r"nonReentrant",),
      cei=True,
      detail="Compounding reentrancy: the compound/claim path "
             "makes its external call BEFORE updating the "
             "user's reward state (checks-effects-interactions "
             "violated, no reentrancy guard), so a caller "
             "contract can re-enter during the payout and "
             "compound/claim against the stale position "
             "repeatedly."),
    S("staking_total_shares_mismatch", FAMILY, severity="medium",
      outcome="a", fn_re=r"deposit|stake",
      need_any=(r"shares\w*\s*\[\s*msg\.sender\s*\]\s*\+=",
                r"totalShares\w*\s*\+=",
                r"balanceOf\s*\[\s*msg\.sender\s*\]\s*\+=\s*_?\w*"
                r"[Aa]mount"),
      forbid=(r"balanceBefore|balanceAfter|received\s*=|"
              r"amountReceived"),
      detail="Total-shares mismatch: shares are credited from "
             "the REQUESTED deposit amount, never from the "
             "balance delta actually received. With a "
             "fee-on-transfer staking token (the BNB Chain "
             "norm), every deposit over-credits shares, so "
             "totalShares permanently exceeds the assets "
             "backing them and late withdrawers are shorted."),
    S("staking_zero_deposit_harvest", FAMILY, severity="high",
      outcome="a", fn_re=r"deposit|harvest|claim",
      need=(r"acc\w*PerShare",),
      need_any=(r"safeTransfer|safeRewardTransfer|"
                r"\.transfer\s*\("),
      need_absent=(r"rewardDebt\s*=",),
      detail="Zero-deposit harvest loop: this deposit/claim "
             "path pays out pending rewards but never writes "
             "rewardDebt, so the same pending amount stays "
             "claimable - calling deposit(0) (or the claim "
             "path) repeatedly harvests the same rewards until "
             "the reward balance is empty."),
]

register_family(globals(), SPECS)
