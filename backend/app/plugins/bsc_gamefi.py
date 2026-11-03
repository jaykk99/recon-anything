"""BSC detectors: GameFi & NFTs - BEP-721/1155, marketplaces
(10 plugins).

Dedupe map (outcome per ID, also in the PR body):
- bep721_mint_index_overflow: (c) shared overflow routine
  restricted to the token-id counter increment.
- bep721_reentrancy_on_safe_mint: (c) shared CEI routine
  restricted to _safeMint ordering (custom check - safeMint is
  not in the generic external-call table).
- bep1155_batch_transfer_balance_mismatch: (a) NEW - batch
  transfer with no ids/amounts length equality check.
- marketplace_atomic_match_frontrun: (a) NEW - order
  settlement at a caller-supplied price with no signature /
  order validation.
- marketplace_fee_deduction_underflow: (c) shared overflow
  routine restricted to the settlement fee subtraction.
- marketplace_royalties_recipient_spoofing: (a) NEW - royalty
  paid to a caller-supplied recipient instead of royaltyInfo.
- gamefi_randomness_blockhash_reliance: (b) BSC variant -
  block-variable randomness for game/NFT outcomes (the
  generic detectors do not cover outcome randomness).
- gamefi_state_desync_reward_claim: (a) NEW - claim pays out
  without zeroing/marking the claim state.
- gamefi_asset_duplication_on_burn: (a) NEW - burn path pays
  out (mints/transfers) while never burning anything.
- marketplace_expired_order_execution: (a) NEW - order struct
  carries an expiry that execution never reads.
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "gamefi"

SPECS = [
    S("bep721_mint_index_overflow", FAMILY, severity="medium",
      outcome="c", fn_re=r"mint",
      version_gate="pre080_or_unchecked",
      need_any=(r"\+\+", r"\+=\s*1"),
      forbid=(r"\.add\s*\(", r"SafeMath"),
      detail="Mint index overflow: the token-id counter is "
             "incremented with raw pre-0.8 / unchecked "
             "arithmetic, so at the counter's ceiling the id "
             "wraps and the mint overwrites/collides with an "
             "existing token id instead of reverting."),
    S("bep721_reentrancy_on_safe_mint", FAMILY, severity="high",
      outcome="c", custom="safe_mint_cei", fn_re=r"mint",
      detail="Safe-mint reentrancy: _safeMint (which calls "
             "back into the receiver) executes BEFORE the "
             "mint's own state (id counter / supply / per-wallet "
             "count) is updated and there is no reentrancy "
             "guard, so a receiver contract can re-enter the "
             "mint during the callback and mint past per-wallet "
             "or supply limits."),
    S("bep1155_batch_transfer_balance_mismatch", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"BatchTransfer|batchTransfer|safeBatch",
      need_any=(r"for\s*\(", r"safeBatchTransferFrom|_batch"),
      forbid=(r"\.length\s*==|\.length\s*!=",),
      detail="BEP-1155 batch balance mismatch: the batch "
             "transfer processes ids[] and amounts[] without "
             "ever checking the arrays have equal length. "
             "Mismatched arrays desync the per-id balance "
             "accounting (later ids silently skipped or read "
             "out of bounds) instead of reverting."),
    S("marketplace_atomic_match_frontrun", FAMILY,
      severity="high", outcome="a",
      fn_re=r"match|executeOrder|fulfill|buy|settle",
      need=(r"uint256\s+(price|_price)\b",),
      need_any=(r"transferFrom\s*\(", r"safeTransferFrom\s*\("),
      forbid=(r"ecrecover|signature|_validate|validateOrder|"
              r"orderHash",),
      recipient=True,
      detail="Atomic match frontrunning: the settlement "
             "function transfers the NFT at a price taken from "
             "the CALLER's parameters with no order signature "
             "or order-state validation, so anyone can settle "
             "any listed (or unlisted) asset at a price they "
             "choose - the 'order' is whatever the frontrunner "
             "says it is."),
    S("marketplace_fee_deduction_underflow", FAMILY,
      severity="medium", outcome="c",
      fn_re=r"buy|settle|execute|fulfill",
      version_gate="pre080_or_unchecked",
      need=(r"-\s*\w*[Ff]ee",),
      forbid=(r"require\s*\([^)]*(fee\s*<=|price\s*>=|"
              r">= fee)",),
      detail="Marketplace fee underflow: the seller proceeds "
             "are computed as price minus fee in pre-0.8 / "
             "unchecked arithmetic with no fee <= price bound, "
             "so a listing whose fee exceeds its price wraps "
             "the seller amount to a huge number instead of "
             "reverting."),
    S("marketplace_royalties_recipient_spoofing", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"buy|settle|execute|fulfill|sale",
      need=(r"royalt",),
      need_any=(r"payable\s*\([^)]*ecipient",
                r"\.transfer\s*\([^)]*royalt",
                r"\.call\{value[^}]*\}\([^)]*ecipient"),
      forbid=(r"royaltyInfo",),
      detail="Royalty recipient spoofing: the settlement pays "
             "the royalty to a recipient taken from the "
             "caller's parameters instead of the token's "
             "royaltyInfo (EIP-2981), so the buyer/settler can "
             "name themselves as the 'creator' and pocket the "
             "royalty on every sale."),
    S("gamefi_randomness_blockhash_reliance", FAMILY,
      severity="high", outcome="b",
      fn_re=r"mint|draw|open|roll|spin|play|reward|loot|random",
      need_any=(r"blockhash\s*\(", r"block\.timestamp",
                r"block\.difficulty|block\.prevrandao",
                r"block\.number"),
      forbid=(r"VRF|requestRandomness|fulfillRandomWords|"
              r"Chainlink",),
      detail="Predictable randomness: a game/NFT outcome "
             "(mint rarity, draw, loot, reward) is derived "
             "from block variables (blockhash / timestamp / "
             "block number). Miners and any caller who can "
             "choose WHEN to transact can predict or grind the "
             "outcome before committing - the house edge runs "
             "the wrong way."),
    S("gamefi_state_desync_reward_claim", FAMILY,
      severity="high", outcome="a", fn_re=r"claim",
      need=(r"pending|earned",),
      need_any=(r"\.transfer\s*\(", r"_mint\s*\(",
                r"safeTransfer"),
      need_absent=(r"pending\w*\s*(\[[^\]]*\])?\s*=",
                   r"claimed\s*\[", r"lastClaim", r"claimTime"),
      forbid=(r"claimed\s*\[|lastClaim|claimTime",),
      detail="Reward-claim state desync: the claim path pays "
             "the reward but never zeroes the pending balance "
             "and never marks the claim (no claimed / lastClaim "
             "write in the function), so the stored claim state "
             "still shows the full amount - the same reward "
             "can be claimed again immediately."),
    S("gamefi_asset_duplication_on_burn", FAMILY,
      severity="high", outcome="a", fn_re=r"burn",
      need_any=(r"_mint\s*\(", r"\.transfer\s*\("),
      need_absent=(r"_burn\s*\(", r"totalSupply\w*\s*-="),
      detail="Asset duplication on burn: the burn path pays "
             "out (mints or transfers a reward/refund asset) "
             "but never actually burns anything - no _burn, "
             "no supply reduction - so the same asset can be "
             "'burned' repeatedly, duplicating the payout asset "
             "every time."),
    S("marketplace_expired_order_execution", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"buy|fulfill|execute|match",
      contract_need=(r"expir\w*\s*[:;]",),
      need_any=(r"transferFrom\s*\(", r"safeTransferFrom\s*\(",
                r"\.transfer\s*\("),
      forbid=(r"(?i)expir",),
      detail="Expired order execution: orders carry an expiry "
             "field, but the execution path never reads it, so "
             "stale orders settle long after the maker "
             "intended them dead - at prices the market has "
             "moved far away from."),
]

register_family(globals(), SPECS)
