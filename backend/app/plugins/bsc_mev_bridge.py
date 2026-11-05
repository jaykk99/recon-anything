"""BSC detectors: MEV, frontrunning & bridges (10 plugins).

Dedupe map (outcome per ID, also in the PR body):
- mev_sandwich_attack_vulnerability: (b) BSC variant - the
  VICTIM-side detector: a contract's own swap API takes no
  slippage parameter at all. The PancakeSwap module's slippage
  detector covers literal amountOutMin=0 at router call sites;
  this one requires NO slippage vocabulary anywhere in the
  function, so the two never fire on the same function.
- bridge_deposit_event_spoofing: (a) NEW - deposit crediting
  with no proof/signature/merkle validation.
- bridge_validator_quorum_manipulation: (a) NEW - validator
  signatures counted without distinct-signer dedup or a real
  quorum comparison.
- bridge_wrapped_token_mint_unbacked: (b) BSC variant -
  ungated mint restricted to wrapped/bridge-marked contracts.
- bridge_message_payload_injection: (b) BSC variant - the
  arbitrary-call custom check restricted to bridge message
  executors; the access module's detector covers generic
  executors and requires non-bridge function names.
- mev_block_number_lock_bypass: (a) NEW - trade lock enforced
  on one transfer path and missing on a sibling path (custom
  asymmetry check).
- bridge_withdrawer_identity_spoof: (a) NEW - bridge payout
  recipient taken from call parameters, unbound from any
  deposit record or signed hash.
- bridge_emergency_pause_lockup: (a) NEW - ungated pause on a
  contract whose funds exit through whenNotPaused paths.
- mev_arbitrary_liquidation_frontrun: (a) NEW - liquidation
  priced by a CALLER-supplied price/rate (the lending module's
  seizure-gap detector requires the absence of price inputs;
  this one requires their presence, so they are disjoint).
- bridge_native_gas_drain: (a) NEW - native 'gas refund' /
  relayer fee paid in a caller-supplied amount, uncapped.
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "mev_bridge"

SPECS = [
    S("mev_sandwich_attack_vulnerability", FAMILY,
      severity="high", outcome="b", custom="victim_slippage",
      custom_data={"calls": {
          "swapExactTokensForTokens": (1,),
          "swapExactTokensForTokensSupportingFeeOnTransferTokens":
              (1,),
          "swapExactETHForTokens": (0,),
          "swapExactTokensForETH": (1,),
          "swapExactTokensForETHSupportingFeeOnTransferTokens":
              (1,)}},
      detail="Sandwich-attack surface: this contract swaps "
             "user or treasury funds through a DEX and its "
             "swap function accepts NO slippage parameter at "
             "all - users cannot bound their execution price "
             "even if they want to, so every swap is fair game "
             "for a sandwich (frontrun + backrun) on BNB "
             "Chain's public mempool."),
    S("bridge_deposit_event_spoofing", FAMILY, severity="high",
      outcome="a", fn_re=r"unlock|release|claim|mint|deposit",
      contract_need=(r"bridge|Bridge",),
      need_any=(r"_mint\s*\(", r"\.transfer\s*\(",
                r"call\{value"),
      forbid=(r"ecrecover|signature|merkle|proof|validator|"
              r"verifySignatures"),
      detail="Deposit event spoofing: this bridge-side credit "
             "function mints or releases assets on a deposit "
             "CLAIM with no validator signature, no merkle "
             "proof and no on-chain proof check of any kind in "
             "the function - anyone can assert a deposit that "
             "never happened on the other chain and be "
             "credited for it."),
    S("bridge_validator_quorum_manipulation", FAMILY,
      severity="high", outcome="a",
      fn_re=r"execute|processMessage|submit|verify",
      need=(r"ecrecover",),
      need_any=(r"count\s*\+=|count\s*\+\+|signatures\.length",
                r"sigCount"),
      forbid=(r"usedSigners|seenSigners|signers\s*\[|distinct",
              r">=\s*quorum|requiredSignatures|"
              r">=\s*threshold"),
      detail="Validator quorum manipulation: validator "
             "signatures are COUNTED (ecrecover in a loop) but "
             "signers are never deduplicated and the count is "
             "never compared against a real quorum - the same "
             "validator signing repeatedly (or a threshold of "
             "one signature) satisfies the 'quorum', so one "
             "compromised or rogue validator is the whole "
             "bridge."),
    S("bridge_wrapped_token_mint_unbacked", FAMILY,
      severity="high", outcome="b", fn_re=r"mint",
      public_only=True,
      contract_need=(r"wrapped|Wrapped|bridge|Bridge",),
      need=(r"_mint\s*\(|totalSupply\w*\s*\+=",),
      gated_suppresses=True,
      detail="Unbacked wrapped-token mint: this wrapped / "
             "bridge token's mint has NO bridge-role gate, so "
             "anyone can mint the wrapped asset without any "
             "corresponding lock or burn on the origin chain - "
             "instant unbacked supply."),
    S("bridge_message_payload_injection", FAMILY,
      severity="high", outcome="b", custom="arbitrary_call",
      fn_re=r"executeMessage|processMessage|receiveMessage|"
            r"handleMessage",
      contract_need=(r"bridge|Bridge|message",),
      contract_forbid=(r"onlyRelayer|onlyValidator",),
      forbid=(r"ecrecover|validator|merkle",),
      recipient=True,
      detail="Bridge message payload injection: the message "
             "executor calls a target taken from the message / "
             "call parameters with no validator verification "
             "in the path, so a forged 'message' makes the "
             "bridge execute arbitrary calls with the bridge's "
             "own identity and balances."),
    S("mev_block_number_lock_bypass", FAMILY, severity="medium",
      outcome="a", custom="asymmetric_lock",
      detail="Block-lock bypass: the contract's trade lock / "
             "cooldown (keyed on a block-number or timestamp "
             "state variable) is enforced on one value-moving "
             "path but a sibling path moves the same value "
             "without ever reading the lock, so the lock "
             "(anti-bot / anti-dump windows on BNB Chain "
             "launches) is bypassed by simply choosing the "
             "other path."),
    S("bridge_withdrawer_identity_spoof", FAMILY,
      severity="high", outcome="a",
      fn_re=r"withdraw|release|unlock",
      need=(r"payable\s*\(\s*(to|recipient|_to|receiver)\s*\)|"
            r"transfer\s*\(\s*(to|recipient|_to|receiver)\s*,|"
            r"call\{value",),
      need_any=(r"address\s+(to|recipient|_to)",),
      forbid=(r"depositId|depositHash|messageHash|"
              r"deposits\s*\[",),
      recipient=True,
      detail="Withdrawer identity spoof: the bridge release "
             "pays a recipient taken straight from the call "
             "parameters, and the recipient is not bound to "
             "any deposit record or signed message hash in the "
             "function - whoever submits the withdrawal names "
             "the payee, so a watcher can redirect other "
             "users' releases to themselves."),
    S("bridge_emergency_pause_lockup", FAMILY, severity="medium",
      outcome="a", fn_re=r"^pause$|pause",
      need=(r"paused\s*=\s*true|_pause\s*\(",),
      gated_suppresses=True,
      detail="Emergency pause lockup: pause() flips the "
             "paused state with NO access gate while user "
             "funds exit through whenNotPaused paths - any "
             "stranger can freeze every withdrawal on the "
             "contract at any time, for as long as they keep "
             "re-pausing after an unpause."),
    S("mev_arbitrary_liquidation_frontrun", FAMILY,
      severity="high", outcome="a", fn_re=r"liquidat",
      need=(r"collateral",),
      need_any=(r"price|rate|discount"),
      forbid=(r"getAccountLiquidity|healthFactor|oracle|"
              r"getPrice|liquidateBorrowAllowed"),
      recipient=True,
      detail="Caller-priced liquidation: the liquidation "
             "computes the seized collateral from a price / "
             "rate / discount supplied BY THE CALLER instead "
             "of an oracle or the account's health, so a "
             "frontrunner names their own price and liquidates "
             "any position - healthy or not - at terms they "
             "dictate."),
    S("bridge_native_gas_drain", FAMILY, severity="medium",
      outcome="a", fn_re=r"refund|claimGas|processMessage|relay",
      need_any=(r"msg\.sender\.transfer\s*\(",
                r"payable\s*\(\s*msg\.sender\s*\)\.transfer",
                r"msg\.sender\.call\{value"),
      need=(r"fee|amount|refund|reward",),
      forbid=(r"gasPrice|MAX_GAS|cap\b|require\s*\([^)]*<=",),
      detail="Native gas drain: the relayer 'gas refund' / fee "
             "is paid to msg.sender in an amount taken from "
             "the call/message parameters, with no gas-price "
             "derivation and no cap - anyone can name the "
             "refund and drain the bridge's native balance "
             "fee by fee."),
]

register_family(globals(), SPECS)
