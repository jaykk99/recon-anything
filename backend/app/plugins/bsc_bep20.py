"""BSC detectors: BEP-20 & token standards (10 plugins).

One registered plugin per ID, all built on the shared engine in
bsc_common (contract_logic scope/gate/recipient discipline).
Dedupe map (outcome per ID, also in the PR body):
- bep20_transfer_fee_miscalculation: (a) NEW - fee accounting is
  not covered by any existing detector.
- bep20_blacklist_authority_check: (b) BSC variant of the generic
  access-control lane, restricted to blacklist administration.
- bep20_mint_cap_bypass: (b) BSC variant - the declared-cap
  promise check (a cap alone is not a gate, PR #78 lesson); fires
  only when no supply-vs-cap comparison exists anywhere.
- bep20_allowance_double_spend: (c) shared approval-analysis
  routine restricted to the BEP-20 approve() overwrite pattern.
- bep20_balance_of_side_effects: (a) NEW - view-with-side-effects.
- bep20_owner_privilege_abuse: (b) BSC honeypot variant - an
  entry point that debits a NON-sender balance with no allowance
  path (owner-can-seize shape), gated or not.
- bep20_burn_from_overflow: (c) shared overflow routine
  restricted to the burn path (pre-0.8 / unchecked only).
- bep20_fake_transfer_events: (a) NEW - silent transfers.
- bep20_arbitrary_minting_endpoints: (c) shared ungated-mint
  routine restricted to mint endpoints whose names do NOT say
  mint (issue / airdrop / distribute shapes).
- bep20_decimal_mismatch: (a) NEW - decimals() vs scaling
  constants comparison (custom check).
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "bep20"

SPECS = [
    S("bep20_transfer_fee_miscalculation", FAMILY, severity="high",
      outcome="a", fn_re=r"^transfer",
      need=(r"\bfee\w*\s*=[^;]*\*", r"\]\s*\+=\s*(amount|_amount|value)\b",
            r"\]\s*\+=\s*fee"),
      forbid=(r"amount\s*-\s*fee", r"_amount\s*-\s*fee",
              r"netAmount", r"received\s*=", r"amountAfterFee"),
      recipient=True,
      detail="Transfer-fee miscalculation: the transfer path "
             "computes a fee, credits the recipient the FULL "
             "amount, and ALSO credits the fee to a fee address. "
             "The fee is created out of nothing, so the sum of "
             "balances grows past totalSupply on every taxed "
             "transfer (BNB Chain fee tokens are the classic "
             "carrier of this bug)."),
    S("bep20_blacklist_authority_check", FAMILY, severity="high",
      outcome="b", fn_re=r"blacklist|black_list|botlist|blocklist",
      need=(r"(?i)blacklist|black_list|blocklist|isBot",
            r"\]\s*=\s*true|\]\s*=\s*1\b|push\s*\("),
      gated_suppresses=True,
      detail="Blacklist authority: a blacklist/blocklist "
             "administration function performs the state write "
             "with NO access gate, so any stranger can blacklist "
             "arbitrary addresses (freezing their transfers on "
             "BNB Chain tokens that enforce the list in the "
             "transfer path). Properly owner/role-gated blacklist "
             "administration does not flag."),
    S("bep20_mint_cap_bypass", FAMILY, severity="medium",
      outcome="b", scope="contract",
      contract_need=(r"(maxSupply|MAX_SUPPLY|supplyCap|mintCap|_cap)"
                     r"\s*(=|;)",
                     r"_mint\s*\(|totalSupply\w*\s*\+="),
      contract_forbid=(
          r"(cap|MAX_SUPPLY|maxSupply)[^;\n]{0,50}(<=|>=|<|>|==)",
          r"(<=|>=|<|>|==)[^;\n]{0,50}(cap|MAX_SUPPLY|maxSupply)"),
      detail="Mint cap bypass: the token declares a supply cap "
             "but NO code path ever compares the supply against "
             "it, so the cap is decorative - minting can blow "
             "straight past the advertised maximum on BNB Chain. "
             "(A cap variable alone is not a gate; enforcement "
             "has to compare, per the PR #78 adjudication.)"),
    S("bep20_allowance_double_spend", FAMILY, severity="medium",
      outcome="c", fn_re=r"approve", fn_exclude_re=r"^_|increase|decrease",
      public_only=True,
      contract_forbid=(r"increaseAllowance",),
      need_any=(r"allowances?\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=",
                r"_approve\s*\("),
      forbid=(r"value\s*==\s*0\s*\|\|", r"amount\s*==\s*0\s*\|\|",
              r"allowances?\s*\[[^\]]+\]\s*\[[^\]]+\]\s*==\s*0"),
      detail="Allowance double-spend (approve race): approve() "
             "overwrites a non-zero allowance directly, so a "
             "spender watching the mempool can spend the OLD "
             "allowance and then the NEW one. The safe BEP-20 "
             "shapes (require zero-first, or increase/decrease "
             "allowance) do not flag."),
    S("bep20_balance_of_side_effects", FAMILY, severity="medium",
      outcome="a", fn_re=r"^balanceOf$", include_view=True,
      need_any=(r"\w+\s*\[[^\]]*\]\s*(\+|-)?=",
                r"\.call\s*\{|\.transfer\s*\("),
      detail="balanceOf side effects: balanceOf() is specified "
             "as a pure read, but this implementation WRITES "
             "state (or calls out) inside it. Wallets, DEXes and "
             "lending markets on BNB Chain read balanceOf inside "
             "larger operations; a mutating balanceOf desyncs "
             "their accounting and breaks the read-only "
             "assumption (it is also unusable from other "
             "contracts' view paths)."),
    S("bep20_owner_privilege_abuse", FAMILY, severity="high",
      outcome="b", public_only=True, recipient=True,
      fn_exclude_re=r"burn",
      need_any=(r"balances?\w*\s*\[\s*(?!msg\.sender)[^\]]+\]\s*-=",
                r"balances?\w*\s*\[\s*(?!msg\.sender)[^\]]+\]\s*=\s*"
                r"balances?\w*\s*\[\s*(?!msg\.sender)[^\]]+\]\s*-"),
      forbid=(r"allowance",),
      detail="Owner privilege abuse (seizure shape): an external "
             "entry point debits a balance that is NOT the "
             "caller's, with no allowance check anywhere in the "
             "function. Whoever can call it (an onlyOwner gate "
             "does NOT excuse this - it is the caller who "
             "receives) can move other holders' tokens at will: "
             "the canonical BNB Chain honeypot / rug shape. "
             "Legitimate transferFrom debits check the allowance "
             "and do not flag."),
    S("bep20_burn_from_overflow", FAMILY, severity="high",
      outcome="c", fn_re=r"burn",
      version_gate="pre080_or_unchecked",
      need=(r"-=",),
      need_any=(r"balances?\w*\s*\[", r"totalSupply"),
      forbid=(r"require\s*\([^)]*(>=|>)", r"\.sub\s*\("),
      detail="Burn-path underflow: a burn/burnFrom function "
             "subtracts from a balance (or the supply) with raw "
             "pre-0.8 / unchecked arithmetic and no balance bound "
             "checked first, so burning more than the balance "
             "wraps it to a huge number instead of reverting. "
             "Checked 0.8 math and SafeMath .sub do not flag."),
    S("bep20_fake_transfer_events", FAMILY, severity="medium",
      outcome="a", fn_re=r"^transfer$|^transferFrom$",
      need=(r"return\s+true",),
      need_any=(r"balances?\w*\s*\[",),
      forbid=(r"emit\s+Transfer", r"_transfer\s*\("),
      detail="Fake transfer events: transfer/transferFrom moves "
             "balances and returns true but never emits the "
             "Transfer event (and does not route through an "
             "internal _transfer that does). Indexers, exchanges "
             "and tax/accounting tooling on BNB Chain track "
             "tokens by Transfer logs; silent transfers make "
             "real movements invisible to them."),
    S("bep20_arbitrary_minting_endpoints", FAMILY, severity="high",
      outcome="c", fn_exclude_re=r"mint",
      public_only=True,
      contract_forbid=(r"bridge|Bridge",),
      need=(r"_mint\s*\(|totalSupply\w*\s*\+="),
      gated_suppresses=True,
      detail="Arbitrary minting endpoint: a function whose name "
             "does NOT say mint (issue / airdrop / distribute / "
             "release shapes) increases the supply with NO "
             "access gate. These side-door mint endpoints are "
             "routinely missed by reviewers who only audit the "
             "function literally named mint(). Gated endpoints "
             "and the mint() function itself (covered by the "
             "generic ungated-mint lane) do not flag here."),
    S("bep20_decimal_mismatch", FAMILY, severity="medium",
      outcome="a", custom="decimal_mismatch",
      detail="Decimal mismatch: the token's decimals() disagrees "
             "with the scaling constants its own math uses, so "
             "amounts are off by orders of magnitude somewhere "
             "in the contract (a classic BNB Chain fork bug: "
             "the token is forked from an 18-decimal reference "
             "but issued with different decimals)."),
]

register_family(globals(), SPECS)
