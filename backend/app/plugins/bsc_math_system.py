"""BSC detectors: core math & system architecture (10 plugins).

Dedupe map (outcome per ID, also in the PR body):
- math_unchecked_downcasting: (a) NEW - narrowing casts are
  silent in EVERY Solidity version (0.8 included); no existing
  detector looks at casts.
- gas_denial_of_service_loop: (c) shared loop-DoS routine
  restricted to loops carrying external calls / payouts (the
  timelock module's gas detector is restricted to timelock
  batch execution; disjoint function shapes).
- system_stale_oracle_data: (b) BSC variant - Chainlink
  latestRoundData consumed with no freshness fields read at
  all (the Pancake module covers pair-reserve spot oracles).
- math_division_before_multiplication: (a) NEW - division
  ordered before multiplication in value math.
- system_ether_transfer_fallback_brick: (a) NEW - 2300-gas
  .transfer()/.send() payouts to arbitrary recipients.
- system_hardcoded_gas_limits: (a) NEW - literal gas stipends
  baked into low-level calls.
- math_signed_unsigned_comparison: (a) NEW - signed state
  cast to unsigned before comparison (custom check pairs the
  cast with the signed declaration).
- system_selfdestruct_funds_trap: (a) NEW - selfdestruct in a
  non-proxy compilation (the proxy module's detector requires
  a delegatecall surface alongside; disjoint).
- system_assembly_memory_overwrite: (a) NEW - assembly mstore
  to the free-memory-pointer / scratch slots.
- system_unbounded_fee_parameter: (a) NEW - fee setters with
  no upper-bound require (a gate does NOT excuse this one: an
  owner-set 100% fee is the honeypot shape).
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "math_system"

SPECS = [
    S("math_unchecked_downcasting", FAMILY, severity="medium",
      outcome="a",
      need=(r"uint(8|16|32|64|128)\s*\(\s*[A-Za-z_]",),
      forbid=(r"SafeCast|toUint(8|16|32|64|128)\s*\(",
              r"type\s*\(\s*uint"),
      detail="Unchecked downcasting: a value is explicitly "
             "cast to a narrower uint type with no range check. "
             "Narrowing casts truncate SILENTLY in every "
             "Solidity version (0.8's checked arithmetic does "
             "not cover casts), so any value above the target "
             "type's max wraps - balances, ids and timestamps "
             "all corrupt the same way. SafeCast usage does "
             "not flag."),
    S("gas_denial_of_service_loop", FAMILY, severity="medium",
      outcome="c", gated_suppresses=True,
      need=(r"for\s*\(", r"\.length"),
      need_any=(r"\.transfer\s*\(", r"\.call\s*\{",
                r"safeTransfer"),
      forbid=(r"MAX_|maxIterations|require\s*\([^)]*(end|limit)"
              r"|offset|start\s*\+"),
      detail="Gas denial of service: the function loops over "
             "an ever-growing array (users / holders / stakes) "
             "performing calls or payouts per element, with no "
             "pagination or bound. Once the array is large "
             "enough the function can never complete inside a "
             "block's gas limit and the operation is bricked "
             "for everyone."),
    S("system_stale_oracle_data", FAMILY, severity="high",
      outcome="b", include_view=True,
      need=(r"latestRoundData\s*\(",),
      forbid=(r"updatedAt|answeredInRound|stale|STALE|"
              r"heartbeat|timeSince"),
      detail="Stale oracle data: the Chainlink "
             "latestRoundData() result is consumed reading "
             "ONLY the price - updatedAt / answeredInRound are "
             "never touched anywhere in the function - so a "
             "stalled or stale feed is indistinguishable from "
             "a live one and every price decision settles on "
             "dead data."),
    S("math_division_before_multiplication", FAMILY,
      severity="medium", outcome="a",
      need_any=(r"\w+\s*/\s*\w+\s*\*(?!\*)\s*\w+",
                r"\(\s*\w+\s*/\s*\w+\s*\)\s*\*(?!\*)",
                r"/\s*\d+\s*\*(?!\*)\s*\w"),
      detail="Division before multiplication: value math "
             "divides first and multiplies second, so integer "
             "truncation eats the remainder BEFORE it is "
             "scaled - fees, shares and rewards come out "
             "systematically short (and zero for small "
             "amounts). Multiply-first ordering does not flag."),
    S("system_ether_transfer_fallback_brick", FAMILY,
      severity="medium", outcome="a",
      need=(r"\.transfer\s*\(\s*[^,)]+\)",),
      need_any=(r"payable", r"msg\.sender", r"recipient|to\b"),
      forbid=(r"\.call\s*\{value",),
      detail="Ether transfer brick: native payouts use "
             ".transfer()/.send()-style 2300-gas semantics "
             "(.transfer with a single value argument), which "
             "permanently fails for recipients whose fallback "
             "does real work (smart wallets, multisigs, "
             "contracts) - their withdrawals brick while "
             "plain accounts succeed. Call-based payouts in "
             "the same function suppress this."),
    S("system_hardcoded_gas_limits", FAMILY, severity="low",
      outcome="a",
      need_any=(r"\.call\.gas\s*\(\s*\d+",
                r"gas\s*:\s*\d{3,}"),
      detail="Hardcoded gas limit: a low-level call carries a "
             "literal gas stipend baked into the code. "
             "Stipends chosen for today's opcode prices break "
             "silently when gas repricing lands (the 2300 "
             "transfer stipend class of bug), and a stipend "
             "too small for the callee's fallback bricks the "
             "call path."),
    S("math_signed_unsigned_comparison", FAMILY,
      severity="medium", outcome="a", custom="signed_unsigned",
      detail="Signed/unsigned comparison: a signed (int) "
             "state variable is cast to an unsigned type "
             "before use, so negative values become enormous "
             "positive ones in any comparison or accounting "
             "that consumes the cast - sign logic inverts "
             "exactly where the value goes negative."),
    S("system_selfdestruct_funds_trap", FAMILY,
      severity="medium", outcome="a",
      need=(r"selfdestruct\s*\(",),
      contract_forbid=(r"delegatecall",),
      detail="Selfdestruct funds trap: the contract contains "
             "a selfdestruct. Beyond the destruction itself, "
             "any native funds sent to the contract's address "
             "AFTER destruction are trapped forever (the "
             "address can still receive, nothing can ever move "
             "them), and pre-destruction the opcode is a "
             "one-call kill switch for every integration "
             "pointing at the address. (Proxy compilations are "
             "covered by the proxy module's detector.)"),
    S("system_assembly_memory_overwrite", FAMILY, severity="low",
      outcome="a",
      need=(r"assembly\s*\{",),
      need_any=(r"mstore\s*\(\s*0x40\s*,",
                r"mstore\s*\(\s*0\s*,", r"mstore\s*\(\s*0x00\s*,"),
      detail="Assembly memory overwrite: inline assembly "
             "writes directly to memory slot 0x40 (the free "
             "memory pointer) or the 0x00 scratch slot with a "
             "value that is not a computed allocation, "
             "corrupting the allocator for every subsequent "
             "memory operation in the call."),
    S("system_unbounded_fee_parameter", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"setFee|setTax|setCommission|setRoyalt|setCharge",
      need=(r"\w*[Ff]ee\w*\s*=|\w*[Tt]ax\w*\s*=|"
            r"commission\w*\s*=",),
      forbid=(r"require\s*\([^)]*(<|<=|>|>=)",),
      detail="Unbounded fee parameter: the fee/tax setter "
             "stores the new fee with NO upper-bound check, so "
             "the fee can be set to 100% (or more) - every "
             "subsequent transfer is confiscated by the fee. "
             "An owner gate does not excuse this: owner-set "
             "100% fees are the standard BNB Chain honeypot "
             "shape. A bounded setter (require fee <= cap) "
             "does not flag."),
]

register_family(globals(), SPECS)
