"""Deep-audit detectors, batch 6: Financial + Oracle slices
(2026-11-04).

Nine chain-agnostic EVM detectors covering the partial / gap
slices named in the 2026-11-04 coverage audit (coverage-b.json:
FIN-001, FIN-003, FIN-005, FIN-006, FIN-008, FIN-009, ORC-001,
ORC-003, ORC-006). Built to the batch-1/2/3/4 standard:
recipient classification computed inside the detector and
carried on the finding where value flows (CALLER /
CALLER-SUPPLIED = candidate; FIXED / HOLDER-SELF =
trigger-only, never a candidate), the exact code plus a gate
analysis on every finding, body / condition parsing (balanced
parens and braces, top-level argument splitting), never naive
whole-file regex.

- unchecked_math_user_input (FIN-001 slice): an unchecked{}
  block doing arithmetic on an operand that is a parameter of
  the enclosing function, with the result assigned onward (a
  state variable, or a local that is later stored / returned /
  passed to a call). contract_logic's unchecked lane skips
  caller-gated functions entirely and requires the assignment
  LHS to be a state variable; this lane fires in BOTH cases
  (a gate does not bound the arithmetic, and a local that is
  stored onward is state one hop later). Pure loop-counter
  increments (a variable declared in a for-init, only
  incremented, never stored onward) stay silent, as does
  unchecked math over constants / bounded internals only.
- strict_balance_equality (FIN-003): a require / assert / if
  condition compares address(this).balance with == (either
  order, or via a local assigned from address(this).balance in
  the same function) gating a value / state path. Strict
  equality on a balance is broken by forced ETH (selfdestruct
  / coinbase), so the gate can be made permanently true or
  permanently false by a stranger. >= / <= / > stay silent.
- swap_fixed_min_amount_out (FIN-005 slice) and
  swap_deadline_unbound (FIN-006 slice): one argument-parsing
  analyzer over the four Uniswap-V2-router swap signatures.
  The min-out lane fires when the amountOutMin-position
  argument is a NON-ZERO numeric literal (zero is owned by
  pancake_insufficient_slippage_protection /
  cp_proto_unbounded_slippage; a hardcoded non-zero floor is
  not derived from any quote, so it is either dust that
  protects nothing or a stale constant that bricks / leaks
  the swap). The deadline lane fires when the
  deadline-position argument is a numeric literal or
  type(uint256).max (a fixed or effectively-infinite
  deadline leaves the swap executable by miners / searchers
  indefinitely). Identifier / expression /
  block.timestamp-derived arguments stay silent.
  swapTokensForExactETH has no min-out position (deadline
  lane only).
- shadowed_state_variable_legacy (FIN-008 slice): only when
  the source pragma allows solc < 0.6.0 (from 0.6 the compiler
  rejects shadowing): two contracts in one source in an `is`
  inheritance relation where the derived contract redeclares
  a base contract's state variable name. The two declarations
  are DIFFERENT storage slots pre-0.6 semantics confusion:
  writes through one name do not move the other.
- hardcoded_decimals_scaling (FIN-009 slice): arithmetic
  scaling by a literal 1e18 / 10**18 applied to amounts in a
  contract that calls transfer / transferFrom / approve on
  external token interfaces, while the contract NEVER calls
  decimals() anywhere (no dot-call). A 6-decimal token priced
  or accounted at 18 decimals is off by 1e12.
- twap_observe_window_short (ORC-001 slice): a Uniswap V3
  observe() call whose secondsAgo literal array maxes below
  1800 seconds, or a contract calling observe / consult with
  a PERIOD / WINDOW-named constant assigned a literal below
  1800. A sub-30-minute TWAP is movable within a few blocks
  at feasible capital. Non-literal windows cannot be judged
  and stay silent.
- chainlink_price_unbounded (ORC-003): a function consumes
  latestRoundData() and the price value (or a local derived
  from it) flows into arithmetic / a transfer / a return,
  while NO condition anywhere in the contract compares that
  price variable against a literal bound or a *MIN* / *MAX*
  -named identifier: no de-peg / sanity circuit breaker. A
  malfunctioning or manipulated feed prints any price and
  the consumer takes it at face value. Staleness is owned by
  system_stale_oracle_data and is NOT duplicated here.
- view_price_no_reentrancy_protection (ORC-006 slice +
  REE-004 price slice): the contract has NO reentrancy
  protection anywhere (no nonReentrant / ReentrancyGuard /
  _status-style lock), a view / pure function computes a
  price / ratio from live pool state (getReserves(),
  balanceOf of a pair-ish target, get_virtual_price, reserve
  state reads), and non-view functions make external calls -
  so a consumer reading the price mid-callback reads pool
  state an attacker is actively moving. This is exactly the
  case readonly_reentrancy_gap returns [] for (it requires a
  lock somewhere in the contract); when any guard IS present
  this lane stays silent and the native lane owns it.

Detection only: verified-source static analysis in the fast
lane, never sends a transaction, never calls the contract
for value. Fetch failure is reported honestly by the shared
scaffolding (analyzed 0 / no verified source - skipped),
never dressed up as a clean result.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from . import crypto_drain as cd
from .bsc_common import DetectorSpec, S

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "deep6"

SPECS = [
    S("unchecked_math_user_input", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Unchecked arithmetic on caller-supplied input: "
             "an unchecked{} block performs arithmetic on an "
             "operand that is a parameter of the enclosing "
             "function and the result is assigned onward (a "
             "state variable, or a local that is stored, "
             "returned or passed on). Since Solidity 0.8 the "
             "compiler's overflow checks are the only thing "
             "standing between a crafted input and a wrapped "
             "balance / fee / share figure; inside unchecked{} "
             "that protection is explicitly switched off, and "
             "a caller-identity gate on the function does not "
             "bound the arithmetic for the callers who ARE "
             "allowed through (or for a compromised / "
             "relayer path).",
      fix="Remove the unchecked{} block around math on "
          "user-supplied operands, or bound every input "
          "inside the block (require the operand and the "
          "intermediate result stay below an explicit cap) "
          "and re-check the result before it is stored."),
    S("strict_balance_equality", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Strict equality on the contract balance: a "
             "validation condition compares "
             "address(this).balance with == (directly or "
             "through a local assigned from it) gating a "
             "value / state path. ETH can be forced into any "
             "contract (selfdestruct, coinbase payment, "
             "pre-funded address), so an exact-balance "
             "equality can be broken - or satisfied - by a "
             "stranger at will: the gated path can be bricked "
             "permanently or opened off-schedule.",
      fix="Never gate on exact balance equality: compare "
          "with >= / <= against a threshold, or track the "
          "expected funds in an internal accounting variable "
          "that forced transfers cannot move."),
    S("swap_fixed_min_amount_out", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Hardcoded non-zero minimum-out on a swap: the "
             "amountOutMin-position argument of a V2-router "
             "swap call is a fixed numeric literal rather "
             "than a value derived from a quote / expected "
             "output for THIS trade size. A constant floor "
             "protects nothing proportionally: on a large "
             "swap it is dust (sandwichable down to the "
             "literal), on a small swap it can exceed the "
             "honest output and brick the path. (A literal 0 "
             "is the unbounded case owned by the slippage "
             "detectors; this lane is the non-zero constant.)",
      fix="Compute amountOutMin per call from a live quote "
          "(router getAmountsOut / an oracle price) scaled "
          "by the caller's slippage tolerance, never a "
          "source-level constant."),
    S("swap_deadline_unbound", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Unbound swap deadline: the deadline-position "
             "argument of a V2-router swap call is a numeric "
             "literal or type(uint256).max rather than a "
             "block.timestamp-derived expiry. A fixed or "
             "effectively-infinite deadline leaves a signed / "
             "queued swap executable at any future block, so "
             "whoever relays or mines it can hold it until "
             "the market moves against the signer.",
      fix="Pass a short block.timestamp-derived deadline "
          "(e.g. block.timestamp + 600) computed at call "
          "time on every swap."),
    S("shadowed_state_variable_legacy", FAMILY,
      severity="low", outcome="a",
      detail="Shadowed state variable (legacy compiler): "
             "under a pragma that allows solc < 0.6.0, a "
             "derived contract redeclares a state variable "
             "with the same name as a base contract's state "
             "variable. Pre-0.6 the compiler accepts this and "
             "the two names are separate storage slots: code "
             "reading the base variable and code reading the "
             "derived variable silently disagree about the "
             "value (the classic pre-0.6 shadowing bug class "
             "the 0.6 compiler change made an error).",
      fix="Rename the derived contract's variable (or drop "
          "the redeclaration and use the inherited one), "
          "and raise the pragma floor to ^0.6.0 or newer so "
          "the compiler rejects shadowing outright."),
    S("hardcoded_decimals_scaling", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="Hardcoded 18-decimal scaling of external token "
             "amounts: amounts are scaled by a literal 1e18 / "
             "10**18 in a contract that moves external tokens "
             "(transfer / transferFrom / approve) yet never "
             "calls decimals() on any token. Token decimals "
             "are per-token metadata (USDC / USDT use 6, "
             "others 8 or 24); assuming 18 misprices or "
             "misaccounts every non-18-decimal token by "
             "orders of magnitude.",
      fix="Read the token's decimals() at integration time "
          "and scale by 10 ** decimals (cached per token), "
          "or normalize through a decimals-aware adapter; "
          "never bake 1e18 into amount math for arbitrary "
          "external tokens."),
    S("twap_observe_window_short", FAMILY, severity="medium",
      outcome="a",
      detail="TWAP observation window too short: a Uniswap "
             "V3 observe() secondsAgo window (or the PERIOD / "
             "WINDOW constant feeding an observe / consult "
             "consumer) maxes below 1800 seconds. A sub-30-"
             "minute TWAP can be moved within a handful of "
             "blocks by a funded attacker and held long "
             "enough for the victim to read it, so the "
             "'manipulation-resistant' price is manipulable "
             "at feasible capital.",
      fix="Use an observation window of at least 1800 "
          "seconds (30 minutes; longer for high-value "
          "consumers) and grow the pool's observation "
          "cardinality so the window is actually served."),
    S("chainlink_price_unbounded", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Oracle price consumed with no sanity bounds: "
             "a function takes the price from "
             "latestRoundData() into arithmetic / a transfer "
             "decision / a return, and no condition anywhere "
             "in the contract compares that price against a "
             "literal bound or a MIN / MAX bound variable - "
             "there is no de-peg / circuit-breaker check. A "
             "malfunctioning, stale-but-fresh-looking or "
             "manipulated feed can print any value and every "
             "consumer downstream takes it at face value.",
      fix="Bound every consumed feed price: require it sits "
          "inside a per-asset [MIN, MAX] sanity band (and "
          "deviation-check against the previous round) "
          "before the value flows into any decision."),
    S("view_price_no_reentrancy_protection", FAMILY,
      severity="medium", outcome="a",
      detail="Read-only reentrancy exposure with NO lock "
             "anywhere: a view / pure function computes a "
             "price / ratio from live pool state "
             "(getReserves(), a pair balanceOf, "
             "get_virtual_price, reserve reads) while the "
             "contract carries no reentrancy protection at "
             "all (no nonReentrant / ReentrancyGuard / "
             "_status-style lock) and its non-view functions "
             "make external calls. During any callback out "
             "of this contract (or a sibling integration), "
             "the pool state behind the price is mid-flight, "
             "and an external consumer reading the view "
             "price settles against a state that does not "
             "exist outside the callback.",
      fix="Add a reentrancy lock (ReentrancyGuard) to the "
          "state-changing functions and gate the pricing "
          "views on the same lock (nonReentrantView-style), "
          "or price from state that external calls cannot "
          "leave mid-flight."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirror batch 4)
# ---------------------------------------------------------------------------

def _scope_fns(src: str, contract_name: str):
    scope = cl._Scope(src, contract_name)
    fns = [fn for fn in scope.functions if "{" in fn["text"]]
    return scope, fns


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str, gate: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail,
            "gate_analysis": gate}


def _classify(item: Dict[str, Any], recipient: str,
              rdetail: str) -> Dict[str, Any]:
    """The Nov 2 receive rule, carried on the finding."""
    item["recipient"] = recipient
    if recipient in ("FIXED", "HOLDER-SELF"):
        item["report_class"] = "trigger_only"
        item["severity"] = "low"
        item["detail"] += (
            f" Recipient analysis: the value / power lands at "
            f"a {recipient} destination ({rdetail}), so a "
            f"stranger can trigger this but receives nothing - "
            f"classified TRIGGER-ONLY under the receive rule.")
    else:
        item["report_class"] = "candidate"
        item["detail"] += (
            f" Recipient analysis: recipient classified "
            f"{recipient} ({rdetail}) - a stranger can receive "
            f"value or control here, classified CANDIDATE under "
            f"the receive rule.")
    return item


def _finish_recipient(spec: DetectorSpec, item: Dict[str, Any],
                      fn_text: str) -> Dict[str, Any]:
    recipient, rdetail = cl.classify_recipient(fn_text)
    return _classify(item, recipient, rdetail)


def _candidate(item: Dict[str, Any]) -> Dict[str, Any]:
    """Contract-scope findings with no per-function value
    destination: candidate at the spec severity, recipient
    honestly UNRESOLVED."""
    item["recipient"] = "UNRESOLVED"
    item["report_class"] = "candidate"
    return item


_IDENTITY_GATE_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]*\b")


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the paren group at open_pos."""
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
        i += 1
    return text[open_pos + 1:], len(text) - 1


def _balanced_brace(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the brace group at open_pos."""
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
        i += 1
    return text[open_pos + 1:], len(text) - 1


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (mirror of batch 4). NOTE:
    batch 6 does NOT suppress on this in general - it is used
    only to REPORT the gate honestly in gate_analysis where a
    sibling lane (contract_logic) would have skipped."""
    sig, text = fn["signature"], fn["text"]
    if _ONLY_MOD_RE.search(sig) or _IDENTITY_GATE_RE.search(text):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        _, pend = _balanced(stripped, i)
        tail = stripped[pend + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and ("msg.sender" in body and
                         ("==" in body or "!=" in body)):
                return True
    return False


def _conditions(text: str) -> List[str]:
    """Contents of every require(...) / assert(...) / if(...)
    condition in the text (balanced-paren extraction)."""
    out: List[str] = []
    for m in re.finditer(r"\b(?:require|assert|if)\s*\(", text):
        inner, _ = _balanced(text, m.end() - 1)
        out.append(inner)
    return out


def _split_args(inner: str) -> List[str]:
    """Top-level comma split of a call argument list."""
    return cd._split_top(inner)


_NUM_LITERAL_RE = re.compile(
    r"^\d[\d_]*(?:\.\d+)?(?:e\d+)?$|"
    r"^0x[0-9a-fA-F][0-9a-fA-F_]*$")


def _num_literal_value(arg: str) -> Optional[int]:
    """Integer value of a bare numeric literal argument, else
    None. Handles decimal digits with _ separators, hex, and
    simple e-notation used in source literals (1e6)."""
    a = (arg or "").strip()
    if not _NUM_LITERAL_RE.match(a):
        return None
    try:
        if a.lower().startswith("0x"):
            return int(a.replace("_", ""), 16)
        if "e" in a and "." not in a:
            mant, exp = a.split("e")
            return int(mant.replace("_", "")) * (10 ** int(exp))
        if "." in a or "e" in a:
            return int(float(a))
        return int(a.replace("_", ""))
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# 1. unchecked_math_user_input (FIN-001 slice)
# ---------------------------------------------------------------------------

_UNCHECKED_RE = re.compile(r"\bunchecked\s*\{")
_ASSIGN_STMT_RE = re.compile(
    r"^\s*(?:uint\w*|int\w*|var|address|bool|bytes\w*)?\s*"
    r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*"
    r"(\+=|-=|\*=|/=|=(?!=))\s*(.+)$", re.S)
_FOR_INIT_RE = re.compile(
    r"\bfor\s*\(\s*(?:uint\w*|int\w*|var)?\s*([A-Za-z_]\w*)\s*=")
_BINOP_RE = re.compile(r"[+\-*/%]")
_VALUE_MOVE_RE = re.compile(
    r"\.transfer\s*\(|\.call\s*\{\s*value|_mint\s*\(|"
    r"safeTransfer")


def _local_stored_onward(local: str, tail: str,
                         state: set) -> bool:
    """True when `local` is stored onward in `tail`: assigned
    into a state variable, returned, or passed as a call
    argument."""
    w = r"\b" + re.escape(local) + r"\b"
    for v in state:
        if re.search(r"\b" + re.escape(v) + r"\b\s*(?:\[[^\]]*\])"
                     r"?\s*(?:\+=|-=|\*=|=(?!=))[^;]*" + w, tail):
            return True
    if re.search(r"\breturn\b[^;]*" + w, tail):
        return True
    if re.search(r"\.\w+\s*\([^;]*" + w, tail):
        return True
    if re.search(r"\b\w+\s*\([^;]*" + w + r"[^;]*\)\s*;", tail):
        return True
    return False


def _norm_ws(s: str) -> str:
    return re.sub(r"\s+", "", s)


_LOCAL_DEF_RE = re.compile(
    r"(?:uint\w*|int\w*|address|bool|bytes\w*|var)?\s*"
    r"([A-Za-z_]\w*)\s*=\s*([^;]+);")


def _local_defs(text: str) -> Dict[str, str]:
    """First defining expression per local variable name."""
    out: Dict[str, str] = {}
    for m in _LOCAL_DEF_RE.finditer(text):
        out.setdefault(m.group(1), m.group(2).strip())
    return out


def _has_bound_check(flat_text: str, minuend_exprs: List[str],
                     subtrahend: str) -> bool:
    """True when the function visibly bounds a subtraction:
    require/assert(EXPR >= SUB), require(SUB <= EXPR), or an
    if (EXPR < SUB) revert / if (SUB > EXPR) revert guard, for
    any candidate spelling of the minuend expression."""
    sub = _norm_ws(subtrahend)
    if not sub:
        return False
    for expr in minuend_exprs:
        e = _norm_ws(expr)
        if not e:
            continue
        pats = (
            "require(" + e + ">=" + sub,
            "require(" + sub + "<=" + e,
            "assert(" + e + ">=" + sub,
            "assert(" + sub + "<=" + e,
            "if(" + e + "<" + sub + ")revert",
            "if(" + e + "<" + sub + "){revert",
            "if(" + sub + ">" + e + ")revert",
            "if(" + sub + ">" + e + "){revert",
        )
        if any(p in flat_text for p in pats):
            return True
    return False


_SUB_FORM_RE = re.compile(
    r"^([A-Za-z_][\w\.\[\]]*)\s*-\s*(.+)$", re.S)
_ADD_FORM_RE = re.compile(
    r"^([A-Za-z_][\w\.\[\]]*)\s*\+\s*(.+)$", re.S)


def _stmt_arith_form(lhs: str, op: str, rhs: str):
    """Classify an assignment statement's arithmetic on the
    parameter: ('sub', minuend_expr, subtrahend) or
    ('add', addend) or None when the statement is not plain
    value arithmetic (hashing, recovery, bare increments)."""
    rhs = rhs.strip()
    if "keccak256(" in rhs or "ecrecover(" in rhs or \
            "sha256(" in rhs:
        return None
    if re.fullmatch(r"[A-Za-z_][\w\.\[\]]*(\+\+|--)", rhs) or \
            re.fullmatch(r"(\+\+|--)[A-Za-z_][\w\.\[\]]*", rhs):
        return None
    if op == "-=":
        return ("sub", lhs, rhs)
    if op == "+=":
        return ("add", rhs)
    if op == "=":
        m = _SUB_FORM_RE.match(rhs)
        if m:
            return ("sub", m.group(1), m.group(2))
        m = _ADD_FORM_RE.match(rhs)
        if m and (m.group(1) == lhs or
                  m.group(1).split("[")[0] == lhs):
            return ("add", m.group(2))
    return ("other", rhs)


def _fn_adds(text: str, hit_param: str):
    """All addition statements on the parameter in a function:
    (lhs_text) for `L += p` and `L = L + p` forms."""
    out = []
    hp = _norm_ws(hit_param)
    for m in re.finditer(
            r"([A-Za-z_]\w*(?:\[[^\]]*\])?)\s*\+=\s*([^;]+)", text):
        if hp in _norm_ws(m.group(2)):
            out.append(m.group(1))
    for m in re.finditer(
            r"([A-Za-z_]\w*(?:\[[^\]]*\])?)\s*=\s*"
            r"([A-Za-z_]\w*(?:\[[^\]]*\])?)\s*\+\s*([^;]+)", text):
        if m.group(1).split("[")[0] == m.group(2).split("[")[0] \
                and hp in _norm_ws(m.group(3)):
            out.append(m.group(1))
    return out


def _bounded_suppressed(text: str, block: str, lhs: str,
                        op: str, rhs: str, hit_param: str,
                        defs: Dict[str, str],
                        checked_default: bool = False,
                        state: Optional[set] = None) -> bool:
    """True when the fired statement's arithmetic on the
    parameter is provably bounded, so the unchecked block is
    the standard checked-ledger pattern rather than a hazard:

    - a subtraction whose minuend is bound-checked against the
      subtrahend in the same function (the OpenZeppelin ERC20
      _update/_burn shape: load balance, revert if < amount,
      then subtract inside unchecked);
    - a credit (or supply move) paired in the same function
      with such a bound-checked subtraction of the SAME
      parameter (transfer/burn conservation: the credit cannot
      exceed the checked debit);
    - the canonical mint ledger pair inside one unchecked
      block: totalSupply += p together with a balance-slot
      += p (supply and balance move atomically; neither can
      wrap short of a 2**256 total supply).
    """
    form = _stmt_arith_form(lhs, op, rhs)
    if form is None:
        return True  # not value arithmetic at all
    flat = _norm_ws(text)
    if form[0] == "sub":
        minuend, sub = form[1], form[2]
        exprs = [minuend]
        base = minuend.split("[")[0].split(".")[0]
        if base in defs:
            exprs.append(defs[base])
        if hit_param in _norm_ws(sub) or \
                _norm_ws(sub) == _norm_ws(hit_param):
            if _has_bound_check(flat, exprs, sub):
                return True
            # Supply-accounting subtraction: totalSupply can
            # only fall by an amount some balance check in the
            # same function already bounded (a balance is a
            # component of the supply, so p <= balance <=
            # totalSupply whenever any subtraction of p in the
            # function is bound-checked).
            if "totalsupply" in _norm_ws(lhs).lower():
                for m in re.finditer(
                        r"([A-Za-z_][\w\.\[\]]*)\s*-\s*([^;]+)",
                        text):
                    ex = [m.group(1)]
                    b2 = m.group(1).split("[")[0].split(".")[0]
                    if b2 in defs:
                        ex.append(defs[b2])
                    if _has_bound_check(flat, ex, m.group(2)) \
                            and hit_param in _norm_ws(m.group(2)):
                        return True
                # Compiler-checked slot debit of the same
                # parameter (solc >= 0.8, outside unchecked)
                # bounds the supply fall the same way: a
                # balance is a component of the supply.
                if checked_default:
                    spans = [(m.start(), m.end()) for m in
                             _UNCHECKED_RE.finditer(text)]
                    for m in re.finditer(
                            r"([A-Za-z_]\w*(?:\[[^\]]*\])?)\s*"
                            r"(?:-=|=\s*[A-Za-z_][\w\.\[\]]*"
                            r"\s*-)\s*([^;]+)", text):
                        if hit_param not in _norm_ws(m.group(2)):
                            continue
                        if "[" not in m.group(1):
                            continue
                        if not any(s <= m.start() < e
                                   for s, e in spans):
                            return True
            return False
        return False
    if form[0] == "add":
        # The parameter that matters for pairing is the
        # addend itself when it is a bare identifier (the
        # index parameter of the credited slot is not the
        # value being added).
        addend = form[1].strip()
        eff_param = addend if re.fullmatch(
            r"[A-Za-z_]\w*", addend) else hit_param
        # Any bound-checked subtraction of the same parameter
        # in this function bounds this credit by conservation.
        # On solc >= 0.8 a subtraction OUTSIDE an unchecked
        # block is itself compiler-checked, so a checked debit
        # beside the credit bounds it the same way.
        spans = [(m.start(), m.end()) for m in
                 _UNCHECKED_RE.finditer(text)]
        for m in re.finditer(
                r"([A-Za-z_][\w\.\[\]]*)\s*-\s*([^;]+)", text):
            if eff_param not in _norm_ws(m.group(2)):
                continue
            exprs = [m.group(1)]
            base = m.group(1).split("[")[0].split(".")[0]
            if base in defs:
                exprs.append(defs[base])
            if _has_bound_check(flat, exprs, m.group(2)):
                return True
        if checked_default:
            state = state or set()
            # A compiler-checked debit of the same parameter
            # from a storage slot outside every unchecked
            # block bounds the credit by conservation.
            for m in re.finditer(
                    r"([A-Za-z_]\w*(?:\[[^\]]*\])?)\s*(?:-=|"
                    r"=\s*[A-Za-z_][\w\.\[\]]*\s*-)\s*([^;]+)",
                    text):
                if eff_param not in _norm_ws(m.group(2)):
                    continue
                if "[" not in m.group(1) and \
                        m.group(1) not in state:
                    continue
                if not any(s <= m.start() < e for s, e in spans):
                    return True
        # Canonical mint ledger pair in the same function:
        # totalSupply += p together with a balance-slot += p
        # (in or out of the unchecked block; the supply side
        # bounds the balance side by the ledger identity).
        adds = _fn_adds(text, eff_param)
        lhs_bases = {a.split("[")[0] for a in adds}
        if any("totalsupply" in b.lower() for b in lhs_bases) \
                and any("[" in a for a in adds):
            return True
        return False
    return False


def _analyze_unchecked_math(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    _ver = cl.solc_version(src, compiler)
    checked_default = bool(_ver and _ver >= (0, 8, 0))
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if "unchecked" not in text:
            continue
        params = cd._param_names(fn["signature"])
        if not params:
            continue
        param_re = [re.compile(r"\b" + re.escape(p) + r"\b")
                    for p in params]
        loop_vars = set(_FOR_INIT_RE.findall(text))
        defs = _local_defs(text)
        fired = None
        for m in _UNCHECKED_RE.finditer(text):
            block, bend = _balanced_brace(text, m.end() - 1)
            # Statements of the block, with global offsets.
            pos = 0
            for stmt in block.split(";"):
                stmt_start = m.end() + pos
                pos += len(stmt) + 1
                am = _ASSIGN_STMT_RE.match(stmt)
                if not am:
                    continue
                lhs, op, rhs = am.group(1), am.group(2), \
                    am.group(3)
                if op == "=" and not _BINOP_RE.search(rhs):
                    continue
                operands = rhs + (" " + lhs if op != "=" else "")
                hit_param = next(
                    (p for p, pre in zip(params, param_re)
                     if pre.search(operands)), None)
                if hit_param is None:
                    continue
                # Result assigned onward?
                if lhs in state:
                    onward = True
                elif lhs in loop_vars:
                    # Pure loop counter: excluded unless the
                    # counted value is itself stored onward.
                    tail = text[stmt_start + len(stmt):]
                    onward = _local_stored_onward(
                        lhs, tail, state)
                else:
                    tail = text[stmt_start + len(stmt):]
                    onward = _local_stored_onward(
                        lhs, tail, state)
                if not onward:
                    continue
                # Bounded-arithmetic suppression: the standard
                # checked-ledger shapes (bound-checked
                # subtraction, its paired credit, the mint
                # ledger pair) and non-arithmetic statements
                # (hashing, recovery, nonce increments) are not
                # unchecked-math hazards.
                if _stmt_arith_form(lhs, op, rhs) is None:
                    continue
                if _bounded_suppressed(text, block, lhs, op,
                                       rhs, hit_param, defs,
                                       checked_default, state):
                    continue
                fired = (hit_param, lhs, stmt.strip()[:120])
                break
            if fired:
                break
        if not fired:
            continue
        hit_param, lhs, stmt_txt = fired
        gated = _caller_gated(fn, scope)
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes '{stmt_txt}' "
            f"inside an unchecked block on parameter "
            f"'{hit_param}', assigning onward to '{lhs}'"
            + (" - the function IS caller-gated, which the "
               "contract_logic unchecked lane treats as out "
               "of scope; the gate does not bound the math"
               if gated else "")
            + ".")
        gate = ("caller-gated function: gate noted, NOT "
                "suppressing (FIN-001 slice: the existing lane "
                "skips gated functions and local-result math; "
                "a gate does not bound arithmetic)"
                if gated else
                "no caller gate on the function; unchecked "
                "arithmetic on a function parameter with the "
                "result assigned onward")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    gate)
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. strict_balance_equality (FIN-003)
# ---------------------------------------------------------------------------

_BALANCE_EXPR = r"address\s*\(\s*this\s*\)\s*\.balance"
_BAL_ASSIGN_RE = re.compile(
    r"([A-Za-z_]\w*)\s*=\s*" + _BALANCE_EXPR + r"\b")
_STATE_PATH_RE = re.compile(
    r"\.transfer\s*\(|\.call\s*\{|\.send\s*\(|_mint\s*\(|"
    r"safeTransfer|selfdestruct")


def _eq_on(cond: str, expr_re: str) -> bool:
    return bool(
        re.search(expr_re + r"\s*==", cond) or
        re.search(r"==\s*" + expr_re, cond))


def _analyze_strict_balance(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if "balance" not in text:
            continue
        # The condition must gate a value / state path.
        if not (_STATE_PATH_RE.search(text) or
                cl._state_writes(text, state)):
            continue
        locals_bal = _BAL_ASSIGN_RE.findall(text)
        hit_desc = None
        for cond in _conditions(text):
            if _eq_on(cond, _BALANCE_EXPR):
                hit_desc = "address(this).balance compared " \
                           "with =="
                break
            for v in locals_bal:
                if _eq_on(cond, r"\b" + re.escape(v) + r"\b"):
                    hit_desc = (f"local '{v}' (assigned from "
                                f"address(this).balance) "
                                f"compared with ==")
                    break
            if hit_desc:
                break
        if not hit_desc:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' gates a value / state "
            f"path on {hit_desc} inside a require / assert / "
            f"if condition.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "strict == on the live contract balance in "
                    "a validation condition gating value / "
                    "state movement; only >= / <= / > "
                    "comparisons stay silent")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3+4. Swap argument parsing (FIN-005 / FIN-006 slices)
# ---------------------------------------------------------------------------

# V2-router swap signatures: arg positions per function name.
#   swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)
#   swapExactTokensForETH   (amountIn, amountOutMin, path, to, deadline)
#   swapExactETHForTokens   (amountOutMin, path, to, deadline)
#   swapTokensForExactETH   (amountOut, amountInMax, path, to, deadline)
# swapTokensForExactETH fixes the OUTPUT, so it has no min-out
# position: deadline lane only.
_SWAP_LAYOUTS = {
    "swapExactTokensForTokens": {"min": 1, "deadline": 4,
                                 "to": 3},
    "swapExactTokensForETH": {"min": 1, "deadline": 4, "to": 3},
    "swapExactETHForTokens": {"min": 0, "deadline": 3, "to": 2},
    "swapTokensForExactETH": {"min": None, "deadline": 4,
                              "to": 3},
}
_UINT_MAX_RE = re.compile(
    r"^type\s*\(\s*uint256\s*\)\s*\.\s*max$")


def _swap_calls(text: str):
    """Yield (fn_name_in_source, callee, args) for each
    V2-router swap call in the text (balanced-paren parse)."""
    for callee, layout in _SWAP_LAYOUTS.items():
        for m in re.finditer(r"\b" + callee + r"\s*\(", text):
            inner, _ = _balanced(text, m.end() - 1)
            args = _split_args(inner)
            if len(args) >= 4:
                yield callee, layout, args


def _swap_recipient(spec: DetectorSpec, item: Dict[str, Any],
                    fn: Dict[str, Any], to_arg: str,
                    scope) -> Dict[str, Any]:
    """The swap's `to` argument IS the value destination."""
    state = cl.state_variables(scope.scoped_text)
    params = cd._param_names(fn["signature"])
    a = (to_arg or "").strip()
    if a == "msg.sender":
        return _classify(item, "CALLER",
                         "swap output addressed to msg.sender")
    if a in params:
        return _classify(item, "CALLER-SUPPLIED",
                         f"swap output addressed to caller-"
                         f"supplied parameter '{a}'")
    if a in state or re.match(r"^0x[0-9a-fA-F]{40}$", a) or \
            a == "address(this)":
        return _classify(item, "FIXED",
                         f"swap output addressed to fixed "
                         f"destination '{a}'")
    return _classify(item, "UNRESOLVED",
                     f"swap output destination '{a}' not "
                     f"classifiable from source")


def _analyze_swap(src: str, spec: DetectorSpec,
                  compiler: str = "",
                  contract_name: str = ""
                  ) -> List[Dict[str, Any]]:
    want_min = spec.id == "swap_fixed_min_amount_out"
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        for callee, layout, args in _swap_calls(text):
            if want_min:
                idx = layout["min"]
                if idx is None or len(args) <= idx:
                    continue
                val = _num_literal_value(args[idx])
                if val is None or val == 0:
                    continue  # identifiers / expressions are
                    # fine; literal 0 is the unbounded case
                    # owned by the slippage detectors
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' calls "
                    f"{callee} with amountOutMin = "
                    f"{args[idx].strip()} (a source-level "
                    f"numeric literal).")
                item = _hit(
                    spec, fn["name"], cc._snip(text), detail,
                    "amountOutMin position holds a non-zero "
                    "numeric literal, not a quote-derived "
                    "value; literal 0 and identifier / "
                    "expression arguments stay silent")
                out.append(_swap_recipient(
                    spec, item, fn, args[layout["to"]], scope))
                break
            else:
                idx = layout["deadline"]
                if len(args) <= idx:
                    continue
                arg = args[idx].strip()
                val = _num_literal_value(arg)
                if val is None and not _UINT_MAX_RE.match(arg):
                    continue  # block.timestamp-derived or
                    # identifier deadline: bounded, silent
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' calls "
                    f"{callee} with deadline = {arg} "
                    f"(a fixed literal / unbounded value, "
                    f"not block.timestamp-derived).")
                item = _hit(
                    spec, fn["name"], cc._snip(text), detail,
                    "deadline position holds a numeric literal "
                    "or type(uint256).max; block.timestamp-"
                    "derived and identifier deadlines stay "
                    "silent")
                out.append(_swap_recipient(
                    spec, item, fn, args[layout["to"]], scope))
                break
    return out


# ---------------------------------------------------------------------------
# 5. shadowed_state_variable_legacy (FIN-008 slice)
# ---------------------------------------------------------------------------

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_VERSION_TOKEN_RE = re.compile(
    r"(>=|<=|>|<|\^|=)?\s*(\d+)\.(\d+)(?:\.(\d+))?")


def _pragma_allows_pre06(src: str) -> bool:
    """True when some pragma in the source permits a solc
    version below 0.6.0. No pragma at all: the compilation
    predates / ignores the floor, stay silent (cannot prove
    the legacy compiler was usable)."""
    pragmas = _PRAGMA_RE.findall(src)
    if not pragmas:
        return False
    for pragma in pragmas:
        lowers: List[Tuple[int, int, int]] = []
        allv: List[Tuple[int, int, int]] = []
        for op, maj, mino, pat in _VERSION_TOKEN_RE.findall(
                pragma):
            v = (int(maj), int(mino), int(pat or 0))
            allv.append(v)
            if op in (">=", ">", "^", "=", ""):
                lowers.append(v)
        cands = lowers or allv
        if cands and min(cands) < (0, 6, 0):
            return True
    return False


def _analyze_shadowed_state(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    if not _pragma_allows_pre06(src):
        return []
    scope, _fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    spans: List[Dict[str, Any]] = []
    for _path, raw in cl._split_units(src):
        clean = cc._strip_comments(raw)
        for s in cl._contract_spans(clean):
            s["_clean"] = clean
            spans.append(s)
    by_name = {s["name"]: s for s in spans if s["name"]}

    def vars_of(span) -> set:
        clean = span.get("_clean", "")
        body = clean[span["start"]:span["end"]]
        return cl.state_variables(body)

    for span in spans:
        if not span.get("ancestors"):
            continue
        derived_vars = vars_of(span)
        if not derived_vars:
            continue
        for anc in span["ancestors"]:
            base = by_name.get(anc)
            if base is None or base is span:
                continue
            shared = sorted(derived_vars & vars_of(base))
            for var in shared:
                detail = spec.detail + (
                    f" Observed: contract '{span['name']}' "
                    f"(is {anc}) redeclares state variable "
                    f"'{var}', which base contract '{anc}' "
                    f"already declares; the source pragma "
                    f"allows solc < 0.6.0, where this "
                    f"shadowing compiles.")
                span_clean = span.get("_clean", "")
                item = _hit(
                    spec, span["name"],
                    cc._snip(span_clean[span["start"]:
                                        span["end"]]),
                    detail,
                    "pragma allows solc < 0.6.0 (the compiler "
                    "only rejects state-variable shadowing "
                    "from 0.6.0); derived and base contracts "
                    "declare the same state variable name")
                out.append(_candidate(item))
    return out


# ---------------------------------------------------------------------------
# 6. hardcoded_decimals_scaling (FIN-009 slice)
# ---------------------------------------------------------------------------

_SCALE_LITERAL_RE = re.compile(
    r"\b1e18\b|\b10\s*\*\*\s*18\b")
_TOKEN_CALL_RE = re.compile(
    r"\.(?:transfer|transferFrom|approve)\s*\(")
_DECIMALS_CALL_RE = re.compile(r"\.\s*decimals\s*\(")


def _analyze_decimals_scaling(src: str, spec: DetectorSpec,
                              compiler: str = "",
                              contract_name: str = ""
                              ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if not _TOKEN_CALL_RE.search(text_all):
        return []
    if _DECIMALS_CALL_RE.search(text_all):
        return []  # decimals() consulted somewhere: the
        # integration is decimals-aware, stay silent
    out: List[Dict[str, Any]] = []
    for fn in fns:
        m = _SCALE_LITERAL_RE.search(fn["text"])
        if not m:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' scales amounts by "
            f"the literal {m.group(0)} while the contract "
            f"calls transfer / transferFrom / approve on "
            f"external tokens and never calls decimals() "
            f"anywhere.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "literal 1e18 / 10**18 scaling in a "
                    "token-moving contract with zero "
                    "decimals() calls in the whole contract")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 7. twap_observe_window_short (ORC-001 slice)
# ---------------------------------------------------------------------------

_OBSERVE_RE = re.compile(r"\bobserve\s*\(")
_CONSULT_RE = re.compile(r"\bconsult\s*\(")
_WINDOW_CONST_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:PERIOD|WINDOW)"
    r"[A-Za-z0-9_]*|PERIOD|WINDOW|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:period|window)"
    r"[A-Za-z0-9_]*)\s*=\s*(\d[\d_]*)\s*;")
_INT_IN_ARRAY_RE = re.compile(r"(?<![A-Za-z0-9_])(\d[\d_]*)")
_TWAP_MIN_WINDOW = 1800


def _analyze_twap_window(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    out: List[Dict[str, Any]] = []
    const_windows = [
        (m.group(1), int(m.group(2).replace("_", "")))
        for m in _WINDOW_CONST_RE.finditer(text_all)]
    short_consts = [(n, v) for n, v in const_windows
                    if v < _TWAP_MIN_WINDOW]
    has_oracle_call = bool(_OBSERVE_RE.search(text_all) or
                           _CONSULT_RE.search(text_all))
    for fn in fns:
        text = fn["text"]
        fired = None
        for m in _OBSERVE_RE.finditer(text):
            inner, _ = _balanced(text, m.end() - 1)
            args = _split_args(inner)
            if not args:
                continue
            first = args[0].strip()
            if not first.startswith("["):
                continue  # non-literal window: cannot judge
            lits = [int(x.replace("_", ""))
                    for x in _INT_IN_ARRAY_RE.findall(first)]
            if lits and max(lits) < _TWAP_MIN_WINDOW:
                fired = (f"observe() called with literal "
                         f"secondsAgo window maxing at "
                         f"{max(lits)}s")
                break
        if not fired and short_consts and (
                _OBSERVE_RE.search(text) or
                _CONSULT_RE.search(text)):
            n, v = short_consts[0]
            fired = (f"constant {n} = {v}s (< 1800s) feeds "
                     f"an observe / consult consumer")
        if not fired:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}': {fired}.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "observation window is a literal below "
                    "the 1800s floor; windows >= 1800s and "
                    "non-literal windows stay silent")
        out.append(_candidate(item))
    if not out and short_consts and has_oracle_call:
        n, v = short_consts[0]
        detail = spec.detail + (
            f" Observed: constant {n} = {v}s (< 1800s) in a "
            f"contract calling observe / consult.")
        item = _hit(spec, "", cc._snip(text_all), detail,
                    "PERIOD / WINDOW constant below the "
                    "1800s floor in an observe / consult "
                    "consumer contract")
        out.append(_candidate(item))
    return out


# ---------------------------------------------------------------------------
# 8. chainlink_price_unbounded (ORC-003)
# ---------------------------------------------------------------------------

_LATEST_ROUND_RE = re.compile(r"latestRoundData\s*\(")
_LOCAL_ASSIGN_RE = re.compile(
    r"(?:uint\w*|int\w*|var)\s+([A-Za-z_]\w*)\s*=\s*([^;]+);")
_BOUND_NAME_RE = re.compile(r"MIN|MAX")


def _split_keep(s: str) -> List[str]:
    """Top-level comma split KEEPING empty parts (tuple
    destructuring has meaningful empty slots, unlike call
    argument lists)."""
    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return parts


def _price_var_and_pos(text: str) -> Tuple[Optional[str], int]:
    """The destructured price variable of a latestRoundData
    call: the second tuple element (answer)."""
    m = _LATEST_ROUND_RE.search(text)
    if not m:
        return None, -1
    head = text[:m.start()]
    # The destructuring tuple sits right before the call's
    # receiver: ...( ... ) = <recv>.latestRoundData(
    eq = head.rfind("=")
    if eq > 0:
        open_paren = head.rfind("(", 0, eq)
        if open_paren >= 0:
            tuple_inner = head[open_paren + 1:eq]
            if tuple_inner.rstrip().endswith(")"):
                tuple_inner = tuple_inner.rstrip()[:-1]
            parts = _split_keep(tuple_inner)
            if len(parts) >= 2:
                toks = parts[1].split()
                if toks and re.fullmatch(
                        r"[A-Za-z_]\w*", toks[-1]):
                    return toks[-1], m.start()
    for cand in ("answer", "price"):
        if re.search(r"\b" + cand + r"\b", text):
            return cand, m.start()
    return None, m.start()


def _price_bounded(text_all: str, var: str) -> bool:
    """Any condition anywhere in the contract comparing the
    price variable against a literal or a MIN/MAX-named
    identifier (a de-peg / sanity circuit breaker)."""
    w = r"\b" + re.escape(var) + r"\b"
    cmpop = r"(?:==|!=|<=|>=|<|>)"
    for cond in _conditions(text_all):
        if not re.search(w, cond):
            continue
        if not re.search(cmpop, cond):
            continue
        rest = re.sub(w, " ", cond)
        if re.search(r"\d", rest) or _BOUND_NAME_RE.search(rest):
            return True
    return False


def _analyze_chainlink_unbounded(src: str, spec: DetectorSpec,
                                 compiler: str = "",
                                 contract_name: str = ""
                                 ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if "latestRoundData" not in text:
            continue
        var, pos = _price_var_and_pos(text)
        if not var:
            continue
        # Derived locals (one hop): price = uint256(answer).
        watched = {var}
        tail0 = text[pos:]
        for lm in _LOCAL_ASSIGN_RE.finditer(tail0):
            if re.search(r"\b" + re.escape(var) + r"\b",
                         lm.group(2)):
                watched.add(lm.group(1))
        # A bound on the raw var OR on any local derived
        # from it is a circuit breaker.
        if any(_price_bounded(text_all, v) for v in watched):
            continue
        tail = text[pos:]
        flow = None
        for v in sorted(watched):
            w = r"\b" + re.escape(v) + r"\b"
            if re.search(w + r"\s*[+\-*/%]|[+\-*/%]\s*" + w,
                         tail):
                flow = f"'{v}' flows into arithmetic"
                break
            if re.search(r"\.transfer\s*\([^;]*" + w, tail) or \
                    re.search(r"\breturn\b[^;]*" + w, tail):
                flow = f"'{v}' flows into a transfer / return"
                break
        if not flow:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' consumes "
            f"latestRoundData() and {flow}, with no bounds "
            f"comparison on '{var}' anywhere in the "
            f"contract.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "no condition in the contract compares "
                    "the consumed price variable against a "
                    "literal bound or a MIN / MAX identifier; "
                    "staleness is owned by "
                    "system_stale_oracle_data and not "
                    "duplicated here")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 9. view_price_no_reentrancy_protection (ORC-006 slice)
# ---------------------------------------------------------------------------

_GUARD_ANYWHERE_RE = re.compile(
    r"\bnonReentrant\w*\b|ReentrancyGuard|\b_status\b|"
    r"\b_locked\b|\b__reentrancyGuard\b")
_POOL_READ_RES = [
    re.compile(r"getReserves\s*\("),
    re.compile(r"get_virtual_price\s*\("),
    re.compile(r"\.balanceOf\s*\(\s*(?!address\s*\(\s*this)"),
]
_WRITER_CALL_RE = re.compile(
    r"\.(?:transfer|transferFrom|approve|call|send|mint|"
    r"burn)\s*\(|safeTransfer")
_PRICEY_NAME_RE = re.compile(
    r"price|rate|ratio|value|quote|spot|exchange", re.I)


def _analyze_view_price_unguarded(src: str, spec: DetectorSpec,
                                  compiler: str = "",
                                  contract_name: str = ""
                                  ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if _GUARD_ANYWHERE_RE.search(text_all):
        return []  # a lock exists somewhere: the native
        # readonly_reentrancy_gap lane owns that shape
    state = cl.state_variables(text_all)
    reserve_vars = [v for v in state if "reserve" in v.lower()]
    # Non-view functions making external calls: the callback
    # surface that leaves pool state mid-flight.
    writers = [fn for fn in fns
               if not re.search(r"\b(view|pure)\b",
                                fn["signature"])
               and (cl._external_calls(fn["text"]) or
                    _WRITER_CALL_RE.search(fn["text"]))]
    if not writers:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        anchor = None
        for pat in _POOL_READ_RES:
            if pat.search(text):
                anchor = pat.pattern
                break
        if not anchor and reserve_vars and any(
                re.search(r"\b" + re.escape(v) + r"\b", text)
                for v in reserve_vars):
            anchor = "reserve state read"
        if not anchor:
            continue
        if not (re.search(r"[*/]", text) or
                _PRICEY_NAME_RE.search(fn["name"])):
            continue  # a bare reserve getter, not a price
        detail = spec.detail + (
            f" Observed: view function '{fn['name']}' "
            f"computes from live pool state ({anchor}) while "
            f"'{writers[0]['name']}' makes external calls "
            f"and no reentrancy guard exists anywhere in "
            f"the contract.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "no nonReentrant / ReentrancyGuard / "
                    "_status-style lock anywhere in the "
                    "contract (any guard present hands the "
                    "shape to readonly_reentrancy_gap, which "
                    "returns [] for exactly this no-lock "
                    "case)")
        out.append(_candidate(item))
    return out


ANALYZERS = {
    "unchecked_math_user_input": _analyze_unchecked_math,
    "strict_balance_equality": _analyze_strict_balance,
    "swap_fixed_min_amount_out": _analyze_swap,
    "swap_deadline_unbound": _analyze_swap,
    "shadowed_state_variable_legacy": _analyze_shadowed_state,
    "hardcoded_decimals_scaling": _analyze_decimals_scaling,
    "twap_observe_window_short": _analyze_twap_window,
    "chainlink_price_unbounded": _analyze_chainlink_unbounded,
    "view_price_no_reentrancy_protection":
        _analyze_view_price_unguarded,
}


def analyze_deep6_source(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Run ONE batch-6 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-4 collection / fetch /
# proxy resolution; analysis is analyze_deep6_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit6Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 6)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = ""
    phase = 2
    timeout_s = 120
    _spec: Optional[DetectorSpec] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec = self._spec
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        work = self._collect(target, ctx)
        if not work or spec is None:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. bsc:0x...) "
                "or a web target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        analyzed = 0
        no_source = 0
        pairs_done = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs, got = await self._scan_address(
                    ctx, key, chain_hint, addr, findings)
            except Exception:
                pairs, got = 0, False
            pairs_done += pairs
            if pairs:
                analyzed += 1
                if not got:
                    no_source += 1
        dur = int((time.monotonic() - t0) * 1000)
        hits = sum(1 for f in findings if f.key == spec.id)
        res = self._ok(
            findings,
            f"{spec.id}: analyzed {analyzed} contract address(es) "
            f"({no_source} without verified source - skipped, no "
            f"guess made), {hits} finding(s)")
        res.duration_ms = dur
        return res

    def _collect(self, target: Target,
                 ctx: Ctx) -> List[Tuple[Optional[str], str]]:
        out: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(chain_hint: Optional[str], addr: str) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS:
                return
            k = addr.lower()
            if k in seen:
                return
            seen.add(k)
            out.append((chain_hint, addr))

        for raw in (target.normalized, target.raw):
            chain_hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add(chain_hint, addr)
                break
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str(item.get("address", ""))
                add(None, a)
        for item in ctx.consume("chain_contracts"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(hint if isinstance(hint, str) and
                    hint in cc.CHAINS else None,
                    str(item.get("address", "")))
        return out[:MAX_ADDRESSES]

    async def _scan_address(self, ctx: Ctx, key: Optional[str],
                            chain_hint: Optional[str], addr: str,
                            findings: List[Finding]
                            ) -> Tuple[int, bool]:
        if chain_hint:
            chain_ids = [chain_hint]
        else:
            chain_ids = list(cc.DEFAULT_CHAIN_ORDER)
        pairs = 0
        got_source = False
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None or code == "0x" or len(code) < 4:
                continue
            pairs += 1
            if await self._scan_on_chain(ctx, key, chain, addr,
                                         code, findings):
                got_source = True
            if chain_hint:
                break
        return pairs, got_source

    async def _scan_on_chain(self, ctx: Ctx, key: Optional[str],
                             chain: cc.ChainConfig, addr: str,
                             code_hex: str,
                             findings: List[Finding]) -> bool:
        src = await cc.fetch_verified_source(ctx, chain, addr, key)
        res = {"implementation": "", "via": "", "beacon": ""}
        try:
            res = await cc.resolve_implementation(
                ctx, chain, addr, code_hex,
                {"implementation": (src or {}).get(
                    "implementation", "")})
        except Exception:
            pass
        impl = res.get("implementation") or ""
        role = "proxy_shell" if impl else "standalone"
        got = self._analyze_contract(chain, addr, src, findings,
                                     role=role, impl_addr=impl)
        if not impl:
            return got
        impl_code = None
        impl_src = None
        try:
            impl_code = await cc.rpc_get_code(ctx, chain, impl)
            impl_src = await cc.fetch_verified_source(
                ctx, chain, impl, key)
        except Exception:
            impl_code, impl_src = None, None
        if not impl_code or impl_code == "0x" or len(impl_code) < 4:
            return got
        return self._analyze_contract(
            chain, impl, impl_src, findings,
            role="implementation", proxy_addr=addr) or got

    def _analyze_contract(self, chain: cc.ChainConfig, addr: str,
                          src: Optional[Dict[str, Any]],
                          findings: List[Finding], role: str,
                          proxy_addr: str = "",
                          impl_addr: str = "") -> bool:
        spec = self._spec
        if spec is None or not src:
            return False
        url = cc.explorer_url(chain, addr)
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id,
                   "contract_role": role}
        if role == "implementation":
            base_ev["proxy_address"] = proxy_addr
            base_ev["implementation_address"] = addr
            tag = f" [implementation behind proxy {proxy_addr}]"
        elif role == "proxy_shell":
            base_ev["proxy_address"] = addr
            base_ev["implementation_address"] = impl_addr
            tag = f" [proxy shell; implementation {impl_addr}]"
        else:
            tag = ""
        for item in analyze_deep6_source(
                src["source"], spec, src.get("compiler", ""),
                contract_name=src.get("contract_name", "")):
            ev = dict(base_ev)
            ev.update({
                "severity": item["severity"],
                "check": spec.id,
                "kind": spec.id,
                "detector_outcome": spec.outcome,
                "function": item["function"],
                "code": item["code"],
                "detail": item["detail"],
                "bytecode_only": False,
                "source_origin": src.get("origin", ""),
                "contract_name": src.get("contract_name", ""),
                "remediation": spec.fix,
            })
            if item.get("report_class"):
                ev["report_class"] = item["report_class"]
                ev["recipient"] = item.get("recipient", "")
            if item.get("gate_analysis"):
                ev["gate_analysis"] = item["gate_analysis"]
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="deep audit detector batch 6 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit6Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 6) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
