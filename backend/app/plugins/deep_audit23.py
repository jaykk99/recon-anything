"""Deep-audit detectors, batch 23: accrual denominators, stale
capacity, resettable caps, recallable pots, non-zero-sum ledgers.

Five chain-agnostic EVM detectors from the 2026-11-16 research
(Kava Lend, Firelight Immunefi #88615, Beatland CodeHawks M-01,
MyCut CodeHawks H-4, Arcus Perps), built to the batch-19 /
recipient-first standard: recipient classification computed
inside the detector and carried on the finding (CALLER /
CALLER-SUPPLIED = candidate; FIXED / HOLDER-SELF = trigger-only,
never a candidate), the exact code plus a gate analysis on every
finding, and a finding shape the auto-validator can consume
unchanged (kind, function, recipient, report_class, gate).

- interest_accrual_near_zero_denominator_inflation: an accrual /
  borrow function divides newly accrued interest by a
  net-supply-style denominator (cash + outstanding - reserves,
  or totalSupply minus reserves) with no minimum-denominator
  floor and no cap on the result, feeding a borrow / collateral
  / exchange-rate computation - the Kava Lend Nov 14 2026
  shape (~$3.8M: a small loan pushed net supply just above
  zero, so every BUSD deposit was suddenly valued ~243,000x).
  A minimum-denominator floor, or a capped result, is the
  protected shape. Precision note (live-corpus fix, 2026-11-16):
  a bare "rate" / "distribute" function name is NOT enough - a
  reflection token's _getRate (rSupply / tSupply minus excluded
  balances) and a staking reward-per-share distribute (rewards /
  totalShares) both divide by a subtraction-derived denominator
  but feed no borrow, so they are false positives. The detector
  therefore requires an accrual / borrow / exchange / lending-
  shaped function, and a view / pure rate function additionally
  needs a borrow-side consumer that reads it; both FP shapes are
  pinned as regression fixtures. Distinct from built
  lending_accumulator_donation_inflation (a donation inflates
  the rate NUMERATOR - this is a near-zero DENOMINATOR) and
  venus_accrue_interest_omission (accrual skipped - this is
  accrual computed wrong).
- stale_capacity_snapshot_after_payout: a capacity / underwrite
  function reads a period-start snapshot (or cached capacity)
  while a payout / settlement function reduces the collateral
  WITHOUT refreshing or invalidating that snapshot, and nothing
  re-reads live collateral before allocating - the Firelight
  Immunefi #88615 shape (High: the allocator keeps selling
  cover against the stale snapshot after a mid-period payout,
  so approved claims cannot be fully paid). The distinguishing
  element vs built cover_capacity_counts_unpaid_prior_period
  (#88214, deep_audit20) is the snapshot-read +
  payout-without-refresh conjunction, NOT the double-count of
  unpaid prior-period collateral: the deep_audit20 capacity
  fixtures (no snapshot variable, no collateral reduction in
  the payout) stay silent here, pinned by test.
- cap_counter_reset_by_setter: a setter / config function
  assigns 0 (or an arbitrary value) to a counter variable,
  while a mint / buy function checks counter + amount <=
  maxSupply / cap - the Beatland Festival CodeHawks M-01
  shape (configurePass() resets passSupply, so maxSupply is
  not a real cap). A reset that lives only in a constructor /
  initializer, or a cap derived from totalSupply() directly,
  is the protected shape. Distinct from built
  bep20_mint_cap_bypass (the cap is NEVER compared - here the
  cap IS compared, but its counter is resettable) and
  supply_cap_bypass_direct_transfer (the cap is bypassed by
  direct transfer - here the counter is RESET).
- finalize_recallable_drains_pot: a close / finalize / settle
  function transfers the contract / pot balance out with no
  closed / finalized state guard set BEFORE the transfer - the
  MyCut CodeHawks H-4 shape (closePot re-callable, drains the
  entire pot on the second call). A finalized flag checked at
  entry AND set before any value movement is the protected
  shape; a flag checked at entry but set AFTER the transfer
  still fires (the second call is only blocked once the first
  finishes, and the transfer itself is unguarded). Distinct
  from the reentrancy family (sequential re-call, not a
  reentrant callback) and from
  claim_callback_before_claimed_flag (a timing shape).
- internal_transfer_credit_without_debit: an internal-ledger
  transfer / transferBetween / move writes balances[to] +=
  amount with no corresponding balances[from] -= amount (or a
  debit of a different variable / amount), PLUS a withdraw
  function reading those balances - the Arcus Perps Nov 9-10
  2026 shape (~$2.23M: transfers between the attacker's own
  subaccounts inflated the recorded balance, then withdrew
  against it). A debit of the same amount on the same ledger,
  or a pure external token transfer, is the protected shape.
  Distinct from built share_transfer_cancel_desync and
  staking_total_shares_mismatch (share-entitlement desyncs,
  not a transfer zero-sum invariant).

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding on the permissionless entry point - a stranger cannot
reach the path. The payout consumer in the stale-capacity
detector is exempt by design (it is privileged; the bug is
the stale snapshot the permissionless allocator consumes),
and the rate function in the accrual detector may be view
(the borrow consumer is the gated check, via the consumer
fallback).

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
from .bsc_common import DetectorSpec, S

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "deep23"

SPECS = [
    S("interest_accrual_near_zero_denominator_inflation", FAMILY,
      severity="high",
      outcome="a", recipient=True,
      detail="Interest accrual divides by a near-zero net "
             "supply: an accrual / borrow function computes a "
             "per-share rate / exchange rate / borrow index as "
             "newly accrued interest divided by a net-supply-"
             "style denominator (cash + outstanding - reserves, "
             "or totalSupply minus reserves), guarded at most "
             "by an == 0 skip, with no minimum-denominator "
             "floor and no cap on the result, feeding borrow / "
             "collateral / exchange-rate math - so a small loan "
             "pushing net supply just above zero inflates every "
             "deposit's value by orders of magnitude and the "
             "attacker borrows against it - the Kava Lend Nov "
             "14 2026 shape (~$3.8M, deposits valued ~243,000x). "
             "A minimum-denominator floor, or a capped result, "
             "is the protected shape.",
      fix="Floor the accrual denominator: require the net "
          "supply above a minimum (e.g. a MIN_SUPPLY constant) "
          "before dividing, and cap the resulting rate / index. "
          "Never divide accrued interest by a net supply that "
          "a small loan can push arbitrarily close to zero."),
    S("stale_capacity_snapshot_after_payout", FAMILY,
      severity="high",
      outcome="a", recipient=True,
      detail="Stale period-start capacity snapshot lets the "
             "allocator over-sell cover after a mid-period "
             "payout: a capacity / underwrite function reads a "
             "period-start snapshot (or cached capacity) while "
             "a payout / settlement function reduces the "
             "collateral WITHOUT refreshing or invalidating "
             "that snapshot, and nothing re-reads live "
             "collateral before allocating - so the protocol "
             "underwrites more cover than its collateral backs "
             "and approved claims cannot be fully paid - the "
             "Firelight Immunefi #88615 shape (High). A live "
             "capacity re-read before allocating, or a payout "
             "that refreshes / invalidates the snapshot, is "
             "the protected shape.",
      fix="Re-read live collateral before allocating cover, or "
          "refresh / invalidate the period-start capacity "
          "snapshot in every payout / settlement path. Never "
          "let a payout reduce collateral while the allocator "
          "still reads the pre-payout snapshot."),
    S("cap_counter_reset_by_setter", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Config setter resets the consumed counter a cap "
             "reads: a setter / config function assigns 0 (or "
             "an arbitrary value) to a counter variable, while "
             "a mint / buy function checks counter + amount <= "
             "maxSupply / cap - so the cap is not a real cap, "
             "the counter can be re-armed and the supply "
             "minted past it - the Beatland Festival CodeHawks "
             "M-01 shape (configurePass() resets passSupply). "
             "A reset that lives only in a constructor / "
             "initializer, or a cap derived from totalSupply() "
             "directly, is the protected shape.",
      fix="Never let a setter write the consumed counter: make "
          "the counter append-only (only the mint / buy path "
          "increments it), or derive the cap check from "
          "totalSupply() directly. If a reset is ever needed, "
          "gate it behind governance with a timelock."),
    S("finalize_recallable_drains_pot", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Close / finalize re-callable drains the pot: a "
             "close / finalize / settle function transfers the "
             "contract / pot balance out with no closed / "
             "finalized state guard set BEFORE the transfer - "
             "so a second call pays the whole pot out again - "
             "the MyCut CodeHawks H-4 shape (closePot "
             "re-callable, drains the entire pot). A finalized "
             "flag checked at entry AND set before any value "
             "movement is the protected shape.",
      fix="Set the closed / finalized flag BEFORE any value "
          "movement and require(!closed) at entry (checks-"
          "effects-interactions): the first finalize must "
          "make every later call revert before it can move "
          "value."),
    S("internal_transfer_credit_without_debit", FAMILY,
      severity="high",
      outcome="a", recipient=True,
      detail="Internal transfer between subaccounts is not "
             "zero-sum: an internal-ledger transfer / "
             "transferBetween / move writes balances[to] += "
             "amount with no corresponding balances[from] -= "
             "amount (or a debit of a different variable / "
             "amount), PLUS a withdraw function reading those "
             "balances - so the sum of internal balances grows "
             "on every transfer and the inflated balance "
             "withdraws through the normal path - the Arcus "
             "Perps Nov 9-10 2026 shape (~$2.23M). A debit of "
             "the same amount on the same ledger, or a pure "
             "external token transfer, is the protected shape.",
      fix="Make every internal transfer zero-sum: debit "
          "balances[from] by exactly the amount credited to "
          "balances[to], in the same function, before any "
          "external call. Assert sum(balances) <= "
          "token.balanceOf(address(this)) as an invariant."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 19 / deep19)
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
            "stranger can trigger this but receives nothing - "
            "classified TRIGGER-ONLY under the receive rule.")
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


def _finish_recipient_meter_broken(
        spec: DetectorSpec, item: Dict[str, Any], fn_text: str,
        meter_note: str) -> Dict[str, Any]:
    """HOLDER-SELF -> CALLER when the bug breaks the meter.

    The Nov 14 meter-broken rule (first used by the batch-21
    oracle detector): the shared classifier reads a payout
    bounded by the caller's own recorded position as
    HOLDER-SELF, but when the bug itself breaks that meter -
    the meter bounds the payout by a value the bug distorts -
    the caller receives value beyond what the meter should
    allow, so the finding upgrades to CALLER. FIXED stays
    FIXED (trigger-only): the meter-broken rule never
    upgrades a fixed destination.
    """
    recipient, rdetail = cl.classify_recipient(fn_text)
    if recipient == "HOLDER-SELF":
        item["detail"] += (
            f" Recipient analysis: the shared classifier reads "
            f"this as HOLDER-SELF (the payout is bounded by "
            f"the caller's own recorded position), but the bug "
            f"breaks that meter itself - {meter_note} - so the "
            f"caller receives value beyond what the meter "
            f"should allow. Upgraded to CALLER under the Nov "
            f"14 meter-broken rule.")
        return _classify(item, "CALLER",
                         rdetail + "; meter broken by the bug")
    return _classify(item, recipient, rdetail)


_IDENTITY_GATE_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]*\b")


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses.
    """
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


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the paren group at open_pos."""
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
    return text[open_pos + 1:], len(text)


def _split_top(text: str) -> List[str]:
    depth = 0
    parts: List[str] = []
    cur: List[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _fn_params(fn: Dict[str, Any]) -> List[str]:
    """Parameter names from a function signature."""
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append(toks[-1])
    return out


def _fn_param_addrs(fn: Dict[str, Any]) -> List[str]:
    """Address-typed parameter names from a function signature."""
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        if "address" not in part:
            continue
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append(toks[-1])
    return out


def _moves_value(text: str) -> bool:
    """A token transfer / ETH call / send in the function."""
    if re.search(r"\.(transfer|transferFrom|send|call)\s*"
                 r"(\{|\(|\.)", text):
        return True
    if re.search(r"\.call\s*\{[^}]*value\s*:", text):
        return True
    return False


def _is_constructor_or_initializer(fn: Dict[str, Any]) -> bool:
    name = fn["name"].lower()
    return name in ("constructor", "initialize", "init",
                    "initializer", "setup")


def _plain_assign_rhs(scoped: str, var: str) -> List[str]:
    """Right-hand sides of plain `var = <rhs>;` assignments.

    Compound assignments (+=, -=, *=, /=) and comparisons
    (==, !=, >=, <=) are excluded: a plain assignment is the
    only way a setter re-arms a counter or a period start
    takes a snapshot.
    """
    out: List[str] = []
    for m in re.finditer(r"\b" + re.escape(var) + r"\s*=",
                         scoped):
        # The char before the `=` (past whitespace) must not
        # be +, -, *, / or another =.
        eq = m.end() - 1
        j = eq - 1
        while j >= 0 and scoped[j] in " \t":
            j -= 1
        if j >= 0 and scoped[j] in "+-*/=":
            continue
        # The char after the `=` must not be = or >.
        k = eq + 1
        if k < len(scoped) and scoped[k] in "=>":
            continue
        semi = scoped.find(";", eq)
        if semi < 0:
            continue
        out.append(scoped[eq + 1:semi].strip())
    return out


# ---------------------------------------------------------------------------
# 1. interest_accrual_near_zero_denominator_inflation
# ---------------------------------------------------------------------------

_ACCRUAL_FN_RE = re.compile(
    r"(accrue|accrual|interest|exchange|borrow|lending|"
    r"market|supply)", re.I)
_BORROW_CONSUMER_RE = re.compile(
    r"(borrow|deposit|mint|redeem|withdraw|liquidat|"
    r"collateral|repay|supply)", re.I)
_RATE_VAR_RE = re.compile(
    r"(rate|index|exchange|accrual|interest|perShare)", re.I)
_NUMERATOR_RE = re.compile(
    r"(interest|accrued|reward|yield|profit|newInterest)", re.I)
_NET_NAME_RE = re.compile(
    r"net|supplyNet|netSupply|netCash|netAssets|availableSupply|"
    r"netLiquidity", re.I)


def _divisions_in_statement(stmt: str):
    """Yield (result_var, numerator, denominator) per division.

    A statement is one `;`-terminated chunk of a function body.
    The result var is the identifier before the `=` when the
    statement is an assignment; the numerator is the text
    between `=` (or the statement start) and `/`; the
    denominator is the text after `/` to the statement end,
    with a trailing close-paren / comma stripped.
    """
    if "/" not in stmt:
        return
    # Skip `//` comments (scoped text is comment-stripped,
    # but be safe) and `/*`.
    if "//" in stmt or "/*" in stmt:
        return
    for m in re.finditer(r"/(?![/=*])", stmt):
        slash = m.start()
        if slash > 0 and stmt[slash - 1] in "/*":
            continue
        left = stmt[:slash]
        right = stmt[slash + 1:]
        result_var = None
        # Result-var extraction: last `name =` before the slash
        # inside this statement.
        m_eq = None
        for em in re.finditer(
                r"([A-Za-z_]\w*)\s*=(?![=>])", left):
            m_eq = em
        if m_eq is not None:
            # Exclude `==` / `<=` / `>=` / `!=` leftovers.
            before = left[max(0, m_eq.start() - 1):m_eq.start()]
            if before not in ("=", "!", "<", ">"):
                result_var = m_eq.group(1)
        numerator = left
        if m_eq is not None:
            numerator = left[m_eq.end():]
        denominator = right.strip()
        # Strip a trailing `)` / `,` / `;` that closes an
        # outer call, and anything after a top-level operator
        # that is not part of the denominator group.
        denominator = re.sub(r"[;,]\s*$", "", denominator)
        denominator = denominator.strip()
        if denominator.startswith("("):
            inner, _ = _balanced(denominator, 0)
            denominator = "(" + inner + ")"
        else:
            denominator = re.split(
                r"\s*[+*/%]\s*|\s*\)\s*$", denominator,
                maxsplit=1)[0].strip()
        numerator = numerator.strip()
        if numerator and denominator:
            yield result_var, numerator, denominator


def _denom_is_net_supply(denominator: str, scoped: str
                         ) -> bool:
    """The denominator is a net-supply-style expression.

    Either an inline subtraction (cash + outstanding -
    reserves, or totalSupply - reserves), a single identifier
    whose plain assignment is a subtraction expression, or a
    net-named identifier (netSupply, supplyNet, ...). A bare
    totalSupply (the lending-accumulator shape) is NOT net:
    its only assignments are += / -=, never a subtraction
    expression.
    """
    d = denominator.strip()
    inner = d
    if d.startswith("(") and d.endswith(")"):
        inner = d[1:-1]
    if "-" in inner:
        return True
    if re.fullmatch(r"[A-Za-z_]\w*", d):
        if _NET_NAME_RE.search(d):
            return True
        for rhs in _plain_assign_rhs(scoped, d):
            if "-" in rhs:
                return True
            # One hop: netSupply = otherVar.
            if re.fullmatch(r"[A-Za-z_]\w*", rhs.strip()):
                for rhs2 in _plain_assign_rhs(
                        scoped, rhs.strip()):
                    if "-" in rhs2:
                        return True
    return False


def _denom_has_floor(denominator: str, scoped: str) -> bool:
    """A minimum-denominator floor exists for this denominator.

    `denom >= N` / `denom > N` with N a positive literal or an
    ALL-CAPS constant, `denom < N` (revert-if-below), or a
    max(denom, ...) clamp. `> 0` / `!= 0` is NOT a floor: it
    only keeps the denominator off exact zero, which is the
    Kava hole.
    """
    d = denominator.strip()
    if d.startswith("(") and d.endswith(")"):
        d = d[1:-1]
    names = [d] if re.fullmatch(r"[A-Za-z_]\w*", d) else \
        re.findall(r"[A-Za-z_]\w*", d)
    for name in names:
        for m in re.finditer(
                r"\b" + re.escape(name) +
                r"\s*(>=|>)\s*([0-9][0-9_]*(?:\.[0-9]+)?"
                r"(?:e[0-9]+)?|[A-Z][A-Z0-9_]*)",
                scoped):
            val = m.group(2)
            if re.fullmatch(r"[0-9][0-9_]*(?:\.[0-9]+)?"
                            r"(?:e[0-9]+)?", val):
                try:
                    if float(val.replace("_", "")) > 0:
                        return True
                except ValueError:
                    pass
            else:
                # An ALL-CAPS named constant floor.
                return True
        if re.search(r"\b" + re.escape(name) +
                     r"\s*<\s*[1-9][0-9_]*", scoped):
            return True
        if re.search(r"\b(?:Math\.)?max\s*\(\s*" +
                     re.escape(name) + r"\b", scoped):
            return True
    return False


def _result_is_capped(result_var: Optional[str],
                      fn_text: str) -> bool:
    if not result_var:
        return False
    if re.search(r"\b(?:Math\.)?min\s*\(\s*" +
                 re.escape(result_var) + r"\b", fn_text):
        return True
    return False


def _analyze_accrual_denominator(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    by_name = {fn["name"]: fn for fn in fns}

    def _consumers_of(fn_name: str, result_var: Optional[str]):
        out = []
        for fn in fns:
            if fn["name"] == fn_name:
                continue
            if re.search(r"\b" + re.escape(fn_name) +
                         r"\s*\(", fn["text"]):
                out.append(fn)
            elif result_var and re.search(
                    r"\b" + re.escape(result_var) + r"\b",
                    fn["text"]):
                out.append(fn)
        return out

    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _is_constructor_or_initializer(fn):
            continue
        text = fn["text"]
        # The division must live in an accrual / rate /
        # borrow-shaped function, or assign a rate-shaped var.
        fn_accrual_shaped = bool(
            _ACCRUAL_FN_RE.search(fn["name"]))
        fired_here = False
        for stmt in text.split(";"):
            for result_var, numerator, denom in \
                    _divisions_in_statement(stmt):
                if not _denom_is_net_supply(denom, scoped):
                    continue
                rate_shaped = (
                    result_var is not None and
                    bool(_RATE_VAR_RE.search(result_var)))
                numerator_shaped = bool(
                    _NUMERATOR_RE.search(numerator))
                if not (fn_accrual_shaped or rate_shaped or
                        numerator_shaped):
                    continue
                # The result must feed a rate / borrow /
                # collateral computation: a rate-shaped result
                # var, an accrual-shaped function, or an
                # interest-shaped numerator.
                if not (rate_shaped or fn_accrual_shaped):
                    continue
                if _denom_has_floor(denom, scoped):
                    continue
                if _result_is_capped(result_var, text):
                    continue
                # Gate / reachability: the accrual must be able
                # to move value for a stranger.
                # - A view / pure rate function only counts when
                #   a borrow-side consumer reads it: a standalone
                #   rate with no borrow consumer cannot move value
                #   (live-corpus FPs: a reflection token's
                #   _getRate, and a staking reward-per-share
                #   distribute - both divide by a subtraction-
                #   derived denominator but feed no borrow).
                # - Otherwise the accrual function must be ungated
                #   itself, or called by an ungated consumer.
                is_view = bool(re.search(
                    r"\b(view|pure)\b", fn["signature"]))
                class_texts = [text]
                if is_view:
                    consumers = [c for c in _consumers_of(
                        fn["name"], result_var)
                        if not _caller_gated(c, scope) and
                        _BORROW_CONSUMER_RE.search(c["name"])]
                    if not consumers:
                        continue
                    class_texts += [c["text"] for c in consumers]
                elif _caller_gated(fn, scope):
                    consumers = [c for c in _consumers_of(
                        fn["name"], result_var)
                        if not _caller_gated(c, scope)]
                    if not consumers:
                        continue
                    class_texts += [c["text"] for c in consumers]
                else:
                    class_texts += [c["text"] for c in
                                    _consumers_of(fn["name"],
                                                  result_var)]
                guard_note = ""
                dname = denom.strip()
                if re.fullmatch(r"[A-Za-z_]\w*", dname):
                    if re.search(
                            r"\b" + re.escape(dname) +
                            r"\s*(==|!=|<=)\s*0\b", text):
                        guard_note = (
                            f" The denominator is guarded "
                            f"only by an == 0 skip "
                            f"({dname} == 0), with no "
                            f"minimum-denominator floor.")
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' computes "
                    f"'{result_var or 'a rate'}' as "
                    f"'{numerator.strip()} / {denom.strip()}' "
                    f"where the denominator is a net-supply-"
                    f"style expression (subtraction-based), "
                    f"and the result feeds borrow / collateral "
                    f"/ exchange-rate math.{guard_note} Gate "
                    f"analysis: the accrual path is reachable "
                    f"by a stranger (no caller-identity gate "
                    f"on the accrual function or its borrow "
                    f"consumer).")
                item = _hit(spec, fn["name"], cc._snip(text),
                            detail,
                            "ungated accrual: interest divided "
                            "by a net-supply denominator with "
                            "no minimum floor and no result cap")
                out.append(_classify_with_meter(item,
                                                class_texts))
                fired_here = True
                break
            if fired_here:
                break
    return out


def _classify_with_meter(item, texts):
    """Classify, upgrading HOLDER-SELF via the meter-broken rule.

    Tries each function text in order (the accrual function
    first, then its borrow consumers) until the shared
    classifier resolves a recipient. The shared classifier
    reads a borrow bounded by the caller's own recorded
    position as HOLDER-SELF, but the bug breaks that meter
    itself, so HOLDER-SELF upgrades to CALLER with a note.
    """
    if isinstance(texts, str):
        texts = [texts]
    recipient, rdetail = "UNRESOLVED", "no value destination"
    for text in texts:
        recipient, rdetail = cl.classify_recipient(text)
        if recipient != "UNRESOLVED":
            break
    if recipient == "HOLDER-SELF":
        item["detail"] += (
            f" Recipient analysis: the shared classifier reads "
            f"this as HOLDER-SELF (the payout is bounded by "
            f"the caller's own recorded position), but the bug "
            f"breaks that meter itself - the borrow / "
            f"collateral meter is fed by the inflated rate, so "
            f"the caller receives value beyond what the meter "
            f"should allow (Kava: deposits valued ~243,000x "
            f"once net supply is pushed near zero). Upgraded "
            f"to CALLER under the Nov 14 meter-broken rule.")
        return _classify(item, "CALLER",
                         rdetail + "; meter broken by the bug")
    return _classify(item, recipient, rdetail)


# ---------------------------------------------------------------------------
# 2. stale_capacity_snapshot_after_payout
# ---------------------------------------------------------------------------

_SNAPSHOT_VAR_RE = re.compile(
    r"snapshot|cachedCapacity|periodStart|startOfPeriod|"
    r"capacityAt|initialCapacity|openingCapacity|"
    r"startCapacity", re.I)
_CAPACITY_FN_RE = re.compile(
    r"(available|capacity|cover|underwrite|allocat|sellCover|"
    r"issueCover|approveCover|buyCover|getCapacity)", re.I)
_ALLOCATOR_FN_RE = re.compile(
    r"(sellCover|allocat|underwrite|issueCover|approveCover|"
    r"buyCover|sell|alloc)", re.I)
_PAYOUT_FN_RE = re.compile(
    r"(payout|payClaim|settle|claim|disburse|payOut)", re.I)
_COLLATERAL_VAR_RE = re.compile(
    r"(totalCollateral|collateral|collateralBalance|"
    r"totalAssets|backing|reserves)", re.I)
_REFRESH_FN_RE = re.compile(
    r"(refresh|invalidate|syncSnapshot|updateSnapshot|"
    r"recompute|resetSnapshot|refreshSnapshot)", re.I)


def _is_snapshot_var(name: str) -> bool:
    lower = name.lower()
    if "snapshot" in lower:
        return True
    if "period" in lower and "start" in lower:
        return True
    if "capacity" in lower and any(
            k in lower for k in ("cached", "initial", "opening",
                                 "start", "at")):
        return True
    return lower in ("cachedcapacity", "startcapacity",
                     "periodcapacity")


def _fn_reads_var(fn: Dict[str, Any], var: str) -> bool:
    return bool(re.search(r"\b" + re.escape(var) + r"\b",
                          fn["text"]))


def _fn_reads_live_collateral(fn: Dict[str, Any],
                              collateral_vars) -> bool:
    text = fn["text"]
    if "balanceOf(address(this))" in text.replace(" ", ""):
        return True
    for var in collateral_vars:
        if re.search(r"\b" + re.escape(var) + r"\b", text):
            return True
    return False


def _analyze_stale_capacity(src, spec, compiler,
                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    # Leg A: a period-start snapshot / cached-capacity state
    # variable that is actually assigned somewhere (a
    # snapshot is taken), not merely declared.
    snapshot_vars = [v for v in state
                     if _is_snapshot_var(v) and
                     _plain_assign_rhs(scoped, v)]
    if not snapshot_vars:
        return []
    by_name = {fn["name"]: fn for fn in fns}

    def _capacity_reads_snapshot(fn):
        for var in snapshot_vars:
            if _fn_reads_var(fn, var):
                return var
        return None

    def _calls(fn, target_name):
        return bool(re.search(
            r"\b" + re.escape(target_name) + r"\s*\(", fn["text"]))

    # The collateral variables: what the payout reduces.
    collateral_vars = set()
    for fn in fns:
        if not _PAYOUT_FN_RE.search(fn["name"]):
            continue
        text = fn["text"]
        for m in re.finditer(
                r"\b([A-Za-z_]\w*)\s*-=(?!=)", text):
            if _COLLATERAL_VAR_RE.search(m.group(1)):
                collateral_vars.add(m.group(1))
        for m in re.finditer(
                r"\b([A-Za-z_]\w*)\s*=\s*\1\s*-", text):
            if _COLLATERAL_VAR_RE.search(m.group(1)):
                collateral_vars.add(m.group(1))
    if not collateral_vars:
        return []
    # Leg B: a payout / settlement function that reduces a
    # collateral variable WITHOUT refreshing / invalidating
    # the snapshot.
    payout_fn = None
    for fn in fns:
        if not _PAYOUT_FN_RE.search(fn["name"]):
            continue
        text = fn["text"]
        reduces = False
        for var in collateral_vars:
            if re.search(r"\b" + re.escape(var) +
                         r"\s*-=(?!=)", text):
                reduces = True
            if re.search(r"\b" + re.escape(var) +
                         r"\s*=\s*" + re.escape(var) +
                         r"\s*-", text):
                reduces = True
        if not reduces:
            continue
        refreshes = False
        for var in snapshot_vars:
            if _plain_assign_rhs(text, var):
                refreshes = True
        for other in fns:
            if _REFRESH_FN_RE.search(other["name"]) and \
                    _calls(fn, other["name"]):
                refreshes = True
        if refreshes:
            continue
        payout_fn = fn
        break
    if payout_fn is None:
        return []
    # Leg C: a capacity / underwrite function reading the
    # snapshot (directly, or through a capacity view it
    # calls), with no live collateral re-read before
    # allocating.
    for fn in fns:
        if not _ALLOCATOR_FN_RE.search(fn["name"]):
            continue
        if _is_constructor_or_initializer(fn):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        snap = _capacity_reads_snapshot(fn)
        capacity_fn = None
        if snap is None:
            for other in fns:
                if _CAPACITY_FN_RE.search(other["name"]) and \
                        _calls(fn, other["name"]):
                    snap = _capacity_reads_snapshot(other)
                    if snap:
                        capacity_fn = other
                        break
        if snap is None:
            continue
        if _fn_reads_live_collateral(fn, collateral_vars):
            continue
        if capacity_fn is not None and \
                _fn_reads_live_collateral(capacity_fn,
                                          collateral_vars):
            continue
        detail = spec.detail + (
            f" Observed: capacity is read from the "
            f"period-start snapshot '{snap}' (assigned at "
            f"period start), '{fn['name']}' allocates cover "
            f"against it with no live collateral re-read, "
            f"and payout '{payout_fn['name']}' reduces "
            f"collateral ({', '.join(sorted(collateral_vars))}) "
            f"without refreshing or invalidating '{snap}' - "
            f"so cover sold after a mid-period payout is "
            f"backed by collateral that no longer exists. "
            f"Gate analysis: the allocator is permissionless "
            f"(no caller-identity gate); the payout is "
            f"privileged by design, the over-selling is done "
            f"by the allocator.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated allocator reads a period-start "
                    "capacity snapshot; payout reduces "
                    "collateral without refreshing it")
        return [_finish_recipient_meter_broken(
            spec, item, text,
            "the capacity meter is the stale snapshot itself: "
            "the meter bounds the cover sold by a capacity "
            "that a mid-period payout already reduced, so the "
            "allocator receives cover beyond what the live "
            "collateral backs (Firelight: a correct live-"
            "capacity guard pays the claim in full, the stale "
            "snapshot leaves 2,000 of it unpaid)")]
    return []


# ---------------------------------------------------------------------------
# 3. cap_counter_reset_by_setter
# ---------------------------------------------------------------------------

_COUNTER_VAR_RE = re.compile(
    r"(supply|minted|issued|sold|passes|claimed|redeemed|"
    r"distributed)", re.I)
_CAP_VAR_RE = re.compile(
    r"(maxSupply|MAX_SUPPLY|maxMint|supplyCap|cap|CAP)", re.I)
_MINT_FN_RE = re.compile(
    r"(mint|buy|purchase|claim|redeem|issue|sell)", re.I)
_SETTER_FN_RE = re.compile(
    r"(set|config|update|reset|admin|manage)", re.I)


def _is_counter_var(name: str) -> bool:
    lower = name.lower()
    if lower.startswith("max") or "cap" in lower or \
            "limit" in lower:
        return False
    return bool(_COUNTER_VAR_RE.search(name))


def _analyze_cap_counter_reset(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    counters = [v for v in state if _is_counter_var(v)]
    if not counters:
        return []
    # The setter: a non-constructor function that plain-assigns
    # a counter variable to 0, a literal, or an arbitrary value
    # (a parameter / local). A reset living only in a
    # constructor / initializer does not count.
    setter_fn = None
    reset_counter = None
    reset_rhs = None
    for fn in fns:
        if _is_constructor_or_initializer(fn):
            continue
        text = fn["text"]
        for var in counters:
            for rhs in _plain_assign_rhs(text, var):
                rhs_s = rhs.strip()
                if re.fullmatch(
                        r"0|0x0+|[0-9][0-9_]*|[A-Za-z_]\w*",
                        rhs_s):
                    setter_fn = fn
                    reset_counter = var
                    reset_rhs = rhs_s
                    break
            if setter_fn is not None:
                break
        if setter_fn is not None:
            break
    if setter_fn is None:
        return []
    # The cap check: a mint / buy function comparing
    # counter + amount <= maxSupply / cap.
    for fn in fns:
        if not _MINT_FN_RE.search(fn["name"]):
            continue
        if _is_constructor_or_initializer(fn):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        cap_hit = False
        for m in re.finditer(
                r"\b" + re.escape(reset_counter) +
                r"\s*\+\s*[A-Za-z_]\w*\s*(<=|<)\s*"
                r"([A-Za-z_]\w*)", text):
            if _CAP_VAR_RE.search(m.group(2)) or \
                    "max" in m.group(2).lower():
                cap_hit = True
        if not cap_hit:
            for m in re.finditer(
                    r"\b" + re.escape(reset_counter) +
                    r"\s*(<=|<)\s*([A-Za-z_]\w*)", text):
                if _CAP_VAR_RE.search(m.group(2)) or \
                        "max" in m.group(2).lower():
                    cap_hit = True
        if not cap_hit:
            continue
        # A cap derived from totalSupply() directly is the
        # protected shape: the counter is not the cap meter.
        if re.search(r"totalSupply\s*\(\s*\)\s*\+", text):
            continue
        detail = spec.detail + (
            f" Observed: setter '{setter_fn['name']}' assigns "
            f"'{reset_counter} = {reset_rhs}' (re-arming the "
            f"consumed counter), while '{fn['name']}' checks "
            f"'{reset_counter} + amount <= maxSupply / cap' - "
            f"so the cap is not a real cap: the counter can be "
            f"reset and the supply minted past it. Gate "
            f"analysis: the mint / buy path is permissionless "
            f"(no caller-identity gate); the setter is the "
            f"re-arm, not the reachability gate.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated mint/buy checks a counter a "
                    "setter can reset; cap is not binding")
        return [_finish_recipient(spec, item, text)]
    return []


# ---------------------------------------------------------------------------
# 4. finalize_recallable_drains_pot
# ---------------------------------------------------------------------------

_CLOSE_FN_RE = re.compile(
    r"(close|finaliz|settle|distribut|conclud)", re.I)
_POT_VAR_RE = re.compile(
    r"(pot|prizePool|poolBalance|totalBalance|jackpot|"
    r"potBalance|prize|vaultBalance)", re.I)
_FINAL_FLAG_RE = re.compile(
    r"(closed|finalized|isClosed|isFinalized|settled|"
    r"isSettled|ended|finished|isFinished|complete|"
    r"isComplete)", re.I)


def _transfer_amounts(text: str) -> List[str]:
    """Amount arguments of token / ETH transfers in the text."""
    amounts: List[str] = []
    for m in re.finditer(
            r"\.(transfer|transferFrom|send)\s*\(", text):
        open_pos = m.end() - 1
        inner, _ = _balanced(text, open_pos)
        parts = _split_top(inner)
        if len(parts) >= 2:
            amounts.append(parts[-1])
        elif parts:
            amounts.append(parts[0])
    for m in re.finditer(r"\.call\s*\{[^}]*value\s*:\s*",
                         text):
        rest = text[m.end():]
        mm = re.match(r"[^,}\n]+", rest)
        if mm:
            amounts.append(mm.group(0).strip())
    return amounts


def _is_full_balance_amount(amount: str, scoped: str) -> bool:
    """The amount is the whole contract / pot balance."""
    a = re.sub(r"\s+", "", amount)
    if "balanceOf(address(this))" in a:
        return True
    if "address(this).balance" in a:
        return True
    if re.fullmatch(r"[A-Za-z_]\w*", a):
        if _POT_VAR_RE.search(a):
            return True
        # A local assigned from the whole balance.
        for rhs in _plain_assign_rhs(scoped, a):
            r = re.sub(r"\s+", "", rhs)
            if "balanceOf(address(this))" in r or \
                    "address(this).balance" in r:
                return True
    return False


def _analyze_finalize_recallable(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    flags = [v for v in state if _FINAL_FLAG_RE.search(v)]
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CLOSE_FN_RE.search(fn["name"]):
            continue
        if _is_constructor_or_initializer(fn):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        amounts = _transfer_amounts(text)
        if not any(_is_full_balance_amount(a, scoped)
                   for a in amounts):
            continue
        # The protected shape: a finalized flag checked at
        # entry AND set to true BEFORE any value movement.
        # A flag checked at entry but set AFTER the transfer
        # still fires (the transfer itself is unguarded).
        protected = False
        for flag in flags:
            entry_checked = bool(re.search(
                r"require\s*\(\s*!" + re.escape(flag) +
                r"\b|" + r"if\s*\(\s*" + re.escape(flag) +
                r"\s*\)\s*revert|" + r"require\s*\(\s*" +
                re.escape(flag) + r"\s*==\s*false\b", text))
            if not entry_checked:
                continue
            set_match = re.search(
                r"\b" + re.escape(flag) +
                r"\s*=\s*true\b", text)
            if not set_match:
                continue
            first_move = None
            for m in re.finditer(
                    r"\.(transfer|transferFrom|send|call)\s*"
                    r"(\{|\(|\.)", text):
                first_move = m.start()
                break
            if first_move is not None and \
                    set_match.start() < first_move:
                protected = True
        if protected:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' transfers the whole "
            f"contract / pot balance out "
            f"({amounts[0].strip() if amounts else 'balance'}) "
            f"with no closed / finalized flag checked at entry "
            f"and set before the transfer - so a second call "
            f"pays the whole pot out again. Gate analysis: no "
            f"caller-identity gate on the close / finalize "
            f"path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated close/finalize transfers the full "
                    "pot balance with no finalized flag set "
                    "before the transfer")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. internal_transfer_credit_without_debit
# ---------------------------------------------------------------------------

_INTERNAL_TRANSFER_FN_RE = re.compile(
    r"(transferBetween|internalTransfer|transferInternal|"
    r"moveBalance|subaccountTransfer|transfer|move)", re.I)
_WITHDRAW_FN_RE = re.compile(
    r"(withdraw|redeem|exit|claim)", re.I)
_LEDGER_WRITE_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]\s*\+=\s*"
    r"([A-Za-z_]\w*)")


def _analyze_internal_transfer(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _INTERNAL_TRANSFER_FN_RE.search(fn["name"]):
            continue
        if _is_constructor_or_initializer(fn):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        # The credit: ledger[to] += amount on an internal
        # ledger mapping, indexed by a parameter.
        credit = None
        for m in _LEDGER_WRITE_RE.finditer(text):
            ledger, idx, amt = (m.group(1), m.group(2).strip(),
                                m.group(3))
            if idx not in params or amt not in params:
                continue
            credit = (ledger, idx, amt)
            break
        if credit is None:
            continue
        ledger, to_idx, amt = credit
        # The debit: the SAME ledger, the SAME amount,
        # subtracted from another index. A debit of a
        # different variable or a different amount does not
        # count - the transfer is still not zero-sum.
        debited = bool(re.search(
            r"\b" + re.escape(ledger) +
            r"\s*\[[^\]]+\]\s*-=\s*" + re.escape(amt) + r"\b",
            text))
        if debited:
            continue
        # The exit: a withdraw function reading this ledger
        # for the caller and moving value out.
        withdraw_fn = None
        for other in fns:
            if other is fn:
                continue
            if not _WITHDRAW_FN_RE.search(other["name"]):
                continue
            otext = other["text"]
            if not re.search(
                    r"\b" + re.escape(ledger) +
                    r"\s*\[\s*msg\.sender\s*\]", otext):
                continue
            if not _moves_value(otext):
                continue
            withdraw_fn = other
            break
        if withdraw_fn is None:
            continue
        if _caller_gated(withdraw_fn, scope):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' writes "
            f"{ledger}[{to_idx}] += {amt} with no "
            f"corresponding {ledger}[from] -= {amt} (no debit "
            f"of the same amount on the same ledger anywhere "
            f"in the function), and '{withdraw_fn['name']}' "
            f"reads {ledger}[msg.sender] and transfers value "
            f"out - so the sum of internal balances grows on "
            f"every transfer and the inflated balance "
            f"withdraws through the normal path. Gate "
            f"analysis: both the internal transfer and the "
            f"withdraw are permissionless (no caller-identity "
            f"gate).")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated internal transfer credits without "
                    "a matching debit; withdraw reads the "
                    "inflated ledger balance")
        # The value exits through the withdraw, so classify
        # the recipient from the withdraw function. The
        # meter-broken rule applies: the withdraw is bounded
        # by the caller's own recorded balance, but the bug
        # inflates that balance itself.
        out.append(_finish_recipient_meter_broken(
            spec, item, withdraw_fn["text"],
            "the withdraw meter is the internal ledger "
            "balance itself: the transfer credits without "
            "debiting, so the balance the withdraw reads is "
            "larger than anything the caller deposited (Arcus: "
            "the recorded balance grew far beyond what the "
            "account held, then withdrew through the normal "
            "path)"))
    return out


ANALYZERS = {
    "interest_accrual_near_zero_denominator_inflation":
        _analyze_accrual_denominator,
    "stale_capacity_snapshot_after_payout":
        _analyze_stale_capacity,
    "cap_counter_reset_by_setter": _analyze_cap_counter_reset,
    "finalize_recallable_drains_pot": _analyze_finalize_recallable,
    "internal_transfer_credit_without_debit":
        _analyze_internal_transfer,
}


def analyze_deep23_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-23 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep23_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit23Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 23)"
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
        for item in analyze_deep23_source(
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
                source="deep audit detector batch 23 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit23Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 23) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
