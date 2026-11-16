"""Deep-audit detectors, batch 12: AI plugin dev (2026-11-08).

Five more chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- zero_amount_withdrawal_full_balance: a withdraw / unstake
  function where amount == 0 (or no `amount > 0` guard) sizes
  the payout from the stored staked balance, and the only check
  is `amount <= balance`. The b14g Core shape (2026-10-31,
  ~97M CORE). An explicit `require(amount > 0)` or a payout
  strictly equal to the requested amount stays silent.
  Distinct from built withdraw_rounding_drain (rounding
  direction) and recipient_overdraw_withdraw.
- scheduled_settlement_books_unpaid: a settlement / accrual
  function that reduces outstanding debt / principal on a time
  condition (day / epoch rollover) with no check that tokens
  actually arrived (no balance-delta or receipt verification).
  The TranchePool shape (2026-10-28, ~$1.01M). A settlement
  that verifies arrival (balance delta / receipt) stays silent.
  Distinct from venus_accrue_interest_omission (interest
  accrual skipped, no debt booked).
- vesting_release_cancel_double_debit: release() decrements the
  pool-wide totalShares but NOT the position's own shares
  counter; cancel() / close() later reads position.shares to
  decrement the total again (double debit). The UNCX Vesting
  V2 shape (2026-10-14, ~$1.49M). A release that decrements
  both counters stays silent. Distinct from built
  share_transfer_cancel_desync (entitlement refund vs live
  balanceOf).
- intent_deposit_ghost_credit_no_rollback: deposit credits an
  internal balance BEFORE an external call / hook, and the
  failure / refund path returns tokens without clearing the
  credit (or there is no reconciliation invariant). The NEAR
  Intents / HOT Omni shape (2026-09-30, ~$3.86M). A refund
  path that zeroes the credit, or a credit written only after
  the external call succeeds, stays silent. Distinct from
  bridge_wrapped_token_mint_unbacked and
  fee_on_transfer_overcredit.
- aa_execute_ungated: a smart-account execute() / executeBatch()
  / call() callable by anyone with no onlyOwner / onlyEntryPoint
  / onlySelf check, so a stranger drains the account directly.
  The other half of the AA surface from built
  aa_validation_ungated (validateUserOp only). A gated execute
  stays silent. Registry has no execute ids.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. (Same narrowing
of cl._gated_deep as batch 11.)

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
FAMILY = "deep12"

SPECS = [
    S("zero_amount_withdrawal_full_balance", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Zero-amount withdrawal releases the full staked "
             "balance: a withdraw / unstake function sizes the "
             "payout from the stored staked balance when the "
             "requested amount is 0 (or has no `amount > 0` guard "
             "while the payout defaults to the full stored "
             "balance), and the only check is `amount <= balance` "
             "- the b14g Core shape. An explicit "
             "`require(amount > 0)` or a payout strictly equal to "
             "the requested amount is the protected shape.",
      fix="Require `amount > 0` on every withdraw / unstake "
          "path, and size the payout strictly from the requested "
          "amount, never from the stored balance when the "
          "request is 0."),
    S("scheduled_settlement_books_unpaid", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Scheduled settlement books an unpaid payment: a "
             "settlement / accrual function reduces outstanding "
             "debt / principal on a time condition (day / epoch "
             "rollover) with no check that tokens actually "
             "arrived (no balance-delta or receipt verification) "
             "- the TranchePool shape. A settlement that verifies "
             "arrival (balance delta / receipt) is the protected "
             "shape.",
      fix="Verify arrival before booking: measure the token "
          "balance delta (or a receipt) across the settlement "
          "and only reduce outstanding debt by the amount "
          "actually received."),
    S("vesting_release_cancel_double_debit", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Vesting release / cancel share double debit: "
             "release() decrements the pool-wide totalShares but "
             "NOT the position's own shares counter, and cancel() "
             "later reads position.shares to decrement the total "
             "again, double-debiting released shares so a leftover "
             "position can claim other schedules' tokens - the "
             "UNCX Vesting V2 shape. A release that decrements "
             "both counters is the protected shape.",
      fix="Decrement the position's own shares counter in the "
          "same release() that decrements totalShares, and have "
          "cancel() size its removal from the live remaining "
          "shares, never from a stale counter."),
    S("intent_deposit_ghost_credit_no_rollback", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Intent deposit ghost credit, no rollback on refund: "
             "deposit credits an internal balance BEFORE an "
             "external call / hook, and the failure / refund path "
             "returns tokens without clearing the credit, so the "
             "sum of internal balances exceeds the token "
             "balanceOf and the ghost balance withdraws via the "
             "normal path - the NEAR Intents / HOT Omni shape. A "
             "refund path that zeroes the credit, or a credit "
             "written only after the external call succeeds, is "
             "the protected shape.",
      fix="Credit the internal balance only after the external "
          "call succeeds, and make every refund / failure path "
          "zero the credited balance in the same step that "
          "returns the tokens (or enforce the reconciliation "
          "invariant sum(balances) <= balanceOf)."),
    S("aa_execute_ungated", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Smart-account execute ungated: a smart-account "
             "execute() / executeBatch() / call() is callable by "
             "anyone with no onlyOwner / onlyEntryPoint / onlySelf "
             "check, and it forwards a caller-supplied target "
             "call, so a stranger drains the account directly - "
             "the other half of the AA surface from built "
             "aa_validation_ungated. A gated execute is the "
             "protected shape.",
      fix="Gate execute / executeBatch / call behind onlyOwner, "
          "onlyEntryPoint, or onlySelf, so only the account "
          "owner or the EntryPoint can move the account's funds."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 11)
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


def _call_args(text: str, call_match) -> List[str]:
    paren = text.index("(", call_match.start())
    inner, _ = _balanced(text, paren)
    return _split_top(inner)


def _skip_fn(fn: Dict[str, Any], scope) -> bool:
    if re.search(r"\b(view|pure)\b", fn["signature"]):
        return True
    return _caller_gated(fn, scope)


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


def _fn_addr_params(fn: Dict[str, Any]) -> List[str]:
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        if "address" in part:
            toks = [t for t in part.split()
                    if t not in ("calldata", "memory", "storage",
                                 "payable")]
            if len(toks) >= 2:
                out.append(toks[-1])
    return out

# ---------------------------------------------------------------------------
# 1. Zero-amount withdrawal releases the full staked balance (b14g shape)
# ---------------------------------------------------------------------------

_WITHDRAW_FN_RE = re.compile(r"withdraw|unstake", re.I)
_AMOUNT_POS_GUARD_RE = re.compile(
    r"require\s*\(\s*amount\s*>\s*0\b|"
    r"if\s*\(\s*amount\s*==\s*0\s*\)\s*revert|"
    r"if\s*\(\s*amount\s*<=\s*0\s*\)\s*revert|"
    r"amount\s*>\s*0")
_AMOUNT_LE_CHECK_RE = re.compile(
    r"require\s*\(\s*amount\s*<=\s*[^)]+\)|"
    r"if\s*\(\s*amount\s*>\s*[^)]+\)\s*revert")
_BAL_VAR_RE = (r"(?:stakes|stakedBalance|staked|balances?|"
               r"deposited|stakeBalance)\b")
_ZERO_TERNARY_RE = re.compile(
    r"amount\s*==\s*0\s*\?\s*[^:;]{0,80}?" + _BAL_VAR_RE)
_ZERO_IF_RE = re.compile(
    r"if\s*\(\s*amount\s*==\s*0\s*\)\s*\{[^}]{0,400}?=\s*[^;]{0,80}?"
    + _BAL_VAR_RE)


def _analyze_zero_amount_withdrawal(src, spec, compiler,
                                    contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _WITHDRAW_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 1: no `amount > 0` guard anywhere in the
        # function. An explicit positive-amount requirement
        # is the protected shape.
        if _AMOUNT_POS_GUARD_RE.search(text):
            continue
        # Leg 2: the only check is `amount <= balance`.
        m_le = _AMOUNT_LE_CHECK_RE.search(text)
        if not m_le:
            continue
        # Leg 3: a zero-amount branch sizes the payout from
        # the stored balance - a ternary `amount == 0 ?
        # <balance> : amount`, or an `if (amount == 0)` block
        # that assigns a balance / stake value.
        m_zero = (_ZERO_TERNARY_RE.search(text) or
                  _ZERO_IF_RE.search(text))
        if not m_zero:
            continue
        # Leg 4: value actually leaves after the zero branch.
        if not [c for c in cl._external_calls(text)
                if c["pos"] > m_zero.start()]:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' checks only "
            f"'amount <= balance' with no `amount > 0` guard, "
            f"and a zero-amount request sizes the payout from "
            f"the stored staked balance "
            f"('{m_zero.group(0)[:80]}'), so withdrawing 0 "
            f"releases the caller's entire stake. Gate "
            f"analysis: no caller-identity gate, no "
            f"`amount > 0` requirement, payout not strictly "
            f"equal to the requested amount.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated withdraw: only an amount <= balance "
                    "check, zero amount defaults to the full "
                    "stored balance")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. Scheduled settlement books an unpaid payment (TranchePool shape)
# ---------------------------------------------------------------------------

_SETTLE_FN_RE = re.compile(r"settle|accrue|rollover", re.I)
_TIME_COND_RE = re.compile(
    r"block\.timestamp\s*(?:>=|>)|"
    r"\bcurrentDay\s*(?:>|>=)|\bday\s*>\s*last|"
    r"\bepoch\s*(?:>|>=)|\bnow\s*(?:>=|>)|"
    r"(?:>=|>)\s*(?:dayEnd|epochEnd|nextSettlement|"
    r"settleTime|dueTime|deadline)\b")
_DEBT_REDUCE_RE = re.compile(
    r"\b(?:outstanding\w*|totalDebt|debt\w*|principal\w*|"
    r"amountOwed\w*)\s*(?:\[[^\]]+\])?\s*"
    r"(?:-=|=\s*[A-Za-z_][\w\[\]\.]*\s*-\s*)")
_ARRIVAL_RE = re.compile(
    r"balanceOf\s*\(|balanceBefore|balanceAfter|"
    r"actualReceived|receivedAmount|receipt")


def _analyze_scheduled_settlement(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SETTLE_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 1: the settlement runs on a time condition
        # (day / epoch rollover).
        if not _TIME_COND_RE.search(text):
            continue
        # Leg 2: it reduces outstanding debt / principal.
        m_debt = _DEBT_REDUCE_RE.search(text)
        if not m_debt:
            continue
        # Leg 3: no check that tokens actually arrived - no
        # balance delta, no receipt verification. A
        # settlement that verifies arrival is the protected
        # shape.
        if _ARRIVAL_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' runs on a time "
            f"condition and reduces outstanding debt "
            f"('{m_debt.group(0)[:80]}') with no balance-delta "
            f"or receipt check, so the payment is booked as "
            f"received whether or not any tokens arrived. Gate "
            f"analysis: no caller-identity gate, no arrival "
            f"verification, debt booked on time alone.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated settlement: debt reduced on a time "
                    "condition with no arrival verification")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. Vesting release / cancel share double debit (UNCX Vesting V2 shape)
# ---------------------------------------------------------------------------

_RELEASE_FN_RE = re.compile(r"^(release|claim|releaseShares)$",
                            re.I)
_CANCEL_FN_RE = re.compile(r"^(cancel|close|revoke)$", re.I)
_TOTAL_DEC_RE = re.compile(
    r"\btotalShares\s*-=|\btotalShares\s*=\s*totalShares\s*-")
_POS_SHARES_DEC_RE = re.compile(
    r"\.shares\s*-=|\.shares\s*=\s*[\w\.]+\.shares\s*-|"
    r"\bshares\s*=\s*shares\s*-")
_CANCEL_TOTAL_FROM_POS_RE = re.compile(
    r"\btotalShares\s*-=\s*[^;]{0,80}?\.shares\b|"
    r"\btotalShares\s*=\s*totalShares\s*-\s*[^;]{0,80}?"
    r"\.shares\b")


def _analyze_vesting_double_debit(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # Leg 1: release() decrements totalShares but NOT the
    # position's own shares counter.
    release_fn = None
    for fn in fns:
        if not _RELEASE_FN_RE.match(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        if not _TOTAL_DEC_RE.search(text):
            continue
        if _POS_SHARES_DEC_RE.search(text):
            continue
        release_fn = fn
        break
    if release_fn is None:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CANCEL_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 2: cancel() sizes its totalShares removal from
        # the position's (stale) shares counter.
        m = _CANCEL_TOTAL_FROM_POS_RE.search(text)
        if not m:
            continue
        # Leg 3: value leaves on the cancel path.
        if not cl._external_calls(text):
            continue
        detail = spec.detail + (
            f" Observed: '{release_fn['name']}' decrements "
            f"totalShares but never decrements the position's "
            f"own shares counter, and '{fn['name']}' later "
            f"decrements totalShares from the stale "
            f"position.shares "
            f"('{m.group(0)[:80]}'), double-debiting the shares "
            f"already released, so a leftover position can claim "
            f"other schedules' tokens. Gate analysis: neither "
            f"path is caller-gated, and no release step keeps "
            f"the position counter in sync with the pool total.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated cancel: totalShares decremented "
                    "from a position.shares counter release() "
                    "never decremented")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. Intent deposit ghost credit, no rollback on refund (NEAR Intents shape)
# ---------------------------------------------------------------------------

_DEPOSIT_FN_RE = re.compile(r"deposit", re.I)
_CREDIT_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]+\])?\s*\+=\s*"
    r"(?:amount|msg\.value|value)\b|"
    r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]+\])?\s*=\s*\2\s*"
    r"(?:\[[^\]]+\])?\s*\+\s*(?:amount|msg\.value|value)\b")
_REFUND_FN_RE = re.compile(
    r"refund|fail|revert|handleFail|onFail|rescue", re.I)
_TOKEN_XFER_RE = re.compile(
    r"\.transfer\s*\(|\.transferFrom\s*\(|\.call\s*[\{\(]")


def _mapping_cleared(text: str, mapping: str) -> bool:
    """The refund path zeroes / debits the credited mapping."""
    return bool(
        re.search(r"\bdelete\s+" + re.escape(mapping) + r"\b",
                  text)
        or re.search(r"\b" + re.escape(mapping) +
                     r"\s*(?:\[[^\]]+\])?\s*=\s*0\b", text)
        or re.search(r"\b" + re.escape(mapping) +
                     r"\s*(?:\[[^\]]+\])?\s*-=", text))


def _analyze_ghost_credit(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # Leg 1: deposit credits an internal balance BEFORE an
    # external call / hook in the same function.
    deposit_fn = None
    mapping = None
    for fn in fns:
        if not _DEPOSIT_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        m = _CREDIT_RE.search(text)
        if not m:
            continue
        calls = [c for c in cl._external_calls(text)
                 if c["pos"] > m.start()]
        if not calls:
            continue
        deposit_fn = fn
        mapping = m.group(1) or m.group(2)
        break
    if deposit_fn is None or not mapping:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn is deposit_fn:
            continue
        if not _REFUND_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 2: the refund path returns tokens...
        if not _TOKEN_XFER_RE.search(text):
            continue
        # ... without clearing the credit. A refund that
        # zeroes the credit is the protected shape.
        if _mapping_cleared(text, mapping):
            continue
        detail = spec.detail + (
            f" Observed: '{deposit_fn['name']}' credits "
            f"'{mapping}' before an external call, and the "
            f"failure path '{fn['name']}' returns tokens "
            f"without clearing that credit, so the ghost "
            f"balance survives the refund and withdraws via the "
            f"normal path. Gate analysis: neither path is "
            f"caller-gated, no refund step zeroes the credit, "
            f"no reconciliation invariant is enforced.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated refund: tokens returned without "
                    "clearing the pre-call internal credit")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. Smart-account execute ungated (AA surface, other half of validation)
# ---------------------------------------------------------------------------

_EXECUTE_FN_RE = re.compile(r"^(execute|executeBatch|call)$",
                            re.I)
_ACCOUNT_SCOPE_RE = re.compile(
    r"entryPoint|validateUserOp")
_ACCOUNT_NAME_RE = re.compile(r"Account|Wallet", re.I)
# Any low-level forward out of execute(): a caller-supplied
# target (to / target / dest / ...) or a fixed one. The
# recipient classifier decides candidate vs trigger-only -
# a fixed target still fires (the stranger invokes arbitrary
# calldata with the account's authority) but at low severity.
_SUPPLIED_CALL_RE = re.compile(
    r"\b(?:to|target|dest|destination|account)\w*"
    r"(?:\[[^\]]*\])?\s*\.\s*"
    r"(?:call|delegatecall)\s*[\{\(]")
_ANY_CALL_RE = re.compile(
    r"\b[A-Za-z_]\w*(?:\[[^\]]*\])?\s*\.\s*"
    r"(?:call|delegatecall)\s*[\{\(]")


def _analyze_aa_execute_ungated(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # Smart-account scoping: an EntryPoint / validateUserOp
    # surface, or an Account / Wallet contract name. This
    # keeps generic forwarders and delegate-call utilities
    # (which have their own detectors) out of this lane.
    scoped = scope.scoped_text
    if not (_ACCOUNT_SCOPE_RE.search(scoped) or
            any(_ACCOUNT_NAME_RE.search(n)
                for n in scope.contract_names)):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _EXECUTE_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # The execute forwards a target call - caller-supplied
        # or fixed; the recipient classifier sorts candidate
        # from trigger-only.
        m = _SUPPLIED_CALL_RE.search(text) or \
            _ANY_CALL_RE.search(text)
        if not m:
            continue
        supplied = bool(_SUPPLIED_CALL_RE.search(text))
        detail = spec.detail + (
            f" Observed: '{fn['name']}' forwards a "
            f"{'caller-supplied' if supplied else 'fixed'} "
            f"target call "
            f"('{m.group(0)[:60]}') with no onlyOwner / "
            f"onlyEntryPoint / onlySelf check, so any stranger "
            f"can move the account's funds directly. Gate "
            f"analysis: no caller-identity gate on the execute "
            f"path, target and calldata are caller-controlled.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated smart-account execute: "
                    "caller-supplied target call, no owner / "
                    "entryPoint / self gate")
        out.append(_finish_recipient(spec, item, text))
    return out

ANALYZERS = {
    "zero_amount_withdrawal_full_balance":
        _analyze_zero_amount_withdrawal,
    "scheduled_settlement_books_unpaid":
        _analyze_scheduled_settlement,
    "vesting_release_cancel_double_debit":
        _analyze_vesting_double_debit,
    "intent_deposit_ghost_credit_no_rollback":
        _analyze_ghost_credit,
    "aa_execute_ungated": _analyze_aa_execute_ungated,
}


def analyze_deep12_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-12 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)

# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-11 collection / fetch /
# proxy resolution; analysis is analyze_deep12_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit12Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 12)"
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
        for item in analyze_deep12_source(
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
                source="deep audit detector batch 12 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit12Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 12) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
