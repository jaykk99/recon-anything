"""Deep-audit detectors, batch 29: liquidations that clear
collateral but keep the debt, bridge withdraws with no consumed
receipt check, restake reward baselines desynced by share
transfers, and subaccount transfers whose unchecked debit
underflows.

Four chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

Four plugins today, not five: the November incident well is
exhausted for novel, fixtureable, stranger-receivable contract
shapes - every other fresh incident this week adjudicates to a
class already built in batches 1-28 (Kava Lend -> the batch-23
near-zero-denominator accrual detector; CoreVault TWAP fallback
-> oracle_twap_fallback_to_spot; Sovryn -> the batch-26 receipt
detector; Firelight #88244 -> the batch-23 stale-capacity
detector; the LUNA answer-band case -> chainlink_price_unbounded;
Ark Project deposit-hash omission -> bridge_replay_unbound_digest;
the batch-payout revert -> push_payment_revert_dos; the
Firelight rescue-flag family -> rescue_marks_future_bucket_claimed;
Troves -> stale_permission_after_replacement; ACryptoS ->
multitoken_deposit_length_mismatch; B14g -> zero_amount_withdrawal
_full_balance), and the rest are key-compromise / infra / backend
incidents with no contract bug to detect (Gonka signing-key swap,
Initia IBC keys, LUKSO email-recovery backend, Lighter API-key
reuse, RNT/Peapods deployer keys, Across domain hijack). The four
below are all incident-anchored, fixtureable, and empirically
silent under their neighbours (see the test file).

- liquidation_clears_collateral_keeps_debt: a liquidate path
  zeroes / seizes the borrower's collateral record but never
  reduces the borrower's debt balance (or total borrows) in the
  same function or its internal callees, while a borrow /
  withdraw function still reads that debt record - the MORE
  Markets shape (Nov 16, ~$308-348k on Flow EVM: a flash-loan
  self-liquidation cleared the ankrFLOW collateral without
  clearing the matching WFLOW debt, and the mismatch let the
  attacker withdraw WFLOW from the reserve). Clearing the debt
  in the same liquidate path is the protected shape. Distinct
  from liquidation_residual_collateral_reborrow (the mirror
  image: that one zeroes the DEBT and leaves the COLLATERAL
  record, so the position re-borrows - this one zeroes the
  COLLATERAL and leaves the DEBT, so the phantom debt keeps
  the reserve's accounting solvent-looking while real funds
  leave).
- bridge_withdraw_no_consumed_receipt_check: a bridge withdraw /
  release verifies a signature over a receipt (messageId, token,
  amount, recipient) but never consults a spent / processed /
  redeemed marker for that receipt id anywhere on the path, and
  pays out from the caller-supplied receipt fields - the Ankr
  shape (Nov 9, ~$304k: five withdrawals, all validly signed,
  all citing one 0.0044 ankrETH Optimism deposit that had
  already been redeemed, with changed recipients, tokens and
  amounts). Reading a consumed marker for the receipt id before
  paying is the protected shape. Distinct from
  bridge_replay_unbound_digest (the digest there under-binds
  the message identity - chain, sender or nonce missing - here
  the digest binds chain + message id and the signature is
  valid; the hole is the missing consumption check) and from
  bridge_release_value_unbound_to_proof (the value there is
  not bound to the proof at all - here the value IS bound to
  the signed receipt, which is exactly why the same signed
  receipt pays again).
- restake_reward_baseline_desync_on_transfer: a staking share
  transfer moves shares without setting (or settling) the
  recipient's reward baseline, while a restake / claim computes
  the reward as (globalRewardPerShare - baseline[caller]) *
  balance and mints it as new shares - the Chain Games shape
  (Nov 15, ~$20k realised / 36M CHAIN: ValidatorShare.restake
  minted rewards to recipients whose initialRewardPerShare was
  still zero because ERC20 transfers never set it; 360
  transfer-restake rounds turned 1,000 CHAIN into 36M shares,
  redeemed through the normal withdrawal). Settling both sides'
  rewards (or setting the recipient's baseline to the current
  global value) in the transfer is the protected shape.
  Distinct from reward_distribution_manipulation (an
  accumulator computed from the raw balance, or shares
  credited before the reward update - this one is the
  TRANSFER not syncing the baseline, with the restake minting
  from the stale baseline) and from
  share_transfer_cancel_desync (a cancel refunding a stored
  entitlement against a live balanceOf).
- subaccount_transfer_unchecked_underflow: an internal-ledger
  transfer between subaccounts debits the source balance
  inside an unchecked{} block with no sufficiency guard on
  that debit anywhere on the path, while a withdraw function
  pays out of the same ledger - the Arcus Perps shape (Nov
  9-10, $2.23M USDG: transfers between a fresh account's own
  subaccounts inflated its recorded balance past what it had
  deposited - CertiK attributes it to an integer underflow -
  and the account withdrew against it; the bridge rate limit
  held back ~$3M more). A balance-sufficiency check on the
  debit, or checked arithmetic for it, is the protected shape.
  Distinct from internal_transfer_credit_without_debit (no
  debit at all - here the debit EXISTS but is unchecked and
  unguarded, so it wraps instead of reverting; that detector
  stays silent on this fixture by construction) and from the
  generic unchecked_math_user_input (which tracks locals and
  user-input arithmetic, not a state-mapping debit inside an
  internal transfer - empirically silent on this fixture, see
  the probe in the research log).

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding on the permissionless entry point - a stranger cannot
reach the path. For the subaccount detector the recipient is
classified from the withdraw consumer (the transfer itself
moves no value out; the stranger receives through the
withdraw it enables).

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
FAMILY = "deep29"

SPECS = [
    S("liquidation_clears_collateral_keeps_debt", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Liquidation clears collateral but keeps the debt: "
             "a liquidate path zeroes / seizes the borrower's "
             "collateral record but never reduces the borrower's "
             "debt balance (or total borrows) in the same "
             "function or its internal callees, while a borrow / "
             "withdraw function still reads that debt record - "
             "so the position's collateral is gone but its debt "
             "stays on the books, and the mismatch lets value "
             "be withdrawn from the reserve - the MORE Markets "
             "shape. Clearing the debt in the same liquidate "
             "path is the protected shape.",
      fix="Clear the debt in the same liquidate path that "
          "seizes the collateral: reduce the borrower's debt "
          "balance and total borrows by the repaid / liquidated "
          "amount in the same transaction, and have borrow() "
          "re-read the live position rather than a stale debt "
          "record."),
    S("bridge_withdraw_no_consumed_receipt_check", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Bridge withdraw with no consumed-receipt check: "
             "a bridge withdraw / release verifies a signature "
             "over a receipt (message id, token, amount, "
             "recipient) but never consults a spent / processed "
             "/ redeemed marker for that receipt id anywhere on "
             "the path, and pays out from the caller-supplied "
             "receipt fields - so one validly signed receipt "
             "pays again and again with changed recipients, "
             "tokens and amounts - the Ankr shape. Reading a "
             "consumed marker for the receipt id before paying "
             "is the protected shape.",
      fix="Mark every receipt consumed before paying: require "
          "the receipt id is not in the spent / processed "
          "registry, then record it consumed in the same "
          "transaction, and never pay a receipt whose id has "
          "already been used."),
    S("restake_reward_baseline_desync_on_transfer", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Restake reward baseline desynced by a share "
             "transfer: a staking share transfer moves shares "
             "without setting (or settling) the recipient's "
             "reward baseline, while a restake / claim computes "
             "the reward as (global reward per share - the "
             "caller's baseline) * balance and mints it as new "
             "shares - so a fresh recipient claims historical "
             "rewards it never earned, and looping "
             "transfer-restake compounds the inflation - the "
             "Chain Games shape. Settling both sides' rewards "
             "(or setting the recipient's baseline to the "
             "current global value) in the transfer is the "
             "protected shape.",
      fix="Synchronize reward baselines on every share "
          "transfer: settle the sender's and the recipient's "
          "pending rewards (or set the recipient's baseline to "
          "the current global reward per share) before the "
          "balances move, so no recipient can claim rewards "
          "accrued before it held shares."),
    S("subaccount_transfer_unchecked_underflow", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Subaccount transfer unchecked underflow: an "
             "internal-ledger transfer between subaccounts "
             "debits the source balance inside an unchecked{} "
             "block with no sufficiency guard on that debit "
             "anywhere on the path, while a withdraw function "
             "pays out of the same ledger - so the debit wraps "
             "to a huge balance instead of reverting, and the "
             "account withdraws against it - the Arcus Perps "
             "shape. A balance-sufficiency check on the debit, "
             "or checked arithmetic for it, is the protected "
             "shape.",
      fix="Guard every internal-ledger debit: require the "
          "source balance covers the amount before debiting, "
          "and do the debit in checked arithmetic (or prove "
          "the guard makes the unchecked block safe). Never "
          "let an internal transfer wrap a balance."),
]
SPECS_BY_ID = {s.id: s for s in SPECS}

# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19 / deep25)
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
    or a role check suppresses. The signature check and the
    _msgSender() gate under analysis are NOT gates here.
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


def _fn_params_typed(fn: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(type, name) parameter pairs from a function signature."""
    sig = fn["signature"]
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    if "(" not in stripped:
        return []
    i = stripped.find("(")
    inner, _ = _balanced(stripped, i)
    out: List[Tuple[str, str]] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append((" ".join(toks[:-1]), toks[-1]))
    return out


def _fn_body(text: str) -> str:
    """The function body (after the first `{`), for searches
    that must not match the signature's own parameter names."""
    i = text.find("{")
    return text[i + 1:] if i >= 0 else text


def _called_internal_texts(fn_text: str, scope) -> str:
    """Text of internal functions this function calls.

    A claimed-marker write, a collateral check, or a refund
    leg may live in a small internal helper (_markClaimed,
    _checkCollateral, _refundPreviousBidder) rather than in
    the entry point itself. A bare `foo(` call whose name
    matches a function defined in this contract is treated
    as an internal call; external calls (obj.foo(), token
    .transfer) and builtins (require, keccak256) never match
    a defined function name, so they are excluded.
    """
    defined = {f["name"]: f["text"] for f in scope.functions}
    out: List[str] = []
    for m in re.finditer(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                         fn_text):
        name = m.group(1)
        if name in defined and defined[name] not in out:
            out.append(defined[name])
    return "\n".join(out)


def _applied_modifier_bodies(fn: Dict[str, Any], scope) -> str:
    """Bodies of the modifiers applied to this function.

    A deadline check (or any other enforcement) may live in a
    modifier (auctionOpen, onlyBeforeEnd) rather than in the
    entry point itself.
    """
    sig = fn["signature"]
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i < 0:
        return ""
    _, pend = _balanced(stripped, i)
    tail = stripped[pend + 1:]
    out: List[str] = []
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
        body = scope.modifiers.get(tok)
        if body:
            out.append(body)
    return "\n".join(out)


def _mentions(text: str, param: str) -> bool:
    """A word-boundary mention of a parameter name, excluding
    the `value` inside `msg.value` (a parameter literally named
    `value` must not match the msg.value keyword)."""
    return bool(re.search(r"(?<!msg\.)\b" + re.escape(param) +
                          r"\b", text))


def _dest_class(dest: str, params: List[str],
                state: set) -> Tuple[str, str]:
    """Recipient class of a value destination expression."""
    d = dest.split("[")[0].split(".")[0].strip()
    if d in params:
        return ("CALLER-SUPPLIED",
                f"destination is the caller parameter '{d}'")
    if d == "msg":
        return ("CALLER", "destination is msg.sender")
    if d in state:
        return ("FIXED",
                f"destination is the stored address '{d}'")
    return ("UNRESOLVED", f"destination '{d}'")


_VALUE_MOVE_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*transferFrom\s*\(|"
    r"safeTransfer\s*\(|safeTransferFrom\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\.\s*send\s*\(|\.\s*transfer\s*\{\s*value")


def _moves_value(text: str) -> bool:
    """A token / ETH payout of some kind in the function."""
    return bool(_VALUE_MOVE_RE.search(text))


_ALLOWLIST_RE = re.compile(
    r"allowlist|whitelist|allowedTargets|isAllowed|"
    r"approvedTargets|trustedRouter|isTrusted|onlyAllowed",
    re.I)


# ---------------------------------------------------------------------------
# 1. liquidation_clears_collateral_keeps_debt
# ---------------------------------------------------------------------------

_LIQ_FN_RE = re.compile(r"liquidat", re.I)
_COLLATERAL_VAR_RE = re.compile(r"collateral", re.I)
_DEBT_VAR_RE = re.compile(r"debt|borrow", re.I)
_CONSUMER_FN_RE = re.compile(r"^(?:borrow|withdraw|redeem|repay)\w*$",
                             re.I)


def _mapping_write_forms(text: str, var: str) -> List[str]:
    """Write forms on a mapping variable: zero, delete, -=, or
    `var[...] = var[...] - x`."""
    w = r"\b" + re.escape(var) + r"\b\s*\[[^\]]+\]"
    forms = []
    if re.search(w + r"\s*=\s*0\s*;", text):
        forms.append("zeroed")
    if re.search(r"\bdelete\s+" + w + r"\s*;", text):
        forms.append("deleted")
    if re.search(w + r"\s*-=", text):
        forms.append("decremented")
    if re.search(w + r"\s*=\s*" + r"\b" + re.escape(var) +
                 r"\b\s*\[[^\]]+\]\s*-", text):
        forms.append("subtracted")
    return forms


def _analyze_liquidation_clears_collateral(src, spec, compiler,
                                           contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    coll_vars = [v for v in state if _COLLATERAL_VAR_RE.search(v)]
    debt_vars = [v for v in state if _DEBT_VAR_RE.search(v)]
    if not coll_vars or not debt_vars:
        return []
    # A borrow / withdraw consumer must read a debt variable:
    # the uncleared debt is load-bearing, not dead state.
    consumer = False
    for fn in fns:
        if not _CONSUMER_FN_RE.match(fn["name"]):
            continue
        text = fn["text"] + _called_internal_texts(fn["text"], scope)
        if any(re.search(r"\b" + re.escape(d) + r"\b", text)
               for d in debt_vars):
            consumer = True
            break
    if not consumer:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _LIQ_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"] + _called_internal_texts(fn["text"], scope)
        text += _applied_modifier_bodies(fn, scope)
        cleared = []
        for v in coll_vars:
            cleared += [(v, f) for f in
                        _mapping_write_forms(text, v)]
        if not cleared:
            continue
        reduced = False
        for v in debt_vars:
            if _mapping_write_forms(text, v):
                reduced = True
                break
        if reduced:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' "
            f"{cleared[0][1]} the collateral record "
            f"'{cleared[0][0]}' but never reduces any debt "
            f"record ({', '.join(sorted(debt_vars))}) on this "
            f"path, while a borrow / withdraw function still "
            f"reads the debt - the collateral is gone and the "
            f"debt stays on the books.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]), detail,
                    "ungated liquidate: collateral cleared, debt "
                    "never reduced on the path, debt record "
                    "still read by borrow / withdraw")
        out.append(_finish_recipient(spec, item, fn["text"]))
        break
    return out


# ---------------------------------------------------------------------------
# 2. bridge_withdraw_no_consumed_receipt_check
# ---------------------------------------------------------------------------

_BRIDGE_WITHDRAW_FN_RE = re.compile(
    r"^(?:withdraw|release|claim|redeem|execute|process|relay)"
    r"\w*$", re.I)
_SIG_RE = re.compile(
    r"ecrecover|ECDSA\s*\.\s*recover|isValidSignature|"
    r"\.\s*verify\s*\(", re.I)
_RECEIPT_ID_RE = re.compile(
    r"\b(?:messageId|receiptId|depositId|depositTxHash|txHash|"
    r"claimId|withdrawalId|transferId)\b")
_CONSUMED_MARKER_RE = re.compile(
    r"\b(?:used|processed|redeemed|claimed|spent|consumed|"
    r"executed|withdrawn|fulfilled|settled|completed|handled)"
    r"\w*\b", re.I)


def _consumed_marker_checked(text: str) -> bool:
    """A consumed / spent / processed marker is actually
    consulted before paying: an indexed read of a marker
    variable inside a require / if (or an assignment of the
    read into a checked local). A bare write (`used[x] =
    true`) with no read does NOT count - the replay still
    works."""
    for m in _CONSUMED_MARKER_RE.finditer(text):
        tail = text[m.start():]
        idx = re.search(r"\s*\[[^\]]+\]", tail)
        if not idx:
            continue
        before = text[max(0, m.start() - 40):m.start()]
        after = tail[idx.end():idx.end() + 40]
        if re.search(r"\b(require|if|assert)\s*\([^)]*$",
                     before):
            return True
        if re.search(r"^\s*(==|!=|&&|\|\|)", after):
            return True
        if re.search(r"\breturn\b[^;]{0,40}$", before):
            return True
    return False


def _analyze_bridge_no_consumed_receipt(src, spec, compiler,
                                        contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BRIDGE_WITHDRAW_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"] + _called_internal_texts(fn["text"], scope)
        if not _SIG_RE.search(text):
            continue
        if not _RECEIPT_ID_RE.search(text):
            continue
        if not _moves_value(text):
            continue
        if _consumed_marker_checked(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a signature "
            f"and pays out from caller-supplied receipt fields "
            f"but never consults a spent / processed / redeemed "
            f"marker for the receipt id anywhere on the path - "
            f"the same signed receipt can pay again with "
            f"changed fields.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]), detail,
                    "ungated bridge withdraw: signature verified "
                    "but no consumed-receipt marker consulted "
                    "before the payout")
        out.append(_finish_recipient(spec, item, fn["text"]))
        break
    return out

def _finish_excess_recipient(spec: DetectorSpec,
                             item: Dict[str, Any],
                             consumer_text: str,
                             why: str) -> Dict[str, Any]:
    """The vault_share_inflation / share-price precedent: the
    payout leg meters the caller's own position (a HOLDER-SELF
    shape in isolation), but the value it pays is created by
    the desync proven above - the stranger receives assets
    BEYOND their own deposit, so the excess is caller-received
    and the finding is a candidate. A FIXED payout destination
    stays trigger-only under the receive rule."""
    recipient, rdetail = cl.classify_recipient(consumer_text)
    item["recipient"] = recipient
    if recipient == "FIXED":
        item["report_class"] = "trigger_only"
        item["severity"] = "low"
        item["detail"] += (
            f" Recipient analysis: the payout destination is "
            f"FIXED ({rdetail}), so a stranger can trigger "
            f"this but receives nothing - classified "
            f"TRIGGER-ONLY under the receive rule.")
    else:
        item["report_class"] = "candidate"
        if recipient == "HOLDER-SELF":
            item["detail"] += (
                " Recipient analysis: the payout leg meters "
                "the caller's own position (HOLDER-SELF "
                f"shape), but {why} - the excess is "
                "CALLER-received, classified CANDIDATE under "
                "the receive rule.")
        else:
            item["detail"] += (
                f" Recipient analysis: recipient classified "
                f"{recipient} ({rdetail}) - a stranger can "
                f"receive value here, classified CANDIDATE "
                f"under the receive rule.")
    return item


# ---------------------------------------------------------------------------
# 3. restake_reward_baseline_desync_on_transfer
# ---------------------------------------------------------------------------

_ACCUM_RE = re.compile(
    r"\b(?:rewardPerShare|rewardPerToken|accRewardPerShare|"
    r"rewardPerStake|rewardIndex)\b")
_BASELINE_RE = re.compile(
    r"\b(?:initialRewardPerShare|rewardPerTokenPaid|"
    r"userRewardPerTokenPaid|initialRewardPerToken|"
    r"rewardPerSharePaid|initialRewardPerStake)\b")
_TRANSFER_FN_RE = re.compile(r"^transfer(?:From)?$", re.I)
_RESTAKE_FN_RE = re.compile(
    r"^(?:restake|claim\w*|getReward\w*|harvest\w*)$", re.I)
_SHARE_BAL_RE = re.compile(
    r"\b(?:shares|balances|stakeBalances?|stakedBalances?)\b")


def _baseline_synced_for_to(fn, scope, baseline: str,
                            accum: str) -> bool:
    """The transfer syncs the recipient's reward baseline:
    a direct write `baseline[to] = ...` in the transfer, or
    an internal updater called with `to` whose text writes
    the baseline indexed by its own address parameter."""
    text = fn["text"]
    w = (r"\b" + re.escape(baseline) + r"\b\s*\[\s*to\s*\]"
         r"\s*=")
    if re.search(w, text):
        return True
    defined = {f["name"]: f for f in scope.functions}
    for m in re.finditer(
            r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        name = m.group(1)
        if name not in defined:
            continue
        i = text.index("(", m.start())
        args, _ = _balanced(text, i)
        if not re.search(r"\bto\b", args):
            continue
        callee = defined[name]
        params = _fn_params(callee)
        for p in params:
            if re.search(r"\b" + re.escape(baseline) +
                         r"\b\s*\[\s*" + re.escape(p) +
                         r"\s*\]\s*=", callee["text"]):
                return True
    return False


def _analyze_restake_baseline_desync(src, spec, compiler,
                                     contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    accums = [v for v in state if _ACCUM_RE.fullmatch(v)]
    baselines = [v for v in state if _BASELINE_RE.fullmatch(v)]
    if not accums or not baselines:
        return []
    accum, baseline = accums[0], baselines[0]
    # A share transfer that moves shares to `to` without
    # syncing `to`'s baseline.
    desynced_transfer = None
    for fn in fns:
        if not _TRANSFER_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        moves_shares = False
        for v in state:
            if not _SHARE_BAL_RE.search(v):
                continue
            if re.search(r"\b" + re.escape(v) +
                         r"\b\s*\[\s*to\s*\]\s*\+=", text):
                moves_shares = True
                break
        if not moves_shares:
            continue
        if _baseline_synced_for_to(fn, scope, baseline, accum):
            continue
        desynced_transfer = fn["name"]
        break
    if not desynced_transfer:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _RESTAKE_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"] + _called_internal_texts(fn["text"], scope)
        reward_calc = re.search(
            r"\b" + re.escape(accum) + r"\b\s*-\s*"
            r"\b" + re.escape(baseline) +
            r"\b\s*\[[^\]]+\]", text)
        if not reward_calc:
            continue
        mints = bool(re.search(r"\b_mint\s*\(", text)) or any(
            re.search(r"\b" + re.escape(v) +
                      r"\b\s*\[[^\]]+\]\s*\+=", text)
            for v in state if _SHARE_BAL_RE.search(v))
        if not mints:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes the reward "
            f"as ({accum} - {baseline}[caller]) * balance "
            f"and mints it as new shares, but the share "
            f"transfer '{desynced_transfer}' never sets or "
            f"settles the recipient's {baseline} - a fresh "
            f"recipient keeps a zero baseline and claims "
            f"rewards accrued before it held shares.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]), detail,
                    "ungated restake mints from a caller "
                    "baseline the share transfer never syncs")
        # Recipient, from the mint / credit destination the
        # restake itself writes: the generic classifier sees
        # no transfer / _mint call here (the shares are
        # credited by a direct ledger write), so read the
        # credited key directly. Crediting the caller mints
        # unbacked value the caller receives (candidate); a
        # FIXED credit stays trigger-only.
        dest = None
        mm = re.search(r"\b_mint\s*\(\s*([^,)]+)", text)
        if mm:
            dest = mm.group(1).strip()
        else:
            for v in state:
                if not _SHARE_BAL_RE.search(v):
                    continue
                cm = re.search(r"\b" + re.escape(v) +
                              r"\b\s*\[\s*([^\]]+)\]\s*\+=",
                              text)
                if cm:
                    dest = cm.group(1).strip()
                    break
        item["recipient"] = "UNRESOLVED"
        if dest == "msg.sender":
            item["recipient"] = "CALLER"
        elif dest in state:
            item["recipient"] = "FIXED"
        elif dest in _fn_params(fn):
            item["recipient"] = "CALLER-SUPPLIED"
        if item["recipient"] == "FIXED":
            item["report_class"] = "trigger_only"
            item["severity"] = "low"
            item["detail"] += (
                " Recipient analysis: the minted reward lands "
                "at a FIXED destination, so a stranger can "
                "trigger this but receives nothing - classified "
                "TRIGGER-ONLY under the receive rule.")
        else:
            item["report_class"] = "candidate"
            item["detail"] += (
                " Recipient analysis: the restake mints the "
                "unbacked reward to the caller "
                f"({item['recipient']}) - the stale baseline "
                "creates shares the caller never deposited "
                "for, classified CANDIDATE under the receive "
                "rule.")
        out.append(item)
        break
    return out


# ---------------------------------------------------------------------------
# 4. subaccount_transfer_unchecked_underflow
# ---------------------------------------------------------------------------

_SUB_TRANSFER_FN_RE = re.compile(
    r"^(?:transfer\w*|move\w*|internalTransfer\w*)$", re.I)
_UNCHECKED_RE = re.compile(r"\bunchecked\s*\{")
_LEDGER_VAR_RE = re.compile(
    r"balance|ledger|subBalance", re.I)
_WITHDRAW_FN_RE = re.compile(r"^(?:withdraw|redeem|exit)\w*$",
                             re.I)


def _unchecked_blocks(text: str) -> List[str]:
    """Bodies of the unchecked{} blocks in a function (brace
    matching - _balanced only counts parens)."""
    out: List[str] = []
    for m in _UNCHECKED_RE.finditer(text):
        i = text.index("{", m.start())
        depth = 0
        for j in range(i, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    out.append(text[i + 1:j])
                    break
    return out


def _has_sufficiency_guard(text: str, minuends: List[str],
                           subtrahend: str) -> bool:
    """A require / assert / if-revert bounding a subtraction:
    require(EXPR >= SUB), require(SUB <= EXPR), or an
    if (EXPR < SUB) revert guard, for any spelling of the
    minuend expression."""
    flat = re.sub(r"\s+", "", text)
    sub = re.sub(r"\s+", "", subtrahend)
    if not sub:
        return False
    for expr in minuends:
        e = re.sub(r"\s+", "", expr)
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
        if any(p in flat for p in pats):
            return True
    return False


def _analyze_subaccount_unchecked_underflow(src, spec, compiler,
                                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # Ledger variable names come from the debit statements
    # themselves: cl.state_variables cannot see nested mappings
    # (mapping(address => mapping(...))), which is exactly the
    # subaccount ledger shape, so the state set is not used
    # here.
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SUB_TRANSFER_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        full = text + _called_internal_texts(text, scope)
        full += _applied_modifier_bodies(fn, scope)
        params = _fn_params(fn)
        if not params:
            continue
        amount = params[-1]
        hit = None
        for block in _unchecked_blocks(text):
            m = re.search(
                r"\b([A-Za-z_]\w*)\s*\[[^\]]+\]"
                r"(?:\s*\[[^\]]+\])?\s*-=\s*" +
                re.escape(amount) + r"\b", block)
            if m and _LEDGER_VAR_RE.search(m.group(1)):
                hit = (m.group(1), m.group(0))
                break
            m = re.search(
                r"\b([A-Za-z_]\w*)\s*\[[^\]]+\]"
                r"(?:\s*\[[^\]]+\])?\s*=\s*"
                r"\b\1\b\s*\[[^\]]+\]"
                r"(?:\s*\[[^\]]+\])?\s*-\s*" +
                re.escape(amount) + r"\b", block)
            if m and _LEDGER_VAR_RE.search(m.group(1)):
                hit = (m.group(1), m.group(0))
                break
        if not hit:
            continue
        minuends = [hit[1].split("-=")[0].split("=")[0].strip(),
                    hit[0]]
        if _has_sufficiency_guard(full, minuends, amount):
            continue
        # A withdraw consumer must pay out of the same ledger.
        consumer_text = None
        for wfn in fns:
            if not _WITHDRAW_FN_RE.match(wfn["name"]):
                continue
            wtext = wfn["text"]
            if not _moves_value(wtext):
                continue
            if re.search(r"\b" + re.escape(hit[0]) + r"\b",
                         wtext):
                consumer_text = wtext
                break
        if consumer_text is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' debits "
            f"'{hit[0]}' by the caller-supplied amount inside "
            f"an unchecked{{}} block ({hit[1].strip()}) with "
            f"no sufficiency guard anywhere on the path, "
            f"while a withdraw pays out of the same ledger - "
            f"the debit wraps instead of reverting and the "
            f"inflated balance withdraws.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]), detail,
                    "ungated internal transfer: unchecked ledger "
                    "debit, no balance-sufficiency guard, "
                    "withdraw consumer on the same ledger")
        # The recipient is the withdraw consumer's payout: the
        # transfer moves nothing out, the withdraw pays from
        # the wrapped balance - the excess over the caller's
        # deposit is caller-received (share-price precedent).
        out.append(_finish_excess_recipient(
            spec, item, consumer_text,
            "the payout is sized off the wrapped balance, so "
            "the stranger withdraws assets beyond their own "
            "deposit"))
        break
    return out


ANALYZERS = {
    "liquidation_clears_collateral_keeps_debt":
        _analyze_liquidation_clears_collateral,
    "bridge_withdraw_no_consumed_receipt_check":
        _analyze_bridge_no_consumed_receipt,
    "restake_reward_baseline_desync_on_transfer":
        _analyze_restake_baseline_desync,
    "subaccount_transfer_unchecked_underflow":
        _analyze_subaccount_unchecked_underflow,
}


def analyze_deep29_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-29 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep29_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit29Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 29)"
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
        for item in analyze_deep29_source(
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
                source="deep audit detector batch 29 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit29Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 29) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
