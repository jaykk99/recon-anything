"""Deep-audit detectors, batch 28: caller-writable snapshot
positions, share prices excluding sub-threshold collateral,
vouchers not bound to the redeemer, period exits writing the
new period's exposure snapshot, withdraws paying another
account's balance.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- snapshot_position_sync_caller_writable: a public sync /
  update / refresh function writes a caller's recorded
  position / snapshot from a caller-supplied value (a
  parameter standing outside any call, not a recompute from
  the contract's own state), ungated, and a withdraw / redeem
  pays out of that same record - the Pool Party shape
  (Nov 13, ~$215k across 15 pools: the attacker changed
  their own recorded position through syncInvestor and
  withdrew far more than deposited). A sync that recomputes
  the position from the contract's own stored state / pool
  balances, or an owner-gated sync, is the protected shape.
  Distinct from checkpoint_overwrite_equal_key_rewrites_snapshot
  (an equal-key checkpoint push overwriting the last entry -
  this one is a direct caller-supplied write to the position
  record, no push, no checkpoint library).
- share_price_excludes_subthreshold_collateral: a vault's
  totalAssets / share-price computation only adds a balance
  leg when it exceeds a nonzero threshold (if / ternary
  gating the add), so collateral below the threshold is held
  but invisible to the share price, while deposit + redeem
  read that valuation - the K3 Capital sBOLD shape (Nov 18,
  ~$3.43M: WETH collateral below a configured threshold was
  excluded from the share price; shares were bought cheap,
  the collateral converted into counted BOLD, then redeemed
  at the higher value). Summing all balance legs
  unconditionally is the protected shape; a `> 0` zero-guard
  is not a threshold. Distinct from vault_share_inflation
  (a donation INFLATES the share denominator - this one
  OMITS a leg from the numerator).
- voucher_redeem_recipient_unbound: a voucher / coupon /
  ticket redeem verifies a signature over a payload that
  does not bind the redeemer (no msg.sender and no
  recipient parameter in the signed digest), while the
  function DOES carry a nonce / consumed marker - so the
  voucher is replay-protected but not recipient-bound, and
  any stranger can present someone else's voucher and be
  paid as the caller. The B18TimeBank anchor (Nov 17,
  ~$404k USDC: signed level-reward vouchers redeemed
  through withdrawLevelReward) has an UNCONFIRMED root
  cause, so this is the generic voucher-recipient class,
  not a claim about B18's exact bug. A digest binding
  msg.sender (or the recipient parameter) is the protected
  shape. Distinct from signature_replay_no_nonce (a nonce
  IS present here) and eip712_digest_unbound_to_payload
  (no batch payload; the missing binding is the recipient).
- period_exit_writes_new_period_exposure_snapshot: a
  withdraw / exit function writes a period-keyed exposure /
  snapshot mapping for the CURRENT period (key derived from
  block.timestamp) from inside the exit path, and a claim /
  payout function sizes payouts from that same record -
  the Firelight #88353 shape (High, Aug 2026: a vault exit
  mined in the first second of a period writes that period's
  own exposure snapshot, permanently short-paying an
  approved cover claim). The snapshot write belongs to a
  deposit / snapshot-entry path, not to an exit. Distinct
  from period_start_checkpoint_zeroes_payout_cap (#88287:
  a withdraw that _burns shares and THEN writes a checkpoint
  keyed to the period start, zeroing the payout cap - this
  one burns nothing and writes the exposure snapshot
  itself). Fires WITHOUT a recipient classification
  (batch-20 auction precedent): the exit pays the caller's
  own balance - the stranger-receivable value is the
  short-paid / mispriced claim the desync enables, not the
  exit. Medium severity.
- withdraw_pays_other_account_balance: a withdraw / redeem
  function takes an address account / from / owner
  parameter, reads and debits THAT account's recorded
  balance, and transfers the amount to the caller, with no
  check that msg.sender is that account and no allowance
  check - the Reental shape (Nov 18, ~$454k: an admin
  upgrade to the USDT/USDC aToken proxies let anyone drain
  the underlying stablecoins). Requiring msg.sender ==
  account, or checking / consuming an allowance, is the
  protected shape. Distinct from recipient_overdraw_withdraw
  (a payout not bounded by the CALLER's balance - here the
  payout IS bounded, by the VICTIM's balance; the overdraw
  detector co-fires on this class by design, because the
  payout is not bounded by the caller's balance, and the
  new detector adds the authorization dimension it cannot
  express - pinned explicitly in the test) and from
  recipient_unbacked_claim (claim-family names, no
  entitlement read at all).

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path.

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
FAMILY = "deep28"

SPECS = [
    S("snapshot_position_sync_caller_writable", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Snapshot position writable by the caller: a "
             "public sync / update / refresh function writes "
             "a caller's recorded position / snapshot from a "
             "caller-supplied value (a parameter standing "
             "outside any call, not a recompute from the "
             "contract's own state), with no caller-identity "
             "gate, and a withdraw / redeem pays out of that "
             "same record, so a stranger inflates their own "
             "recorded position and withdraws more than they "
             "deposited - the Pool Party shape. A sync that "
             "recomputes the position from the contract's own "
             "stored state / pool balances, or an owner-gated "
             "sync, is the protected shape.",
      fix="Never write a position record from a caller-supplied "
          "value: recompute the position from the contract's "
          "own stored state (pool balances, deposit ledger) "
          "inside the sync, or restrict the sync to a "
          "privileged keeper, and require the withdraw to be "
          "covered by an actual deposit."),
    S("share_price_excludes_subthreshold_collateral", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Share price excludes sub-threshold collateral: "
             "a vault's totalAssets / share-price computation "
             "only adds a balance leg when it exceeds a "
             "nonzero threshold (an if / ternary gating the "
             "add), so collateral below the threshold is held "
             "but invisible to the share price, while deposit "
             "and redeem read that valuation - the K3 Capital "
             "sBOLD shape. Summing all balance legs "
             "unconditionally is the protected shape; a `> 0` "
             "zero-guard is not a threshold.",
      fix="Price every held leg unconditionally: sum all "
          "balanceOf-derived legs into totalAssets with no "
          "threshold gate, or floor the share price at the "
          "value of the full holdings including any "
          "sub-threshold leg."),
    S("voucher_redeem_recipient_unbound", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Voucher redeemable by a non-recipient: a "
             "voucher / coupon / ticket redeem verifies a "
             "signature over a payload that does not bind the "
             "redeemer (no msg.sender and no recipient "
             "parameter in the signed digest), while the "
             "function does carry a nonce / consumed marker - "
             "so the voucher is replay-protected but not "
             "recipient-bound, and any stranger can present "
             "someone else's voucher and be paid as the "
             "caller. The B18TimeBank anchor has an "
             "UNCONFIRMED root cause, so this is the generic "
             "voucher-recipient class. A digest binding "
             "msg.sender (or the recipient parameter) is the "
             "protected shape.",
      fix="Bind the redeemer into the signed payload: hash "
          "msg.sender (or the recipient the voucher names) "
          "into the digest the signature is verified against, "
          "and require the payout destination to equal the "
          "bound recipient."),
    S("period_exit_writes_new_period_exposure_snapshot", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="Period exit writes the new period's exposure "
             "snapshot: a withdraw / exit function writes a "
             "period-keyed exposure / snapshot mapping for "
             "the CURRENT period (key derived from "
             "block.timestamp) from inside the exit path, and "
             "a claim / payout function sizes payouts from "
             "that same record - the Firelight #88353 shape. "
             "The snapshot write belongs to a deposit / "
             "snapshot-entry path, not to an exit. No "
             "recipient classification: the exit pays the "
             "caller's own balance - the stranger-receivable "
             "value is the short-paid / mispriced claim the "
             "desync enables.",
      fix="Never write a period exposure snapshot from an exit "
          "path: snapshot the period only on deposit / "
          "period-entry, and have exits read (never write) "
          "the snapshot the claims are sized from."),
    S("withdraw_pays_other_account_balance", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Withdraw pays another account's balance: a "
             "withdraw / redeem function takes an address "
             "account / from / owner parameter, reads and "
             "debits THAT account's recorded balance, and "
             "transfers the amount to the caller, with no "
             "check that msg.sender is that account and no "
             "allowance check - the Reental shape. Requiring "
             "msg.sender == account, or checking / consuming "
             "an allowance, is the protected shape.",
      fix="Authorize the debit: require msg.sender == account "
          "(or that the caller holds an allowance from the "
          "account covering the amount, consumed on the "
          "withdraw) before debiting any balance that is not "
          "the caller's own."),
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
# 1. snapshot_position_sync_caller_writable
# ---------------------------------------------------------------------------

_SYNC_FN_RE = re.compile(
    r"sync|(?:update|refresh)(?:\w*(?:position|snapshot|investor|"
    r"entitlement|record))", re.I)
_POS_MAP_RE = re.compile(
    r"\b(?:positions?|snapshots?|investorPositions?|"
    r"entitlements?|recorded\w*)\b")
_PAYOUT_FN_RE = re.compile(
    r"^(?:withdraw|redeem|exit|claim)\w*$", re.I)


def _mentions_outside_calls(text: str, param: str,
                            defined: set) -> bool:
    """A mention of param outside any call's argument list.

    A sync that recomputes from the contract's own state reads
    like `positions[investor] = pool.balanceOf(investor)` - the
    param appears, but only inside a call's arguments. A
    caller-supplied write reads like `positions[investor] =
    newPosition` - the param stands on its own. Casts
    (uint256(x)) are value forms, not calls, so they do not
    hide a mention.
    """
    spans: List[Tuple[int, int]] = []
    for m in re.finditer(
            r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        name = m.group(1)
        if name in defined or "." in m.group(0):
            i = text.index("(", m.start())
            _, end = _balanced(text, i)
            spans.append((m.start(), end))
    for m in re.finditer(r"\b" + re.escape(param) + r"\b", text):
        if not any(s <= m.start() < e for s, e in spans):
            return True
    return False


def _analyze_snapshot_sync(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    defined = {f["name"] for f in scope.functions}
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SYNC_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        if not params:
            continue
        body = _fn_body(text)
        writes: List[Tuple[str, str]] = []
        for m in re.finditer(
                r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\]]+)\s*\]\s*"
                r"=(?!=)\s*([^;]{0,200})", body):
            mapping, key, rhs = (m.group(1), m.group(2).strip(),
                                 m.group(3))
            if not _POS_MAP_RE.search(mapping):
                continue
            key_base = key.split("[")[0].strip()
            keyed_by_caller = ("msg.sender" in key or
                               key_base in params)
            if not keyed_by_caller:
                continue
            if not any(_mentions_outside_calls(rhs, p, defined)
                       for p in params):
                continue
            writes.append((mapping, key))
        if not writes:
            continue
        payout_fn = None
        payout_mapping = None
        for wfn in fns:
            if not _PAYOUT_FN_RE.match(wfn["name"]):
                continue
            wtext = wfn["text"]
            for mapping, _key in writes:
                if mapping in wtext and _moves_value(wtext):
                    payout_fn = wfn
                    payout_mapping = mapping
                    break
            if payout_fn is not None:
                break
        if payout_fn is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' writes the recorded "
            f"position '{writes[0][0]}[{writes[0][1]}]' from a "
            f"caller-supplied value (a parameter standing "
            f"outside any call, not a recompute from the "
            f"contract's own state), with no caller-identity "
            f"gate, and the downstream '{payout_fn['name']}' "
            f"pays out of that same '{payout_mapping}' record - "
            f"so a stranger inflates their own recorded "
            f"position and withdraws more than they deposited. "
            f"Gate analysis: no caller-identity gate, no "
            f"deposit-backing check on the sync path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated position sync: caller-supplied "
                    "value written to the recorded position, "
                    "withdraw pays the record")
        # The recipient is the key of the write the payout
        # reads: the credited entitlement IS the value the
        # stranger receives (classifying the downstream
        # withdraw's transfer would meter it by the very
        # record that is the fraud - the batch-26 swap
        # precedent). But if the payout itself lands at a
        # FIXED destination (a stored treasury), the stranger
        # receives nothing even though the record is
        # caller-writable - that is the trigger-only variant.
        state = cl.state_variables(scope.scoped_text)
        payout_recipient, _pr = cl.classify_recipient(
            payout_fn["text"])
        if payout_recipient == "FIXED":
            recipient, rdetail = ("FIXED",
                                  "the payout lands at a "
                                  "stored treasury address")
        else:
            recipient, rdetail = _dest_class(
                writes[0][1], params, state)
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 2. share_price_excludes_subthreshold_collateral
# ---------------------------------------------------------------------------

_VAL_FN_RE = re.compile(
    r"totalAssets|sharePrice|pricePerShare|convertToAssets|"
    r"getPrice|exchangeRate|shareValue|\bnav\b|totalValue", re.I)
_DEPOSIT_FN_RE = re.compile(r"^(?:deposit|mint)\w*$", re.I)
_REDEEM_FN_RE = re.compile(r"^(?:redeem|withdraw|exit)\w*$", re.I)
_THRESHOLD_RE = re.compile(
    r"\b(MIN\w*|THRESHOLD\w*|DUST\w*|MINIMUM\w*)\b")


def _balance_proxies(body: str) -> List[str]:
    """Locals assigned from a balanceOf read (e.g. `uint256
    actual = token.balanceOf(address(this))`) - a balance
    proxy, usable wherever a raw balanceOf read is."""
    out: List[str] = []
    for m in re.finditer(
            r"\b(?:uint256|uint)\s+([A-Za-z_][A-Za-z0-9_]*)\s*="
            r"\s*[^;]{0,120}?balanceOf\s*\(", body):
        out.append(m.group(1))
    return out


def _threshold_gated_leg(text: str, proxies: List[str]
                         ) -> Optional[Tuple[str, str]]:
    """(balance proxy, threshold) for a balance leg that is
    only added to a total under a nonzero-threshold
    comparison - `if (wethBal > MIN_WETH) total += ...` or
    the ternary equivalent. A `> 0` zero-guard is NOT a
    threshold: the compared value must be a named constant
    (MIN_*, THRESHOLD, DUST, MINIMUM_*) or a nonzero
    literal."""
    for proxy in proxies:
        pp = re.escape(proxy)
        # if-form: the condition compares the proxy against a
        # nonzero threshold, and the branch adds the proxy leg.
        for m in re.finditer(r"\bif\s*\(", text):
            i = text.index("(", m.start())
            cond, end = _balanced(text, i)
            if not re.search(r"\b" + pp +
                             r"\b\s*(?:>|>=)", cond):
                continue
            tm = re.search(r"\b" + pp +
                           r"\b\s*(?:>|>=)\s*"
                           r"([A-Za-z_][A-Za-z0-9_]*|"
                           r"0x[0-9a-fA-F]+|\d[\d_]*)", cond)
            if tm is None:
                continue
            threshold = tm.group(1)
            if threshold == "0":
                continue
            if (not _THRESHOLD_RE.search(threshold) and
                    not re.match(r"\d", threshold)):
                continue
            branch = text[end:end + 500]
            if _mentions(branch, proxy) and \
                    ("+=" in branch or "+" in branch):
                return proxy, threshold
        # ternary-form: `proxy > MIN ? proxy * price / 1e18 : 0`
        for m in re.finditer(
                r"\b" + pp + r"\b\s*(?:>|>=)\s*"
                r"([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|"
                r"\d[\d_]*)\s*\?", text):
            threshold = m.group(1)
            if threshold == "0":
                continue
            if (not _THRESHOLD_RE.search(threshold) and
                    not re.match(r"\d", threshold)):
                continue
            return proxy, threshold
    return None


def _analyze_share_price(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    if not any(_DEPOSIT_FN_RE.match(f["name"]) for f in fns):
        return []
    redeem = None
    for f in fns:
        if _REDEEM_FN_RE.match(f["name"]) and \
                _moves_value(f["text"]):
            redeem = f
            break
    if redeem is None:
        return []
    # The entry / exit legs must be stranger-reachable: if
    # every deposit / redeem leg is caller-gated, the
    # threshold exclusion is not reachable by a stranger.
    legs = [f for f in fns
            if _DEPOSIT_FN_RE.match(f["name"]) or
            _REDEEM_FN_RE.match(f["name"])]
    if legs and all(_skip_fn(f, scope) for f in legs):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _VAL_FN_RE.search(fn["name"]):
            continue
        text = fn["text"]
        proxies = _balance_proxies(text)
        if not proxies:
            continue
        gated = _threshold_gated_leg(text, proxies)
        if gated is None:
            continue
        proxy, threshold = gated
        detail = spec.detail + (
            f" Observed: '{fn['name']}' only adds the "
            f"'{proxy}' balance leg to the valuation when "
            f"'{proxy} > {threshold}' - below that threshold "
            f"the collateral is held by the vault but invisible "
            f"to the share price - while the contract has a "
            f"deposit leg and a value-moving redeem leg "
            f"('{redeem['name']}') reading that valuation, so "
            f"shares are bought cheap while the leg is excluded "
            f"and redeemed after the leg is converted into a "
            f"counted asset. Gate analysis: the valuation is a "
            f"view; the entry / exit legs carry no "
            f"caller-identity gate and no threshold-exclusion "
            f"guard.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "share valuation excludes a collateral leg "
                    "below a threshold; deposit + redeem read "
                    "that valuation")
        # Recipient classification for this class needs the
        # cross-function fact the generic classifier cannot
        # see: the payout leg meters the caller's own shares
        # (a HOLDER-SELF shape in isolation), but the payout
        # is priced off the threshold-excluded valuation
        # proven above, so the redeeming stranger receives
        # assets BEYOND their own deposit - the excess is
        # caller-received value taken from other depositors
        # (the vault_share_inflation precedent). A FIXED
        # payout destination stays trigger-only under the
        # receive rule.
        recipient, rdetail = cl.classify_recipient(
            redeem["text"])
        item["recipient"] = recipient
        if recipient == "FIXED":
            item["report_class"] = "trigger_only"
            item["severity"] = "low"
            item["detail"] += (
                f" Recipient analysis: the payout destination "
                f"is FIXED ({rdetail}), so a stranger can "
                f"trigger this but receives nothing - "
                f"classified TRIGGER-ONLY under the receive "
                f"rule.")
        else:
            item["report_class"] = "candidate"
            if recipient == "HOLDER-SELF":
                item["detail"] += (
                    " Recipient analysis: the payout leg meters "
                    "the caller's own shares (HOLDER-SELF "
                    "shape), but it is priced off the "
                    "threshold-excluded valuation above, so "
                    "the redeeming stranger receives assets "
                    "beyond their own deposit - the excess is "
                    "CALLER-received, classified CANDIDATE "
                    "under the receive rule.")
            else:
                item["detail"] += (
                    f" Recipient analysis: recipient classified "
                    f"{recipient} ({rdetail}) - a stranger can "
                    f"receive value here, classified CANDIDATE "
                    f"under the receive rule.")
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 3. voucher_redeem_recipient_unbound
# ---------------------------------------------------------------------------

_VOUCHER_FN_RE = re.compile(
    r"(?:redeem|claim|withdraw|collect)\w*(?:voucher|coupon|"
    r"ticket|reward|level|pass)|(?:voucher|coupon|ticket)"
    r"\w*(?:redeem|claim|withdraw)", re.I)
_SIG_CHECK_RE = re.compile(
    r"ecrecover\s*\(|ECDSA\s*\.\s*recover\s*\(|"
    r"isValidSignature\s*\(|Signature\s*\.\s*recover\s*\(")
_RECIPIENT_PARAM_RE = re.compile(
    r"^(?:recipient|beneficiary|to|account|user|claimer|"
    r"receiver|payee)$", re.I)


def _digest_args(text: str) -> Optional[str]:
    """The argument list of the first keccak256(...) in the
    text, or None."""
    m = re.search(r"keccak256\s*\(", text)
    if m is None:
        return None
    i = text.index("(", m.start())
    inner, _ = _balanced(text, i)
    return inner


def _has_consumed_marker(text: str, params: List[str]
                         ) -> bool:
    """A nonce / voucher id is marked consumed on this path:
    a used-mapping read AND write, or a claimed-flag set.
    (The replay class owns the no-nonce shape; this detector
    is the recipient-binding dimension, so a consumed marker
    must be present.)"""
    nonce_params = [p for p in params
                    if re.search(r"nonce|voucherId|couponId|"
                                 r"ticketId|voucher|coupon",
                                 p, re.I)]
    for p in nonce_params:
        pp = re.escape(p)
        if re.search(r"\b\w+\s*\[\s*" + pp + r"\s*\]", text) and \
                re.search(r"\b\w+\s*\[\s*" + pp +
                         r"\s*\]\s*=\s*true", text):
            return True
        if re.search(r"used\w*\s*\[\s*" + pp + r"\s*\]", text,
                     re.I) and \
                re.search(r"used\w*\s*\[\s*" + pp +
                         r"\s*\]\s*=\s*true", text, re.I):
            return True
    return False


def _analyze_voucher_recipient(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _VOUCHER_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _SIG_CHECK_RE.search(text):
            continue
        if not _moves_value(text):
            continue
        params = _fn_params(fn)
        typed = _fn_params_typed(fn)
        if not _has_consumed_marker(text, params):
            continue
        digest = _digest_args(text)
        if digest is None:
            continue
        # The redeemer is bound only if the signed payload
        # mentions msg.sender or a recipient-named parameter.
        bound = "msg.sender" in digest
        if not bound:
            for (t, n) in typed:
                if _RECIPIENT_PARAM_RE.match(n) and \
                        _mentions(digest, n):
                    bound = True
                    break
        if bound:
            continue
        # The signature must be compared against a stored
        # authority - a recovered signer that is never checked
        # authorizes nothing and belongs to the zero-signer /
        # unchecked-signature family, not this one.
        if not re.search(
                r"require\s*\([^;]{0,200}?signer\s*(==|!=)",
                text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a signature "
            f"over a payload that does not bind the redeemer "
            f"(no msg.sender and no recipient parameter in the "
            f"keccak256 digest), while the function does carry "
            f"a nonce / consumed marker - so the voucher is "
            f"replay-protected but not recipient-bound: any "
            f"stranger can present someone else's voucher and "
            f"be paid as the caller. Gate analysis: no "
            f"caller-identity gate, no recipient binding in "
            f"the signed payload.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated voucher redeem: signature verified "
                    "over a payload that never binds the "
                    "redeemer, payout to the caller")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. period_exit_writes_new_period_exposure_snapshot
# ---------------------------------------------------------------------------

_EXIT_FN_RE = re.compile(
    r"^(?:withdraw|exit|redeem|unstake|requestWithdraw)\w*$",
    re.I)
_EXPOSURE_MAP_RE = re.compile(
    r"\b(?:periodExposure|exposures?|periodSnapshot|"
    r"snapshots?|exposureSnapshot|coveredExposure|"
    r"periodCover)\b")
_CLAIM_FN_RE = re.compile(
    r"^(?:claim|payout|payClaim|settle|assess)\w*$", re.I)


def _analyze_period_exit_snapshot(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _EXIT_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        if not _moves_value(text):
            continue
        # The current period, derived from block.timestamp.
        period_var = None
        for m in re.finditer(
                r"\b(?:uint256|uint)\s+([A-Za-z_][A-Za-z0-9_]*)\s*="
                r"\s*[^;]{0,120}?block\.timestamp\s*/", body):
            period_var = m.group(1)
            break
        if period_var is None and \
                not re.search(r"currentPeriod", body):
            continue
        # A write of a period-keyed exposure/snapshot mapping
        # for the CURRENT period, inside the exit itself (not
        # a checkpoint push - that is the #88287/#89588
        # family, which this detector must not re-fire).
        written = None
        for m in re.finditer(
                r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\]]+)\s*\]\s*"
                r"(\+?=)(?!=)\s*([^;]{0,200})", body):
            mapping, key = m.group(1), m.group(2).strip()
            if not _EXPOSURE_MAP_RE.search(mapping):
                continue
            if period_var is not None and \
                    period_var not in key and \
                    "currentPeriod" not in key:
                continue
            if "push" in body[max(0, m.start() - 40):m.start()]:
                continue
            written = (mapping, key)
            break
        if written is None:
            continue
        # A claim / payout function must read the same
        # mapping - the snapshot the exit writes is the one
        # claims are sized from.
        claim_fn = None
        for cfn in fns:
            if not _CLAIM_FN_RE.match(cfn["name"]):
                continue
            if written[0] in cfn["text"]:
                claim_fn = cfn
                break
        if claim_fn is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' writes the "
            f"period-keyed exposure snapshot "
            f"'{written[0]}[{written[1]}]' for the CURRENT "
            f"period from inside the exit path (a write that "
            f"belongs to a deposit / snapshot-entry path, not "
            f"to an exit), and '{claim_fn['name']}' sizes "
            f"payouts from that same '{written[0]}' record - "
            f"so an exit mined at a period boundary rewrites "
            f"the exposure snapshot the claim reads, "
            f"short-paying it. Gate analysis: no "
            f"caller-identity gate; the exit is the writer, "
            f"the claim is the reader.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated exit writes the current period's "
                    "exposure snapshot; claim payouts read it")
        # No recipient classification (batch-20 auction
        # precedent): the exit pays the caller's own balance -
        # the stranger-receivable value is the short-paid /
        # mispriced claim the desync enables, not the exit.
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 5. withdraw_pays_other_account_balance
# ---------------------------------------------------------------------------

_WITHDRAW_OTHER_FN_RE = re.compile(
    r"^(?:withdraw|redeem|unstake|exit|release|unwrap)\w*$",
    re.I)
_VICTIM_PARAM_RE = re.compile(
    r"^(?:account|from|owner|holder|user|depositor|"
    r"staker|investor)$", re.I)
_BALANCE_MAP_RE = re.compile(
    r"\b(?:balances?|entitlements?|deposits?|stakes?|"
    r"shares?|positions?)\b")


def _analyze_withdraw_other(src, spec, compiler,
                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _WITHDRAW_OTHER_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        if not _moves_value(text):
            continue
        typed = _fn_params_typed(fn)
        victim_params = [n for (t, n) in typed
                         if t == "address" and
                         _VICTIM_PARAM_RE.match(n)]
        if not victim_params:
            continue
        searched = text + "\n" + _called_internal_texts(
            text, scope)
        for victim in victim_params:
            vp = re.escape(victim)
            # The caller must NOT be proven to be the victim:
            # no `msg.sender == victim` comparison and no
            # allowance check on the path.
            if re.search(r"msg\.sender\s*==\s*\b" + vp +
                         r"\b|\b" + vp +
                         r"\b\s*==\s*msg\.sender", searched):
                continue
            if re.search(r"allowance\s*\[\s*\b" + vp +
                         r"\b\s*\]\s*\[\s*msg\.sender\s*\]",
                         searched):
                continue
            if re.search(r"allowance\s*\(\s*\b" + vp +
                         r"\b\s*,\s*msg\.sender\s*\)", searched):
                continue
            # The victim's recorded balance is read, bounded
            # and debited by the payout.
            reads_victim = False
            debits_victim = False
            for m in re.finditer(
                    r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\b" + vp +
                    r"\b\s*\]", searched):
                if _BALANCE_MAP_RE.search(m.group(1)):
                    reads_victim = True
            if not reads_victim:
                continue
            if re.search(
                    r"\b(?:balances?|entitlements?|deposits?|"
                    r"stakes?|shares?|positions?)\s*\[\s*\b" +
                    vp + r"\b\s*\]\s*-=", searched):
                debits_victim = True
            if not debits_victim:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' reads and debits "
                f"the recorded balance of the address "
                f"parameter '{victim}' and transfers the "
                f"amount to the caller, with no check that "
                f"msg.sender is '{victim}' and no allowance "
                f"check anywhere on the path (not even in an "
                f"internal helper it calls) - so a stranger "
                f"withdraws another account's funds as their "
                f"own. Gate analysis: no caller-identity gate, "
                f"no victim-identity check, no allowance "
                f"check.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        "ungated withdraw: another account's "
                        "balance debited, payout to the caller, "
                        "no authorization check")
            out.append(_finish_recipient(spec, item, text))
            break
    return out


ANALYZERS = {
    "snapshot_position_sync_caller_writable": _analyze_snapshot_sync,
    "share_price_excludes_subthreshold_collateral":
        _analyze_share_price,
    "voucher_redeem_recipient_unbound": _analyze_voucher_recipient,
    "period_exit_writes_new_period_exposure_snapshot":
        _analyze_period_exit_snapshot,
    "withdraw_pays_other_account_balance": _analyze_withdraw_other,
}


def analyze_deep28_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-28 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep28_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit28Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 28)"
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
        for item in analyze_deep28_source(
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
                source="deep audit detector batch 28 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit28Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 28) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
