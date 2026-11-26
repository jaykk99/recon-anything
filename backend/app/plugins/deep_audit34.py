"""Deep-audit detectors, batch 34: a burn that skips the
liquidity decrement when both withdrawal amounts round to
zero, a mint/claim that burns tokens from a caller-supplied
address, a liquidation that burns the debt token in the
wrong units, an OFT _credit that subtracts from an
uninitialized unclamped accumulator, and a reward
distribution that overwrites duplicate array entries
instead of accumulating them.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- burn_zero_amount_skips_liquidity_decrement: a burn /
  removeLiquidity function that conditionally skips the
  liquidity decrement when both computed withdrawal amounts
  are zero (an `if (amount0 > 0 || amount1 > 0)` guard around
  the decrement, or an early return on both-zero after the
  position is burned), while still burning the position /
  removing the underlying liquidity - the Biswap V3 shape
  (BSC, Nov 24 2026, ~$51k): repeated burns strip the pool's
  real liquidity while phantom liquidity stays recorded, and
  a later swap extracts value against the phantom book.
  Liquidity decremented unconditionally is the protected
  shape. Distinct from zero_amount_withdrawal_full_balance
  (zero amount releases the FULL balance - this is the
  opposite direction: zero amounts skip the accounting
  decrement while the position is still removed) and from
  withdraw_rounding_drain (rounding DIRECTION on payout).
- burn_debits_caller_supplied_address: a mint / claim / buy
  function that calls token.burn(addressParam) /
  _burn(addressParam) / burnFrom(addressParam) where
  addressParam is a caller-supplied parameter (not
  msg.sender), while the minted / credited asset goes to
  msg.sender, with no allowance / approval check and no
  `param == msg.sender` check - the SantasList buyPresent
  shape (CodeHawks H-03): a stranger burns anyone's tokens
  and mints the present to themself. The debited address
  being msg.sender, or an allowance check existing, is the
  protected shape. Distinct from evm_caller_token_
  transferfrom (transferFrom with caller-supplied token +
  from + to - a transfer, not a burn).
- liquidation_burns_wrong_units_debt: a liquidation /
  finalizeLiquidation function that calls debtToken.burn
  (user, amount) where amount is computed by dividing by an
  index (liquidityIndex / rayDiv / normalized division) with
  no multiply-back before the burn, in the same path that
  seizes the borrower's collateral - the RAAC LendingPool
  finalizeLiquidation shape (CodeHawks #5709, High): the
  burn clears only part of the debt while the liquidation
  takes all the collateral, leaving permanent bad debt.
  A burn amount re-scaled by the index, or the raw scaled
  balance, is the protected shape. Distinct from
  liquidation_clears_collateral_keeps_debt (that one zeroes
  the debt but keeps the collateral - here the debt is NOT
  cleared because of the unit mismatch).
- oft_credit_unclamped_accumulator_underflow: an OFT
  _credit / _debit override doing accumulator -= amount
  (totalBridgedOut) with no initialization, no
  require(accumulator >= amount), and no clamp, in a
  contract with OFT / LayerZero markers - the Overlayer
  shape (HackenProof OVLRSCDD-180): the first credit on a
  peer chain underflows (panic 0x11) and every bridge
  transfer to that peer fails while the source burn already
  happened - funds LOCKED, not stranger-receivable; the
  finding says so honestly and is never sold as a drain. A
  clamp, an init, or a >= guard is the protected shape.
  Distinct from bridge_replay_unbound_digest (bridge digest
  binding, not an OFT _credit accumulator) and from
  merkle_proof_unbounded_leaf_index (leaf index bound, not
  an OFT accumulator).
- duplicate_array_entries_overwrite_rewards: a constructor /
  init function looping over parallel arrays and assigning
  mapping[key] = value with `=` (not `+=`), with no
  seen-set / duplicate check, in a reward / claim
  distribution context - the MyCut Pot constructor shape
  (CodeHawks H-03): a duplicate address silently overwrites
  earlier rewards, so funds for the overwritten entries are
  lost / mis-distributed. `+=`, or a duplicate check, is
  the protected shape. Distinct from masterchef_duplicate_
  pool_registration (pool registration dedupe, not a
  reward-mapping overwrite).

Gate discipline: these five are state-logic bugs, not
access-control bugs - a role gate does NOT suppress them
(the Biswap burn, the OFT credit, the duplicate-rewards
loop and the liquidation-unit mismatch are wrong in the
state logic itself; the burn-debit shape suppresses only
on the allowance / msg.sender checks named above). Only a
view / pure function is skipped (it cannot change state).

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
FAMILY = "deep34"

SPECS = [
    S("burn_zero_amount_skips_liquidity_decrement", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Burn skips the liquidity decrement when both "
             "withdrawal amounts are zero: a burn / "
             "removeLiquidity function conditionally skips the "
             "liquidity decrement when both computed withdrawal "
             "amounts are zero (an `if (amount0 > 0 || amount1 "
             "> 0)` guard around the decrement, or an early "
             "return on both-zero after the position is burned), "
             "while still burning the position / removing the "
             "underlying liquidity - the Biswap V3 shape: "
             "repeated burns strip the pool's real liquidity "
             "while phantom liquidity stays recorded, and a "
             "later swap extracts value against the phantom "
             "book. Liquidity decremented unconditionally is "
             "the protected shape.",
      fix="Decrement the position's liquidity unconditionally "
          "on every burn, before any zero-amount early return, "
          "and delete the position only after the decrement; "
          "add a test that burns a position whose amounts both "
          "round to zero and expects the recorded liquidity "
          "to fall to zero."),
    S("burn_debits_caller_supplied_address", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Mint / claim burns tokens from a caller-supplied "
             "address: a mint / claim / buy function calls "
             "token.burn(addressParam) / _burn(addressParam) / "
             "burnFrom(addressParam) where addressParam is a "
             "caller-supplied parameter (not msg.sender), while "
             "the minted / credited asset goes to msg.sender, "
             "with no allowance / approval check and no "
             "`param == msg.sender` check - the SantasList "
             "buyPresent shape: a stranger burns anyone's "
             "tokens and mints to themself. The debited address "
             "being msg.sender, or an allowance check existing, "
             "is the protected shape.",
      fix="Burn only from msg.sender (or from an address the "
          "caller has approved via allowance / burnFrom with "
          "an allowance check), and require the debited "
          "address to equal msg.sender when no allowance is "
          "involved."),
    S("liquidation_burns_wrong_units_debt", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Liquidation burns the debt token in the wrong "
             "units: a liquidation / finalizeLiquidation "
             "function calls debtToken.burn(user, amount) where "
             "amount is computed by dividing by an index "
             "(liquidityIndex / rayDiv / normalized division) "
             "with no multiply-back before the burn, in the "
             "same path that seizes the borrower's collateral - "
             "the RAAC LendingPool finalizeLiquidation shape: "
             "the burn clears only part of the debt while the "
             "liquidation takes all the collateral, leaving "
             "permanent bad debt. A burn amount re-scaled by "
             "the index, or the raw scaled balance, is the "
             "protected shape.",
      fix="Burn the debt in the token's own units: re-scale "
          "the normalized amount by the liquidity index "
          "(rayMul) before the burn, or burn the raw scaled "
          "balance directly, and assert after the burn that "
          "the borrower's scaled debt is zero."),
    S("oft_credit_unclamped_accumulator_underflow", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="OFT _credit subtracts from an uninitialized, "
             "unclamped accumulator: an OFT _credit / _debit "
             "override does accumulator -= amount "
             "(totalBridgedOut) with no initialization, no "
             "require(accumulator >= amount), and no clamp, in "
             "a contract with OFT / LayerZero markers - the "
             "Overlayer shape: the first credit on a peer "
             "chain underflows (panic 0x11) and every bridge "
             "transfer to that peer fails while the source "
             "burn already happened. This is a FUND-LOCKING "
             "class, not a stranger-receivable drain: the "
             "funds are stuck, not extractable. A clamp, an "
             "init, or a >= guard is the protected shape.",
      fix="Clamp the accumulator (subtract at most the "
          "accumulated amount, flooring at zero) or guard it "
          "with require(accumulator >= amount), and "
          "initialize the accumulator on the first credit "
          "for a peer; add a test that credits a fresh peer "
          "and expects no underflow."),
    S("duplicate_array_entries_overwrite_rewards", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Parallel-array reward assignment overwrites "
             "duplicates instead of accumulating: a "
             "constructor / init function loops over parallel "
             "arrays assigning mapping[key] = value with `=` "
             "(not `+=`), with no seen-set / duplicate check, "
             "in a reward / claim distribution context - the "
             "MyCut Pot constructor shape: a duplicate address "
             "silently overwrites earlier rewards, so funds "
             "for the overwritten entries are lost / "
             "mis-distributed. `+=`, or a duplicate check, is "
             "the protected shape. The array supplier is the "
             "actor here, so this is a fund-loss / "
             "mis-distribution class, weaker as a "
             "stranger-receivable case than a direct drain.",
      fix="Accumulate with `+=` instead of overwriting with "
          "`=`, or reject duplicate entries with a seen-set "
          "check in the loop, and add a test that passes a "
          "duplicate address and expects the rewards to sum."),
]
SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19 / deep25 / deep28)
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


def _balanced_brace(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the brace group at open_pos."""
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
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
    """Batch-34 gate discipline: these five are state-logic
    bugs, so a role / caller-identity gate does NOT suppress
    them. Only a view / pure function is skipped - it cannot
    change state."""
    return bool(re.search(r"\b(view|pure)\b", fn["signature"]))


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


def _mentions(text: str, param: str) -> bool:
    """A word-boundary mention of a parameter name, excluding
    the `value` inside `msg.value` (a parameter literally named
    `value` must not match the msg.value keyword)."""
    return bool(re.search(r"(?<!msg\.)\b" + re.escape(param) +
                          r"\b", text))


_VALUE_MOVE_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*transferFrom\s*\(|"
    r"safeTransfer\s*\(|safeTransferFrom\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\.\s*send\s*\(|\.\s*transfer\s*\{\s*value")


def _moves_value(text: str) -> bool:
    """A token / ETH payout of some kind in the function."""
    return bool(_VALUE_MOVE_RE.search(text))


# ---------------------------------------------------------------------------
# 1. burn_zero_amount_skips_liquidity_decrement
# ---------------------------------------------------------------------------

_BURN_FN_RE = re.compile(
    r"^(?:burn|removeLiquidity|burnPosition)\w*$", re.I)
_LIQ_DEC_RE = re.compile(
    r"(?:liquidity\s*-=|liquidity\s*=\s*liquidity\s*-|"
    r"positions?\s*\[[^\]]+\]\s*\.\s*liquidity\s*-=|"
    r"position\w*\.liquidity\s*-=|"
    r"decreaseLiquidity\s*\()")
_ZERO_GUARD_RE = re.compile(
    r"if\s*\(\s*amount0\s*>\s*0\s*\|\|\s*amount1\s*>\s*0\s*\)")
_BOTH_ZERO_RE = re.compile(
    r"if\s*\(\s*amount0\s*==\s*0\s*&&\s*amount1\s*==\s*0\s*\)")
_POSITION_REMOVE_RE = re.compile(
    r"_burn\s*\(|delete\s+positions?\b|delete\s+position\b")


def _analyze_burn_zero_skip(src, spec, compiler,
                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BURN_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        body = _fn_body(fn["text"])
        if not re.search(r"\bamount0\b", body) or \
                not re.search(r"\bamount1\b", body):
            continue
        # Shape A: `if (amount0 > 0 || amount1 > 0)` guards
        # the liquidity decrement, while the position is
        # removed outside the guard.
        fired = False
        for m in _ZERO_GUARD_RE.finditer(body):
            brace = body.find("{", m.end())
            if brace < 0:
                continue
            gbody, gend = _balanced_brace(body, brace)
            if not _LIQ_DEC_RE.search(gbody):
                continue
            outside = body[:m.start()] + body[gend + 1:]
            # The decrement must NOT also happen
            # unconditionally outside the guard.
            if _LIQ_DEC_RE.search(outside):
                continue
            if not _POSITION_REMOVE_RE.search(outside):
                continue
            fired = True
            break
        # Shape B: the position is burned first, then an
        # early return on both-zero skips the decrement
        # that sits after the guard.
        if not fired:
            for m in _BOTH_ZERO_RE.finditer(body):
                brace = body.find("{", m.end())
                if brace < 0:
                    continue
                gbody, gend = _balanced_brace(body, brace)
                if not re.search(r"\breturn\b|\bcontinue\b",
                                 gbody):
                    continue
                before = body[:m.start()]
                after = body[gend + 1:]
                if not _POSITION_REMOVE_RE.search(before):
                    continue
                if not _LIQ_DEC_RE.search(after):
                    continue
                # No unconditional decrement before the guard
                # either (the burn already happened).
                if _LIQ_DEC_RE.search(before):
                    continue
                fired = True
                break
        if not fired:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' conditionally skips "
            f"the liquidity decrement when both computed "
            f"withdrawal amounts are zero, while still "
            f"burning / removing the position - so repeated "
            f"burns strip the pool's real liquidity while "
            f"phantom liquidity stays recorded. Gate "
            f"analysis: no view / pure restriction; the "
            f"decrement is skipped by the zero-amount logic "
            f"itself, not by any access gate.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "burn skips the liquidity decrement on "
                    "zero amounts; the position is still removed")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 2. burn_debits_caller_supplied_address
# ---------------------------------------------------------------------------

_MINTBUY_FN_RE = re.compile(
    r"^(?:mint|claim|buy|purchase|redeem)\w*$", re.I)
_BURN_CALL_RE = re.compile(
    r"(?:\.burn\s*\(|\.burnFrom\s*\(|\bburnFrom\s*\(|"
    r"\b_burn\s*\()\s*([A-Za-z_][A-Za-z0-9_]*)")
# The minted / credited asset goes to SOME address - msg.sender
# in the vulnerable shape, a fixed address in the variant.
# Recipient classification (not this regex) decides whether the
# stranger receives it.
_CREDIT_RE = re.compile(
    r"(?:_mint|_safeMint)\s*\(\s*(?:msg\.sender|"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*,|"
    r"\.transfer\s*\(\s*(?:msg\.sender|"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*,|"
    r"balances\s*\[\s*(?:msg\.sender|"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*\]\s*\+=")
_ALLOWANCE_RE = re.compile(r"allowance\s*\(")


def _analyze_burn_debits_caller(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _MINTBUY_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        body = _fn_body(fn["text"])
        typed = _fn_params_typed(fn)
        addr_params = [n for (t, n) in typed if t == "address"]
        if not addr_params:
            continue
        # The minted / credited asset goes to some address.
        if not _CREDIT_RE.search(body):
            continue
        # An allowance / approval check is the protected
        # shape: the caller may only burn what they are
        # approved to spend.
        if _ALLOWANCE_RE.search(body):
            continue
        for param in addr_params:
            debited = None
            for bm in _BURN_CALL_RE.finditer(body):
                if bm.group(1) == param:
                    debited = bm.group(0)
                    break
            if debited is None:
                continue
            # `param == msg.sender` on the path is the
            # protected shape: the debit is the caller's own.
            if re.search(
                    r"\b" + re.escape(param) +
                    r"\s*==\s*msg\.sender|msg\.sender\s*==\s*" +
                    re.escape(param) + r"\b", body):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' burns tokens from "
                f"the caller-supplied address '{param}' "
                f"({debited.strip()}) while minting / crediting "
                f"the asset to msg.sender, with no allowance / "
                f"approval check and no '{param} == msg.sender' "
                f"check - so a stranger burns anyone's tokens "
                f"and mints to themself. Gate analysis: the "
                f"debit is not gated on the debited address "
                f"being the caller or an approved spender.")
            item = _hit(spec, fn["name"],
                        cc._snip(fn["text"]), detail,
                        "ungated burn of a caller-supplied "
                        "address in a mint / claim / buy path")
            out.append(_finish_recipient(spec, item, fn["text"]))
            break
    return out


# ---------------------------------------------------------------------------
# 3. liquidation_burns_wrong_units_debt
# ---------------------------------------------------------------------------

_LIQUIDATE_FN_RE = re.compile(
    r"^(?:liquidate|finalizeLiquidation|liquidation)\w*$",
    re.I)
_BURN_DEBT_RE = re.compile(
    r"(?:\.burn\s*\(|\b_burn\s*\()\s*([^,]+),\s*([^)]+)\)")
_SEIZURE_RE = re.compile(
    r"collateral\w*\s*\.\s*(?:safeTransfer|transfer)\s*\(|"
    r"\bseize\w*\s*\(")


def _analyze_liquidation_wrong_units(src, spec, compiler,
                                     contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _LIQUIDATE_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        body = _fn_body(fn["text"])
        # The path seizes the borrower's collateral.
        if not _SEIZURE_RE.search(body):
            continue
        # A local computed by dividing by an index
        # (liquidityIndex / rayDiv / normalized division).
        divided: List[Tuple[str, str]] = []
        for m in re.finditer(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]{0,200})",
                body):
            var, rhs = m.group(1), m.group(2)
            idx = re.search(
                r"/\s*([A-Za-z_][A-Za-z0-9_]*)", rhs)
            if idx and re.search(r"index", idx.group(1), re.I):
                divided.append((var, idx.group(1)))
                continue
            if re.search(r"\brayDiv\s*\(", rhs):
                divided.append((var, "rayDiv"))
                continue
            if re.search(r"\.\s*rayDiv\s*\(", rhs):
                divided.append((var, "rayDiv"))
        if not divided:
            continue
        for bm in _BURN_DEBT_RE.finditer(body):
            amount = bm.group(2).strip()
            # The burn amount must be exactly the divided
            # local - a re-scaled amount (var * index,
            # rayMul(var, index)) or the raw scaled balance
            # is the protected shape.
            hit_var = None
            for var, _idx in divided:
                if amount == var:
                    hit_var = var
                    break
            if hit_var is None:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' burns the debt "
                f"token for '{bm.group(1).strip()}' with "
                f"amount '{hit_var}' - computed by dividing by "
                f"an index with no multiply-back before the "
                f"burn - while seizing the borrower's "
                f"collateral in the same path, so the burn "
                f"clears only part of the debt while the "
                f"liquidation takes all the collateral, "
                f"leaving permanent bad debt. Gate analysis: "
                f"the unit mismatch is in the liquidation "
                f"logic itself, not in any access gate.")
            item = _hit(spec, fn["name"],
                        cc._snip(fn["text"]), detail,
                        "liquidation burns the debt token in "
                        "normalized units with no re-scaling; "
                        "collateral seized in the same path")
            out.append(_finish_recipient(spec, item, fn["text"]))
            break
    return out


# ---------------------------------------------------------------------------
# 4. oft_credit_unclamped_accumulator_underflow
# ---------------------------------------------------------------------------

_CREDIT_FN_RE = re.compile(r"^_?(credit|debit)$", re.I)
_OFT_MARKER_RE = re.compile(
    r"\bOFT\b|LayerZero|lzReceive", re.I)


def _analyze_oft_credit_underflow(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # The contract must carry OFT / LayerZero markers.
    if not _OFT_MARKER_RE.search(scope.scoped_text):
        return []
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CREDIT_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        body = _fn_body(fn["text"])
        params = _fn_params(fn)
        if not params:
            continue
        for acc in state:
            a = re.escape(acc)
            # accumulator -= amount, or accumulator =
            # accumulator - amount, where amount is a
            # function parameter.
            dec = None
            for m in re.finditer(
                    r"\b" + a + r"\s*-=\s*"
                    r"([A-Za-z_][A-Za-z0-9_]*)", body):
                if m.group(1) in params:
                    dec = (m.group(1), m.group(0))
                    break
            if dec is None:
                for m in re.finditer(
                        r"\b" + a + r"\s*=\s*\b" + a +
                        r"\s*-\s*([A-Za-z_][A-Za-z0-9_]*)",
                        body):
                    if m.group(1) in params:
                        dec = (m.group(1), m.group(0))
                        break
            if dec is None:
                continue
            amount = dec[0]
            # Protected shapes: a >= guard, a clamp, or an
            # init on first use.
            if re.search(
                    r"require\s*\(\s*\b" + a + r"\b\s*>=|"
                    r"require\s*\(\s*\b" + re.escape(amount) +
                    r"\b\s*<=\s*\b" + a + r"\b|"
                    r"if\s*\(\s*\b" + a + r"\b\s*<\s*\b" +
                    re.escape(amount) + r"\b", body):
                continue
            if re.search(
                    r"\b" + a + r"\b\s*=\s*\b" + a +
                    r"\b\s*>=\s*\b" + re.escape(amount) +
                    r"\b\s*\?|"
                    r"\bmin\s*\(\s*\b" + a + r"\b", body):
                continue
            if re.search(
                    r"if\s*\(\s*\b" + a + r"\b\s*==\s*0\s*\)",
                    body):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' does "
                f"'{dec[1].strip()}' - subtracting the "
                f"credited amount from the accumulator "
                f"'{acc}' with no initialization, no "
                f"require({acc} >= {amount}), and no clamp - "
                f"so the first credit on a peer chain "
                f"underflows (panic 0x11) and every bridge "
                f"transfer to that peer fails while the "
                f"source burn already happened. This is "
                f"FUND-LOCKING, not a stranger-receivable "
                f"drain: the funds are stuck, not "
                f"extractable. Gate analysis: the underflow "
                f"is in the _credit logic itself, not in any "
                f"access gate.")
            item = _hit(spec, fn["name"],
                        cc._snip(fn["text"]), detail,
                        "OFT _credit subtracts from an "
                        "uninitialized, unclamped accumulator")
            out.append(_finish_recipient(spec, item, fn["text"]))
            break
    return out


# ---------------------------------------------------------------------------
# 5. duplicate_array_entries_overwrite_rewards
# ---------------------------------------------------------------------------

_INIT_FN_RE = re.compile(
    r"^(?:constructor|init\w*|initialize\w*|setup\w*)$", re.I)
_REWARD_CTX_RE = re.compile(
    r"reward|claim|allocat|distribut|prize|payout", re.I)
_PAYOUT_FN_RE = re.compile(
    r"^(?:claim|withdraw|redeem|distribute|collect)\w*$", re.I)


def _for_loops(body: str):
    """(loop_var, loop_body) for every `for` loop in body."""
    out = []
    for m in re.finditer(r"\bfor\s*\(", body):
        open_paren = m.end() - 1
        inner, pend = _balanced(body, open_paren)
        vm = re.search(
            r"(?:uint\d*|uint|int\d*|int)\s+"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=", inner)
        if vm is None:
            vm = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=",
                           inner)
        if vm is None:
            continue
        brace = body.find("{", pend + 1)
        if brace < 0:
            continue
        lbody, _ = _balanced_brace(body, brace)
        out.append((vm.group(1), lbody))
    return out


def _analyze_duplicate_rewards(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _INIT_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        body = _fn_body(fn["text"])
        for loop_var, lbody in _for_loops(body):
            if ".length" not in body:
                continue
            # A mapping assignment mapping[key[i]] = value[i]
            # with plain `=` (not `+=`). The key may itself
            # contain one level of brackets (players[i]), so
            # the key pattern allows an indexed sub-expression.
            for m in re.finditer(
                    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*"
                    r"((?:[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]*\]|"
                    r"[^]]+?))\s*\]\s*=(?![=>])\s*"
                    r"([^;]+)", lbody):
                map_name, key, value = (m.group(1),
                                        m.group(2), m.group(3))
                if map_name not in state:
                    continue
                if "[" + loop_var + "]" not in key.replace(
                        " ", ""):
                    continue
                if "[" + loop_var + "]" not in value.replace(
                        " ", ""):
                    continue
                # Reward / claim distribution context: the
                # mapping name says so, or a payout function
                # reads the same mapping.
                payout_fn = None
                for other in fns:
                    if other is fn:
                        continue
                    if _PAYOUT_FN_RE.match(other["name"]) and \
                            re.search(r"\b" + re.escape(map_name) +
                                      r"\b", other["text"]):
                        payout_fn = other
                        break
                if not _REWARD_CTX_RE.search(map_name) and \
                        payout_fn is None:
                    continue
                # Protected shapes: `+=` for the same mapping
                # in the loop, or a duplicate check.
                if re.search(
                        r"\b" + re.escape(map_name) +
                        r"\s*\[[^\]]+\]\s*\+=", lbody):
                    continue
                if re.search(r"\bseen\s*\[", lbody) or \
                        re.search(
                            r"require\s*\(\s*!" +
                            r"\s*seen\s*\[", lbody) or \
                        re.search(
                            r"require\s*\(\s*\b" +
                            re.escape(map_name) +
                            r"\s*\[[^\]]+\]\s*==\s*0\s*\)",
                            lbody):
                    continue
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' loops over "
                    f"parallel arrays assigning "
                    f"'{map_name}[{key.strip()}] = "
                    f"{value.strip()}' with `=` (not `+=`) and "
                    f"no seen-set / duplicate check, in a "
                    f"reward / claim distribution context - so "
                    f"a duplicate address silently overwrites "
                    f"earlier rewards and the funds for the "
                    f"overwritten entries are lost / "
                    f"mis-distributed. Gate analysis: the "
                    f"overwrite is in the distribution logic "
                    f"itself, not in any access gate.")
                item = _hit(spec, fn["name"],
                            cc._snip(fn["text"]), detail,
                            "constructor / init overwrites "
                            "duplicate reward entries with `=`; "
                            "no duplicate check")
                # Recipient: the payout function that pays
                # out of this mapping is the value path.
                if payout_fn is not None:
                    out.append(_finish_recipient(
                        spec, item, payout_fn["text"]))
                else:
                    out.append(_finish_recipient(
                        spec, item, fn["text"]))
                break
    return out


ANALYZERS = {
    "burn_zero_amount_skips_liquidity_decrement":
        _analyze_burn_zero_skip,
    "burn_debits_caller_supplied_address":
        _analyze_burn_debits_caller,
    "liquidation_burns_wrong_units_debt":
        _analyze_liquidation_wrong_units,
    "oft_credit_unclamped_accumulator_underflow":
        _analyze_oft_credit_underflow,
    "duplicate_array_entries_overwrite_rewards":
        _analyze_duplicate_rewards,
}


def analyze_deep34_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-34 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep34_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit34Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 33)"
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
        for item in analyze_deep34_source(
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
                source="deep audit detector batch 34 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit34Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 34) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
