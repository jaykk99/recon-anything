"""Deep-audit detectors, batch 15: AI plugin dev (2026-11-11).

Five more chain-agnostic EVM detectors from fresh 2026 research,
built to the batch-15 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- unsafe_narrowing_cast_collateral_zero: a raw narrowing cast
  uint128(x) / uint64(x) / int128(x) applied to an int256 /
  uint256 balance, liability or .abs() value that feeds a
  free-collateral / borrow / solvency check (freeCollateral >= 0
  gate), with no SafeCast / bounds check on that path, so a
  liability of exactly 2^128 truncates to 0 and the position
  looks solvent. The Notional Finance V1 escrow shape, 3-4 Sep
  2026 (~$1.73M). SafeCast.toUint128, or an explicit
  require(value <= type(uint128).max) before the cast, stays
  silent; a cast used only for display / events stays silent.
- negative_fee_mint_inflation: a bridge / deposit credit
  computed as credited = deposit - fee where fee is a signed
  int256 (settable below zero), AND a setter (setMinFee / setFee)
  callable by an admin / relayer role with no >= 0 check, so a
  negative fee mints unbacked wrapped tokens. The Symbiosis
  Bitcoin Bridge shape, 11 Sep 2026 (~$770k real loss: 330
  satoshi deposited, ~46.1B unbacked syBTC minted). A uint256
  fee, a signed fee with require(fee >= 0) in the setter and in
  the credit math, or a credit clamped to <= deposit, stays
  silent.
- scaled_allowance_overapproval: transferFrom (or
  _spendAllowance) checks the allowance against a scaled-down
  amount (amount.rayDiv(liquidityIndex) / amount / index, scale
  < 1 and growing) while approve() records the allowance in
  underlying / unscaled units, so the spender can move more
  underlying than the owner approved. The CodeHawks / Cyfrin
  RAAC contest shape ("Scaled Allowance Mismatch Enables
  Over-Approval Exploit", High). Approve and transferFrom in
  the same unit, an allowance check on the raw amount before
  scaling, or a fixed index of 1e27 / 1, stays silent.
- claim_callback_before_claimed_flag: a claim() that lets a
  group creator name an arbitrary lockup / callback contract per
  claim group (stored, attacker-suppliable), calls that contract
  (e.g. to mint a locked / ve position) BEFORE setting
  claimed = true / updating per-group holdings, and has no
  nonReentrant on that path, so the callback re-enters claim()
  and drains unclaimed allocations. The Hemi Genesis Drop
  (MerkleBox) shape, 7 Sep 2026 (~124.5M unclaimed HEMI,
  ~$255k). Updating the claimed flag / holdings before any
  external call, restricting the callback to a stored allowlist
  of known lockup contracts, or nonReentrant on claim, stays
  silent.
- post_slash_erc4626_offset_inversion: an ERC-4626 vault using
  virtual-offset conversion (shares = assets * (totalSupply + 1)
  / (totalAssets + 1), or OZ _decimalsOffset) AND a slash /
  payout path that reduces totalAssets without burning shares,
  making totalAssets == 0 && totalSupply > 0 reachable, with
  deposit() still open afterwards, so a 1-wei deposit mints an
  outsized share of the vault. Immunefi Audit Comp Firelight
  report #88330 (Medium, 12 Aug 2026). Distinct from built
  vault_share_inflation (first-depositor / donation inflation
  from an EMPTY vault - this is the opposite direction: the
  offset defence itself inverts after a designed slash). A slash
  that burns shares pro-rata, a vault that pauses / reverts
  deposits when totalAssets == 0 && totalSupply > 0, or a
  conversion using a fixed minimum-supply floor independent of
  the slash, stays silent.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. The mechanism
under analysis itself does NOT count as such a gate.

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
FAMILY = "deep15"

SPECS = [
    S("unsafe_narrowing_cast_collateral_zero", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Unsafe narrowing cast zeroes collateral: a raw "
             "narrowing cast uint128(x) / uint64(x) / int128(x) "
             "applied to an int256 / uint256 balance, liability "
             "or .abs() value feeds a free-collateral / borrow / "
             "solvency check (freeCollateral >= 0 gate) with no "
             "SafeCast / bounds check on that path, so a "
             "liability of exactly 2^128 truncates to 0 and the "
             "position looks solvent - the Notional Finance V1 "
             "escrow shape. SafeCast.toUint128, or an explicit "
             "require(value <= type(uint128).max) before the "
             "cast, is the protected shape.",
      fix="Cast through SafeCast.toUint128 / toUint64 (reverts "
          "on overflow) or require the value fits in the "
          "target type before the cast, and never feed a "
          "narrowed value into a solvency check."),
    S("negative_fee_mint_inflation", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Negative fee mints unbacked wrapped tokens: a "
             "bridge / deposit credit is computed as credited = "
             "deposit - fee where fee is a signed int256 "
             "settable below zero, and a setter (setMinFee / "
             "setFee) callable by an admin / relayer role has "
             "no >= 0 check, so a negative fee mints unbacked "
             "tokens - the Symbiosis Bitcoin Bridge shape. A "
             "uint256 fee, a signed fee with require(fee >= 0) "
             "in the setter and in the credit math, or a credit "
             "clamped to <= deposit, is the protected shape.",
      fix="Type the fee uint256, or require(fee >= 0) in every "
          "setter and in the credit math, and clamp the "
          "credited amount to at most the deposit."),
    S("scaled_allowance_overapproval", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Scaled allowance over-approval: transferFrom (or "
             "_spendAllowance) checks the allowance against a "
             "scaled-down amount (amount.rayDiv(liquidityIndex) "
             "/ amount / index, scale < 1 and growing) while "
             "approve() records the allowance in underlying / "
             "unscaled units, so the spender moves more "
             "underlying than the owner approved - the RAAC "
             "contest shape. Approve and transferFrom in the "
             "same unit, an allowance check on the raw amount "
             "before scaling, or a fixed index of 1e27 / 1, is "
             "the protected shape.",
      fix="Record and check the allowance in one unit only - "
          "scale in approve() exactly as transferFrom scales, "
          "or check the allowance against the raw amount "
          "before any scaling."),
    S("claim_callback_before_claimed_flag", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Claim callback before claimed flag: a claim() "
             "lets a group creator name an arbitrary lockup / "
             "callback contract per claim group (stored, "
             "attacker-suppliable), calls that contract (e.g. "
             "to mint a locked / ve position) BEFORE setting "
             "claimed = true / updating per-group holdings, and "
             "has no nonReentrant on that path, so the callback "
             "re-enters claim() and drains unclaimed "
             "allocations - the Hemi Genesis Drop (MerkleBox) "
             "shape. Updating the claimed flag / holdings "
             "before any external call, restricting the "
             "callback to a stored allowlist of known lockup "
             "contracts, or nonReentrant on claim, is the "
             "protected shape.",
      fix="Set claimed = true and update per-group holdings "
          "before any external call (checks-effects-"
          "interactions), restrict callbacks to a stored "
          "allowlist of known lockup contracts, and add "
          "nonReentrant to claim()."),
    S("post_slash_erc4626_offset_inversion", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Post-slash ERC-4626 offset inversion: a vault "
             "uses virtual-offset conversion (shares = assets "
             "* (totalSupply + 1) / (totalAssets + 1), or OZ "
             "_decimalsOffset) AND a slash / payout path "
             "reduces totalAssets without burning shares, "
             "making totalAssets == 0 && totalSupply > 0 "
             "reachable, with deposit() still open afterwards, "
             "so a 1-wei deposit mints an outsized share of "
             "the vault - Firelight report #88330. Distinct "
             "from first-depositor inflation: the offset "
             "defence itself inverts after a designed slash. "
             "A slash that burns shares pro-rata, or deposits "
             "that pause / revert when totalAssets == 0 && "
             "totalSupply > 0, is the protected shape.",
      fix="Burn shares pro-rata on every slash so totalSupply "
          "tracks totalAssets, and make deposit() revert (or "
          "pause the vault) whenever totalAssets == 0 while "
          "totalSupply > 0."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 3)
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
# 1. Unsafe narrowing cast zeroes collateral (Notional V1 shape)
# ---------------------------------------------------------------------------

_NARROW_CAST_RE = re.compile(
    r"\b(?:uint128|uint64|int128|uint96|uint32)\s*\(\s*([^)]{1,120})\)")
_NARROW_SAFE_RE = re.compile(
    r"SafeCast\s*\.\s*to(?:Uint128|Uint64|Int128|Uint96|Uint32)\b")
_NARROW_MAX_RE = re.compile(
    r"require\s*\([^;]{0,120}type\s*\(\s*(?:uint128|uint64|int128|"
    r"uint96|uint32)\s*\)\s*\.max")
_BAL_ARG_RE = re.compile(
    r"balance|liabilit|debt|collateral|borrow|\.abs\s*\(", re.I)
_SOLVENCY_GATE_RE = re.compile(
    r"(?:freeCollateral|healthFactor|isSolvent)\s*>=\s*0")


def _analyze_narrowing_cast(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Suppressors anywhere in scope: a SafeCast conversion, or
    # an explicit require(value <= type(uint128).max) before a
    # cast, is the protected shape.
    if _NARROW_SAFE_RE.search(scoped) or _NARROW_MAX_RE.search(scoped):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        cast = None
        for m in _NARROW_CAST_RE.finditer(text):
            if _BAL_ARG_RE.search(m.group(1)):
                cast = m
                break
        if cast is None:
            continue
        # The narrowed value must feed a solvency gate AFTER
        # the cast in the same function (freeCollateral >= 0).
        gate = _SOLVENCY_GATE_RE.search(text, cast.start())
        if not gate:
            continue
        # Value actually leaves: a transfer / mint after the
        # cast. A cast used only for display / events has no
        # payout after it and stays silent.
        if not [c for c in cl._external_calls(text)
                if c["pos"] > cast.start()]:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' applies a raw narrowing "
            f"cast to '{cast.group(1).strip()}' and the narrowed "
            f"value feeds a solvency gate "
            f"('{text[gate.start():gate.end()]}') with no "
            f"SafeCast or bounds check on that path, so a "
            f"liability of exactly 2^128 truncates to 0 and the "
            f"position looks solvent while value leaves the "
            f"contract. Gate analysis: no caller-identity gate, "
            f"no SafeCast, no require(value <= "
            f"type(uint128).max).")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated borrow: raw narrowing cast on a "
                    "balance / liability feeds a free-collateral "
                    ">= 0 gate, no SafeCast or bounds check")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. Negative fee mint inflation (Symbiosis bridge shape)
# ---------------------------------------------------------------------------

_SIGNED_FEE_RE = re.compile(
    r"\bint256\s+(?:public\s+|private\s+|internal\s+)?"
    r"([A-Za-z_]*[Ff]ee[A-Za-z_]*)\b")
_SETTER_FN_RE = re.compile(
    r"^(setFee|setMinFee|setBridgeFee|setDepositFee|updateFee)$",
    re.I)
_CREDIT_FN_RE = re.compile(
    r"^(deposit|bridge|mint|wrap|lock|depositAndMint|"
    r"depositBTC|bridgeDeposit)$", re.I)
_FEE_NONNEG_RE = re.compile(r">=\s*0|< 0")
_CLAMP_RE = re.compile(
    r"require\s*\([^;]{0,120}?\b(?:credited|mintAmount|credit)\b"
    r"[^;]{0,60}?<=|"
    r"if\s*\(\s*(?:credited|mintAmount|credit)\s*>")
_MINT_CALL_RE = re.compile(r"\b(?:_mint|mint|transfer)\s*\(")


def _fee_base(name: str) -> str:
    return name.lstrip("_").lower()


def _analyze_negative_fee(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Leg 1: a signed fee (int256) that a setter can push
    # below zero. A uint256 fee can never go negative.
    fee_names = {_fee_base(m.group(1))
                 for m in _SIGNED_FEE_RE.finditer(scoped)}
    for fn in fns:
        for m in _SIGNED_FEE_RE.finditer(fn["signature"]):
            fee_names.add(_fee_base(m.group(1)))
    if not fee_names:
        return []
    # Leg 2: at least one fee setter with NO >= 0 check (and
    # no < 0 revert) on the fee it writes.
    unguarded_setter = None
    setter_found = False
    for fn in fns:
        if not _SETTER_FN_RE.match(fn["name"]):
            continue
        setter_found = True
        if not _FEE_NONNEG_RE.search(fn["text"]):
            unguarded_setter = fn["name"]
            break
    if not setter_found or unguarded_setter is None:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CREDIT_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 3: the credit subtracts the signed fee
        # (credited = deposit - fee).
        fee_used = None
        for fname in sorted(fee_names):
            if re.search(r"-\s*" + re.escape(fname) + r"\b",
                         text, re.I) or \
                    re.search(r"-\s*_" + re.escape(fname) + r"\b",
                              text, re.I):
                fee_used = fname
                break
        if fee_used is None:
            continue
        # The credit math itself must not re-check the fee.
        if _FEE_NONNEG_RE.search(text):
            continue
        # A credit clamped to <= deposit is the protected
        # shape.
        if _CLAMP_RE.search(text):
            continue
        if not _MINT_CALL_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' credits deposit minus "
            f"a signed int256 fee ('{fee_used}'), and setter "
            f"'{unguarded_setter}' can push that fee below zero "
            f"with no >= 0 check, so a negative fee mints "
            f"unbacked wrapped tokens. Gate analysis: the "
            f"deposit path is ungated, the setter has no "
            f">= 0 check, and the credit is not clamped to the "
            f"deposit.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated deposit: credited = deposit - "
                    "signed int256 fee, setter has no >= 0 "
                    "check, credit not clamped to deposit")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. Scaled allowance over-approval (RAAC contest shape)
# ---------------------------------------------------------------------------

_SCALED_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*[^;]{0,100}?"
    r"(?:\.rayDiv\s*\(\s*([A-Za-z_][\w.]*)\s*\)|"
    r"/\s*([A-Za-z_]\w*[Ii]ndex\w*))")
_ALLOWANCE_RAW_RE = re.compile(
    r"allowance\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=\s*amount\s*;")
_ALLOWANCE_CMP_RE = re.compile(
    r"allowance\s*\[[^\]]+\]\s*\[[^\]]+\]\s*(?:>=|<)\s*"
    r"([A-Za-z_]\w*)")
_SPEND_ALLOW_RE = re.compile(
    r"_spendAllowance\s*\([^)]*\)")
_CONST_1E27_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*1e27\b")


def _analyze_scaled_allowance(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Leg 1: approve() records the allowance in underlying /
    # unscaled units (raw `= amount;`).
    approve_raw = False
    for fn in fns:
        if fn["name"] == "approve" and \
                _ALLOWANCE_RAW_RE.search(fn["text"]):
            approve_raw = True
            break
    if not approve_raw:
        return []
    # Constants fixed at 1e27 (the identity index) make the
    # scaling a no-op and are the protected shape.
    consts_1e27 = {m.group(1)
                   for m in _CONST_1E27_RE.finditer(scoped)}
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] not in ("transferFrom", "_spendAllowance"):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 2: a scaled-down amount (rayDiv / divide by the
        # liquidity index) computed in this function.
        scaled = None
        divisor = None
        for m in _SCALED_ASSIGN_RE.finditer(text):
            scaled = m.group(1)
            divisor = m.group(2) or m.group(3)
            break
        if scaled is None:
            continue
        if divisor == "1e27" or divisor in consts_1e27:
            continue
        # Leg 3: the allowance is checked against the SCALED
        # amount (not the raw amount).
        checked = False
        for m in _ALLOWANCE_CMP_RE.finditer(text):
            if m.group(1) == scaled:
                checked = True
                break
        if not checked:
            for m in _SPEND_ALLOW_RE.finditer(text):
                if re.search(r"\b" + re.escape(scaled) + r"\b",
                             m.group(0)):
                    checked = True
                    break
        if not checked:
            continue
        detail = spec.detail + (
            f" Observed: 'approve' records the allowance in "
            f"underlying units ('= amount;') while "
            f"'{fn['name']}' checks it against a scaled-down "
            f"amount ('{scaled}' = amount scaled by "
            f"'{divisor}'), so the spender can move more "
            f"underlying than the owner approved. Gate "
            f"analysis: no caller-identity gate, approve and "
            f"transferFrom use different units, the index is "
            f"not fixed at 1e27.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated transferFrom: allowance checked "
                    "against a scaled-down amount while approve "
                    "records underlying units")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. Claim callback before claimed flag (Hemi MerkleBox shape)
# ---------------------------------------------------------------------------

_LOCKUP_MAP_RE = re.compile(
    r"mapping\s*\(\s*(?:uint256|uint|bytes32)\s*=>\s*address\s*\)"
    r"\s*(?:public\s+|private\s+|internal\s+)?"
    r"([A-Za-z_]\w*)")
_CLAIM_FN_RE = re.compile(r"^claim", re.I)
_ALLOWLIST_RE = re.compile(r"[Aa]llowlist")
_NONREENTRANT_RE = re.compile(r"\bnonReentrant\b")


def _analyze_claim_callback(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Leg 1: a per-group lockup / callback address, stored from
    # a caller-supplied address parameter (a group creator
    # names an arbitrary contract per claim group).
    lockup_vars = set()
    for m in _LOCKUP_MAP_RE.finditer(scoped):
        name = m.group(1)
        if re.search(r"lockup|callback", name, re.I):
            lockup_vars.add(name)
    if not lockup_vars:
        return []
    supplied = False
    for fn in fns:
        params = _fn_params(fn)
        for var in sorted(lockup_vars):
            if re.search(
                    r"\b" + re.escape(var) +
                    r"\s*\[[^\]]+\]\s*=\s*(" +
                    "|".join(re.escape(p) for p in params) + r")\b",
                    fn["text"]) if params else False:
                supplied = True
                break
        if supplied:
            break
    if not supplied:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CLAIM_FN_RE.match(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if _NONREENTRANT_RE.search(fn["signature"]):
            continue
        text = fn["text"]
        # A stored allowlist check on the callback target is
        # the protected shape.
        if _ALLOWLIST_RE.search(text) and \
                re.search(r"require\s*\(", text):
            continue
        # The claim must load the stored callback (directly or
        # into a local) and call it.
        called_var = None
        called_map = None
        call_pos = -1
        for var in sorted(lockup_vars):
            local = None
            lm = re.search(
                r"\baddress\s+([A-Za-z_]\w*)\s*=\s*" +
                re.escape(var) + r"\s*\[", text)
            if lm:
                local = lm.group(1)
            targets = [var] + ([local] if local else [])
            for tgt in targets:
                cm = re.search(
                    r"\b" + re.escape(tgt) + r"\b[^;]{0,160}?"
                    r"\.\s*(?:call|createLockedPosition|"
                    r"mintLocked|createLocked|lock|deposit|"
                    r"mint|create)\s*\(", text)
                if cm:
                    called_var = tgt
                    called_map = var
                    call_pos = cm.start()
                    break
            if call_pos >= 0:
                break
        if call_pos < 0:
            continue
        # Leg 2: the claimed flag / holdings update must come
        # AFTER the external call (or the flag is set first
        # and the shape is protected).
        flag = re.search(
            r"\bclaimed\s*\[[^\]]+\](?:\s*\[[^\]]+\])?\s*=\s*true",
            text)
        if not flag or flag.start() < call_pos:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' calls the stored "
            f"per-group callback ('{called_var}' from "
            f"'{called_map}', named by the group creator) "
            f"BEFORE setting claimed = true, "
            f"with no nonReentrant on the claim path, so the "
            f"callback can re-enter claim() and drain "
            f"unclaimed allocations. Gate analysis: the claim "
            f"path is ungated, the callback target is "
            f"attacker-suppliable, no allowlist restricts it, "
            f"and the claimed flag is set after the call.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated claim: attacker-suppliable lockup "
                    "callback invoked before claimed = true, "
                    "no nonReentrant")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. Post-slash ERC-4626 offset inversion (Firelight #88330)
# ---------------------------------------------------------------------------

_OFFSET_RE = re.compile(
    r"totalSupply\s*\+\s*1")
_OFFSET_ASSETS_RE = re.compile(
    r"totalAssets\s*\+\s*1")
_DECIMALS_OFFSET_RE = re.compile(
    r"_decimalsOffset|decimalsOffset")
_SLASH_FN_RE = re.compile(r"slash|seize|confiscat", re.I)
_TOTAL_ASSETS_DOWN_RE = re.compile(
    r"totalAssets\s*(?:-=\s*[^;]+|=\s*totalAssets\s*-)")
_BURN_RE = re.compile(r"\b_burn\s*\(|totalSupply\s*-=")
_ZERO_ASSETS_GUARD_RE = re.compile(
    r"require\s*\([^;]{0,120}?totalAssets\s*>\s*0|"
    r"if\s*\(\s*totalAssets\s*==\s*0[^)]*\)\s*revert|"
    r"totalAssets\s*==\s*0[^;]{0,60}?revert")


def _analyze_post_slash_offset(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # Leg 1: virtual-offset conversion - (totalSupply + 1) /
    # (totalAssets + 1), or an OZ _decimalsOffset conversion.
    offset_fns = set()
    for fn in fns:
        if (_OFFSET_RE.search(fn["text"]) and
                _OFFSET_ASSETS_RE.search(fn["text"])) or \
                _DECIMALS_OFFSET_RE.search(fn["text"]):
            offset_fns.add(fn["name"])
    if not offset_fns:
        return []
    # One-hop wrappers: a deposit that calls an offset helper
    # inherits the offset conversion.
    changed = True
    while changed:
        changed = False
        for fn in fns:
            if fn["name"] in offset_fns:
                continue
            if any(re.search(r"\b" + re.escape(d) + r"\s*\(",
                             fn["text"]) for d in offset_fns):
                offset_fns.add(fn["name"])
                changed = True
    # Leg 2: a slash / payout path that reduces totalAssets
    # WITHOUT burning shares pro-rata.
    slash_fn = None
    for fn in fns:
        if not _SLASH_FN_RE.search(fn["name"]):
            continue
        if not _TOTAL_ASSETS_DOWN_RE.search(fn["text"]):
            continue
        if _BURN_RE.search(fn["text"]):
            continue
        slash_fn = fn["name"]
        break
    if slash_fn is None:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] not in ("deposit", "mint"):
            continue
        if fn["name"] not in offset_fns:
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 3: deposit() stays open in the slashed-empty
        # state - no revert / pause when totalAssets == 0
        # while totalSupply > 0.
        if _ZERO_ASSETS_GUARD_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' converts through a "
            f"virtual offset (totalSupply + 1) / (totalAssets "
            f"+ 1), and '{slash_fn}' reduces totalAssets "
            f"without burning shares, so totalAssets == 0 && "
            f"totalSupply > 0 is reachable with deposit() "
            f"still open and a 1-wei deposit mints an outsized "
            f"share of the vault. Gate analysis: deposit is "
            f"ungated, the slash burns no shares, and no "
            f"zero-assets guard closes deposit after a slash.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated deposit: virtual-offset conversion "
                    "after a slash that cuts totalAssets without "
                    "burning shares, no zero-assets guard")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "unsafe_narrowing_cast_collateral_zero": _analyze_narrowing_cast,
    "negative_fee_mint_inflation": _analyze_negative_fee,
    "scaled_allowance_overapproval": _analyze_scaled_allowance,
    "claim_callback_before_claimed_flag": _analyze_claim_callback,
    "post_slash_erc4626_offset_inversion": _analyze_post_slash_offset,
}


def analyze_deep15_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-10 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-3 collection / fetch /
# proxy resolution; analysis is analyze_deep15_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit15Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 15)"
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
        for item in analyze_deep15_source(
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
                source="deep audit detector batch 15 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit15Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 15) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
