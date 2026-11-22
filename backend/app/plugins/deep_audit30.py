"""Deep-audit detectors, batch 30: an OFT credit accumulator
that underflows on first credit, Uniswap v4 hook fees charged
on the requested amount instead of the realised delta, hook
fees computed on the wrong leg for exact-output swaps, a vault
swap that never verifies the sold token left, and a vault swap
that leaves a router approval unrevoked.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- oft_credit_accumulator_underflow: an OFT _credit / _debit
  override does `totalBridgedOut -= amount` (or a similar
  named accumulator subtraction) with no initialization and
  no clamp, so the first credit on a peer chain underflows
  (panic 0x11) and every bridge transfer to that peer fails
  while the source burn already happened - funds
  unrecoverable. The Overlayer shape (HackenProof
  OVLRSCDD-180). Fund-LOCKING class, not stranger-receivable:
  no recipient classification (batch-28 period-exit
  precedent). Medium severity. A guard (require / clamp
  around the subtraction) or any initialization of the
  accumulator is the protected shape.
- hook_fee_on_requested_not_realized: a Uniswap v4 hook
  beforeSwap computes the specified-side fee from
  params.amountSpecified and returns it as a fixed
  BeforeSwapDelta, and afterSwap never compares the fee with
  the realised delta - so partial fills overpay (up to
  ~25.5% in the IMDuel opening seconds). The fee lands at
  the hook itself (FIXED), so this is a user-harm /
  trigger-only finding by construction (the
  redeem_burns_shares_for_zero_assets precedent), never a
  candidate. An afterSwap that compares the realised delta
  with the fee / requested amount and reverts or adjusts on
  a partial fill is the protected shape. Distinct from
  hook_fee_exact_output_wrong_leg: this one is fee base =
  requested vs realised; that one is the wrong leg.
- hook_fee_exact_output_wrong_leg: a Uniswap v4 hook
  afterSwap computes `feeAmount = |unspecifiedAmount| -
  targetOutput` unconditionally, assuming the unspecified
  amount is always the output. On exactOutput swaps the
  unspecified amount is the INPUT, so the fee is computed on
  the wrong leg (CaliperForge M-01, OZ BaseDynamicAfterFee
  pre-commit-2678eb9). Same FIXED / trigger-only recipient
  labelling as the requested-fee detector. A branch on
  exactInput / the amountSpecified sign distinguishing the
  legs before the fee arithmetic is the protected shape.
- swap_fake_order_no_sold_token_check: a vault's public
  swap() converts collateral to BOLD through a fixed router,
  approves the router, passes along the caller's order, and
  checks only that it received at least the oracle value
  minus a tolerance - it never verifies the intended sold
  token actually left the contract. A crafted order delivers
  the expected BOLD from elsewhere while selling nothing;
  the delivered tokens act as a donation inflating the share
  price, then the attacker redeems at the inflated price.
  The K3 Capital sBOLD shape (Nov 18, ~$3.43M). A
  sold-token balance-delta check is the protected shape.
  Recipient classification mirrors the batch-28
  share-price precedent: the redeem leg pays the caller
  beyond their deposit off the inflated valuation, so the
  redeeming stranger is a CANDIDATE; a FIXED payout
  destination stays trigger-only.
- swap_approval_leftover_unrevoked: a swap function grants
  a router / adapter an allowance over the vault's tokens
  and never resets it to zero, while the order data the
  router executes is caller-supplied - so a later call can
  direct the router to take a different approved token out
  of the vault (K3 Capital sBOLD, same post-mortem, the
  second named root cause: "it did not reset the allowance
  to zero afterwards"). Resetting the approval to zero after
  the swap is the protected shape. The later extraction pays
  the caller-supplied order's recipient, so the swap
  function classifies via the shared recipient helper; a
  FIXED destination stays trigger-only.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding for the OFT and vault-swap detectors - a stranger
cannot reach the path. The two hook-fee detectors do NOT
suppress on the poolManager caller check: onlyPoolManager
is the legitimate v4 entry gate for every hook callback,
and the bug is the fee math, not who may call the hook.

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
FAMILY = "deep30"

SPECS = [
    S("oft_credit_accumulator_underflow", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="OFT credit accumulator underflows on first "
             "credit: an OFT _credit / _debit override does "
             "`accumulator -= amount` (a named state-variable "
             "accumulator subtraction) with no initialization "
             "anywhere and no underflow guard, so the first "
             "credit on a peer chain underflows (panic 0x11) "
             "and every bridge transfer to that peer fails "
             "while the source burn already happened - funds "
             "unrecoverable. The Overlayer shape (HackenProof "
             "OVLRSCDD-180). Fund-LOCKING class, not "
             "stranger-receivable: no recipient classification. "
             "A guard (require / clamp around the subtraction) "
             "or any initialization of the accumulator is the "
             "protected shape.",
      fix="Initialize the accumulator before the first credit "
          "(or clamp the subtraction): require the accumulator "
          "covers the amount before subtracting, or track "
          "bridged-out per peer from zero with a saturating "
          "subtraction that cannot panic."),
    S("hook_fee_on_requested_not_realized", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Hook fee charged on the requested amount, not "
             "the realised delta: a Uniswap v4 hook beforeSwap "
             "computes the specified-side fee from "
             "params.amountSpecified and returns it as a fixed "
             "BeforeSwapDelta, and afterSwap never compares the "
             "fee with the realised delta - so partial fills "
             "overpay (up to ~25.5% in the IMDuel opening "
             "seconds). The fee lands at the hook itself "
             "(FIXED), so this is a user-harm / trigger-only "
             "finding by construction, never a candidate. An "
             "afterSwap that compares the realised delta with "
             "the fee / requested amount and reverts or "
             "adjusts on a partial fill is the protected shape.",
      fix="Charge the fee on what actually swapped: in "
          "afterSwap compare the realised delta with the "
          "requested amount and scale the fee down (or revert) "
          "when the fill is partial, instead of collecting "
          "the full requested-amount fee."),
    S("hook_fee_exact_output_wrong_leg", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Hook fee computed on the wrong leg for "
             "exactOutput swaps: a Uniswap v4 hook afterSwap "
             "computes `feeAmount = |unspecifiedAmount| - "
             "targetOutput` unconditionally, assuming the "
             "unspecified amount is always the output. On "
             "exactOutput swaps the unspecified amount is the "
             "INPUT, so the fee is computed on the wrong leg "
             "(CaliperForge M-01). The fee lands at the hook "
             "itself (FIXED), so this is a user-harm / "
             "trigger-only finding by construction, never a "
             "candidate. A branch on exactInput / the "
             "amountSpecified sign distinguishing the legs "
             "before the fee arithmetic is the protected shape.",
      fix="Branch on the swap direction before computing the "
          "fee: on exactInput the unspecified amount is the "
          "output, on exactOutput it is the input - compute "
          "the fee from the output leg in each case."),
    S("swap_fake_order_no_sold_token_check", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Vault swap never verifies the sold token left: "
             "a vault's public swap() converts collateral "
             "through a fixed router, approves the router, "
             "passes along the caller's order, and checks only "
             "that it received at least the oracle value minus "
             "a tolerance - it never verifies the intended "
             "sold token actually left the contract. A crafted "
             "order delivers the expected output from elsewhere "
             "while selling nothing; the delivered tokens act "
             "as a donation inflating the share price, then "
             "the attacker redeems at the inflated price. The "
             "K3 Capital sBOLD shape (Nov 18, ~$3.43M). A "
             "sold-token balance-delta check (the sold balance "
             "decreased by the expected amount) is the "
             "protected shape.",
      fix="Verify the sold leg, not just the received leg: "
          "record the sold-token balance before the router "
          "call and require it decreased by the expected "
          "amount afterwards, before crediting the received "
          "output."),
    S("swap_approval_leftover_unrevoked", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Vault swap leaves a router approval unrevoked: "
             "a swap function grants a router / adapter an "
             "allowance over the vault's tokens and never "
             "resets it to zero, while the order data the "
             "router executes is caller-supplied - so a later "
             "call can direct the router to take a different "
             "approved token out of the vault (K3 Capital "
             "sBOLD, same post-mortem, the second named root "
             "cause: the allowance was not reset to zero "
             "afterwards). Resetting the approval to zero "
             "after the swap is the protected shape.",
      fix="Reset the router approval to zero immediately after "
          "the swap call (or approve exactly the amount the "
          "swap needs, scoped to that call), so no standing "
          "allowance survives for a later caller-supplied "
          "order to spend."),
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
# 1. oft_credit_accumulator_underflow
# ---------------------------------------------------------------------------

_CREDIT_FN_RE = re.compile(r"^_(?:credit|debit)$")
_SEND_FN_RE = re.compile(r"^(?:send|lzReceive)$")


def _accumulator_subtractions(body: str, state: set,
                              params: List[str]
                              ) -> List[Tuple[str, str]]:
    """(accumulator, amount) for `ACC -= AMT` in the body where
    ACC is a state variable and AMT is a parameter of the
    function."""
    out: List[Tuple[str, str]] = []
    for m in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*-=\s*"
            r"([A-Za-z_][A-Za-z0-9_]*)", body):
        acc, amt = m.group(1), m.group(2)
        if acc in state and amt in params:
            out.append((acc, amt))
    return out


def _accumulator_never_initialized(scoped: str, acc: str) -> bool:
    """No `ACC = ...`, `ACC += ...` or `ACC++` anywhere in the
    contract - only `-=` occurrences. The `-=` itself must not
    match the plain-assignment pattern (`ACC -= x` has a `-`
    between the name and the `=`)."""
    ap = re.escape(acc)
    if re.search(r"\b" + ap + r"\s*=(?!=)", scoped):
        return False
    if re.search(r"\b" + ap + r"\s*\+=", scoped):
        return False
    if re.search(r"\b" + ap + r"\s*\+\+", scoped):
        return False
    return True


def _has_underflow_guard(fn_text: str, acc: str, amt: str
                         ) -> bool:
    """A require / if / assert whose condition mentions both
    the accumulator and the amount - a `require(acc >= amt)`,
    a clamp, or any comparison between the two before the
    subtraction."""
    ap, mp = re.escape(acc), re.escape(amt)
    for m in re.finditer(r"(?:require|if|assert)\s*\(", fn_text):
        i = fn_text.index("(", m.start())
        cond, _ = _balanced(fn_text, i)
        if re.search(r"\b" + ap + r"\b", cond) and \
                re.search(r"\b" + mp + r"\b", cond):
            return True
    return False


def _analyze_oft_credit_underflow(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    # The OFT markers: a contract named *OFT*, or a send /
    # lzReceive entry point, or an `override` on the credit
    # function itself.
    is_oft = any(re.search(r"oft", n, re.I)
                 for n in scope.contract_names)
    if not is_oft:
        is_oft = any(_SEND_FN_RE.match(f["name"]) for f in fns)
    credit_fns = [f for f in fns
                  if _CREDIT_FN_RE.match(f["name"])]
    if not credit_fns:
        return []
    if not is_oft:
        is_oft = any("override" in f["signature"]
                     for f in credit_fns)
    if not is_oft:
        return []
    out: List[Dict[str, Any]] = []
    for fn in credit_fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        params = _fn_params(fn)
        subs = _accumulator_subtractions(body, state, params)
        for acc, amt in subs:
            if not _accumulator_never_initialized(
                    scope.scoped_text, acc):
                continue
            if _has_underflow_guard(text, acc, amt):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' does "
                f"'{acc} -= {amt}' on the state-variable "
                f"accumulator '{acc}', which is never assigned "
                f"or initialized anywhere in the contract (no "
                f"`=`, `+=` or constructor assignment - only "
                f"`-=` occurrences) and has no underflow guard "
                f"(no require / clamp comparing '{acc}' with "
                f"'{amt}') - so the first credit on a peer "
                f"chain underflows (panic 0x11) and every "
                f"bridge transfer to that peer fails while the "
                f"source burn already happened. Gate analysis: "
                f"no caller-identity gate on the credit path; "
                f"the credit is reached via LayerZero delivery, "
                f"not a locally gated call.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "OFT credit subtracts an uninitialized "
                        "accumulator with no underflow guard; "
                        "first credit on a peer panics")
            # No recipient classification (batch-28 period-exit
            # precedent): the credit path locks funds - the
            # stranger-receivable value is the failed bridge,
            # not a payout from this function.
            out.append(item)
            break
    return out


# ---------------------------------------------------------------------------
# 2. hook_fee_on_requested_not_realized
# ---------------------------------------------------------------------------

_BEFORE_SWAP_RE = re.compile(r"^_?beforeSwap$")
_AFTER_SWAP_RE = re.compile(r"^_?afterSwap$")
_FEE_DELTA_RE = re.compile(
    r"BeforeSwapDelta|toBeforeSwapDelta|_chargeFee")


def _requested_proxies(body: str) -> set:
    """amountSpecified itself, plus locals assigned from an
    expression containing it (e.g. `uint256 amount =
    params.amountSpecified < 0 ? ...`)."""
    proxies = {"amountSpecified"}
    for m in re.finditer(
            r"\b(?:uint256|uint|int256|int)\s+([A-Za-z_]"
            r"[A-Za-z0-9_]*)\s*=\s*[^;]{0,200}?amountSpecified",
            body):
        proxies.add(m.group(1))
    return proxies


def _fee_from_requested(body: str) -> Optional[str]:
    """The fee variable assigned from a requested-amount proxy
    (`fee = amount * FEE_BPS / BPS`), or None."""
    proxies = _requested_proxies(body)
    for m in re.finditer(
            r"\b((?:[A-Za-z_][A-Za-z0-9_]*)?[Ff]ee[A-Za-z0-9_]*)"
            r"\s*=\s*([^;]{1,200})", body):
        rhs = m.group(2)
        if any(re.search(r"\b" + re.escape(p) + r"\b", rhs)
               for p in proxies):
            return m.group(1)
    return None


def _after_swap_checks_realised(text: str) -> bool:
    """afterSwap compares the realised delta with the fee /
    requested amount, or recomputes the fee from the realised
    delta - the protected shape. A bare `require(fee > 0)` or
    a comparison that never mentions a realised figure is not
    a check."""
    # The fee recomputed from the realised delta.
    if re.search(
            r"\b(?:[A-Za-z_][A-Za-z0-9_]*)?[Ff]ee[A-Za-z0-9_]*"
            r"\s*=\s*[^;]{0,200}?(?:realis\w*|"
            r"delta\.amount[01]\b)",
            text, re.I):
        return True
    # A require / if comparing a realised figure with the fee
    # / requested amount (or reverting on a partial fill).
    for m in re.finditer(r"(?:require|if|assert)\s*\(", text):
        i = text.index("(", m.start())
        cond, _ = _balanced(text, i)
        if not re.search(
                r"realis\w*|delta\.amount[01]\b|actual\w*",
                cond, re.I):
            continue
        if re.search(r"fee|request|amountSpecified", cond, re.I):
            return True
    return False


def _analyze_hook_fee_requested(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BEFORE_SWAP_RE.match(fn["name"]):
            continue
        text = fn["text"]
        body = _fn_body(text)
        fee_var = _fee_from_requested(body)
        if fee_var is None:
            continue
        if not _FEE_DELTA_RE.search(text):
            continue
        # The afterSwap must charge the stored fee without ever
        # comparing it with the realised delta. The poolManager
        # caller check is the legitimate v4 entry gate, not a
        # suppressor for fee math (see module docstring), so no
        # _skip_fn here.
        after = None
        for afn in fns:
            if _AFTER_SWAP_RE.match(afn["name"]):
                after = afn
                break
        if after is None:
            continue
        searched = after["text"] + "\n" + \
            _called_internal_texts(after["text"], scope)
        if "fee" not in searched.lower():
            continue
        if _after_swap_checks_realised(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes the fee "
            f"'{fee_var}' from params.amountSpecified (the "
            f"REQUESTED amount) and returns it as a fixed "
            f"BeforeSwapDelta, while '{after['name']}' only "
            f"reloads the stored fee and never compares the "
            f"realised delta with the fee / requested amount "
            f"and never reverts on a partial fill - so a "
            f"partial fill is charged the full requested-amount "
            f"fee. Gate analysis: the hook callbacks are "
            f"poolManager-gated by design (the legitimate v4 "
            f"entry gate); the bug is the fee math, not who "
            f"may call the hook.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "hook fee from the requested amount, fixed "
                    "delta, afterSwap never checks the realised "
                    "delta")
        # The fee lands at the hook itself (FIXED): a stranger
        # can trigger the overcharge but receives nothing -
        # trigger-only by construction (the batch-21 redeem
        # precedent).
        out.append(_classify(
            item, "FIXED",
            "the fee is collected by the hook contract itself "
            "(address(this)): the overcharged swapper pays the "
            "hook, and a stranger triggering the swap receives "
            "nothing"))
        break
    return out


# ---------------------------------------------------------------------------
# 3. hook_fee_exact_output_wrong_leg
# ---------------------------------------------------------------------------

_LEG_BRANCH_RE = re.compile(r"\bexactInput\b")
_SIGN_BRANCH_RE = re.compile(
    r"amountSpecified\s*(?:<|>|<=|>=|==|!=)")
_ZEROFORONE_BRANCH_RE = re.compile(
    r"\bif\s*\([^)]*zeroForOne[^)]*\)")


def _wrong_leg_fee(searched: str) -> Optional[str]:
    """The fee variable computed as `unspecified - target`
    (the unspecified amount first, a target figure after the
    minus) - or None. The reversed order (`target -
    unspecified`) is the correct exactOutput leg and does not
    match."""
    for m in re.finditer(
            r"\b((?:[A-Za-z_][A-Za-z0-9_]*)?[Ff]ee[A-Za-z0-9_]*)"
            r"\s*=\s*([^;]{1,200})", searched):
        rhs = m.group(2)
        um = re.search(
            r"(?:unspecified\w*|delta\.amount[01]\b)", rhs, re.I)
        if not um:
            continue
        minus = rhs.find("-", um.end())
        if minus < 0:
            continue
        tail = rhs[minus + 1:]
        if re.search(r"\b(?:target|expected)\w*\b", tail, re.I):
            return m.group(1)
    return None


def _has_leg_branch(searched: str) -> bool:
    """A branch distinguishing the legs before the fee
    arithmetic: an exactInput branch, an amountSpecified-sign
    branch, or a zeroForOne branch."""
    if _LEG_BRANCH_RE.search(searched):
        return True
    if _SIGN_BRANCH_RE.search(searched):
        return True
    if _ZEROFORONE_BRANCH_RE.search(searched):
        return True
    return False


def _analyze_hook_fee_wrong_leg(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # Prefer the public entry; an internal-only _afterSwap is
    # the fallback (its fee math is reached through the entry,
    # so the two must not double-fire).
    afters = [f for f in fns
              if _AFTER_SWAP_RE.match(f["name"])]
    public = [f for f in afters if f["name"] == "afterSwap"]
    if public:
        afters = public
    out: List[Dict[str, Any]] = []
    for fn in afters:
        searched = fn["text"] + "\n" + \
            _called_internal_texts(fn["text"], scope)
        fee_var = _wrong_leg_fee(searched)
        if fee_var is None:
            continue
        if _has_leg_branch(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes the fee "
            f"'{fee_var}' as the unspecified amount minus a "
            f"target output (`unspecified - target`) "
            f"unconditionally, with no branch on exactInput / "
            f"the amountSpecified sign / zeroForOne "
            f"distinguishing the legs before the fee "
            f"arithmetic - so on exactOutput swaps, where the "
            f"unspecified amount is the INPUT, the fee is "
            f"computed on the wrong leg. Gate analysis: the "
            f"hook callbacks are poolManager-gated by design "
            f"(the legitimate v4 entry gate); the bug is the "
            f"fee math, not who may call the hook.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "hook fee from the unspecified amount minus "
                    "a target, no leg-distinguishing branch")
        # The fee lands at the hook itself (FIXED): same
        # trigger-only labelling as the requested-fee
        # detector.
        out.append(_classify(
            item, "FIXED",
            "the fee is collected by the hook contract itself "
            "(address(this)): the overcharged swapper pays the "
            "hook, and a stranger triggering the swap receives "
            "nothing"))
        break
    return out


# ---------------------------------------------------------------------------
# Shared vault-swap helpers (detectors 4 and 5)
# ---------------------------------------------------------------------------

_SWAP_FN_RE = re.compile(r"swap", re.I)
_ORDER_PARAM_RE = re.compile(
    r"^(?:order|swapOrder|swapData|calldata|payload|route|"
    r"swapCalldata|orderData)$", re.I)
_ROUTER_METHOD_EXCLUDE_RE = re.compile(
    r"^(?:approve|safeApprove|forceApprove|transfer|"
    r"transferFrom|balanceOf|call|delegatecall)$")


def _strip_interface_casts(body: str) -> str:
    """`ISwapRouter(router).executeOrder(...)` -> 
    `router.executeOrder(...)`, so the receiver of a wrapped
    call is readable (the batch-26 _reported_var trick)."""
    return re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\((\w+)\)\.",
                  r"\1.", body)


def _unwrap_address_cast(expr: str) -> str:
    """`address(router)` -> `router` (and nested casts)."""
    e = expr.strip()
    for _ in range(4):
        m = re.fullmatch(r"address\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
                         e)
        if not m:
            return e
        e = m.group(1)
    return e



def _stored_receiver_names(fn: Dict[str, Any], body: str,
                           scope) -> set:
    """Identifiers usable as a stored router / adapter
    receiver: contract-level names minus the function's own
    parameters and locals. cl.state_variables only knows
    mapping / uint / int / address / bool / bytes32, so a
    custom-type declaration like `ISwapRouter public router`
    is found by scanning contract-level declarations of any
    type instead. A caller-supplied router parameter, or a
    router instantiated as a function local, is never in the
    set - the receiver must come from contract storage."""
    names = set(cl.state_variables(scope.scoped_text))
    for m in re.finditer(
            r"(?m)^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*\s+)+"
            r"(?:(?:public|private|internal|immutable|"
            r"constant)\s+)*([A-Za-z_][A-Za-z0-9_]*)"
            r"\s*(?:=[^;]*)?;",
            scope.scoped_text):
        names.add(m.group(1))
    params = set(_fn_params(fn))
    for m in re.finditer(
            r"\b(?:uint256|uint|int256|int|address|bool|"
            r"bytes[0-9]*|string|[A-Za-z_][A-Za-z0-9_]*)\s+"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=", body):
        params.add(m.group(1))
    names -= params
    names.discard("msg")
    names.discard("block")
    names.discard("tx")
    return names


def _router_call_with_order(body: str, state: set,
                            order_params: List[str]
                            ) -> Optional[Tuple[str, str]]:
    """(router, order param) for a call on a stored router /
    adapter whose arguments mention a caller-supplied order
    parameter. A plain `.call(` on a caller-supplied target is
    NOT this shape (the settlement detector owns it); a call
    to a stored router is NOT that shape."""
    flat = _strip_interface_casts(body)
    for m in re.finditer(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", flat):
        recv, method = m.group(1), m.group(2)
        if recv not in state:
            continue
        if _ROUTER_METHOD_EXCLUDE_RE.match(method):
            continue
        i = flat.index("(", m.start())
        inner, _ = _balanced(flat, i)
        for p in order_params:
            if _mentions(inner, p):
                return recv, p
    return None


def _has_received_min_check(body: str) -> bool:
    """A require comparing a received / actual figure against
    a min / oracle / expected value (`require(received >=
    minOut)`)."""
    for m in re.finditer(r"require\s*\(", body):
        i = body.index("(", m.start())
        cond, _ = _balanced(body, i)
        if not re.search(
                r"\b(?:received|actual\w*|amountOut|"
                r"outputAmount)\b", cond):
            continue
        if ">=" not in cond and ">" not in cond:
            continue
        if re.search(r"\b(?:min\w*|oracle\w*|expected\w*)\b",
                     cond, re.I):
            return True
    return False


def _balance_locals(body: str) -> Dict[str, List[str]]:
    """token expression -> locals assigned from a balanceOf
    read of it (`uint256 soldBefore =
    sold.balanceOf(address(this))`)."""
    by_token: Dict[str, List[str]] = {}
    for m in re.finditer(
            r"\b(?:uint256|uint)\s+([A-Za-z_][A-Za-z0-9_]*)\s*="
            r"\s*[^;]{0,200}?([A-Za-z_][A-Za-z0-9_]*(?:\."
            r"[A-Za-z_][A-Za-z0-9_]*)*)\.balanceOf\s*\(",
            body):
        by_token.setdefault(m.group(2), []).append(m.group(1))
    return by_token


def _has_sold_balance_delta_check(body: str) -> bool:
    """A sold-token balance-delta check: two locals read from
    balanceOf of the same token, with a require that the
    BEFORE local minus the AFTER local covers an amount
    (`require(soldBefore - soldAfter >= amountIn)`), or the
    same decrease computed into a local and required. A
    received-amount check (`received = after - before`,
    `require(received >= minOut)`) is an INCREASE, not a
    decrease, and does not count."""
    by_token = _balance_locals(body)
    for _tok, locals_ in by_token.items():
        if len(locals_) < 2:
            continue
        for a in locals_:
            for b in locals_:
                if a == b:
                    continue
                if re.search(
                        r"require\s*\([^;]{0,300}?\b" +
                        re.escape(a) + r"\b\s*-\s*\b" +
                        re.escape(b) +
                        r"\b[^;]{0,120}?(?:>=|>)", body):
                    return True
                for m in re.finditer(
                        r"\b(?:uint256|uint)\s+([A-Za-z_]"
                        r"[A-Za-z0-9_]*)\s*=\s*\b" +
                        re.escape(a) + r"\b\s*-\s*\b" +
                        re.escape(b) + r"\b", body):
                    dec = m.group(1)
                    if re.search(
                            r"require\s*\([^;]{0,200}?\b" +
                            re.escape(dec) +
                            r"\b[^;]{0,120}?(?:>=|>)", body):
                        return True
    return False


def _swap_order_params(fn: Dict[str, Any]) -> List[str]:
    """Caller-supplied order / calldata parameters of the swap
    function (bytes-typed, or order-named)."""
    out: List[str] = []
    for (t, n) in _fn_params_typed(fn):
        if t == "bytes" or t.startswith("bytes[") or \
                t.startswith("bytes "):
            out.append(n)
        elif _ORDER_PARAM_RE.match(n):
            out.append(n)
    return out


def _approval_to_router(body: str, router: str
                        ) -> Optional[str]:
    """The amount expression of an approve-family call whose
    spender is the router (allowing an `address(router)`
    cast), or None. `token.approve(router, X)`,
    `safeApprove(token, router, X)`,
    `forceApprove(token, router, X)`."""
    rp = re.escape(router)
    spender = r"(?:address\s*\(\s*)?" + rp + r"(?:\s*\))?"
    for m in re.finditer(
            r"\.\s*(?:safeApprove|forceApprove|approve)\s*\(",
            body):
        i = body.index("(", m.start())
        inner, _ = _balanced(body, i)
        args = _split_top(inner)
        method = m.group(0)
        if "safeApprove" in method or "forceApprove" in method:
            if len(args) >= 3 and \
                    re.fullmatch(spender, args[1].strip()):
                return args[2].strip()
        else:
            if len(args) >= 2 and \
                    re.fullmatch(spender, args[0].strip()):
                return args[1].strip()
    return None


def _router_approval_reset_anywhere(scoped: str, router: str
                                    ) -> bool:
    """An approve-family call resetting the router's allowance
    to zero anywhere in the contract."""
    rp = re.escape(router)
    spender = r"(?:address\s*\(\s*)?" + rp + r"(?:\s*\))?"
    if re.search(r"\.\s*approve\s*\(\s*" + spender +
                 r"\s*,\s*0\s*\)", scoped):
        return True
    if re.search(r"\b(?:safeApprove|forceApprove)\s*\(\s*"
                 r"[A-Za-z_][A-Za-z0-9_]*\s*,\s*" + spender +
                 r"\s*,\s*0\s*\)", scoped):
        return True
    return False


def _deposit_and_redeem(fns) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """(has deposit leg, redeem fn) - the entry / exit legs
    the K3 redemption runs through."""
    has_deposit = any(
        re.match(r"^(?:deposit|mint)\w*$", f["name"], re.I)
        for f in fns)
    redeem = None
    for f in fns:
        if re.match(r"^(?:redeem|withdraw|exit)\w*$",
                    f["name"], re.I) and _moves_value(f["text"]):
            redeem = f
            break
    return has_deposit, redeem


# ---------------------------------------------------------------------------
# 4. swap_fake_order_no_sold_token_check
# ---------------------------------------------------------------------------

def _analyze_swap_fake_order(src, spec, compiler,
                             contract_name):
    scope, fns = _scope_fns(src, contract_name)
    has_deposit, redeem = _deposit_and_redeem(fns)
    if not has_deposit or redeem is None:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SWAP_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        order_params = _swap_order_params(fn)
        if not order_params:
            continue
        if _router_call_with_order(
                body,
                _stored_receiver_names(fn, body, scope),
                order_params) is None:
            continue
        if not _has_received_min_check(body):
            continue
        if _has_sold_balance_delta_check(body):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' forwards the "
            f"caller-supplied order to a fixed router and "
            f"checks only that the received amount covers a "
            f"minimum / oracle value (`require(received >= "
            f"minOut)`), with no balance check that the sold "
            f"token actually left the contract (no "
            f"before/after balanceOf delta on the sold leg) - "
            f"so a crafted order can deliver the expected "
            f"output from elsewhere while selling nothing, "
            f"and the delivered tokens inflate the share "
            f"price the '{redeem['name']}' leg pays out "
            f"against. Gate analysis: no caller-identity gate, "
            f"no sold-leg check on the swap path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated vault swap: caller order to a "
                    "fixed router, received-only check, no "
                    "sold-token balance check")
        # Recipient classification mirrors the batch-28
        # share-price precedent: the payout leg meters the
        # caller's own shares (HOLDER-SELF in isolation), but
        # it is priced off the donation-inflated valuation
        # proven above, so the redeeming stranger receives
        # assets BEYOND their own deposit - the excess is
        # CALLER-received. A FIXED payout destination stays
        # trigger-only under the receive rule.
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
                    "donation-inflated valuation above, so the "
                    "redeeming stranger receives assets beyond "
                    "their own deposit - the excess is "
                    "CALLER-received, classified CANDIDATE "
                    "under the receive rule.")
            else:
                item["detail"] += (
                    f" Recipient analysis: recipient classified "
                    f"{recipient} ({rdetail}) - a stranger can "
                    f"receive value here, classified CANDIDATE "
                    f"under the receive rule.")
        out.append(item)
        break
    return out


# ---------------------------------------------------------------------------
# 5. swap_approval_leftover_unrevoked
# ---------------------------------------------------------------------------

def _analyze_swap_approval_leftover(src, spec, compiler,
                                    contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SWAP_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        order_params = _swap_order_params(fn)
        if not order_params:
            continue
        routed = _router_call_with_order(
            body, _stored_receiver_names(fn, body, scope),
            order_params)
        if routed is None:
            continue
        router, _order = routed
        amount = _approval_to_router(body, router)
        if amount is None or amount == "0":
            continue
        if _router_approval_reset_anywhere(
                scope.scoped_text, router):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' approves the fixed "
            f"router '{router}' for '{amount}' and forwards "
            f"the caller-supplied order to it, and the "
            f"contract never resets that approval to zero "
            f"anywhere (no approve(router, 0) in the contract) "
            f"- so a later call can direct the router to take "
            f"a different approved token out of the vault "
            f"using the leftover allowance. Gate analysis: no "
            f"caller-identity gate, no approval reset on the "
            f"swap path or anywhere else in the contract.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated vault swap: router approved with "
                    "no zero reset, caller-supplied order "
                    "forwarded to the router")
        # The later extraction pays the caller-supplied
        # order's recipient: classify on the swap function
        # itself; a FIXED destination stays trigger-only.
        out.append(_finish_recipient(spec, item, text))
        break
    return out


ANALYZERS = {
    "oft_credit_accumulator_underflow":
        _analyze_oft_credit_underflow,
    "hook_fee_on_requested_not_realized":
        _analyze_hook_fee_requested,
    "hook_fee_exact_output_wrong_leg":
        _analyze_hook_fee_wrong_leg,
    "swap_fake_order_no_sold_token_check":
        _analyze_swap_fake_order,
    "swap_approval_leftover_unrevoked":
        _analyze_swap_approval_leftover,
}


def analyze_deep30_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-30 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep30_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit30Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 30)"
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
        for item in analyze_deep30_source(
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
                source="deep audit detector batch 30 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit30Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 30) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
