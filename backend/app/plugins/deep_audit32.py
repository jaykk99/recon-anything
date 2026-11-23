"""Deep-audit detectors, batch 32: a bridge redeem that honours a
fixed 1:1 rate with no peg read and no circuit breaker, a 4337/7579
validator whose owner branch skips the execution policy the
session-key branch enforces, an exact-output swap with an
unbounded maximum input, a period/duration config setter with a
lower bound only and no escape, and a v4 hook that credits a
per-swap rebate to the router (the hook's `sender`) with a direct
claim path.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- bridge_redeem_no_peg_circuit_breaker: a bridge redeem /
  release burns a wrapped token and pays the reserve token at
  a fixed 1:1 ratio (the same amount variable burned and
  paid), where the redeem path reads NO oracle / price / peg
  value and NO paused / circuit-breaker flag anywhere - the
  Fusionist / Endurance Bridge shape (Nov 22, ~$5.7M: the
  bridge kept honouring 1 burn = 1 real ACE after the wrapped
  price collapsed, so cheap wrapped tokens bought on the
  market redeemed at full reserve value). A peg / price check
  (an oracle read with a bound) or a pause / circuit-breaker
  check on the redeem path is the protected shape. Recipient
  mirrors the batch-28 share-price precedent: the payout leg
  meters the caller's own wrapped balance (HOLDER-SELF in
  isolation), but it is priced off the unpegged 1:1 rate proven
  above, so the redeeming stranger receives reserve assets
  beyond the market value of what they burned - the excess is
  CALLER-received. A FIXED payout destination stays
  trigger-only. Distinct from bridge_wrapped_token_mint_unbacked
  (a mint, not a redeem - this fixture mints nothing) and from
  chainlink_price_unbounded (no latestRoundData anywhere here).
- aa_validator_owner_branch_no_execution_policy: a 4337/7579
  smart-account validator with TWO branches: an owner branch
  that returns valid on the signature alone with NO
  target / selector / value execution-policy check, AND a
  session-key branch that DOES check execution policy (allowed
  targets / selectors / value caps). The contrast is the
  required signal - a validator with no policy anywhere, or a
  single-branch validator, stays silent. The ENS Immunefi
  #92779 shape (owner-signed HCA intents, no
  execution-equivalence check). The EntryPoint caller check
  is the legitimate 4337 entry gate, not a suppressor (the
  batch-30 hook precedent): a stranger submits the UserOp
  through the EntryPoint, so the check does not stop the
  attack. The recipient is the validated UserOp's execution,
  whose target / calldata is caller-supplied - CALLER-SUPPLIED.
  An owner branch that is policy-checked too is the protected
  shape. Distinct from aa_validation_ungated (a real signature
  check AND an EntryPoint caller check are both present here).
- swap_exact_output_unbounded_max_input: an exactOutput-family
  swap call (exactOutput, exactOutputSingle,
  swapTokensForExactTokens) whose amountInMaximum is
  type(uint256).max / uint256.max, or an exactOutput call with
  no max-input bound at all, in a helper where the caller
  supplies the output amount - the input-side mirror of
  cp_proto_unbounded_slippage (which covers only min-out == 0
  and deadline == max). A caller-supplied slippage parameter
  or a computed cap is the protected shape; a struct passed
  straight through from the caller is not a missing bound.
  User-harm / trigger-only by construction (the caller is the
  victim: the unbounded max lets their own swap execute at
  any price) - no recipient classification, the batch-28
  period-exit precedent. Medium severity.
- period_config_no_upper_bound_no_escape: a config setter for
  a period / duration / lockup that enforces only a LOWER
  bound (require(x >= MIN)) with NO upper bound, where the
  configured duration gates withdrawals / claims, AND the
  contract has NO cancel / replace / reset path for the
  configured item - the Firelight Immunefi #88525 shape.
  A privileged setter is NOT a suppressor here: the finding
  is the freeze the config enables (the setter is admin-only
  by design - the batch-30 hook precedent for a legitimate
  entry gate), so an onlyOwner setter still fires. An upper
  bound on the duration, or a cancel / replace path, is the
  protected shape. Privileged freeze / trigger-only - no
  recipient classification, the batch-28 period-exit
  precedent. Distinct from the period checkpoint / capacity /
  rescue detectors (no checkpoint write, capacity snapshot or
  rescue function anywhere in the fixture).
- hook_sender_is_router_rebate_credit: a Uniswap v4 hook whose
  afterSwap / beforeSwap credits a per-swap rebate / reward to
  the `sender` parameter (in v4 `sender` is the router, not
  the trader) AND exposes a claim / withdraw that pays the
  credited balance to the credited address (rewards[msg.sender]
  paid to msg.sender), with NO distribution logic and NO
  extraction of the actual trader from hookData. The direct
  claim path is required: a router credit with no claim path
  (swept to a fixed treasury) stays silent, as does a rebate
  credited to a trader address extracted from hookData. The
  poolManager caller check is the legitimate v4 entry gate,
  not a suppressor (the batch-30 hook precedent), and the hook
  must carry no fee math from amountSpecified and no
  wrong-leg fee arithmetic, so the hook-fee pair stays silent.
  The credited recipient is the FIXED router address, so this
  is user-harm / trigger-only - no recipient classification,
  the batch-28 period-exit precedent. Medium severity.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding for the bridge, swap and period detectors - a
stranger cannot reach the path. The two exceptions are
documented above: the 4337 validator (the EntryPoint check
is the legitimate entry gate) and the v4 hook (the
poolManager check is the legitimate entry gate), and the
period setter (the privileged setter IS the trigger - the
finding is the freeze it enables, not unauthorized access).

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
FAMILY = "deep32"

SPECS = [
    S("bridge_redeem_no_peg_circuit_breaker", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Bridge redeem honours a fixed 1:1 rate with no peg "
             "read and no circuit breaker: a bridge redeem / "
             "release burns a wrapped token and pays the reserve "
             "token at a fixed 1:1 ratio (the same amount burned "
             "and paid), while the redeem path reads NO oracle / "
             "price / peg value and NO paused / circuit-breaker "
             "flag anywhere - the Fusionist / Endurance Bridge "
             "shape (Nov 22, ~$5.7M: the bridge kept honouring "
             "1 burn = 1 real ACE after the wrapped price "
             "collapsed). A peg / price check (an oracle read "
             "with a bound) or a pause / circuit-breaker check "
             "on the redeem path is the protected shape.",
      fix="Read the peg before paying: price the redeem off a "
          "live oracle / peg feed with a sanity bound (revert "
          "when the wrapped price leaves its band), and gate "
          "the redeem behind a pause / circuit breaker the "
          "bridge can trip when the peg breaks."),
    S("aa_validator_owner_branch_no_execution_policy", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Account validator owner branch skips the execution "
             "policy: a 4337 / 7579 validator has TWO branches - "
             "an owner branch that returns valid on the "
             "signature alone with NO target / selector / value "
             "execution-policy check, AND a session-key branch "
             "that DOES check execution policy (allowed targets "
             "/ selectors / value caps). The contrast is the "
             "signal: a validator with no policy anywhere, or a "
             "single-branch validator, is not this shape. The "
             "ENS Immunefi #92779 shape (owner-signed HCA "
             "intents, no execution-equivalence check). An owner "
             "branch that is policy-checked too is the protected "
             "shape.",
      fix="Enforce the same execution policy on every branch: "
          "check the UserOp's target, selector and value "
          "against the allowed-target / allowed-selector / "
          "value-cap policy in the owner branch exactly as the "
          "session-key branch does, and never return valid "
          "from a signature alone."),
    S("swap_exact_output_unbounded_max_input", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="Exact-output swap with an unbounded maximum input: "
             "an exactOutput-family swap call (exactOutput, "
             "exactOutputSingle, swapTokensForExactTokens) whose "
             "amountInMaximum is type(uint256).max / uint256.max, "
             "or an exactOutput call with no max-input bound at "
             "all, in a helper where the caller supplies the "
             "output amount - the input-side mirror of "
             "cp_proto_unbounded_slippage (which covers only "
             "min-out == 0 and deadline == max). A caller-supplied "
             "slippage parameter or a computed cap is the "
             "protected shape. The caller is the victim (their "
             "own swap executes at any price), so this is "
             "user-harm / trigger-only, never a candidate.",
      fix="Bound the input on every exact-output swap: pass a "
          "caller-supplied amountInMaximum (a real slippage "
          "parameter) or a computed cap, and never default the "
          "maximum input to type(uint256).max or leave the "
          "field out."),
    S("period_config_no_upper_bound_no_escape", FAMILY,
      severity="high", outcome="a", recipient=False,
      detail="Period config with a lower bound only and no "
             "escape: a config setter for a period / duration / "
             "lockup enforces only a LOWER bound (require(x >= "
             "MIN)) with NO upper bound, where the configured "
             "duration gates withdrawals / claims, AND the "
             "contract has NO cancel / replace / reset path for "
             "the configured item - the Firelight Immunefi "
             "#88525 shape. An upper bound on the duration, or "
             "a cancel / replace path, is the protected shape. "
             "Privileged freeze / trigger-only: the setter is "
             "admin-only by design and the freeze lands on "
             "users, never a candidate.",
      fix="Bound the duration both ways (require it under a "
          "MAX as well as over a MIN) and give every configured "
          "item an escape: a cancel / replace / reset path so a "
          "misconfigured duration can never freeze withdrawals "
          "permanently."),
    S("hook_sender_is_router_rebate_credit", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="v4 hook credits the per-swap rebate to the router: "
             "a Uniswap v4 hook whose afterSwap / beforeSwap "
             "credits a per-swap rebate / reward to the `sender` "
             "parameter (in v4 `sender` is the router, not the "
             "trader) AND exposes a claim / withdraw that pays "
             "the credited balance to the credited address "
             "(rewards[msg.sender] paid to msg.sender), with NO "
             "distribution logic and NO extraction of the actual "
             "trader from hookData. The direct claim path is "
             "required. A rebate credited to a trader address "
             "extracted from hookData, or a router credit with "
             "no claim path (swept to a fixed treasury), is the "
             "protected shape. The credited recipient is the "
             "FIXED router address, so this is user-harm / "
             "trigger-only, never a candidate.",
      fix="Credit the rebate to the trader, not the router: "
          "extract the actual trader from hookData (or the "
          "swap's recipient) and credit rewards[trader], or "
          "drop the claim path and sweep router-side accruals "
          "to a fixed treasury instead of letting the router "
          "claim them."),
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
# 1. bridge_redeem_no_peg_circuit_breaker
# ---------------------------------------------------------------------------

_REDEEM_FN_RE = re.compile(r"^(?:redeem|release)\w*$", re.I)
_BRIDGE_MARKER_RE = re.compile(r"bridge|wrapped", re.I)
_ORACLE_READ_RE = re.compile(
    r"latestRoundData|getPrice|priceFeed|aggregator|oracle|"
    r"\bpeg\w*\b|exchangeRate|getRate|pricePerShare|TWAP|"
    r"consult\s*\(|observe\s*\(|\bprice\b", re.I)
_PAUSE_READ_RE = re.compile(
    r"paused|circuitBreaker|emergencyStop|halted|circuit",
    re.I)
_BURN_RE = re.compile(
    r"\b(?:_burn|burn|burnFrom)\s*\(([^)]*)\)")


def _burn_amounts(body: str) -> List[str]:
    """Amount identifiers burned in the body: the last bare
    identifier argument of a _burn / burn / burnFrom call
    (`_burn(msg.sender, amount)` -> amount)."""
    out: List[str] = []
    for m in _BURN_RE.finditer(body):
        args = _split_top(m.group(1))
        for a in reversed(args):
            a = a.strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", a):
                out.append(a)
                break
    return out


def _payout_amounts(body: str) -> List[str]:
    """Amount identifiers paid out in the body: the amount
    argument of a transfer / safeTransfer call, or the value
    of a call{value: ...}."""
    out: List[str] = []
    for m in re.finditer(
            r"\.\s*(transfer|safeTransfer|transferFrom|"
            r"safeTransferFrom)\s*\(", body):
        method = m.group(1)
        i = body.index("(", m.start())
        inner, _ = _balanced(body, i)
        args = _split_top(inner)
        idx = 2 if method in ("safeTransfer",
                              "safeTransferFrom") else 1
        if len(args) > idx:
            a = args[idx].strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", a):
                out.append(a)
    for m in re.finditer(
            r"\.\s*call\s*\{\s*value\s*:\s*"
            r"([A-Za-z_][A-Za-z0-9_]*)", body):
        out.append(m.group(1))
    return out


def _analyze_bridge_redeem_no_peg(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _REDEEM_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        searched = text + "\n" + _called_internal_texts(
            text, scope) + "\n" + _applied_modifier_bodies(
                fn, scope)
        # Bridge / wrapped flavour: the contract name, or the
        # redeem path itself, names a bridge or a wrapped
        # token. A plain vault redeem (burn shares, pay assets
        # at a computed rate) is not this shape.
        if not _BRIDGE_MARKER_RE.search(
                " ".join(scope.contract_names) + "\n" + searched):
            continue
        burns = _burn_amounts(searched)
        if not burns:
            continue
        payouts = _payout_amounts(searched)
        if not payouts:
            continue
        # Fixed 1:1: the same amount variable is burned and
        # paid, with no price conversion anywhere on the path.
        # A redeem that pays a computed amount (shares * rate)
        # is a different shape.
        shared = [a for a in burns if a in payouts]
        if not shared:
            continue
        if _ORACLE_READ_RE.search(searched):
            continue
        if _PAUSE_READ_RE.search(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' burns the wrapped "
            f"token ({shared[0]}) and pays the reserve token "
            f"the same '{shared[0]}' (a fixed 1:1 rate), while "
            f"the redeem path reads NO oracle / price / peg "
            f"value (no latestRoundData, price feed, oracle or "
            f"peg read anywhere on the path, not even in a "
            f"helper it calls or a modifier it carries) and NO "
            f"paused / circuit-breaker flag - so after the "
            f"wrapped price collapses the bridge keeps "
            f"honouring 1 burn = 1 reserve token, and cheap "
            f"wrapped tokens bought on the market redeem at "
            f"full reserve value. Gate analysis: no "
            f"caller-identity gate, no peg check, no pause "
            f"check on the redeem path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated bridge redeem: fixed 1:1 burn-to-"
                    "payout, no oracle / peg read, no pause / "
                    "circuit-breaker read")
        # Recipient mirrors the batch-28 share-price precedent:
        # the payout leg meters the caller's own wrapped
        # balance (HOLDER-SELF in isolation), but it is priced
        # off the unpegged 1:1 rate proven above, so the
        # redeeming stranger receives reserve assets beyond
        # the market value of what they burned - the excess
        # is CALLER-received. A FIXED payout destination stays
        # trigger-only under the receive rule.
        recipient, rdetail = cl.classify_recipient(searched)
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
                    "the caller's own wrapped balance "
                    "(HOLDER-SELF shape), but it is priced off "
                    "the unpegged 1:1 rate above, so the "
                    "redeeming stranger receives reserve assets "
                    "beyond the market value of the wrapped "
                    "tokens they burned - the excess is "
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
# 2. aa_validator_owner_branch_no_execution_policy
# ---------------------------------------------------------------------------

_VALIDATOR_FN_RE = re.compile(
    r"^(?:validateUserOp|validateSignature|"
    r"validatePaymasterUserOp)$")
_POLICY_RE = re.compile(
    r"allowedTarget|allowedSelector|isAllowed|valueCap|"
    r"maxValue|spendingLimit|policy|targetAllowed|"
    r"selectorAllowed|callPolicy|executionPolicy|allowedCall|"
    r"allowedTargets|allowedSelectors", re.I)
_SIG_RE = re.compile(
    r"ecrecover\s*\(|ECDSA\s*\.\s*recover\s*\(|"
    r"tryRecover\s*\(")
_VALID_RETURN_RE = re.compile(
    r"return\s+(?:0|VALIDATION_SUCCESS|"
    r"SIG_VALIDATION_SUCCESS|true)\b")


def _skip_validator_fn(fn: Dict[str, Any], scope) -> bool:
    """The EntryPoint caller check is the legitimate 4337
    entry gate, not a suppressor (the batch-30 hook
    precedent): a stranger submits the UserOp through the
    EntryPoint, so `msg.sender == entryPoint` does not stop
    the attack. Only an only* modifier or a role check
    suppresses - and a view / pure validator is nonsense."""
    if re.search(r"\b(view|pure)\b", fn["signature"]):
        return True
    if _ONLY_MOD_RE.search(fn["signature"]):
        return True
    if re.search(r"hasRole\s*\(|_checkRole|_checkOwner",
                 fn["text"]):
        return True
    return False


def _if_blocks(text: str) -> List[Tuple[str, str, bool]]:
    """(condition, block_text, is_else) for every if / else
    block in the text, in order. An `else if` is captured as
    its own if (its condition is what matters); a bare `else`
    is captured with condition '' and is_else True."""
    out: List[Tuple[str, str, bool]] = []
    for m in re.finditer(r"\bif\s*\(", text):
        i = text.index("(", m.start())
        cond, pend = _balanced(text, i)
        j = pend + 1
        while j < len(text) and text[j] in " \t\n":
            j += 1
        if j < len(text) and text[j] == "{":
            depth = 0
            k = j
            while k < len(text):
                if text[k] == "{":
                    depth += 1
                elif text[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            block = text[j:k + 1]
            out.append((cond, block, False))
            # A bare else following this block.
            e = k + 1
            while e < len(text) and text[e] in " \t\n":
                e += 1
            if text[e:e + 4] == "else" and \
                    not re.match(r"else\s+if\b", text[e:e + 8]):
                j2 = e + 4
                while j2 < len(text) and text[j2] in " \t\n":
                    j2 += 1
                if j2 < len(text) and text[j2] == "{":
                    depth = 0
                    k2 = j2
                    while k2 < len(text):
                        if text[k2] == "{":
                            depth += 1
                        elif text[k2] == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        k2 += 1
                    out.append(("", text[j2:k2 + 1], True))
        else:
            semi = text.find(";", j)
            if semi >= 0:
                out.append((cond, text[j:semi + 1], False))
    return out


def _analyze_aa_validator_owner_no_policy(src, spec, compiler,
                                          contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _VALIDATOR_FN_RE.match(fn["name"]):
            continue
        if _skip_validator_fn(fn, scope):
            continue
        text = fn["text"]
        searched = text + "\n" + _called_internal_texts(
            text, scope)
        # A real signature check must be present: without it
        # the validator belongs to aa_validation_ungated, not
        # this detector.
        if not _SIG_RE.search(searched):
            continue
        body = _fn_body(text)
        blocks = _if_blocks(body)
        if not blocks:
            continue
        owner_branch = None
        session_branch = None
        for cond, block, is_else in blocks:
            branch_text = block + "\n" + \
                _called_internal_texts(block, scope)
            returns_valid = bool(
                _VALID_RETURN_RE.search(branch_text))
            policy_checked = bool(
                _POLICY_RE.search(branch_text))
            is_owner = bool(re.search(
                r"owner", cond, re.I))
            is_session = bool(re.search(
                r"session", cond, re.I))
            if is_else and session_branch is not None:
                # A bare else after the session branch is the
                # owner fallback: valid on signature alone.
                is_owner = True
            if is_owner and returns_valid and \
                    not policy_checked and owner_branch is None:
                owner_branch = (cond, block)
            if is_session and policy_checked and \
                    session_branch is None:
                session_branch = (cond, block)
        # The contrast is the required signal: both branches
        # must be present. A validator with no policy
        # anywhere, or a single-branch validator, stays
        # silent.
        if owner_branch is None or session_branch is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' has TWO branches: an "
            f"owner branch (condition '{owner_branch[0].strip()}'"
            f") that returns valid on the signature alone with "
            f"no target / selector / value execution-policy "
            f"check, AND a session-key branch (condition "
            f"'{session_branch[0].strip()}') that DOES check "
            f"execution policy (allowed targets / selectors / "
            f"value caps) - so an owner-signed intent executes "
            f"any target with any value, while a session-key "
            f"intent is confined by policy. Gate analysis: the "
            f"EntryPoint caller check is the legitimate 4337 "
            f"entry gate, not a suppressor - a stranger submits "
            f"the UserOp through the EntryPoint; the bug is the "
            f"missing policy check in the owner branch, not who "
            f"may call the validator.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "validator owner branch returns valid on "
                    "signature alone; session-key branch is "
                    "policy-checked - the contrast is the signal")
        # The validated UserOp's execution target / calldata
        # is caller-supplied: the owner branch approves it
        # with no policy check, so the execution it releases
        # is CALLER-SUPPLIED.
        out.append(_classify(
            item, "CALLER-SUPPLIED",
            "the validated UserOp's execution target and "
            "calldata are caller-supplied - the owner branch "
            "approves them with no execution-policy check"))
        break
    return out


# ---------------------------------------------------------------------------
# 3. swap_exact_output_unbounded_max_input
# ---------------------------------------------------------------------------

_EXACT_OUTPUT_RE = re.compile(
    r"\b(?:exactOutputSingle|exactOutput|"
    r"swapTokensForExactTokens)\s*\(")
_MAX_CONST_RE = re.compile(
    r"type\s*\(\s*uint(?:256)?\s*\)\s*\.\s*max|"
    r"\buint(?:256)?\s*\.\s*max\b|"
    r"2\s*\*\*\s*256\s*-\s*1|"
    r"0x[fF]{32,64}\b")


def _struct_field_value(args_text: str, field: str
                        ) -> Optional[str]:
    """The value of a `field: <value>` entry in a struct
    literal's argument text, or None when the field is
    absent."""
    m = re.search(r"\b" + field + r"\s*:", args_text)
    if not m:
        return None
    rest = args_text[m.end():]
    depth = 0
    out: List[str] = []
    for ch in rest:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            break
        out.append(ch)
    return "".join(out).strip()


def _local_struct_literal(body: str, var: str
                          ) -> Optional[str]:
    """The struct-literal text of a local built in-function
    (`Params memory params = Params({...})`), or None when
    the variable is a parameter passed through."""
    m = re.search(
        r"\b" + re.escape(var) +
        r"\b\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\{",
        body)
    if m is None:
        return None
    i = body.index("{", m.start())
    depth = 0
    for k in range(i, len(body)):
        if body[k] == "{":
            depth += 1
        elif body[k] == "}":
            depth -= 1
            if depth == 0:
                return body[i + 1:k]
    return None


def _analyze_swap_exact_output_unbounded(src, spec, compiler,
                                         contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        params = _fn_params(fn)
        for m in _EXACT_OUTPUT_RE.finditer(body):
            method = m.group(0).split("(")[0].strip()
            i = body.index("(", m.start())
            args_text, _ = _balanced(body, i)
            args = _split_top(args_text)
            # The caller-supplied output amount: the amountOut
            # field (struct calls) or the first positional arg
            # (swapTokensForExactTokens).
            if method == "swapTokensForExactTokens":
                out_amt = args[0] if args else ""
                max_val = args[1] if len(args) > 1 else None
                has_max_field = max_val is not None
            else:
                out_amt = _struct_field_value(
                    args_text, "amountOut") or ""
                max_val = _struct_field_value(
                    args_text, "amountInMaximum")
                has_max_field = max_val is not None
            # The output amount must be caller-supplied: it
            # must mention a function parameter.
            if not any(_mentions(out_amt, p) for p in params):
                continue
            reason = None
            if has_max_field:
                if _MAX_CONST_RE.search(max_val or ""):
                    reason = (
                        f"amountInMaximum is '{(max_val or '').strip()}' "
                        f"(an unbounded maximum input)")
            else:
                # No max-input bound at all: an inline struct
                # literal with no amountInMaximum field, or a
                # local built in-function without the field. A
                # struct passed straight through from the caller
                # is not a missing bound.
                if "{" in args_text:
                    reason = (
                        "the exactOutput call carries no "
                        "amountInMaximum field at all (an inline "
                        "struct literal with no max-input bound)")
                elif args:
                    lit = _local_struct_literal(
                        body, args[0].strip())
                    if lit is not None and \
                            "amountInMaximum" not in lit:
                        reason = (
                            "the exactOutput params are built "
                            "in-function with no amountInMaximum "
                            "field (no max-input bound)")
            if reason is None:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' calls "
                f"'{method}' with a caller-supplied output "
                f"amount ('{out_amt.strip()}') and {reason} - "
                f"so the swap executes at any input price: the "
                f"caller asked for an exact output and gave the "
                f"router an unbounded (or absent) maximum input. "
                f"Gate analysis: no caller-identity gate, no "
                f"max-input bound on the swap path.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        "ungated exact-output swap: caller-"
                        "supplied output amount, unbounded or "
                        "absent maximum input")
            # No recipient classification (batch-28 period-exit
            # precedent): the caller is the victim - their own
            # swap executes at any price - so a stranger gains
            # nothing directly from triggering this.
            out.append(item)
            break
        if out:
            break
    return out


# ---------------------------------------------------------------------------
# 4. period_config_no_upper_bound_no_escape
# ---------------------------------------------------------------------------

_SETTER_NAME_RE = re.compile(
    r"(period|duration|lockup)", re.I)
_SETTER_VERB_RE = re.compile(
    r"(config|set|add|create|register)", re.I)
_DURATION_PARAM_RE = re.compile(
    r"(duration|lockup|period|length)", re.I)
_ESCAPE_FN_RE = re.compile(
    r"^(?:cancel|remove|reset|delete|revoke|clear)\w*$",
    re.I)
_WITHDRAW_FN_RE = re.compile(
    r"^(?:withdraw|claim|exit|unstake|redeem)\w*$", re.I)


def _duration_param(fn: Dict[str, Any]
                    ) -> Optional[str]:
    """The duration parameter of a config setter: a uint
    parameter named *duration / *lockup / *period / *length,
    never an *Id parameter."""
    for (t, n) in _fn_params_typed(fn):
        if "uint" not in t:
            continue
        if n.lower().endswith("id"):
            continue
        if _DURATION_PARAM_RE.search(n):
            return n
    return None


def _has_lower_bound(body: str, dur: str) -> bool:
    """A require / if comparing the duration with >= or >
    against a MIN-named constant or a literal."""
    dp = re.escape(dur)
    for m in re.finditer(r"(?:require|if|assert)\s*\(", body):
        i = body.index("(", m.start())
        cond, _ = _balanced(body, i)
        if not re.search(r"\b" + dp + r"\b", cond):
            continue
        if re.search(r"\b" + dp +
                     r"\b\s*(?:>=|>)\s*"
                     r"(?:[A-Za-z_][A-Za-z0-9_]*|\d[\d_]*)",
                     cond):
            return True
    return False


def _has_upper_bound(body: str, dur: str) -> bool:
    """Any upper bound on the duration in the setter: a <= /
    < comparison against anything, or a > / >= comparison
    against a MAX-named identifier."""
    dp = re.escape(dur)
    for m in re.finditer(r"(?:require|if|assert)\s*\(", body):
        i = body.index("(", m.start())
        cond, _ = _balanced(body, i)
        if not re.search(r"\b" + dp + r"\b", cond):
            continue
        if re.search(r"\b" + dp +
                     r"\b\s*(?:<=|<)\s*", cond):
            return True
        if re.search(r"\b" + dp +
                     r"\b\s*(?:>|>=)\s*"
                     r"[A-Za-z_]*MAX[A-Za-z0-9_]*", cond):
            return True
    return False


def _config_write(body: str, dur: str
                  ) -> Optional[str]:
    """The mapping / state variable the setter writes the
    duration into, or None."""
    dp = re.escape(dur)
    for m in re.finditer(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*[^\]]+\s*\]\s*"
            r"=(?!=)\s*([^;]{0,300})", body):
        if re.search(r"\b" + dp + r"\b", m.group(2)):
            return m.group(1)
    for m in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*[^;]{0,120}?"
            r"\b" + dp + r"\b", body):
        return m.group(1)
    return None


def _mapping_writers(scope, mapping: str) -> List[str]:
    """Names of functions that write the mapping (a replace
    path for the configured item)."""
    out: List[str] = []
    mp = re.escape(mapping)
    for f in scope.functions:
        if re.search(r"\b" + mp +
                     r"\s*\[[^\]]+\]\s*=(?!=)",
                     _fn_body(f["text"])):
            out.append(f["name"])
    return out


def _analyze_period_config_no_bound_no_escape(
        src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        name = fn["name"]
        if not _SETTER_NAME_RE.search(name):
            continue
        if not _SETTER_VERB_RE.search(name):
            continue
        # The privileged setter IS the trigger here (the
        # finding is the freeze the config enables, not
        # unauthorized access), so no _skip_fn on the setter:
        # an onlyOwner setter still fires (the batch-30 hook
        # precedent for a legitimate entry gate).
        dur = _duration_param(fn)
        if dur is None:
            continue
        text = fn["text"]
        body = _fn_body(text)
        if not _has_lower_bound(body, dur):
            continue
        if _has_upper_bound(body, dur):
            continue
        mapping = _config_write(body, dur)
        if mapping is None:
            continue
        # The configured duration must gate withdrawals /
        # claims: a withdraw / claim / exit function reads the
        # same config and a block.timestamp check.
        gates_withdrawal = False
        for wfn in fns:
            if not _WITHDRAW_FN_RE.match(wfn["name"]):
                continue
            wtext = wfn["text"]
            if mapping in wtext and \
                    "block.timestamp" in wtext:
                gates_withdrawal = True
                break
        if not gates_withdrawal:
            continue
        # No escape: no cancel / remove / reset / delete path,
        # and no other function that writes the same config
        # (a replace path).
        if any(_ESCAPE_FN_RE.match(f["name"]) for f in fns):
            continue
        writers = _mapping_writers(scope, mapping)
        if any(w != name for w in writers):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' configures the "
            f"'{mapping}' duration '{dur}' with only a LOWER "
            f"bound (require({dur} >= MIN)) and NO upper bound, "
            f"the configured duration gates withdrawals / "
            f"claims (a withdraw / claim reads '{mapping}' "
            f"under a block.timestamp check), and the contract "
            f"has NO cancel / replace / reset path for the "
            f"configured item (no cancel / remove / reset "
            f"function, and '{fn['name']}' is the only writer "
            f"of '{mapping}') - so a misconfigured (or "
            f"maliciously set) duration freezes withdrawals "
            f"permanently with no way out. Gate analysis: the "
            f"setter is privileged by design - the finding is "
            f"the unescapable freeze it enables, not "
            f"unauthorized access; no upper bound and no escape "
            f"on the config path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "privileged period config: lower bound "
                    "only, no upper bound, no cancel / replace "
                    "/ reset path, duration gates withdrawals")
        # No recipient classification (batch-28 period-exit
        # precedent): the freeze lands on users - a stranger
        # triggering the config receives nothing directly.
        out.append(item)
        break
    return out


# ---------------------------------------------------------------------------
# 5. hook_sender_is_router_rebate_credit
# ---------------------------------------------------------------------------

_HOOK_FN_RE = re.compile(r"^_?(?:afterSwap|beforeSwap)$")
_REWARD_MAP_RE = re.compile(
    r"(?:rewards|rebates|pendingRewards|rebateCredits|"
    r"rewardCredits)")
_CLAIM_FN_RE = re.compile(r"^(?:claim|withdraw)\w*$", re.I)
_DISTRIBUTE_FN_RE = re.compile(
    r"^(?:distribute|split|disburse|allocate)\w*$", re.I)


def _sender_credit(body: str) -> Optional[str]:
    """The rewards mapping credited to the `sender`
    parameter (`rewards[sender] += ...` / `rewards[sender]
    = rewards[sender] + ...`), or None. A `= 0` reset is
    not a credit."""
    for m in re.finditer(
            r"\b((?:rewards|rebates|pendingRewards|"
            r"rebateCredits|rewardCredits))\s*\[\s*sender\s*\]"
            r"\s*(\+=|=(?!=))\s*([^;]{0,200})", body):
        mapping, op, rhs = (m.group(1), m.group(2),
                            m.group(3))
        if op == "+=":
            return mapping
        rhs = rhs.strip()
        if rhs == "0":
            continue
        return mapping
    return None


def _claim_pays_credited(searched_claims: str, mapping: str
                         ) -> bool:
    """A claim / withdraw function reads the credited
    mapping for msg.sender and transfers that balance to
    msg.sender (the direct claim path)."""
    mp = re.escape(mapping)
    if not re.search(r"\b" + mp +
                     r"\s*\[\s*msg\.sender\s*\]", searched_claims):
        return False
    if re.search(r"\.\s*transfer\s*\(\s*msg\.sender\b",
                 searched_claims):
        return True
    if re.search(r"\bsafeTransfer\s*\([^,]+,\s*msg\.sender\b",
                 searched_claims):
        return True
    if re.search(r"\.\s*call\s*\{\s*value\s*:[^}]*\}\s*\(\s*\"\"\)",
                 searched_claims) and \
            re.search(r"payable\s*\(\s*msg\.sender\s*\)",
                      searched_claims):
        return True
    return False


def _analyze_hook_sender_rebate(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _HOOK_FN_RE.match(fn["name"]):
            continue
        # The poolManager caller check is the legitimate v4
        # entry gate, not a suppressor (the batch-30 hook
        # precedent) - so no _skip_fn on hook callbacks.
        text = fn["text"]
        searched = text + "\n" + _called_internal_texts(
            text, scope)
        mapping = _sender_credit(searched)
        if mapping is None:
            continue
        # No distribution logic: a distribute / split /
        # disburse function that reads the same mapping
        # means the router credit is an intermediate, not the
        # payout.
        distributed = False
        for dfn in fns:
            if _DISTRIBUTE_FN_RE.match(dfn["name"]) and \
                    mapping in dfn["text"]:
                distributed = True
                break
        if distributed:
            continue
        # The direct claim path is REQUIRED: a claim /
        # withdraw that pays rewards[msg.sender] to
        # msg.sender.
        claims = "\n".join(
            cfn["text"] for cfn in fns
            if _CLAIM_FN_RE.match(cfn["name"]))
        if not claims:
            continue
        if not _claim_pays_credited(claims, mapping):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' credits the per-swap "
            f"rebate to the '{mapping}[sender]' balance - and "
            f"in v4 `sender` is the router, not the trader - "
            f"while a claim / withdraw pays "
            f"'{mapping}[msg.sender]' straight to msg.sender, "
            f"so the router accrues every swap's rebate and "
            f"claims it as its own, and the trader the rebate "
            f"was meant for receives nothing; there is no "
            f"distribution logic and no extraction of the "
            f"actual trader from hookData anywhere on the hook "
            f"path. Gate analysis: the hook callbacks are "
            f"poolManager-gated by design (the legitimate v4 "
            f"entry gate); the bug is the credited recipient, "
            f"not who may call the hook.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "hook credits the rebate to the router "
                    "(sender) with a direct claim path; no "
                    "trader extraction, no distribution")
        # No recipient classification (batch-28 period-exit
        # precedent): the credited recipient is the FIXED
        # router address - a stranger triggering the swap
        # receives nothing directly; the value accrues to the
        # router.
        out.append(item)
        break
    return out


ANALYZERS = {
    "bridge_redeem_no_peg_circuit_breaker":
        _analyze_bridge_redeem_no_peg,
    "aa_validator_owner_branch_no_execution_policy":
        _analyze_aa_validator_owner_no_policy,
    "swap_exact_output_unbounded_max_input":
        _analyze_swap_exact_output_unbounded,
    "period_config_no_upper_bound_no_escape":
        _analyze_period_config_no_bound_no_escape,
    "hook_sender_is_router_rebate_credit":
        _analyze_hook_sender_rebate,
}


def analyze_deep32_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-32 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep32_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit32Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 32)"
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
        for item in analyze_deep32_source(
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
                source="deep audit detector batch 32 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit32Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 32) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
