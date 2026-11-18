"""Deep-audit detectors, batch 26: order-signature description
validation, swap-output trusted reports, fee claims above
accrued fees, settlement swaps spending approvals, recorded
supply capping pool reserves.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- order_signature_validates_description_not_hash: a signature /
  order validation function verifies a description / metadata /
  label field (hashes it into the signed digest) and then
  executes / trades an order whose hash / id is never compared
  against the signed value, with value movement downstream of
  the check - the Curve CowSwapBurner shape (Nov 10, ~$38k:
  138 forged orders paired a legitimate description with
  wholly different transactions while the burner held
  unlimited CoW allowances). Hashing the order hash (or the
  full order struct) into the digest, or comparing it against
  the signed value, is the protected shape; a validation with
  no value movement downstream is out of scope. Distinct from
  eip712_digest_unbound_to_payload (a signature STRUCT that
  omits the payload it authorizes - here the struct is fine,
  the CHECK validates a different value than the one
  executed).
- swap_output_trusted_report_no_receipt_check: a swap / fee /
  settlement function credits reserves / an entitlement ledger
  from a reported / returned output amount (a router return
  value, a helper report, or a caller-supplied amountOut)
  with NO balance-delta receipt check on that leg, plus a
  downstream payout / withdraw reading the credited
  accounting - the Sovryn shape (Nov 10, Rootstock XUSD/WRBTC
  fee processing: a reported swap output was accepted though
  the tokens had never arrived, distorting reserves and
  enabling a large XUSD withdrawal). A before/after balanceOf
  receipt check, or crediting the measured balance delta
  itself, is the protected shape; a credit with no downstream
  payout is out of scope. Distinct from
  fee_on_transfer_overcredit (the RECEIVING / deposit leg -
  this one is the PAYOUT / settlement leg).
- fee_claim_exceeds_accrued_fees: a claimFees / withdrawFees /
  collectFees function pays an amount sized by a caller-
  supplied or pool-reported figure (a fee amount parameter,
  or a return value from a pool / market call) with NO
  comparison against a stored accrued-fees record for that
  pool / market, payout to the caller or a caller-supplied
  recipient - the Premia V3 fee-claim leg (Nov 1, ~$437k:
  fee claims from attacker-created empty option pools
  withdrew collateral "substantially more than the fees
  economically generated"). Capping the claim by a stored
  accrued-fees balance, or computing the figure from the
  contract's own stored state, is the protected shape.
  Distinct from vault_underwrites_attacker_created_pool
  (collateral sent INTO the pool - this one is fees claimed
  OUT of it).
- settlement_swap_executes_caller_target_spends_approvals:
  a swap / settle / execute function makes an external plain
  CALL to a caller-supplied target with caller-supplied
  calldata, with NO allowlist / router check on the target,
  in a contract holding standing token approvals (an approve
  / allowance pattern, or a transferFrom reachable on the
  path) - the Pennysia shape (Nov 12: the attacker routed
  malicious token interactions through the PennysiaSettlement
  executeSwap path, bypassing spending restrictions and
  abusing existing token approvals from four wallets).
  An allowlist / registry check binding the target, an
  owner gate, or no approval-spendable path at all is the
  protected shape. Distinct from
  multicall_arbitrary_delegatecall (DELEGATECALL to a
  caller-supplied target - this one is a plain call) and
  from access_control_arbitrary_call_injection (exec-family
  function names only, no approval context - this one
  requires the settlement / swap function family PLUS the
  standing-approval context).
- recorded_supply_caps_pool_reserves: a pool reserve /
  pricing read uses min(actual balance, recordedSupply) (or
  the equivalent ternary) where the recorded supply is a
  stored variable, PLUS a withdrawal / settlement path that
  decrements that same recorded supply without verifying the
  underlying transfer succeeded (unchecked return, try/catch
  swallowing the failure, or a state write the transfer
  cannot roll back) - the Polkadot dotUSD shape (Oct 2026,
  ~$1.38M DOT), translated to EVM: a failed withdrawal
  still decrements the recorded supply, the pool then prices
  the asset as scarcer than it is. Reading the raw balance
  only, or guarding the decrement with a transfer-success
  check, is the protected shape. This one fires WITHOUT a
  recipient classification (batch-20 auction precedent):
  the withdraw itself pays the caller's own balance - the
  stranger-receivable value is the mispriced pool trade the
  desync enables, not the withdrawal, so it is medium
  severity, no candidate claim.

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
FAMILY = "deep26"

SPECS = [
    S("order_signature_validates_description_not_hash", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Order signature validates the description, not "
             "the executed order: a signature / order "
             "validation function hashes a description / "
             "metadata / label field into the signed digest "
             "and then executes / trades an order whose hash / "
             "id is never compared against the signed value, "
             "with value movement downstream of the check, so "
             "a legitimate description pairs with a wholly "
             "different order - the Curve CowSwapBurner shape. "
             "Hashing the order hash (or the full order struct) "
             "into the digest, or comparing it against the "
             "signed value, is the protected shape; a "
             "validation with no value movement downstream is "
             "out of scope.",
      fix="Bind the executed order into the signature: hash "
          "the order hash (or the full order struct) into the "
          "digest the signature is verified against, and "
          "require the executed order's hash to equal the "
          "signed value before any value moves."),
    S("swap_output_trusted_report_no_receipt_check", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Swap settlement trusts a reported output with no "
             "receipt check: a swap / fee / settlement function "
             "credits reserves / an entitlement ledger from a "
             "reported / returned output amount (a router "
             "return value, a helper report, or a "
             "caller-supplied amountOut) with NO balance-delta "
             "receipt check on that leg, plus a downstream "
             "payout / withdraw reading the credited "
             "accounting, so output that never arrived is "
             "still spendable - the Sovryn shape. A before / "
             "after balanceOf receipt check, or crediting the "
             "measured balance delta itself, is the protected "
             "shape.",
      fix="Never credit a reported amount: measure the actual "
          "receipt (balanceOf before and after the swap leg, "
          "require the delta covers the reported amount) and "
          "credit only the delta that really arrived."),
    S("fee_claim_exceeds_accrued_fees", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Fee claim pays more than fees accrued: a "
             "claimFees / withdrawFees / collectFees function "
             "pays an amount sized by a caller-supplied or "
             "pool-reported figure (a fee amount parameter, or "
             "a return value from a pool / market call) with "
             "NO comparison against a stored accrued-fees "
             "record for that pool / market, payout to the "
             "caller or a caller-supplied recipient - the "
             "Premia V3 fee-claim leg. Capping the claim by a "
             "stored accrued-fees balance, or computing the "
             "figure from the contract's own stored state, is "
             "the protected shape.",
      fix="Cap every fee claim by the stored record: require "
          "the claimed amount <= accruedFees[pool] (or the "
          "contract's own fees-earned record for that pool / "
          "market) and decrement the record by the amount "
          "paid, before the payout."),
    S("settlement_swap_executes_caller_target_spends_approvals",
      FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Settlement swap executes a caller target and "
             "spends standing approvals: a swap / settle / "
             "execute function makes an external plain CALL to "
             "a caller-supplied target with caller-supplied "
             "calldata, with NO allowlist / router check on "
             "the target, in a contract holding standing token "
             "approvals (an approve / allowance pattern, or a "
             "transferFrom reachable on the path), so the "
             "caller routes arbitrary token interactions "
             "through the settlement path and spends other "
             "users' approvals - the Pennysia shape. An "
             "allowlist / registry check binding the target, "
             "an owner gate, or no approval-spendable path at "
             "all is the protected shape.",
      fix="Never call a caller-supplied target from a "
          "settlement path: require the target against an "
          "explicit allowlist (or bind it to the stored "
          "router) before the call, and keep settlement "
          "approvals scoped to the exact router the settlement "
          "is for."),
    S("recorded_supply_caps_pool_reserves", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="Pool reserves are capped by a recorded supply "
             "that can desync: a reserve / pricing read uses "
             "min(actual balance, recordedSupply) (or the "
             "equivalent ternary) where the recorded supply is "
             "a stored variable, PLUS a withdrawal / "
             "settlement path decrements that same recorded "
             "supply without verifying the underlying transfer "
             "succeeded (unchecked return, try / catch "
             "swallowing the failure), so a failed withdrawal "
             "still shrinks the recorded supply and the pool "
             "prices the asset as scarcer than it is - the "
             "Polkadot dotUSD shape, translated to EVM. "
             "Reading the raw balance only, or guarding the "
             "decrement with a transfer-success check, is the "
             "protected shape. No recipient classification: "
             "the withdraw itself pays the caller's own "
             "balance - the stranger-receivable value is the "
             "mispriced pool trade the desync enables.",
      fix="Price off the raw balance, never a recorded-supply "
          "cap, and never decrement recorded supply except "
          "after a verified transfer: require the transfer's "
          "success (or the call's ok flag) before writing the "
          "new supply, so a failed withdrawal leaves the "
          "record untouched."),
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
# 1. order_signature_validates_description_not_hash
# ---------------------------------------------------------------------------

_ORDER_FN_RE = re.compile(
    r"isValidSignature|"
    r"(?:validate|verify|execute|settle|fulfill|process|trade)"
    r"\w*order|"
    r"order\w*(?:validate|verify|execute|settle|fulfill|"
    r"process|trade)", re.I)
_DESC_PARAM_RE = re.compile(
    r"^(?:description|orderDescription|metadata|orderMetadata|"
    r"label|memo|orderLabel)$", re.I)
_HASH_PARAM_RE = re.compile(
    r"^(?:orderHash|orderId|hash|orderUid|uid)$", re.I)
_SIG_CHECK_RE = re.compile(
    r"ecrecover\s*\(|ECDSA\s*\.\s*recover\s*\(|"
    r"isValidSignature\s*\(|Signature\s*\.\s*recover\s*\(")


def _keccak_arg_mentions(text: str, param: str) -> bool:
    """A keccak256(...) argument list mentioning the param."""
    for m in re.finditer(r"keccak256\s*\(", text):
        i = text.index("(", m.start())
        inner, _ = _balanced(text, i)
        if _mentions(inner, param):
            return True
    return False


def _order_hash_bound(searched: str, hash_param: str) -> bool:
    """The order hash is bound into the signature check: it is
    hashed into a digest, or compared (==) against a signed /
    digest value. A bare mention (passed to an executor, stored
    in a mapping) is NOT a binding."""
    if _keccak_arg_mentions(searched, hash_param):
        return True
    hp = re.escape(hash_param)
    if re.search(r"\b" + hp + r"\b\s*==|==\s*\b" + hp + r"\b",
                 searched):
        return True
    return False


def _analyze_order_sig(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _ORDER_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        typed = _fn_params_typed(fn)
        hash_params = [n for (t, n) in typed
                       if _HASH_PARAM_RE.match(n)]
        desc_params = [n for (t, n) in typed
                       if _DESC_PARAM_RE.match(n)]
        if not hash_params or not desc_params:
            continue
        text = fn["text"]
        searched = text + "\n" + _called_internal_texts(text, scope)
        if not _SIG_CHECK_RE.search(text):
            continue
        # The description must be the value the signature is
        # verified over: it appears inside a keccak256 digest
        # (or inside the recover call's arguments).
        desc_in_digest = any(
            _keccak_arg_mentions(text, d) for d in desc_params)
        if not desc_in_digest:
            for m in _SIG_CHECK_RE.finditer(text):
                i = text.index("(", m.start())
                inner, _ = _balanced(text, i)
                if any(_mentions(inner, d)
                       for d in desc_params):
                    desc_in_digest = True
                    break
        if not desc_in_digest:
            continue
        hash_param = hash_params[0]
        if _order_hash_bound(searched, hash_param):
            continue
        if not _moves_value(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a signature "
            f"over the description '{desc_params[0]}' (hashed "
            f"into the signed digest) but the executed order "
            f"hash '{hash_param}' is never hashed into that "
            f"digest and never compared against the signed "
            f"value anywhere on the path (not in the function, "
            f"not in an internal helper it calls), while value "
            f"moves downstream of the check - so a legitimate "
            f"description pairs with a wholly different order. "
            f"Gate analysis: no caller-identity gate, no order "
            f"hash binding on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated order validation: signature checks "
                    "the description, the executed order hash "
                    "is never bound to the signed value")
        out.append(_finish_recipient(spec, item, searched))
    return out


# ---------------------------------------------------------------------------
# 2. swap_output_trusted_report_no_receipt_check
# ---------------------------------------------------------------------------

_SWAP_FN_RE = re.compile(
    r"swap|settle|processFee|handleFee|distributeFee|"
    r"processSwap|handleSwap", re.I)
_REPORTED_PARAM_RE = re.compile(
    r"^(?:amountOut|outputAmount|reportedAmount|reportedOutput|"
    r"swapOutput)$", re.I)
_SWAP_CALL_RE = re.compile(
    r"\b(?:swap|exchange|convert|swapExact\w+|exactInput|"
    r"exactOutput)\s*\(")
_PAYOUT_FN_RE = re.compile(
    r"^(?:withdraw|payout|claim|redeem|exit)\w*$", re.I)


def _reported_var(body: str, params: List[str]
                  ) -> Optional[str]:
    """The reported-output variable: a local assigned from a
    swap-ish external call's return value, or a caller-supplied
    amountOut-style parameter. The call-assigned form wins
    (a router return is the canonical Sovryn shape)."""
    # Strip interface casts (IPool(pool).feesOwed -> pool.feesOwed)
    # so the receiver of a wrapped call is readable.
    flat = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\((\w+)\)\.",
                  r"\1.", body)
    for m in re.finditer(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]{0,200}?\.\s*"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", flat):
        if _SWAP_CALL_RE.search(m.group(0)) or \
                _SWAP_CALL_RE.search(m.group(2)):
            return m.group(1)
    for p in params:
        if _REPORTED_PARAM_RE.match(p):
            return p
    return None


def _has_receipt_check(searched: str, reported: str) -> bool:
    """A balance-delta / actual-receipt check on the path: a
    before/after balanceOf pair, or a require/if comparing a
    received/actual figure against the reported amount. A
    single stray balanceOf read (a cap check, a view) is NOT
    a receipt check."""
    if searched.count("balanceOf") >= 2:
        return True
    rp = re.escape(reported)
    if re.search(
            r"(?:require|if)\s*\([^;]{0,300}?\b(?:received|"
            r"actual\w*)\b[^;]{0,120}?(?:>=|<=|==)[^;]{0,120}?\b"
            + rp + r"\b", searched):
        return True
    if re.search(
            r"(?:require|if)\s*\([^;]{0,300}?\b" + rp +
            r"\b[^;]{0,120}?(?:<=|>=|==)[^;]{0,120}?\b(?:"
            r"received|actual\w*)\b", searched):
        return True
    return False


def _credit_statements(body: str, reported: str
                       ) -> List[Tuple[str, str]]:
    """(mapping, key) for every `mapping[key] += <reported>`
    credit in the body, plus bare `stateVar += <reported>`
    credits (mapping, key) with an empty key."""
    out: List[Tuple[str, str]] = []
    for m in re.finditer(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\[([^\]]+)\]\s*\+=\s*"
            r"([^;]{0,120})", body):
        if _mentions(m.group(3), reported):
            out.append((m.group(1), m.group(2).strip()))
    for m in re.finditer(
            r"(?<![\w\.\[])([A-Za-z_][A-Za-z0-9_]*)\s*\+=\s*"
            r"([^;]{0,120})", body):
        if _mentions(m.group(2), reported):
            name = m.group(1)
            if not any(c[0] == name for c in out):
                out.append((name, ""))
    return out


def _payout_reads_mapping(scope, fns, mapping: str
                          ) -> Optional[Dict[str, Any]]:
    """A withdraw / payout / claim / redeem function that reads
    the credited mapping and moves value, else None."""
    for fn in fns:
        if not _PAYOUT_FN_RE.match(fn["name"]):
            continue
        text = fn["text"]
        if mapping not in text:
            continue
        if not _moves_value(text):
            continue
        return fn
    return None


def _analyze_swap_output(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SWAP_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        body = _fn_body(text)
        reported = _reported_var(body, params)
        if reported is None:
            continue
        credits = _credit_statements(body, reported)
        if not credits:
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if _has_receipt_check(searched, reported):
            continue
        # A downstream payout / withdraw must read one of the
        # credited mappings - a credit with no payout is out
        # of scope (no spendable value).
        payout_fn = None
        payout_mapping = None
        for mapping, _key in credits:
            payout_fn = _payout_reads_mapping(scope, fns, mapping)
            if payout_fn is not None:
                payout_mapping = mapping
                break
        if payout_fn is None:
            continue
        # The recipient is the key of the credit the payout
        # reads: the credited entitlement IS the value the
        # stranger receives (classifying the downstream
        # withdraw's transfer would misread it as
        # HOLDER-SELF, metered by the very credit that is
        # the fraud).
        recipient = "UNRESOLVED"
        rdetail = "no credited-entitlement key found"
        for mapping, key in credits:
            if mapping != payout_mapping or not key:
                continue
            recipient, rdetail = _dest_class(key, params, state)
            if recipient == "CALLER":
                break
            if recipient == "CALLER-SUPPLIED":
                continue
            break
        detail = spec.detail + (
            f" Observed: '{fn['name']}' credits the reported "
            f"output '{reported}' to the ledger "
            f"({', '.join(m for m, _k in credits)}) with no "
            f"balance-delta receipt check anywhere on the path "
            f"(no before/after balanceOf pair, no "
            f"received-vs-reported comparison, not even in an "
            f"internal helper it calls), and the downstream "
            f"'{payout_fn['name']}' pays out of the credited "
            f"'{payout_mapping}' accounting - so output that "
            f"never arrived is still spendable. Gate "
            f"analysis: no caller-identity gate, no receipt "
            f"check on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated swap settlement: reported output "
                    "credited with no receipt check, payout "
                    "reads the credited accounting")
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 3. fee_claim_exceeds_accrued_fees
# ---------------------------------------------------------------------------

_FEE_CLAIM_FN_RE = re.compile(
    r"(?:claim|withdraw|collect)\w*[Ff]ee\w*", re.I)
_FEE_AMOUNT_PARAM_RE = re.compile(
    r"^(?:amount|feeAmount|fees|claimAmount|payout)$", re.I)
_ACCRUED_TERM_RE = re.compile(
    r"accrued|earned|claimable|pendingFee|feesAccrued|"
    r"feesAvailable|totalFeesEarned", re.I)
_BALANCE_CALL_RE = re.compile(
    r"^(?:balanceOf|totalSupply|allowance|decimals)$")


def _fee_figure(body: str, params: List[str]
                ) -> Optional[str]:
    """The figure sizing the payout: a fee-amount parameter,
    or a local assigned from an external pool / market call's
    return value. A figure computed from the contract's own
    stored state (a mapping read) is NOT a figure here - it
    is the protected shape, not this one."""
    for p in params:
        if _FEE_AMOUNT_PARAM_RE.match(p):
            return p
    flat = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\((\w+)\)\.",
                  r"\1.", body)
    for m in re.finditer(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]{0,200}?\.\s*"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", flat):
        if _BALANCE_CALL_RE.match(m.group(2)):
            continue
        return m.group(1)
    return None


def _payout_uses_figure(body: str, figure: str) -> bool:
    """A token / ETH payout in the body whose amount argument
    mentions the figure."""
    for m in _VALUE_MOVE_RE.finditer(body):
        i = body.index("(", m.start())
        inner, _ = _balanced(body, i)
        if _mentions(inner, figure):
            return True
    return False


def _accrued_capped(searched: str, figure: str) -> bool:
    """The claim is capped by a stored accrued-fees record: a
    require / if comparing the figure against an accrued term,
    or a min() against one. The record must be CONSULTED on
    the path - merely declaring the mapping does not cap
    anything."""
    fp = re.escape(figure)
    for m in re.finditer(
            r"(?:require|if)\s*\(([^;]{0,300})\)", searched):
        stmt = m.group(1)
        if not _ACCRUED_TERM_RE.search(stmt):
            continue
        if _mentions(stmt, figure) or re.search(r"<=|>=|==|<|>",
                                                stmt):
            return True
    if re.search(r"\bmin\s*\([^)]*(?:" +
                 _ACCRUED_TERM_RE.pattern + r")[^)]*\)", searched):
        return True
    if re.search(r"\b" + fp +
                 r"\b\s*=\s*[^;]{0,80}?min\s*\([^)]*(?:" +
                 _ACCRUED_TERM_RE.pattern + r")", searched):
        return True
    return False


def _analyze_fee_claim(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _FEE_CLAIM_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        body = _fn_body(text)
        figure = _fee_figure(body, params)
        if figure is None:
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if not _payout_uses_figure(_fn_body(searched), figure) \
                and not _payout_uses_figure(body, figure):
            continue
        if _accrued_capped(searched, figure):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' pays out the figure "
            f"'{figure}' (a caller-supplied amount / pool-"
            f"reported return value) with no comparison "
            f"against any stored accrued-fees record for the "
            f"pool / market anywhere on the path (no require / "
            f"if capping the figure by an accrued balance, no "
            f"min() against one, not even in an internal "
            f"helper it calls), so the claim can exceed the "
            f"fees actually accrued. Gate analysis: no "
            f"caller-identity gate, no accrued-fees cap on "
            f"the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated fee claim: payout sized by a "
                    "caller-supplied / pool-reported figure, "
                    "never compared against accrued fees")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. settlement_swap_executes_caller_target_spends_approvals
# ---------------------------------------------------------------------------

_EXEC_FN_RE = re.compile(r"swap|settle|execute", re.I)


def _caller_call(body: str, addr_params: List[str],
                 bytes_params: List[str]
                 ) -> Optional[Tuple[str, str]]:
    """(target param, calldata param) for a plain `.call(`
    (optionally `.call{value: ...}(`) whose receiver is a
    caller-supplied address parameter and whose arguments
    mention a caller-supplied bytes parameter. A
    delegatecall is NOT this shape (multicall detector owns
    it); a call to a stored router is NOT this shape."""
    for m in re.finditer(
            r"\.\s*call\s*(?:\{[^}]*\})?\s*\(", body):
        head = body[:m.start()]
        rm = re.search(
            r"([A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]*\])?)\s*$",
            head)
        if not rm:
            continue
        recv = rm.group(1)
        base = recv.split("[")[0].strip()
        if base not in addr_params:
            continue
        i = body.index("(", m.start())
        inner, _ = _balanced(body, i)
        bp = [p for p in bytes_params
              if _mentions(inner, p)]
        if not bp:
            continue
        return base, bp[0]
    return None


def _target_bound(searched: str, target: str) -> bool:
    """The target is bound to a stored value: a require / if
    comparing it (==) against something that is not
    address(0). A non-zero check is not a binding."""
    tp = re.escape(target)
    for m in re.finditer(
            r"(?:require|if)\s*\(([^;]{0,300})\)", searched):
        stmt = m.group(1)
        if not re.search(r"\b" + tp + r"\b\s*==|==\s*\b" + tp +
                         r"\b", stmt):
            continue
        if "address(0)" in stmt or "address(0x0)" in stmt:
            continue
        return True
    return False


def _has_approval_context(scope, searched: str) -> bool:
    """The contract holds standing token approvals: a
    transferFrom is reachable on this path, or an approve /
    allowance pattern exists anywhere in the contract."""
    if "transferFrom" in searched:
        return True
    scoped = scope.scoped_text
    if re.search(r"\.\s*approve\s*\(|allowance\s*\(", scoped):
        return True
    return False


def _analyze_settlement_swap(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _EXEC_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        typed = _fn_params_typed(fn)
        addr_params = [n for (t, n) in typed
                       if t == "address" or
                       t.startswith("address[")]
        bytes_params = [n for (t, n) in typed
                        if t == "bytes" or
                        t.startswith("bytes[")]
        if not addr_params or not bytes_params:
            continue
        body = _fn_body(fn["text"])
        call = _caller_call(body, addr_params, bytes_params)
        if call is None:
            continue
        target, data = call
        searched = fn["text"] + "\n" + _called_internal_texts(
            fn["text"], scope)
        if _ALLOWLIST_RE.search(searched):
            continue
        if _target_bound(searched, target):
            continue
        if not _has_approval_context(scope, searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' makes an external "
            f"plain call to the caller-supplied target "
            f"'{target}' with the caller-supplied calldata "
            f"'{data}', with no allowlist / router check "
            f"binding the target anywhere on the path (not "
            f"even in an internal helper it calls), in a "
            f"contract holding standing token approvals (a "
            f"transferFrom reachable on the path, and/or an "
            f"approve / allowance pattern in the contract), "
            f"so the caller routes arbitrary token "
            f"interactions through the settlement path and "
            f"spends other users' approvals. Gate analysis: "
            f"no caller-identity gate, no target allowlist, "
            f"approval-spendable path present.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "ungated settlement swap: plain call to a "
                    "caller-supplied target with caller-supplied "
                    "calldata, standing approvals spendable")
        out.append(_classify(
            item, "CALLER",
            f"the caller supplies both the call target "
            f"'{target}' and the calldata '{data}': the caller "
            f"controls the interaction and the contract's "
            f"standing approvals are spendable through it"))
    return out


# ---------------------------------------------------------------------------
# 5. recorded_supply_caps_pool_reserves
# ---------------------------------------------------------------------------

_SUPPLY_TERM_RE = re.compile(
    r"\b(?:recordedSupply|totalSupply|issuedSupply|"
    r"mintedSupply|outstandingSupply|supplyCap|recordedTotal|"
    r"totalIssued)\b")
_WITHDRAW_FN_RE = re.compile(
    r"^(?:withdraw|redeem|settle|exit|burn)\w*$", re.I)


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


def _find_supply_caps(scope, fns) -> Dict[str, str]:
    """{supply var: capping function name} for every reserve /
    pricing read that caps a balance (raw or via a balance
    proxy local) by a recorded-supply variable, via min() or
    a ternary. View functions ARE scanned here: the cap is
    usually read in a view pricing function."""
    caps: Dict[str, str] = {}
    for fn in fns:
        text = fn["text"]
        proxies = _balance_proxies(text)
        for m in _SUPPLY_TERM_RE.finditer(text):
            supply_var = m.group(0)
            if supply_var in caps:
                continue
            # The supply term must appear in a statement that
            # also reads a balance (raw balanceOf, or a
            # balance-proxy local) and caps it (min or
            # ternary) - a bare declaration / read of the
            # supply var is not a cap.
            for stmt in re.split(r"[;\n]", text):
                if supply_var not in stmt:
                    continue
                has_balance = "balanceOf" in stmt or any(
                    _mentions(stmt, p) for p in proxies)
                if not has_balance:
                    continue
                if "min(" in stmt or ("?" in stmt and
                                      ":" in stmt):
                    caps[supply_var] = fn["name"]
                    break
    return caps


def _transfer_guarded(text: str) -> bool:
    """A token / ETH transfer on this path is verified: a
    require wrapping the transfer / call itself, a require on
    the call's ok / success flag, or an if(!ok) revert. A
    try / catch that swallows the failure is NOT a guard."""
    if re.search(
            r"require\s*\([^;]{0,300}?\.\s*(?:transfer|"
            r"transferFrom|call)\s*[\(\{]", text):
        return True
    if re.search(r"require\s*\(\s*(?:ok|success)\b", text):
        return True
    if re.search(
            r"if\s*\(\s*!\s*(?:ok|success)\b[^)]*\)\s*revert",
            text):
        return True
    return False


def _decrements_supply(body: str, supply_var: str) -> bool:
    sv = re.escape(supply_var)
    if re.search(r"\b" + sv + r"\b\s*-=", body):
        return True
    if re.search(r"\b" + sv + r"\b\s*=\s*\b" + sv +
                 r"\b\s*-", body):
        return True
    if re.search(r"\b" + sv + r"\b\s*--", body):
        return True
    return False


def _analyze_recorded_supply(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    caps = _find_supply_caps(scope, fns)
    if not caps:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _WITHDRAW_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        searched = text + "\n" + _called_internal_texts(text, scope)
        if not _moves_value(searched):
            continue
        for supply_var, cap_fn in caps.items():
            if not _decrements_supply(body, supply_var):
                continue
            if _transfer_guarded(searched):
                continue
            detail = spec.detail + (
                f" Observed: the reserve / pricing read in "
                f"'{cap_fn}' caps the actual balance by the "
                f"recorded supply '{supply_var}' "
                f"(min(balance, {supply_var}) or the ternary "
                f"equivalent), and '{fn['name']}' decrements "
                f"that same '{supply_var}' while its token "
                f"transfer is unverified (no require wrapping "
                f"the transfer, no require on the call's ok / "
                f"success flag, no if(!ok) revert on the path "
                f"- a try / catch that swallows the failure "
                f"counts as unverified), so a failed "
                f"withdrawal still shrinks the recorded supply "
                f"and the pool prices the asset as scarcer "
                f"than it is. Gate analysis: no "
                f"caller-identity gate, no transfer-success "
                f"guard on the decrement path.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "ungated withdrawal: recorded supply "
                        "decremented without a verified transfer, "
                        "reserves capped by that supply")
            # No recipient classification: the withdraw pays
            # the caller's own balance - the stranger-receivable
            # value is the mispriced pool trade the desync
            # enables, not the withdrawal (batch-20 auction
            # precedent).
            out.append(item)
            break
    return out


ANALYZERS = {
    "order_signature_validates_description_not_hash":
        _analyze_order_sig,
    "swap_output_trusted_report_no_receipt_check":
        _analyze_swap_output,
    "fee_claim_exceeds_accrued_fees": _analyze_fee_claim,
    "settlement_swap_executes_caller_target_spends_approvals":
        _analyze_settlement_swap,
    "recorded_supply_caps_pool_reserves": _analyze_recorded_supply,
}


def analyze_deep26_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-26 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep26_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit26Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 26)"
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
        for item in analyze_deep26_source(
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
                source="deep audit detector batch 26 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit26Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 26) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
