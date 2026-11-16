"""Deep-audit detectors, batch 3: AI plugin dev (2026-11-04).

Five more chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-2 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- transient_latch_unconsumed: a transient-storage (EIP- transient
  tstore/tload) auth latch checked as one-time proof that a
  privileged delivery/callback happened, then a privileged
  external call or state write follows WITHOUT clearing the slot
  back to zero after the check. The latch stays set, so the same
  proof authorizes the privileged effect again - the zkLink Nova
  Oct 2026 shape (~$743k). A tstore(slot, 0) reset after the
  check - free-function or method-style slot.tstore(0) (OZ
  TransientSlot usage) - or a latch slot hashed over
  target+payload, is the protected shape and stays silent.
- v4_hook_shared_delta_take_pair: a Uniswap v4 hook
  (beforeSwap / afterSwap / beforeAddLiquidity / ...) that
  takes pool credit with PositionManager
  modifyLiquiditiesWithoutUnlock / take (TAKE_PAIR) WITHOUT
  opening its own unlock and WITHOUT asserting currencyDelta ==
  0 / delta isolation. The hook spends from the PoolManager's
  shared ledger without proving the delta it takes is its own -
  the GoldPesa GPXHooks Base Oct 2026 shape (~$115k USDC).
  Distinct from batch-2 hook_cei_reentrancy (CEI ordering: a
  hook invoked BEFORE accounting writes): this one is
  shared-ledger delta accounting - it fires on the WithoutUnlock
  take itself, regardless of call/write ordering, and stays
  silent when the hook opens its own unlock or asserts delta
  isolation first.
- inverted_division_zero_collapse: a lending/borrow function
  computing a rate/price as CONSTANT / oraclePrice (or 1eX /
  sharePrice) with integer division and NO require(result > 0)
  / sanity bound, where the collapsed result feeds a
  solvency/LTV/borrow-limit check that PASSES when the value
  is 0 (e.g. require(amount * rate <= limit): rate 0 makes the
  left side 0, so any amount passes). The ResupplyFi Jun 2025
  shape (~$9.5M). Distinct from
  math_division_before_multiplication (precision loss from
  dividing before multiplying): this one needs the
  constant-over-price shape, the missing zero-guard, AND a
  solvency/borrow-limit use that passes at zero - a bare
  division never fires.
- share_transfer_cancel_desync: a vault/prize contract storing
  a per-user entitlement in a mapping at join/deposit, issuing
  freely ERC-20-transferable shares, but cancel()/withdraw()
  refunding from the STORED mapping while burning
  balanceOf(msg.sender) - which may be 0 after the user
  transferred their shares away, or double-counted if they
  received more. The stored and live ledgers desync, so a user
  can exit twice (transfer shares, then cancel on the stored
  entitlement) or be shorted. The BriVault CodeHawks 2025-11
  shape (findings #4/#259). Distinct from
  staking_total_shares_mismatch (fee-on-transfer deposit
  overcredit: shares credited from the requested rather than
  the received amount): this one needs all three legs -
  stored entitlement, transferable shares, and a cancel path
  that refunds stored while burning live without reconciling
  them. Non-transferable shares, or a cancel that burns from
  the stored mapping, stays silent.
- eip712_digest_unbound_to_payload: an EIP-712 signature
  (fee approval / claim / mint authorization) whose signed
  struct OMITS the payload it authorizes - no payload hash,
  batch index, amount, or recipient - then applied in a
  loop/batch over N distinct payloads or to a caller-chosen
  payload after a single verification. One approval authorizes
  an arbitrary batch. The Lombard Finance Sherlock 2026-04
  shape (M-2). Distinct from cp_proto_permit_signature_replay
  (replay: the same permit reused because nonce/deadline
  handling is missing): this one is digest SCOPE - the
  signature is valid and fresh, it just does not bind what it
  is spent on. A struct carrying a payload hash (plus batch
  nonce) stays silent.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. The mechanism
under analysis itself does NOT count as such a gate: the
tload latch check and the ecrecover verification are the
claimed authorization being audited, so they never suppress.
(This is a deliberate narrowing of cl._gated_deep, which
treats ANY ecrecover and any mapping-balance require as a
gate; applied literally it would suppress both of those
detectors' own subjects.)

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
FAMILY = "deep3"

SPECS = [
    S("transient_latch_unconsumed", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Transient-storage auth latch never consumed: the "
             "function checks a tload latch as one-time proof "
             "that a privileged delivery/callback happened, "
             "then performs a privileged external call or "
             "state write without ever clearing the slot back "
             "to zero. The latch stays set, so the same proof "
             "authorizes the privileged effect again - the "
             "zkLink Nova shape. A tstore(slot, 0) reset after "
             "the check, or a latch slot hashed over "
             "target+payload, is the protected shape.",
      fix="Clear the latch immediately after the check "
          "(tstore(slot, 0)) before any privileged effect, "
          "or bind the latch slot to the exact target and "
          "payload it authorizes (keccak256 over "
          "target+payload)."),
    S("v4_hook_shared_delta_take_pair", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Uniswap v4 hook shared-delta take: the hook "
             "takes pool credit via PositionManager "
             "modifyLiquiditiesWithoutUnlock / take "
             "(TAKE_PAIR) without opening its own unlock and "
             "without asserting currencyDelta == 0 / delta "
             "isolation. The hook spends from the "
             "PoolManager's shared ledger without proving "
             "the delta it takes is its own - the GoldPesa "
             "GPXHooks shape. Opening the hook's own unlock, "
             "or asserting delta isolation before taking, is "
             "the protected shape.",
      fix="Open the hook's own unlock around the take, or "
          "assert currencyDelta == 0 / delta isolation "
          "before taking any credit from the shared ledger."),
    S("inverted_division_zero_collapse", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Inverted-division zero collapse: a borrow "
             "function computes a rate/price as CONSTANT / "
             "oraclePrice with integer division and no "
             "require(result > 0) / sanity bound, and the "
             "result feeds a solvency/LTV/borrow-limit check "
             "that PASSES when the value is 0 (a require of "
             "the form amount * rate <= limit is trivially "
             "true at rate 0). Once the oracle price exceeds "
             "the constant, the rate collapses to 0 and the "
             "borrow limit stops binding - the ResupplyFi "
             "shape.",
      fix="Require the computed rate to be strictly positive "
          "(require(rate > 0)) and bound the oracle price "
          "against the constant before using the rate in "
          "any solvency check."),
    S("share_transfer_cancel_desync", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Share-transfer cancel desync: the contract "
             "stores a per-user entitlement in a mapping at "
             "join/deposit, issues freely transferable "
             "shares, but cancel()/withdraw() refunds from "
             "the STORED mapping while burning "
             "balanceOf(msg.sender) - which may be 0 after "
             "the user transferred their shares away - "
             "without reconciling stored vs live balance. "
             "A user can transfer shares and then still "
             "cancel on the stored entitlement (double "
             "exit), or be shorted when the ledgers diverge "
             "- the BriVault shape. Non-transferable "
             "shares, or a cancel that burns from the "
             "stored mapping, is the protected shape.",
      fix="Make shares non-transferable, or reconcile the "
          "ledgers at cancel: burn from the stored "
          "entitlement (not balanceOf) and require the "
          "stored entitlement to match the live balance "
          "before refunding."),
    S("eip712_digest_unbound_to_payload", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="EIP-712 digest unbound to payload: the signed "
             "struct omits the payload it authorizes - no "
             "payload hash, batch index, amount, or "
             "recipient - and a single verification is then "
             "applied in a loop/batch over N distinct "
             "payloads or to a caller-chosen payload. One "
             "approval authorizes an arbitrary batch - the "
             "Lombard Finance shape. A struct carrying a "
             "payload hash (plus batch nonce) is the "
             "protected shape.",
      fix="Bind the payload into the signed struct: include "
          "a payload hash over the exact recipients, "
          "amounts and calldata, plus a batch nonce, and "
          "verify the hash matches the executed batch "
          "before applying it."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers
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
    or a role check suppresses. The tload latch check and the
    ecrecover verification under analysis are NOT gates here.
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


# ---------------------------------------------------------------------------
# 1. Transient-storage auth latch never consumed
# ---------------------------------------------------------------------------

_TLOAD_RE = re.compile(r"\btload\s*\(")
_TSTORE_RE = re.compile(r"\btstore\s*\(")


def _method_receiver(text: str, m) -> str:
    """Identifier before `.method(` for a method-style call
    (e.g. `slot` in `slot.tstore(0)` / `slot.tload()`), else
    ''. OpenZeppelin TransientSlot is used this way
    (`using TransientSlot for bytes32`), and a reset written
    as `slot.tstore(0)` is a real reset - the free-function
    `tstore(slot, 0)` shape is not the only one."""
    i = m.start() - 1
    if i < 0 or text[i] != ".":
        return ""
    j = i - 1
    while j >= 0 and (text[j].isalnum() or text[j] == "_"):
        j -= 1
    return text[j + 1:i]
_TLOAD_ASSIGN_RE = re.compile(
    r"([A-Za-z_]\w*)\s*(?::=|=)\s*[^;{]*?\btload\s*\(")
_CHECK_RE = re.compile(r"\b(require|assert|if)\s*\(")
_ZERO_VALUE_RE = re.compile(r"^(0|bytes32\s*\(\s*0\s*\)|0x0+)$")


def _analyze_transient_latch(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        tloads = list(_TLOAD_RE.finditer(text))
        if not tloads:
            continue
        # Slot args of every tload; a keccak256-hashed slot
        # binds target+payload and is the protected shape.
        slots: List[Tuple[int, str]] = []
        hash_bound = False
        # A slot hashed over target+payload is the protected
        # shape even when the hash lives in a local: the
        # tload reads the hashed slot, not a bare counter.
        hashed_locals = {
            m.group(1) for m in re.finditer(
                r"([A-Za-z_]\w*)\s*=\s*[^;]*keccak256\s*\(",
                text)}
        for m in tloads:
            recv = _method_receiver(text, m)
            if recv:
                # Method-style: slot.tload() - the receiver
                # IS the slot.
                slot = recv
            else:
                args = _call_args(text, m)
                slot = re.sub(r"\s+", " ", args[0]).strip() \
                    if args else ""
            slots.append((m.start(), slot))
            if "keccak256" in slot or \
                    slot in hashed_locals:
                hash_bound = True
        if hash_bound:
            continue
        # The check: a require/if/assert AFTER a tload that
        # mentions tload itself or a variable assigned from it.
        assigned = {m.group(1) for m in
                    _TLOAD_ASSIGN_RE.finditer(text)}
        check_pos: Optional[int] = None
        for m in _CHECK_RE.finditer(text):
            if m.start() <= tloads[0].start():
                continue
            head = text[m.start():m.start() + 200]
            if "tload" in head or any(
                    re.search(r"\b" + re.escape(v) + r"\b", head)
                    for v in assigned):
                check_pos = m.start()
                break
        if check_pos is None:
            continue
        # Reset: tstore(same slot, 0) anywhere in the function
        # - free-function tstore(slot, 0) or method-style
        # slot.tstore(0).
        reset = False
        slot_names = [s for _, s in slots]
        for m in _TSTORE_RE.finditer(text):
            recv = _method_receiver(text, m)
            args = _call_args(text, m)
            if recv:
                if args and recv in slot_names and \
                        _ZERO_VALUE_RE.match(
                            re.sub(r"\s+", "", args[0])):
                    reset = True
            elif len(args) >= 2:
                slot = re.sub(r"\s+", " ", args[0]).strip()
                val = re.sub(r"\s+", "", args[1])
                if slot in slot_names and \
                        _ZERO_VALUE_RE.match(val):
                    reset = True
        if reset:
            continue
        # Privileged effect after the check: external call or
        # state write.
        effect = [c for c in cl._external_calls(text)
                  if c["pos"] > check_pos] or \
            [v for p, v in cl._state_writes(text, state)
             if p > check_pos]
        if not effect:
            continue
        slot_txt = slots[0][1][:80]
        detail = spec.detail + (
            f" Observed: '{fn['name']}' checks a transient "
            f"latch via tload({slot_txt}) and then performs "
            f"a privileged effect, with no tstore({slot_txt}, "
            f"0) reset anywhere in the function. Gate "
            f"analysis: no caller-identity gate; the latch "
            f"check itself is the claimed authorization and "
            f"it is never consumed, so the proof stays "
            f"replayable.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated: no caller-identity gate, latch "
                    "checked but never cleared to zero")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. Uniswap v4 hook shared-delta take
# ---------------------------------------------------------------------------

_HOOK_FN_RE = re.compile(
    r"^(beforeSwap|afterSwap|beforeAddLiquidity|"
    r"afterAddLiquidity|beforeRemoveLiquidity|"
    r"afterRemoveLiquidity)$")
_TAKE_RE = re.compile(
    r"\.\s*(modifyLiquiditiesWithoutUnlock|takePair|take)\s*\(")
_UNLOCK_RE = re.compile(r"\bunlock\s*\(")
_DELTA_ZERO_RE = re.compile(
    r"(delta|Delta)\w*\s*(?:\.\s*amount[01]\s*\(\))?\s*==\s*0|"
    r"amount[01]\s*\(\s*\)\s*==\s*0|"
    r"currencyDelta\w*\s*==\s*0")


def _take_recipient(fn_text: str, to_expr: str,
                    scope) -> Tuple[str, str]:
    """Recipient of a hook take: hookData-derived locals and
    address parameters are caller-supplied; state variables
    are fixed; msg.sender is the caller."""
    base = re.split(r"[.\[(]", (to_expr or "").strip())[0].strip()
    sig = fn_text.split("{", 1)[0]
    addr_params: List[str] = []
    if "(" in sig:
        inner = sig[sig.index("(") + 1:
                    sig.rindex(")") if ")" in sig else len(sig)]
        for part in inner.split(","):
            if "address" in part:
                toks = [t for t in part.split()
                        if t not in ("calldata", "memory",
                                     "storage")]
                if len(toks) >= 2:
                    addr_params.append(toks[-1])
    if base == "msg" or "msg.sender" in (to_expr or ""):
        return "CALLER", "take recipient is msg.sender"
    if base in addr_params:
        return "CALLER-SUPPLIED", \
            f"take recipient '{base}' is an address parameter"
    # Local decoded from hookData (attacker-controlled bytes
    # the swapper passes through the hook) is caller-supplied.
    for m in re.finditer(
            r"(?:address(?:\s+payable)?)\s+([A-Za-z_]\w*)\s*="
            r"\s*([^;]+);", fn_text):
        if m.group(1) == base and "hookData" in m.group(2):
            return "CALLER-SUPPLIED", (
                f"take recipient '{base}' is decoded from "
                f"hookData, which the swapper supplies")
    state = cl.state_variables(scope.scoped_text)
    if base in state or re.fullmatch(r"[A-Za-z_]\w*", base or ""):
        return "FIXED", \
            f"take recipient '{base}' is a stored address"
    return "UNRESOLVED", \
        f"take recipient '{to_expr}' could not be resolved"


def _analyze_v4_hook_take(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _HOOK_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        m = _TAKE_RE.search(text)
        if not m:
            continue
        args = _call_args(text, m)
        method = m.group(1)
        # A take of a bare numeric literal is a fixed-size
        # take, not a full-credit TAKE_PAIR drain shape.
        if method in ("take", "takePair") and len(args) >= 3:
            if re.fullmatch(r"\d[\d_]*", args[2].strip()):
                continue
        if _UNLOCK_RE.search(text):
            continue  # hook opened its own unlock: protected
        if _DELTA_ZERO_RE.search(text):
            continue  # delta isolation asserted: protected
        if method in ("take", "takePair") and len(args) >= 2:
            recipient, rdetail = _take_recipient(
                text, args[1], scope)
        else:
            # modifyLiquiditiesWithoutUnlock spends through
            # the manager's shared ledger with no explicit
            # take recipient in the call: unresolved, but
            # still a candidate-grade shared-ledger take.
            recipient, rdetail = (
                "UNRESOLVED",
                "modifyLiquiditiesWithoutUnlock spends from "
                "the shared ledger with no explicit recipient")
        detail = spec.detail + (
            f" Observed: hook '{fn['name']}' calls "
            f"'{method}' without opening its own unlock "
            f"and without any delta-zero / delta-isolation "
            f"check. Gate analysis: no caller-identity gate "
            f"and no unlock or delta check bounds the take "
            f"to the hook's own delta.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated: no own unlock, no delta-zero "
                    "check before the shared-ledger take")
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 3. Inverted division zero collapse
# ---------------------------------------------------------------------------

_BORROW_FN_RE = re.compile(
    r"borrow|loan|leverage|liquidate", re.I)
_DIV_RE = re.compile(
    r"([A-Za-z_]\w*)\s*=\s*[^;]*?"
    r"(?:\d[\d_]*e\d+|[A-Z][A-Z0-9_]{2,})\s*/\s*"
    r"\w*(?:price|oracle|Price|Oracle)\w*")
_SOLVENCY_WORDS_RE = re.compile(
    r"borrow|limit|ltv|health|solven|collateral|debt", re.I)


def _zero_guard(text: str, var: str) -> bool:
    guard = re.compile(
        r"(?:require|assert)\s*\([^;]*?\b" + re.escape(var) +
        r"\b[^;]*?(?:>|>=|!=)\s*0")
    if guard.search(text):
        return True
    if re.search(r"if\s*\(\s*" + re.escape(var) +
                  r"\s*==\s*0\s*\)[^}]{0,80}revert", text):
        return True
    return False


def _analyze_inverted_division(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BORROW_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        m = _DIV_RE.search(text)
        if not m:
            continue
        var = m.group(1)
        div_pos = m.start()
        if _zero_guard(text, var):
            continue  # require(rate > 0): protected
        # Solvency/borrow-limit use AFTER the division: a
        # require/assert/if mentioning the collapsed value.
        solvency = False
        for cm in re.finditer(
                r"\b(?:require|assert|if)\s*\(", text):
            if cm.start() <= div_pos:
                continue
            cond = text[cm.start():cm.start() + 220]
            if re.search(r"\b" + re.escape(var) + r"\b", cond) \
                    and (_SOLVENCY_WORDS_RE.search(cond) or
                          "<=" in cond):
                solvency = True
                break
        if not solvency:
            continue
        # Payout after the division: the collapsed check
        # gates value leaving the contract.
        if not [c for c in cl._external_calls(text)
                if c["pos"] > div_pos]:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes '{var}' as "
            f"CONSTANT / oraclePrice ({m.group(0)[:80]}), "
            f"with no require({var} > 0) guard, and the "
            f"value feeds a solvency/borrow-limit check "
            f"that passes when {var} is 0. Gate analysis: "
            f"no caller-identity gate and no zero-guard "
            f"bounds the collapsed rate.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated: no caller-identity gate, no "
                    "require(result > 0) before the solvency "
                    "check")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. Share-transfer cancel desync
# ---------------------------------------------------------------------------

_CANCEL_FN_RE = re.compile(
    r"^(cancel|withdraw|exit|refund)$", re.I)
_JOIN_FN_RE = re.compile(
    r"^(join|deposit|stake|enter|buy|mint)$", re.I)
_MAPPING_RE = re.compile(
    r"mapping\s*\(\s*address[^)]*\)\s*"
    r"(?:(?:public|private|internal)\s+)?([A-Za-z_]\w*)")
_BURN_LIVE_RE = re.compile(
    r"balanceOf\s*\[\s*msg\.sender\s*\]\s*(=\s*0|-=)|"
    r"_burn\s*\(\s*msg\.sender\s*,\s*balanceOf")
_BURN_LIVE_CALL_RE = re.compile(
    r"_burn\w*\s*\(\s*msg\.sender\s*,")
_BALANCE_CALL_RE = re.compile(
    r"balanceOf\s*\(\s*msg\.sender")


def _analyze_share_desync(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    maps = set(_MAPPING_RE.findall(scoped))
    if not maps:
        return []
    # Transferable shares: the contract DEFINES an ERC-20
    # transfer (a bare token.transfer call is not enough).
    transferable = any(
        fn["name"] == "transfer" and
        not re.search(r"\b(view|pure)\b", fn["signature"])
        for fn in fns)
    if not transferable:
        return []
    # Stored entitlement written at join/deposit.
    stored: set = set()
    for fn in fns:
        if not _JOIN_FN_RE.match(fn["name"]):
            continue
        for mp in maps:
            if re.search(re.escape(mp) +
                         r"\s*\[\s*msg\.sender\s*\]\s*"
                         r"(\+=|=)", fn["text"]):
                stored.add(mp)
    if not stored:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CANCEL_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Refund derived from a stored mapping: a local
        # assigned from map[msg.sender], or the map read
        # used directly in a transfer/call.
        refund_vars: set = set()
        used_map: Optional[str] = None
        for mp in stored:
            for m in re.finditer(
                    r"([A-Za-z_]\w*)\s*=\s*[^;]*?" +
                    re.escape(mp) +
                    r"\s*\[\s*msg\.sender\s*\]", text):
                refund_vars.add(m.group(1))
                used_map = mp
            if re.search(re.escape(mp) +
                         r"\s*\[\s*msg\.sender\s*\]", text):
                used_map = mp
        if used_map is None:
            continue
        calls = cl._external_calls(text)
        refund_call = False
        for c in calls:
            frag = text[c["pos"]:c["pos"] + 200]
            if used_map in frag or any(
                    re.search(r"\b" + re.escape(v) + r"\b", frag)
                    for v in refund_vars):
                refund_call = True
        if not refund_call:
            continue
        # Burn from the LIVE balance, not the stored one:
        # either a direct balanceOf[msg.sender] write, or a
        # burn of a live balance read via balanceOf().
        if not (_BURN_LIVE_RE.search(text) or
                (_BURN_LIVE_CALL_RE.search(text) and
                 _BALANCE_CALL_RE.search(text))):
            continue
        # Reconciled: cancel burns from the stored mapping,
        # or a require ties stored to live balance.
        reconciled = False
        if re.search(r"_burn\s*\(\s*msg\.sender\s*,\s*"
                     r"[^)]*?" + re.escape(used_map), text):
            reconciled = True
        if re.search(r"require\s*\([^;]*?" + re.escape(used_map) +
                     r"[^;]*?balanceOf|require\s*\([^;]*?"
                     r"balanceOf[^;]*?" + re.escape(used_map),
                     text):
            reconciled = True
        if reconciled:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' refunds from the "
            f"stored mapping '{used_map}[msg.sender]' while "
            f"burning balanceOf[msg.sender], which may be 0 "
            f"after the shares were transferred away, and "
            f"no require reconciles stored vs live balance. "
            f"Gate analysis: no caller-identity gate and no "
            f"stored-vs-live reconciliation on the cancel "
            f"path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated: no caller-identity gate, no "
                    "stored-vs-live reconciliation at cancel")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. EIP-712 digest unbound to payload
# ---------------------------------------------------------------------------

_STRUCT_RE = re.compile(
    r"\bstruct\s+([A-Za-z_]\w*)\s*\{([^}]*)\}")
_HASH_FIELD_RE = re.compile(
    r"\b(payload|payloadHash|dataHash|digest|calldataHash)\b", re.I)
_AMOUNT_FIELD_RE = re.compile(r"\b(amount|value)\b", re.I)
_RECIP_FIELD_RE = re.compile(
    r"\b(recipient|receiver|beneficiary|to)\b", re.I)
_VERIFY_RE = re.compile(r"ecrecover|ECDSA\s*\.\s*recover")


def _struct_fields(body: str) -> List[str]:
    fields: List[str] = []
    for line in body.split(";"):
        # Field name is the last identifier on the line.
        idents = re.findall(r"[A-Za-z_]\w*", line)
        if idents:
            fields.append(idents[-1])
    return fields


def _analyze_eip712_unbound(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    structs: Dict[str, List[str]] = {}
    for m in _STRUCT_RE.finditer(scoped):
        structs[m.group(1)] = _struct_fields(m.group(2))
    if not structs:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # The verified struct, by name appearing in the fn.
        linked = [name for name in structs
                  if re.search(r"\b" + re.escape(name) + r"\b",
                               text)]
        if not linked:
            continue
        unbound = [name for name in linked
                   if not _HASH_FIELD_RE.search(
                       " ".join(structs[name])) and not (
                       _AMOUNT_FIELD_RE.search(
                           " ".join(structs[name])) and
                       _RECIP_FIELD_RE.search(
                           " ".join(structs[name])))]
        if not unbound:
            continue  # payload hash (or amount+recipient)
        if not _VERIFY_RE.search(text):
            continue
        if not re.search(
                r"keccak256\s*\(\s*abi\.encode", text):
            continue
        vm = _VERIFY_RE.search(text)
        vpos = vm.start()
        # Reuse: a loop/batch over distinct payloads, or a
        # caller-chosen payload parameter used in an effect
        # after the single verification.
        loop = re.search(r"\bfor\s*\(", text)
        effect_after = [c for c in cl._external_calls(text)
                        if c["pos"] > vpos]
        if not effect_after:
            continue
        reuse = False
        if loop and any(c["pos"] > loop.start()
                        for c in effect_after):
            reuse = True
        if not reuse:
            sig = fn["signature"]
            params: List[str] = []
            if "(" in sig:
                inner = sig[sig.index("(") + 1:
                            sig.rindex(")") if ")" in sig
                            else len(sig)]
                for part in inner.split(","):
                    toks = [t for t in part.split()
                            if t not in ("calldata", "memory",
                                         "storage")]
                    if len(toks) >= 2:
                        params.append(toks[-1])
            for c in effect_after:
                frag = text[c["pos"]:c["pos"] + 200]
                if any(re.search(r"\b" + re.escape(p) + r"\b",
                                frag) for p in params):
                    reuse = True
        if not reuse:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a single "
            f"EIP-712 digest over struct '{unbound[0]}', "
            f"whose fields "
            f"({', '.join(structs[unbound[0]])}) omit any "
            f"payload hash, amount, or recipient, then "
            f"applies it across a batch / caller-chosen "
            f"payloads. Gate analysis: the signature "
            f"verification is present but its scope does "
            f"not bind what it is spent on, so one "
            f"approval authorizes an arbitrary batch.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "signature present but digest scope "
                    "unbound: no payload hash, amount, or "
                    "recipient in the signed struct")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "transient_latch_unconsumed": _analyze_transient_latch,
    "v4_hook_shared_delta_take_pair": _analyze_v4_hook_take,
    "inverted_division_zero_collapse": _analyze_inverted_division,
    "share_transfer_cancel_desync": _analyze_share_desync,
    "eip712_digest_unbound_to_payload": _analyze_eip712_unbound,
}


def analyze_deep3_source(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Run ONE batch-3 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-2 collection / fetch /
# proxy resolution; analysis is analyze_deep3_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit3Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 3)"
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
        for item in analyze_deep3_source(
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
                source="deep audit detector batch 3 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit3Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 3) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
