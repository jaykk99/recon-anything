"""Deep-audit detectors, batch 32: authorization through
tx.origin, owner-reachable selfdestruct, unprotected
initializers, delegatecall to a caller-controlled target,
and owner-gated blacklists that freeze transfers.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- tx_origin_authorization: a non-view function authorizes
  an action with tx.origin (require / if comparing
  tx.origin to an owner / admin / allowlist) while never
  checking msg.sender for that authorization, and the
  function moves value or writes privileged state (owner /
  admin / role change, mint, withdraw). tx.origin is the
  origin wallet, not the caller: any contract the victim
  is tricked into calling passes the check, so a stranger
  phishes the owner into calling a malicious contract and
  the action runs as the owner. Checking msg.sender is the
  protected shape. Distinct from the recipient logic in
  deep_audit8 (tx.origin appears there only as a
  destination class, never as an authorization detector).
- selfdestruct_present: a public / external function calls
  selfdestruct (or the legacy suicide alias) with no
  timelock anywhere on the path, so a single admin can
  destroy the contract and force its whole ETH balance to
  the beneficiary in one call. The beneficiary decides the
  classification: a caller-supplied address or msg.sender
  is a CANDIDATE (a stranger directs the funds); a fixed
  stored address is TRIGGER-ONLY (the admin can trigger
  it but the funds land at a fixed destination). No
  selfdestruct at all, or a selfdestruct behind an
  explicit timelock (unlockTime / killTime / delay), is
  the protected shape. Distinct from
  proxy_delegatecall_selfdestruct (that class needs a
  delegatecall reaching the selfdestruct - this one is a
  direct selfdestruct in the contract itself, no
  delegatecall anywhere).
- unprotected_initializer: a function named initialize /
  init writes owner / admin / role state (owner =
  ..., _grantRole, transferOwnership, admin = ...) with
  no initializer modifier, no only* modifier, no
  msg.sender identity check, and no onlyInitializing -
  anyone can call it once and seize ownership of an
  upgradeable proxy's logic contract. An initializer
  modifier, or any caller-identity gate, is the protected
  shape. Distinct from initializer_flag_after_call
  (deep_audit7: an init-named function WITHOUT an
  initializer modifier that makes an EXTERNAL call - this
  one makes no external call at all; the hole is the
  missing access control, not the call).
- delegatecall_user_controlled_target: a .delegatecall
  whose target is a caller-supplied address parameter, or
  a storage variable with an ungated public setter, with
  no allowlist check on the path - so a stranger points
  the contract's own code execution at arbitrary bytecode
  and takes it over (drain, selfdestruct, storage
  rewrite). An immutable / constant / hardcoded target,
  or an allowlist check gating the call, is the protected
  shape. Distinct from multicall_arbitrary_delegatecall
  (deep_audit25: a multicall / batch function looping a
  bytes array through delegatecall - this one is a single
  delegatecall in a non-batch function, no loop, no
  array).
- owner_blacklist_freeze: an owner / role-gated setter
  adds arbitrary addresses to a blacklist / denylist /
  blocked mapping, and transfer / transferFrom reverts
  for blacklisted senders or recipients - so a single
  admin can freeze any holder's funds at will, with no
  timelock and no appeal path. Fires WITHOUT a recipient
  classification (batch-20 auction precedent): the freeze
  power itself is the finding; no value lands anywhere,
  so there is nothing to classify as a recipient.
  Medium severity. Distinct from
  bep20_blacklist_authority_check (bsc_bep20: a blacklist
  setter with NO access gate, so any stranger can
  blacklist - this one is the opposite shape, the setter
  IS owner-gated and the hole is the freeze power the
  gate protects).

Gate discipline: for the tx.origin, initializer, and
delegatecall detectors, a caller-identity gate (only*
modifier, msg.sender identity comparison, role check)
suppresses a finding - a stranger cannot reach the path.
The selfdestruct detector does NOT apply that gate: an
onlyOwner selfdestruct is exactly the dangerous shape
(one admin can kill the contract); the timelock is the
suppressor there instead. The blacklist detector requires
the setter to BE gated (the freeze power is the point).

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
    S("tx_origin_authorization", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Authorization through tx.origin: a public "
             "function authorizes an action by comparing "
             "tx.origin to an owner / admin / allowlist "
             "while never checking msg.sender for that "
             "authorization, and the function moves value "
             "or writes privileged state (owner / admin / "
             "role change, mint, withdraw) - so any "
             "contract a victim is tricked into calling "
             "passes the check and the action runs as the "
             "victim. Checking msg.sender is the protected "
             "shape.",
      fix="Never authorize with tx.origin: check msg.sender "
          "against the owner / role (onlyOwner, hasRole, or "
          "an explicit msg.sender comparison) on every "
          "privileged path, and treat tx.origin as "
          "untrusted input."),
    S("selfdestruct_present", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Owner-reachable selfdestruct: a public / "
             "external function calls selfdestruct (or the "
             "legacy suicide alias) with no timelock "
             "anywhere on the path, so a single admin can "
             "destroy the contract and force its whole ETH "
             "balance to the beneficiary in one call. A "
             "caller-supplied beneficiary or msg.sender is "
             "a CANDIDATE; a fixed stored beneficiary is "
             "TRIGGER-ONLY. No selfdestruct, or a "
             "selfdestruct behind an explicit timelock, is "
             "the protected shape.",
      fix="Remove selfdestruct from the contract, or put "
          "it behind a timelock (a delay between "
          "announcing the kill and executing it) plus "
          "multi-sig control, and hardcode the beneficiary "
          "to a known safe address."),
    S("unprotected_initializer", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Unprotected initializer: a function named "
             "initialize / init writes owner / admin / role "
             "state with no initializer modifier, no only* "
             "modifier, no msg.sender identity check, and "
             "no onlyInitializing - anyone can call it "
             "once and seize ownership of an upgradeable "
             "proxy's logic contract. An initializer "
             "modifier, or any caller-identity gate, is the "
             "protected shape.",
      fix="Guard the initializer with the initializer "
          "modifier (so it runs exactly once) AND an "
          "access check (only the deployer / factory may "
          "call it), and never leave ownership writes in "
          "an ungated public function."),
    S("delegatecall_user_controlled_target", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Delegatecall to a caller-controlled target: "
             "a .delegatecall whose target is a "
             "caller-supplied address parameter, or a "
             "storage variable with an ungated public "
             "setter, with no allowlist check on the path "
             "- so a stranger points the contract's own "
             "code execution at arbitrary bytecode and "
             "takes it over. An immutable / constant / "
             "hardcoded target, or an allowlist check "
             "gating the call, is the protected shape.",
      fix="Never delegatecall to a caller-supplied or "
          "freely-settable address: hardcode the target, "
          "make it immutable, or check it against an "
          "on-chain allowlist before the call."),
    S("owner_blacklist_freeze", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="Owner-gated blacklist freezes transfers: an "
             "owner / role-gated setter adds arbitrary "
             "addresses to a blacklist / denylist / "
             "blocked mapping, and transfer / transferFrom "
             "revert for blacklisted senders or "
             "recipients - so a single admin can freeze "
             "any holder's funds at will, with no timelock "
             "and no appeal path. No recipient "
             "classification: the freeze power itself is "
             "the finding.",
      fix="Do not give one admin unilateral freeze power "
          "over arbitrary holders: remove the blacklist "
          "from the transfer path, or put freezes behind "
          "a timelock plus multi-sig control with a "
          "public appeal / unfreeze path."),
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

    A marker write, a check, or a payout leg may live in a
    small internal helper rather than in the entry point
    itself. A bare `foo(` call whose name matches a function
    defined in this contract is treated as an internal call;
    external calls (obj.foo(), token.transfer) and builtins
    (require, keccak256) never match a defined function name,
    so they are excluded.
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
    """Bodies of the modifiers applied to this function."""
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


def _state_vars(src: str) -> set:
    """Names of state variables declared at contract level."""
    out = set()
    for m in re.finditer(
            r"^\s*(?:address|uint\d*|int\d*|bool|bytes\d*|string|"
            r"mapping\s*\([^)]*\)|"
            r"[A-Za-z_][A-Za-z0-9_\.]*)\s+(?:public\s+|private\s+|"
            r"internal\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
            src, re.M):
        out.add(m.group(1))
    return out


_PRIV_WRITE_RE = re.compile(
    r"\b(?:owner|admin|governor|guardian)\s*=|"
    r"_grantRole\s*\(|_setupRole\s*\(|_revokeRole\s*\(|"
    r"transferOwnership\s*\(|renounceOwnership\s*\(|"
    r"\bowner\s*=\s*msg\.sender|"
    r"roles\s*\[|hasRole\s*\([^)]*\)\s*=\s*true|"
    r"\._mint\s*\(|_mint\s*\(")


def _writes_privileged_state(text: str) -> bool:
    """An owner / admin / role write or a mint in the text."""
    return bool(_PRIV_WRITE_RE.search(text))


# ---------------------------------------------------------------------------
# 1. tx_origin_authorization
# ---------------------------------------------------------------------------

_TX_ORIGIN_AUTH_RE = re.compile(
    r"(require|if|assert)\s*\([^;]*?tx\.origin", re.S)


def _analyze_tx_origin(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _TX_ORIGIN_AUTH_RE.search(text):
            continue
        path = (text + "\n" + _called_internal_texts(text, scope)
                + "\n" + _applied_modifier_bodies(fn, scope))
        if not (_moves_value(path) or _writes_privileged_state(path)):
            continue
        detail = (
            f"Authorization through tx.origin in function "
            f"'{fn['name']}': the function authorizes an "
            f"action by comparing tx.origin (in a require / "
            f"if) while never checking msg.sender for that "
            f"authorization, and it moves value or writes "
            f"privileged state - so any contract a victim is "
            f"tricked into calling passes the check and the "
            f"action runs as the victim. Gate analysis: no "
            f"caller-identity gate, no msg.sender identity "
            f"check anywhere on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated tx.origin authorization: no "
                    "msg.sender check, value move or "
                    "privileged write on the path")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. selfdestruct_present
# ---------------------------------------------------------------------------

_SELFDESTRUCT_RE = re.compile(
    r"\b(?:selfdestruct|suicide)\s*\(\s*([^)]*)\)")
_TIMELOCK_RE = re.compile(
    r"timelock|unlockTime|killTime|unlock_time|kill_time|"
    r"\bdelay\b", re.I)


def _analyze_selfdestruct(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = _state_vars(src)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] in ("constructor",):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        m = _SELFDESTRUCT_RE.search(text)
        if not m:
            continue
        if _TIMELOCK_RE.search(text):
            continue
        if _TIMELOCK_RE.search(_applied_modifier_bodies(fn, scope)):
            continue
        params = _fn_params(fn)
        beneficiary = m.group(1).strip()
        beneficiary = re.sub(r"^payable\s*\(", "", beneficiary)
        if beneficiary.endswith(")"):
            beneficiary = beneficiary[:-1].strip()
        recipient, rdetail = _dest_class(beneficiary, params, state)
        detail = (
            f"Owner-reachable selfdestruct in function "
            f"'{fn['name']}': the contract can be destroyed "
            f"and its whole ETH balance forced to "
            f"'{beneficiary}' in one call, with no timelock "
            f"anywhere on the path. Gate analysis: no "
            f"timelock (no unlockTime / killTime / delay); "
            f"an onlyOwner-style gate does NOT suppress "
            f"this detector - one admin killing the "
            f"contract is exactly the dangerous shape.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "selfdestruct with no timelock: "
                    "single-admin kill switch")
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 3. unprotected_initializer
# ---------------------------------------------------------------------------

_INIT_FN_RE = re.compile(r"^(?:initialize|init)\w*$", re.I)
_INIT_MOD_RE = re.compile(r"\binitializer\b|\bonlyInitializing\b")
_EXTERNAL_CALL_RE = re.compile(
    r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\(")


def _analyze_unprotected_initializer(src, spec, compiler,
                                    contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _INIT_FN_RE.match(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if _INIT_MOD_RE.search(fn["signature"]):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        if not _writes_privileged_state(body):
            continue
        if _EXTERNAL_CALL_RE.search(body):
            continue
        detail = (
            f"Unprotected initializer '{fn['name']}': the "
            f"function writes owner / admin / role state "
            f"with no initializer modifier, no only* "
            f"modifier, no msg.sender identity check, and "
            f"no onlyInitializing - anyone can call it "
            f"once and seize ownership of the upgradeable "
            f"proxy's logic contract. Gate analysis: no "
            f"caller-identity gate and no initializer "
            f"modifier anywhere on the signature or path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated initializer: ownership writes "
                    "with no initializer modifier and no "
                    "access control")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. delegatecall_user_controlled_target
# ---------------------------------------------------------------------------

_DELEGATECALL_RE = re.compile(
    r"([\w\.\[\]]+?)\s*\.\s*delegatecall\s*\(")
_BATCH_FN_RE = re.compile(
    r"multicall|batch|executeBatch|aggregate", re.I)
_IMMUTABLE_RE = re.compile(
    r"\baddress\s+(?:public\s+|private\s+|internal\s+)?"
    r"(?:immutable|constant)\s+([A-Za-z_][A-Za-z0-9_]*)")
_LOCAL_FROM_PARAM_RE = re.compile(
    r"\baddress\s+(?:payable\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"=\s*([A-Za-z_][A-Za-z0-9_]*)")


def _analyze_delegatecall_target(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = _state_vars(src)
    fixed = set(_IMMUTABLE_RE.findall(src))
    setters: set = set()
    for fn in fns:
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if _caller_gated(fn, scope):
            continue
        body = _fn_body(fn["text"])
        for var in state:
            if re.search(r"\b" + re.escape(var) + r"\s*=(?!=)",
                         body):
                setters.add(var)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _BATCH_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        body = _fn_body(text)
        if re.search(r"\bfor\s*\(", body):
            continue
        m = _DELEGATECALL_RE.search(body)
        if not m:
            continue
        path_text = (text + "\n"
                     + _called_internal_texts(text, scope) + "\n"
                     + _applied_modifier_bodies(fn, scope))
        if _ALLOWLIST_RE.search(path_text):
            continue
        params = _fn_params(fn)
        target_base = m.group(1).split("[")[0].split(".")[0].strip()
        if target_base in fixed:
            continue
        if re.match(r"^0x[0-9a-fA-F]{40}$", target_base):
            continue
        how = None
        if target_base in params:
            how = (f"caller parameter '{target_base}'")
        elif target_base in setters:
            how = (f"storage variable '{target_base}' with an "
                   f"ungated public setter")
        else:
            local_src = None
            for lm in _LOCAL_FROM_PARAM_RE.finditer(body):
                if lm.group(1) == target_base:
                    local_src = lm.group(2)
                    break
            if local_src in params:
                how = (f"local '{target_base}' copied from "
                       f"caller parameter '{local_src}'")
        if how is None:
            continue
        detail = (
            f"Delegatecall to a caller-controlled target in "
            f"function '{fn['name']}': the .delegatecall "
            f"target is {how}, with no allowlist check on "
            f"the path - so a stranger points the "
            f"contract's own code execution at arbitrary "
            f"bytecode and takes it over (drain, "
            f"selfdestruct, storage rewrite). Gate "
            f"analysis: no caller-identity gate, no "
            f"allowlist, target is not immutable / "
            f"constant / hardcoded.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "delegatecall target is caller-controlled: "
                    "no allowlist, no immutable target")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. owner_blacklist_freeze
# ---------------------------------------------------------------------------

_BLACKLIST_MAP_RE = re.compile(
    r"mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*"
    r"(?:public\s+|private\s+|internal\s+)?"
    r"(blacklisted|isBlacklisted|blocked|denylisted|"
    r"blacklist|isBlocked)\b", re.I)
_SETTER_FN_RE = re.compile(
    r"^(?:addToBlacklist|removeFromBlacklist|setBlacklist|"
    r"blacklist|unblacklist|blockAddress|unblockAddress|"
    r"setBlocked|setBlacklisted)\w*$", re.I)
_TRANSFER_FN_RE = re.compile(r"^(?:transfer|transferFrom|"
                             r"_beforeTokenTransfer)$")


def _analyze_blacklist_freeze(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    mm = _BLACKLIST_MAP_RE.search(src)
    if not mm:
        return []
    map_name = mm.group(1)
    setter = None
    for fn in fns:
        if not _SETTER_FN_RE.match(fn["name"]):
            continue
        if not _caller_gated(fn, scope):
            continue
        body = _fn_body(fn["text"])
        if not re.search(r"\b" + re.escape(map_name) +
                         r"\s*\[[^\]]+\]\s*=(?!=)", body):
            continue
        setter = fn
        break
    if setter is None:
        return []
    enforced = False
    for fn in fns:
        if not _TRANSFER_FN_RE.match(fn["name"]):
            continue
        path = (fn["text"] + "\n"
                + _called_internal_texts(fn["text"], scope) + "\n"
                + _applied_modifier_bodies(fn, scope))
        if map_name not in path:
            continue
        if re.search(r"require\s*\([^)]*" + re.escape(map_name),
                     path) or re.search(
                         r"if\s*\([^)]*" + re.escape(map_name) +
                         r"[^)]*\)\s*revert", path):
            enforced = True
            break
    if not enforced:
        return []
    detail = (
        f"Owner-gated blacklist freezes transfers: the "
        f"owner / role-gated setter '{setter['name']}' "
        f"adds arbitrary addresses to the '{map_name}' "
        f"mapping, and the transfer path reverts for "
        f"blacklisted senders or recipients - so a single "
        f"admin can freeze any holder's funds at will, "
        f"with no timelock and no appeal path. Gate "
        f"analysis: the setter IS owner-gated (that is "
        f"the point - the freeze power is what the gate "
        f"protects); no recipient classification, the "
        f"freeze power itself is the finding.")
    item = _hit(spec, setter["name"], cc._snip(setter["text"]),
                detail,
                "owner-gated blacklist setter + transfer "
                "path enforces the blacklist")
    return [item]


ANALYZERS = {
    "tx_origin_authorization": _analyze_tx_origin,
    "selfdestruct_present": _analyze_selfdestruct,
    "unprotected_initializer": _analyze_unprotected_initializer,
    "delegatecall_user_controlled_target":
        _analyze_delegatecall_target,
    "owner_blacklist_freeze": _analyze_blacklist_freeze,
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
