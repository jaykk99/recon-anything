"""Deep-audit detectors, batch 20: cover capacity, user selectors,
settlement sweeps, wrapper creation, supply-cap bypass.

Five chain-agnostic EVM detectors from the standing backlog queue,
built to the batch-11 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- cover_capacity_counts_unpaid_prior_period: a capacity /
  availableCover function computes available cover from
  collateral (totalCollateral / totalAssets) while the contract
  holds a prior-period unpaid-liability variable
  (unpaidPriorPeriod / priorPeriodUnpaid / outstandingPrior /
  unpaidLosses) that the capacity function never subtracts, and
  a claim / payout function pays out sized by that capacity.
  The unpaid liability is real cover already owed, so the
  capacity is overstated by exactly that amount - the Firelight
  Immunefi #88214 shape. Subtracting the unpaid variable in
  the capacity function is the protected shape. Capacity
  functions are often view, so the view/pure skip does NOT
  apply to this detector.
- user_bytes_as_call_selector: a low-level .call() whose
  calldata is built from a user-controlled selector -
  abi.encodePacked(bytes4(<param>), ...) or
  abi.encodeWithSelector(bytes4(<param>), ...) where the
  bytes4 argument is a function parameter (or derived from
  one). The caller picks which function the target contract
  executes, so the call can be redirected to any selector on
  the callee - the Scroll ZkEvmVerifierPostFeynman shape
  (disclosed Nov 2026, whitehat ZHOUCHUNGONG). A constant
  selector, an interface .selector, or a keccak256-of-constant
  selector is the protected shape.
- permissionless_sweep_breaks_settlement_finality: an ungated
  sweep function pays out to the caller while the contract has
  a settlement-finality latch (claimsStarted /
  settlementFinalized / claimsFinalized) that claim functions
  set but the sweep never reads, and a re-flag / recompute
  function re-derives settlement from current balances. The
  sweep drains value the settlement already booked as claimed,
  then the re-flag re-books it - the CodeHawks BattleChain
  confidence-pools shape (2026-07). Reading the latch before
  paying (or gating the sweep) is the protected shape.
- wrapper_create_no_code_check: a create*Wrapper function
  takes an address token parameter and registers / creates a
  wrapper for it (wrapper-mapping write, factory create, or
  CREATE2 / new deployment) with no isContract / extcodesize /
  code.length check on the token anywhere in the function or
  the contract. An EOA or a contract with no code can be
  registered as a wrapped token and the wrapper then
  misroutes funds - the Dex223 bug-bounty issue #46 F-03 shape
  (Nov 2026). Address.isContract(token) / token.code.length
  is the protected shape.
- supply_cap_bypass_direct_transfer: a supply / borrow /
  deposit cap is compared only in the mint / deposit
  entrypoint, while cash / the exchange rate is computed from
  token.balanceOf(address(this)) and a borrow function sizes
  borrowing from that rate with no cap check of its own. A
  direct ERC-20 transfer inflates the on-chain balance past
  the cap, the rate follows the inflated balance, and the
  borrower draws value the cap was meant to forbid - the
  Moonwell MAMO shape (2026-08-27, ~$11M; Certora write-up
  2026-11-02), same shape at Venus (2026-03-15) and Tectonic.
  ADJUDICATION: distinct from bep20_mint_cap_bypass (that one
  fires when the cap is NEVER compared anywhere - here the cap
  IS compared, but only in the mint path, so a direct ERC-20
  transfer bypasses it) and from
  lending_accumulator_donation_inflation (rate inflation with
  no cap in the picture - here the cap is the bypassed
  control). Tracking cash in an internal ledger variable
  (updated only by mint / redeem) instead of reading
  balanceOf(address(this)) is the protected shape.

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
FAMILY = "deep20"

SPECS = [
    S("cover_capacity_counts_unpaid_prior_period", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Cover capacity counts collateral that is already "
             "owed: a capacity / availableCover function computes "
             "available cover from collateral (totalCollateral / "
             "totalAssets) while the contract holds a prior-period "
             "unpaid-liability variable (unpaidPriorPeriod / "
             "priorPeriodUnpaid / outstandingPrior / unpaidLosses) "
             "that the capacity function never subtracts, and a "
             "claim / payout function pays out sized by that "
             "capacity - the Firelight Immunefi #88214 shape. The "
             "unpaid liability is cover already owed, so the "
             "capacity is overstated by exactly that amount. "
             "Subtracting the unpaid variable in the capacity "
             "function is the protected shape.",
      fix="Subtract the prior-period unpaid liability in the "
          "capacity function (availableCover = totalCollateral "
          "- claimed - unpaidPriorPeriod) so cover already owed "
          "is never counted as available, and re-check the "
          "capacity inside the claim function before paying."),
    S("user_bytes_as_call_selector", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Low-level call with a user-controlled selector: a "
             ".call() builds its calldata from "
             "abi.encodePacked(bytes4(<param>), ...) or "
             "abi.encodeWithSelector(bytes4(<param>), ...) where "
             "the bytes4 argument is a function parameter (or "
             "derived from one), so the caller picks which "
             "function the target contract executes - the Scroll "
             "ZkEvmVerifierPostFeynman shape (disclosed Nov 2026, "
             "whitehat ZHOUCHUNGONG). A constant selector, an "
             "interface .selector, or a keccak256-of-constant "
             "selector is the protected shape.",
      fix="Never build a call selector from caller-supplied "
          "bytes: use a constant selector, an interface "
          ".selector (IVerifier.verify.selector), or a fixed "
          "function selector, and validate the calldata layout "
          "before the low-level call."),
    S("permissionless_sweep_breaks_settlement_finality", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Permissionless sweep breaks settlement finality: an "
             "ungated sweep function pays value to the caller "
             "while the contract has a settlement-finality latch "
             "(claimsStarted / settlementFinalized / "
             "claimsFinalized) that claim functions set but the "
             "sweep never reads, and a re-flag / recompute "
             "function re-derives settlement from current "
             "balances - the CodeHawks BattleChain "
             "confidence-pools shape (2026-07). The sweep drains "
             "value the settlement already booked as claimed, "
             "then the re-flag re-books it. Reading the latch "
             "before paying (or gating the sweep) is the "
             "protected shape.",
      fix="Require the settlement-finality latch in the sweep "
          "function (require(claimsStarted) / "
          "require(settlementFinalized)) before any value moves, "
          "or gate the sweep to an authorized role, so a sweep "
          "can never run against a settlement that is already "
          "final."),
    S("wrapper_create_no_code_check", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Wrapper created for a token with no code check: a "
             "create*Wrapper function takes an address token "
             "parameter and registers / creates a wrapper for it "
             "(wrapper-mapping write, factory create, or CREATE2 "
             "/ new deployment) with no isContract / extcodesize "
             "/ code.length check on the token anywhere in the "
             "function or the contract - the Dex223 bug-bounty "
             "issue #46 F-03 shape (Nov 2026). An EOA or a "
             "contract with no code can be registered as a "
             "wrapped token and the wrapper then misroutes funds. "
             "Address.isContract(token) / token.code.length is "
             "the protected shape.",
      fix="Check the token has code before registering a wrapper "
          "for it: require(Address.isContract(token)) or "
          "require(token.code.length > 0), and reject EOAs and "
          "not-yet-deployed addresses."),
    S("supply_cap_bypass_direct_transfer", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Supply cap bypassed by direct transfer: a supply / "
             "borrow / deposit cap is compared only in the mint / "
             "deposit entrypoint, while cash / the exchange rate "
             "is computed from token.balanceOf(address(this)) and "
             "a borrow function sizes borrowing from that rate "
             "with no cap check of its own - the Moonwell MAMO "
             "shape (2026-08-27, ~$11M; Certora write-up "
             "2026-11-02), same shape at Venus (2026-03-15) and "
             "Tectonic. A direct ERC-20 transfer inflates the "
             "on-chain balance past the cap, the rate follows the "
             "inflated balance, and the borrower draws value the "
             "cap was meant to forbid. Tracking cash in an "
             "internal ledger variable (updated only by mint / "
             "redeem) instead of reading balanceOf(address(this)) "
             "is the protected shape.",
      fix="Track cash in an internal ledger variable updated only "
          "by mint / redeem (never read balanceOf(address(this)) "
          "for the exchange rate), and enforce the cap in the "
          "borrow path as well as the mint path, so a direct "
          "transfer cannot inflate the rate or bypass the cap."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19)
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
            "stranger can trigger this but receives nothing - "
            "classified TRIGGER-ONLY under the receive rule.")
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
    """Parameter names from a function signature.

    Uses the first balanced paren group, so a trailing
    `returns (...)` clause is never mistaken for parameters.
    """
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner, _ = _balanced(sig, sig.index("("))
    out: List[str] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append(toks[-1])
    return out


def _address_params(fn: Dict[str, Any]) -> List[str]:
    """Names of the address-typed parameters of a function."""
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner, _ = _balanced(sig, sig.index("("))
    out: List[str] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2 and toks[0].startswith("address"):
            out.append(toks[-1])
    return out


# A value move out of the contract: ERC-20 transfer /
# transferFrom, or a native-value low-level call.
_VALUE_MOVE_RE = re.compile(
    r"\b(transfer|transferFrom)\s*\(|\.call\s*\{\s*value\s*:")

# ---------------------------------------------------------------------------
# 1. cover_capacity_counts_unpaid_prior_period (Firelight #88214)
# ---------------------------------------------------------------------------

_UNPAID_VAR_RE = re.compile(
    r"(?i)(unpaid\w*prior|prior\w*unpaid|outstanding\w*prior|"
    r"unpaid\w*loss)")
_CAPACITY_FN_RE = re.compile(
    r"(?i)(available\w*cover|cover\w*capacit|capacity)")
_COLLATERAL_RE = re.compile(
    r"(?i)\b(totalCollateral|totalAssets|collateral)\b")
_CONSUMER_FN_RE = re.compile(r"(?i)(claim|payout)")


def _subtracts(text: str, var: str) -> bool:
    """`var` is subtracted in `text`: `- var`, `-= var`, or
    `.sub(var)` / `.sub(x, var)` (SafeMath spelling)."""
    v = re.escape(var)
    return bool(
        re.search(r"-\s*\(?\s*" + v + r"\b", text) or
        re.search(r"\.sub\s*\([^)]*\b" + v + r"\b", text) or
        re.search(r"-=\s*" + v + r"\b", text))


def _analyze_cover_capacity(src, spec, compiler,
                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    unpaid_vars = [v for v in state if _UNPAID_VAR_RE.search(v)]
    if not unpaid_vars:
        return []
    # Capacity functions: name match + reads a collateral
    # variable. NOTE: capacity functions are often view, so
    # the view/pure skip does NOT apply to this detector.
    capacities = [fn for fn in fns
                  if _CAPACITY_FN_RE.search(fn["name"]) and
                  _COLLATERAL_RE.search(fn["text"])]
    if not capacities:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CONSUMER_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        for cap in capacities:
            if cap["name"] == fn["name"]:
                continue
            if not re.search(r"\b" + re.escape(cap["name"]) +
                             r"\s*\(", text):
                continue
            if not _VALUE_MOVE_RE.search(text):
                continue
            missing = [u for u in unpaid_vars
                       if not _subtracts(cap["text"], u)]
            if not missing:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' pays out sized by "
                f"'{cap['name']}', which computes available cover "
                f"from collateral but never subtracts the "
                f"prior-period unpaid liability "
                f"{', '.join(repr(m) for m in missing)} - so the "
                f"capacity is overstated by exactly that unpaid "
                f"amount and the claim pays it out. Gate "
                f"analysis: no caller-identity gate on the "
                f"consumer, capacity never subtracts the unpaid "
                f"liability.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "ungated claim/payout: capacity counts "
                        "collateral already owed as unpaid prior "
                        "liability, no subtraction on the path")
            out.append(_finish_recipient(spec, item, text))
            break
    return out


# ---------------------------------------------------------------------------
# 2. user_bytes_as_call_selector (Scroll ZkEvmVerifierPostFeynman)
# ---------------------------------------------------------------------------

_CALL_RE = re.compile(r"\.\s*call\s*\(")
_BYTES4_RE = re.compile(r"\bbytes4\s*\(")


def _tainted_names(fn: Dict[str, Any]) -> set:
    """Function parameters plus locals assigned from an
    expression mentioning a tainted name (fixed-point)."""
    tainted = set(_fn_params(fn))
    text = fn["text"]
    for _ in range(3):
        added = False
        for m in re.finditer(
                r"\b([A-Za-z_]\w*)\s*=\s*([^;]{0,200});", text):
            lhs, rhs = m.group(1), m.group(2)
            if lhs in tainted:
                continue
            if any(re.search(r"\b" + re.escape(t) + r"\b", rhs)
                   for t in tainted):
                tainted.add(lhs)
                added = True
        if not added:
            break
    return tainted


def _user_selector(text: str, tainted: set) -> Optional[str]:
    """The bytes4(...) argument when it is user-controlled, or
    None. Constant spellings never count: a hex literal, an
    interface .selector, or keccak256 of a string constant."""
    for m in _BYTES4_RE.finditer(text):
        inner, _ = _balanced(text, m.end() - 1)
        if re.search(r"0x[0-9a-fA-F]+", inner):
            continue
        if ".selector" in inner:
            continue
        if re.search(r"keccak256\s*\(\s*\"", inner):
            continue
        names = set(re.findall(r"[A-Za-z_]\w*", inner))
        if names & tainted:
            return inner.strip()
    return None


def _analyze_user_selector(src, spec, compiler,
                           contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        m = _CALL_RE.search(text)
        if not m:
            continue
        sel = _user_selector(text, _tainted_names(fn))
        if sel is None:
            continue
        # The call result must be used: a state write after the
        # call, or a value move in the function.
        if not (_VALUE_MOVE_RE.search(text) or
                any(p > m.start()
                    for p, _v in cl._state_writes(text, state))):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' makes a low-level "
            f".call() whose calldata is built from a "
            f"user-controlled selector (bytes4({sel})) - the "
            f"caller picks which function the callee executes - "
            f"and then uses the result to change state / move "
            f"value. Gate analysis: no caller-identity gate, "
            f"selector comes from a function parameter, not a "
            f"constant or interface selector.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated low-level call: calldata selector "
                    "comes from caller-supplied bytes, result "
                    "finalizes state / releases value")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. permissionless_sweep_breaks_settlement_finality
#    (CodeHawks BattleChain confidence pools, 2026-07)
# ---------------------------------------------------------------------------

_LATCH_RE = re.compile(
    r"(?i)(claimsStarted|settlementFinalized|claimsFinalized|"
    r"finalized|settlementStarted)")
_SWEEP_FN_RE = re.compile(r"(?i)sweep")
_REFLAG_FN_RE = re.compile(r"(?i)(flag|recompute|recalculate)")
_CLAIM_FN_RE = re.compile(r"(?i)claim")


def _analyze_sweep_finality(src, spec, compiler,
                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    latches = [v for v in state if _LATCH_RE.search(v)]
    if not latches:
        return []
    # (b) a claim function sets or reads the finality latch.
    latch_used_by_claim = any(
        _CLAIM_FN_RE.search(fn["name"]) and
        re.search(r"\b" + re.escape(latch) + r"\b", fn["text"])
        for latch in latches for fn in fns)
    if not latch_used_by_claim:
        return []
    # (c) a re-flag / recompute function reads contract state.
    reflag = False
    for fn in fns:
        if not _REFLAG_FN_RE.search(fn["name"]):
            continue
        text = fn["text"]
        if "address(this).balance" in text or any(
                re.search(r"\b" + re.escape(s) + r"\b", text)
                for s in state):
            reflag = True
            break
    if not reflag:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SWEEP_FN_RE.search(fn["name"]):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        if not _VALUE_MOVE_RE.search(text):
            continue
        touched = [l for l in latches
                   if re.search(r"\b" + re.escape(l) + r"\b",
                                text)]
        if touched:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' is an ungated sweep "
            f"that moves value, but never reads the "
            f"settlement-finality latch "
            f"{', '.join(repr(l) for l in latches)} that claim "
            f"functions set, while a re-flag / recompute "
            f"function re-derives settlement from current "
            f"balances - so the sweep drains value the "
            f"settlement already booked as claimed. Gate "
            f"analysis: no caller-identity gate, no latch read "
            f"on the sweep path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated sweep: pays out without reading the "
                    "settlement-finality latch, re-flag recomputes "
                    "from drained balances")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. wrapper_create_no_code_check (Dex223 issue #46 F-03)
# ---------------------------------------------------------------------------

_CREATE_WRAPPER_RE = re.compile(r"(?i)create\w*wrapper")


def _analyze_wrapper_no_code_check(src, spec, compiler,
                                   contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CREATE_WRAPPER_RE.search(fn["name"]):
            continue
        if _caller_gated(fn, scope):
            continue
        params = _address_params(fn)
        if not params:
            continue
        text = fn["text"]
        # A wrapper is registered / created: a wrapper-mapping
        # write, a `new ...Wrapper` deployment, a factory
        # create call, or CREATE2.
        creates = bool(
            re.search(r"\b\w*[Ww]rapper\w*\s*\[[^\]]*\]\s*=",
                      text) or
            re.search(r"\bnew\s+\w*[Ww]rapper\b", text) or
            re.search(r"\.\s*create\s*\(", text) or
            re.search(r"\bcreate2\b", text, re.I))
        if not creates:
            continue
        # A code check on the token parameter anywhere in the
        # function or the contract suppresses.
        checked = False
        for p in params:
            pe = re.escape(p)
            if (re.search(r"isContract\s*\(\s*" + pe + r"\b",
                          scoped) or
                    re.search(pe + r"\.code\.length\b", scoped) or
                    re.search(r"extcodesize\s*\(\s*" + pe + r"\b",
                              scoped)):
                checked = True
                break
        if checked:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' registers / creates a "
            f"wrapper for token parameter "
            f"{', '.join(repr(p) for p in params)} with no "
            f"isContract / extcodesize / code.length check on "
            f"that address anywhere in the function or the "
            f"contract, so an EOA or a not-yet-deployed address "
            f"can be registered as a wrapped token. Gate "
            f"analysis: no caller-identity gate, no code check "
            f"on the token parameter.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated wrapper creation: no code check on "
                    "the token parameter, wrapper registered "
                    "unconditionally")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. supply_cap_bypass_direct_transfer (Moonwell MAMO, Venus,
#    Tectonic)
# ---------------------------------------------------------------------------

_CAP_VAR_RE = re.compile(
    r"(?i)(supplyCap|borrowCap|depositCap|maxSupply|supply_cap|"
    r"borrow_cap|deposit_cap|max_supply)")
_MINT_ENTRY_RE = re.compile(r"(?i)(mint|deposit)")
_BORROW_FN_RE = re.compile(r"(?i)borrow")
_CASH_FN_RE = re.compile(r"(?i)(cash|exchangeRate)")
_BALANCE_OF_THIS_RE = re.compile(
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")


def _cap_compared(text: str, cap: str) -> bool:
    """`cap` takes part in a comparison in `text` (either side
    of <= / >= / < / >). A bare assignment or arithmetic use is
    not a comparison."""
    c = re.escape(cap)
    return bool(
        re.search(r"\b" + c + r"\b\s*(<=|>=|<|>)", text) or
        re.search(r"(<=|>=|<|>)\s*\b" + c + r"\b", text))


def _analyze_supply_cap_bypass(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    caps = [v for v in state if _CAP_VAR_RE.search(v)]
    if not caps:
        return []
    # (a) the cap is compared inside a mint / deposit entrypoint
    # (or a function that contains the cap comparison and also
    # mints) - the cap EXISTS as a control, but only on that path.
    entry_ok = False
    for fn in fns:
        text = fn["text"]
        if not any(_cap_compared(text, c) for c in caps):
            continue
        if _MINT_ENTRY_RE.search(fn["name"]):
            entry_ok = True
            break
        if re.search(r"\b_mint\s*\(|\bmint\s*\(|"
                     r"totalSupply\s*\+=", text):
            entry_ok = True
            break
    if not entry_ok:
        return []
    # (b) cash / the exchange rate is computed from
    # balanceOf(address(this)) directly - no internal cash ledger.
    cash_ok = False
    for fn in fns:
        if not _CASH_FN_RE.search(fn["name"]):
            continue
        text = fn["text"]
        if _BALANCE_OF_THIS_RE.search(text) and re.search(
                r"(return|=)[^;]*balanceOf\s*\(\s*address\s*"
                r"\(\s*this\s*\)", text):
            cash_ok = True
            break
    if not cash_ok:
        return []
    # (c)+(d) a borrow function sizes borrowing from that
    # rate / cash, with NO cap comparison of its own.
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BORROW_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        if not re.search(r"(?i)(exchangeRate|getCash|\bcash\b)",
                         text):
            continue
        if any(_cap_compared(text, c) for c in caps):
            continue
        if not _VALUE_MOVE_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' sizes borrowing from "
            f"the exchange rate / cash computed from "
            f"token.balanceOf(address(this)), with no "
            f"{', '.join(repr(c) for c in caps)} comparison in "
            f"the borrow path - the cap is only compared in the "
            f"mint / deposit entrypoint, so a direct ERC-20 "
            f"transfer inflates the on-chain balance past the "
            f"cap and the borrow draws value the cap was meant "
            f"to forbid. Gate analysis: no caller-identity gate "
            f"on the borrow path, no cap check in borrow, cash "
            f"read straight from the token balance.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated borrow: sized from balanceOf-derived "
                    "rate with no cap comparison in the borrow "
                    "path, cap enforced only at mint")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "cover_capacity_counts_unpaid_prior_period":
        _analyze_cover_capacity,
    "user_bytes_as_call_selector": _analyze_user_selector,
    "permissionless_sweep_breaks_settlement_finality":
        _analyze_sweep_finality,
    "wrapper_create_no_code_check":
        _analyze_wrapper_no_code_check,
    "supply_cap_bypass_direct_transfer":
        _analyze_supply_cap_bypass,
}


def analyze_deep20_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-20 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)

# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep20_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit20Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 20)"
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
        for item in analyze_deep20_source(
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
                source="deep audit detector batch 20 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit20Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 20) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
