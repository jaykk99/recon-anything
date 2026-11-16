"""Deep-audit detectors, batch 10: AI plugin dev (2026-11-05).

Five more chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-3 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- withdraw_rounding_drain: a withdraw/redeem function on a
  two-balance vault (totalSupply/totalShares vs totalAssets)
  that computes the shares to burn as
  amount * totalSupply / totalAssets with floor division,
  pays out the full caller-chosen amount, and burns only the
  rounded-down share count - no rounding-up (no ceil / mulDiv
  Ceil / +denominator-1) and no minimum-withdrawal / dust
  guard, so tiny withdrawals are loopable and each one burns
  fewer shares than the value taken. The Bunni v2 Sep 2025
  shape (~$8.4M). A payout that rounds DOWN is the protected
  direction for the withdrawer (the protocol keeps the dust),
  so only the shares-burn direction fires; rounding the burn
  up, or a minimum-withdrawal guard, stays silent.
- forwarder_execute_spoof: a MinimalForwarder-style execute()
  that verifies a signature (ecrecover / ECDSA.recover) over a
  digest that does NOT bind all three of from + to + data,
  then forwards an arbitrary call to a caller-controlled
  target with caller-controlled data - and the contract (or
  its wired downstream target) carries a gated privileged
  setter (e.g. setPrice / setOracle) one hop up, which the
  spoofed execute can reach. The KiloEx Apr 2025 shape
  (~$7M). Distinct from a bare ungated arbitrary call (no
  signature is checked at all): this one requires a signature
  check that is present but incompletely bound. A digest that
  binds from + to + data, or a gated execute, stays silent.
- multicall_2771_sender_spoof: a contract with BOTH an
  ERC-2771 _msgSender() override (trusted-forwarder suffix
  read) AND a multicall() that delegatecalls address(this)
  with the raw sub-call data, never re-appending the
  forwarder sender - plus a privileged effect gated on
  _msgSender() (e.g. require(_msgSender() == owner) before a
  payout / state write). The sub-call reads the attacker-
  chosen trailing 20 bytes as its sender, so the gate opens
  for a stranger. The Thirdweb / 0xMacro Dec 2023 shape.
  A multicall that re-appends msg.sender / _msgSender(), or
  no _msgSender()-gated effect, stays silent.
- liquidation_bonus_to_borrower: a permissionless liquidate()
  that pays the liquidator a PROVEN bonus > 0 - the seized
  collateral is computed with a literal multiplier above
  100 over 100, an additive (100 + bonus) factor, or a named
  bonus variable assigned a positive literal and used in the
  seize math - to the CALLER or a caller-supplied recipient,
  with no require(msg.sender != borrower) / liquidator !=
  borrower check, so the borrower can liquidate themselves
  and pocket the bonus. The DSCEngine CodeHawks #262 shape.
  The bonus > 0 proof is mandatory: a liquidate with no
  provable bonus (seize == debt value) never fires, so
  legitimate self-repay paths stay silent. A liquidator !=
  borrower check also stays silent.
- eip7702_low_slot_collision: an EIP-7702 delegation contract
  (literal "7702", a 7702 / Delegation contract name, or
  initialize + an execute() that delegatecalls) that keeps
  owner / module / session state in LOW, non-namespaced
  storage - plain state variables with no ERC-7201 slot - and
  reads that state on the execute path, so a previous
  delegate's state persists into a new delegate. Scoped to
  storage layout only, distinct from
  eip7702_unverified_delegate (delegate trust). A namespaced
  (ERC-7201) layout, or a delegate with no owner/module/
  session state, stays silent. Deliberately tight: a bare
  "Delegat" name or initialize + delegatecall anywhere in
  the bundle misfires on plain Ownable ERC-20s (15/15 false
  positives on the 2026-11-05 corpus), so neither counts.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. The mechanism
under analysis itself does NOT count as such a gate: the
signature check in the forwarder and the _msgSender() gate
in the multicall shape are the claimed authorization being
audited, so they never suppress. (Same narrowing of
cl._gated_deep as batch 3.)

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
FAMILY = "deep10"

SPECS = [
    S("withdraw_rounding_drain", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Withdraw rounding drain: the withdraw/redeem "
             "function computes the shares to burn as amount "
             "* totalSupply / totalAssets with floor division, "
             "pays the full caller-chosen amount, and burns "
             "only the rounded-down share count, with no "
             "rounding-up and no minimum-withdrawal / dust "
             "guard. Tiny withdrawals are loopable and each "
             "one burns fewer shares than the value taken, "
             "draining the vault - the Bunni v2 shape. "
             "Rounding the burn up, or a minimum-withdrawal "
             "guard, is the protected shape.",
      fix="Round the shares-to-burn UP (ceil division / "
          "mulDiv with Rounding.Ceil / +denominator-1) so a "
          "withdrawer can never burn fewer shares than the "
          "value taken, and enforce a minimum withdrawal so "
          "dust-sized withdrawals cannot loop."),
    S("forwarder_execute_spoof", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Forwarder execute spoof: a MinimalForwarder-"
             "style execute() verifies a signature over a "
             "digest that does not bind all three of from + "
             "to + data, then forwards an arbitrary call to "
             "a caller-controlled target with caller-"
             "controlled data, and a gated privileged setter "
             "(e.g. setPrice / setOracle) sits one hop up "
             "that the spoofed execute can reach - the "
             "KiloEx shape. A digest binding from + to + "
             "data, or a gated execute, is the protected "
             "shape.",
      fix="Bind the signature to the full request: hash "
          "from + to + value + data + nonce (+ deadline) "
          "in the signed digest, and verify the recovered "
          "signer is the claimed from address before "
          "forwarding."),
    S("multicall_2771_sender_spoof", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Multicall + ERC-2771 sender spoof: the contract "
             "has an ERC-2771 _msgSender() override reading "
             "the sender from the calldata suffix AND a "
             "multicall() that delegatecalls address(this) "
             "with the raw sub-call data, never re-appending "
             "the forwarder sender, plus a privileged effect "
             "gated on _msgSender(). The sub-call reads the "
             "attacker-chosen trailing 20 bytes as its "
             "sender, so the gate opens for a stranger - the "
             "Thirdweb / 0xMacro shape. Re-appending the "
             "sender in multicall is the protected shape.",
      fix="Re-append the forwarder sender to every sub-call "
          "in multicall (abi.encodePacked(data[i], "
          "msg.sender)) so the inner _msgSender() reads the "
          "real caller, or stop gating privileged effects "
          "on _msgSender() in functions reachable via "
          "multicall."),
    S("liquidation_bonus_to_borrower", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Liquidation bonus to borrower: a permissionless "
             "liquidate() pays the liquidator a proven bonus "
             "> 0 (seized collateral computed with a literal "
             "multiplier above 100 over 100, an additive "
             "(100 + bonus) factor, or a named bonus variable "
             "assigned a positive literal and used in the "
             "seize math) to the CALLER or a caller-supplied "
             "recipient, with no liquidator != borrower "
             "check, so the borrower can liquidate themselves "
             "and pocket the bonus - the DSCEngine CodeHawks "
             "#262 shape. No provable bonus, or a liquidator "
             "!= borrower check, is the protected shape.",
      fix="Pay the bonus only to a liquidator proven "
          "different from the borrower (require(msg.sender "
          "!= borrower)) or remove the bonus so the seized "
          "collateral never exceeds the debt repaid."),
    S("eip7702_low_slot_collision", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="EIP-7702 low-slot storage collision: an EIP-7702 "
             "delegation contract keeps owner / module / "
             "session state in low, non-namespaced storage - "
             "plain state variables with no ERC-7201 slot - "
             "so a previous delegate's state persists into a "
             "new delegate. Scoped to storage layout only. "
             "ERC-7201 namespaced storage is the protected "
             "shape.",
      fix="Move delegate state into ERC-7201 namespaced "
          "storage (keccak256-named slot + struct + .slot "
          "accessor) and clear / re-initialize it on every "
          "delegate change, so no prior delegate's owner, "
          "module, or session state survives."),
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
# 1. Withdraw rounding drain (Bunni v2 shape)
# ---------------------------------------------------------------------------

_WITHDRAW_FN_RE = re.compile(r"withdraw|redeem", re.I)
# shares-to-burn as amount * totalSupply/totalShares / totalAssets:
# an assignment whose RHS multiplies an amount by a supply
# total and divides by an asset total.
_SHARES_BURN_RE = re.compile(
    r"([A-Za-z_]\w*)\s*=\s*[^;]{0,160}?"
    r"\*\s*[^;]{0,80}?"
    r"(?:totalSupply|totalShares)\b[^;]{0,60}?"
    r"/\s*[^;]{0,80}?"
    r"(?:totalAssets|totalUnderlying|totalBalance)")
_CEIL_RE = re.compile(
    r"Rounding\.Ceil|ceilDiv|mulDivRoundingUp|"
    r"Math\.Rounding\.Ceil")
_CEIL_ADD_RE = re.compile(
    r"\+\s*(?:totalAssets|totalUnderlying|totalBalance|"
    r"[A-Za-z_]\w*)\s*-\s*1\s*\)\s*/")
_MIN_GUARD_RE = re.compile(
    r"require\s*\([^;]*?\b(?:MIN|DUST|minimum|MINIMUM)\w*\b|"
    r"require\s*\([^;]*?\b(?:amount|assets|shares)\b[^;]*?"
    r">=\s*[1-9]\d{2,}")
_BURN_RE = re.compile(r"\b_burn\s*\(|burn\s*\(")


def _analyze_withdraw_rounding(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Two-balance model: supply total AND asset total in the
    # contract, otherwise there is no share/asset conversion
    # to round the wrong way.
    if not (re.search(r"\btotalSupply\b|\btotalShares\b", scoped)
            and re.search(r"\btotalAssets\b|\btotalUnderlying\b|"
                          r"\btotalBalance\b", scoped)):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _WITHDRAW_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        m = _SHARES_BURN_RE.search(text)
        if not m:
            continue
        burn_var = m.group(1)
        div_frag = m.group(0)
        # Rounding UP is the protected direction: the
        # withdrawer can never burn fewer shares than the
        # value taken.
        if _CEIL_RE.search(text) or _CEIL_ADD_RE.search(div_frag):
            continue
        # A minimum-withdrawal / dust guard blocks the
        # loopable-tiny-withdrawal leg.
        if _MIN_GUARD_RE.search(text):
            continue
        div_pos = m.start()
        # The rounded-down share count is actually burned.
        if not re.search(
                r"\b_burn\s*\([^;]*?\b" + re.escape(burn_var) +
                r"\b|burn\s*\([^;]*?\b" + re.escape(burn_var) +
                r"\b", text):
            continue
        # Value leaves the contract after the division (the
        # full caller-chosen amount, not the rounded value).
        if not [c for c in cl._external_calls(text)
                if c["pos"] > div_pos]:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes "
            f"'{burn_var}' as amount * totalSupply / "
            f"totalAssets with floor division "
            f"({div_frag[:80]}), burns '{burn_var}' shares "
            f"while paying out the full caller-chosen "
            f"amount, with no rounding-up and no "
            f"minimum-withdrawal guard, so tiny withdrawals "
            f"are loopable and each burns fewer shares than "
            f"the value taken. Gate analysis: no "
            f"caller-identity gate, no ceil, no dust guard.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated: no caller-identity gate, floor "
                    "division on shares-to-burn, no ceil, no "
                    "minimum-withdrawal guard")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. Forwarder execute spoof (KiloEx shape)
# ---------------------------------------------------------------------------

_EXECUTE_FN_RE = re.compile(r"^execute", re.I)
_VERIFY_RE = re.compile(r"ecrecover|ECDSA\s*\.\s*recover")
_PRIV_SETTER_RE = re.compile(
    r"function\s+(setPrice|setOracle|setPriceFeed|setFeed|"
    r"updatePrice|setAdmin|setOwner|setImplementation|"
    r"setPositionManager|setVault|setTreasury)\b", re.I)
_DOWNSTREAM_VAR_RE = re.compile(
    r"\b(priceFeed|priceOracle|oracle|feed|positionManager)\b")
_CALL_FWD_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*call\s*(?:\{[^}]*\})?\s*\(\s*"
    r"([A-Za-z_]\w*)")
_FUNCTION_CALL_RE = re.compile(
    r"\bfunctionCall\s*\(\s*([A-Za-z_]\w*)\s*,\s*"
    r"([A-Za-z_]\w*)")


def _digest_text(fn_text: str, scope) -> str:
    """The signed-digest expression for an execute fn: the
    balanced keccak256(abi.encode(...)) expression in the fn
    itself, else a _hash/_verify/_getHash helper's. The window
    is the digest expression ONLY - a wider window would pick
    up identifiers from the surrounding verification lines
    (e.g. `from` in require(signer == from)) and misread the
    binding."""
    m = re.search(r"keccak256\s*\(", fn_text)
    if m:
        paren = fn_text.index("(", m.start())
        inner, _ = _balanced(fn_text, paren)
        return "keccak256(" + inner + ")"
    for name, helper in scope.helpers.items():
        if re.search(r"hash|verify", name, re.I):
            htext = helper["text"]
            hm = re.search(r"keccak256\s*\(", htext)
            if hm:
                paren = htext.index("(", hm.start())
                inner, _ = _balanced(htext, paren)
                return "keccak256(" + inner + ")"
    return ""


def _digest_binds(digest: str) -> Tuple[bool, List[str]]:
    """Which of from / to / data the digest binds."""
    missing: List[str] = []
    if not re.search(r"\bfrom\b|_from\b|request\.from|\.from\b",
                     digest):
        missing.append("from")
    if not re.search(r"\bto\b|request\.to|\.to\b", digest):
        missing.append("to")
    if not re.search(r"\bdata\b|calldata|payload|\.data\b",
                     digest):
        missing.append("data")
    return (not missing, missing)


def _analyze_forwarder_spoof(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Downstream privileged effect, one hop up: a gated
    # privileged setter in the contract, or a stored
    # downstream privileged target the forwarder is wired to.
    gated_setter = False
    for fn in fns:
        if _PRIV_SETTER_RE.search(fn["signature"]) and \
                _caller_gated(fn, scope):
            gated_setter = True
    downstream_target = bool(_DOWNSTREAM_VAR_RE.search(scoped))
    if not (gated_setter or downstream_target):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _EXECUTE_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # A signature IS checked - just incompletely bound.
        # (No signature at all is a different, ungated-call
        # class, not this one.)
        if not _VERIFY_RE.search(text):
            continue
        digest = _digest_text(text, scope)
        binds, missing = _digest_binds(digest)
        if binds:
            continue  # from + to + data all bound: protected
        # Arbitrary forward: call to a caller-controlled
        # target with caller-controlled data, or to a stored
        # downstream target with caller-controlled data.
        addr_params = _fn_addr_params(fn)
        params = _fn_params(fn)
        fwd = None
        for m in _CALL_FWD_RE.finditer(text):
            target, data = m.group(1), m.group(2)
            if data in params or data in ("data", "calldata"):
                fwd = (target, data)
                break
        if fwd is None:
            for m in _FUNCTION_CALL_RE.finditer(text):
                target, data = m.group(1), m.group(2)
                if data in params or data in ("data", "calldata"):
                    fwd = (target, data)
                    break
        if fwd is None:
            continue
        target, _data = fwd
        state = cl.state_variables(scoped)
        if target in addr_params or target == "msg":
            recipient = "CALLER-SUPPLIED" if target in \
                addr_params else "CALLER"
            rdetail = (f"forward target '{target}' is an "
                       f"address parameter") if target in \
                addr_params else "forward target is msg.sender"
        elif target in state:
            recipient = "FIXED"
            rdetail = (f"forward target '{target}' is a stored "
                       f"address")
        else:
            recipient = "UNRESOLVED"
            rdetail = f"forward target '{target}' unresolved"
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a signature "
            f"whose digest does not bind "
            f"{' + '.join(missing)} "
            f"(digest: {(digest[:100] if digest else 'no keccak256 '
            'digest found in the function')}), then forwards "
            f"'{target}.call({_data})' with caller-controlled "
            f"data, and a gated privileged setter sits one hop "
            f"up (gated setter in contract: {gated_setter}). "
            f"Gate analysis: the execute itself is ungated; "
            f"the signature check is the claimed authorization "
            f"and it does not bind what is forwarded.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated execute: signature present but "
                    "digest does not bind " + " + ".join(missing))
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 3. Multicall + ERC-2771 sender spoof (Thirdweb / 0xMacro shape)
# ---------------------------------------------------------------------------

_MULTICALL_FN_RE = re.compile(r"^multicall$", re.I)
_MSGSENDER_OVERRIDE_RE = re.compile(
    r"function\s+_msgSender\s*\(")
_TRUSTED_FWD_RE = re.compile(
    r"isTrustedForwarder|trustedForwarder|"
    r"msg\.data\.length\s*>=?\s*20|"
    r"abi\.decode\s*\(\s*msg\.data\s*\[\s*msg\.data\.length"
    r"\s*-\s*20")
_DELEGATE_SELF_RE = re.compile(
    r"address\s*\(\s*this\s*\)\s*\.\s*delegatecall\s*\(")
_SENDER_APPEND_RE = re.compile(
    r"abi\.encodePacked\s*\([^;]*?"
    r"(msg\.sender|_msgSender\s*\(\s*\))|"
    r"delegatecall\s*\([^;]*?"
    r"(msg\.sender|_msgSender\s*\(\s*\))")
_MSGSENDER_GATE_RE = re.compile(
    r"(?:require|assert|if)\s*\([^;]*?_msgSender\s*\(\s*\)"
    r"\s*(==|!=)")
_OWNER_GATE_RE = re.compile(
    r"_msgSender\s*\(\s*\)\s*==\s*([A-Za-z_]\w*)")


def _analyze_multicall_2771(src, spec, compiler,
                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Leg 1: ERC-2771 _msgSender() override with a
    # trusted-forwarder suffix read.
    if not (_MSGSENDER_OVERRIDE_RE.search(scoped) and
            _TRUSTED_FWD_RE.search(scoped)):
        return []
    # Leg 3: a privileged effect gated on _msgSender().
    gated_effect = None
    for fn in fns:
        if _MULTICALL_FN_RE.match(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        gm = _MSGSENDER_GATE_RE.search(fn["text"])
        if not gm:
            continue
        # A direct msg.sender identity check in the same fn
        # would make the gate unspoofable via multicall.
        if re.search(r"msg\.sender\s*(==|!=)", fn["text"]):
            continue
        effect = [c for c in cl._external_calls(fn["text"])] or \
            [v for _, v in cl._state_writes(
                fn["text"], cl.state_variables(scoped))]
        if not effect:
            continue
        gated_effect = fn
        break
    if gated_effect is None:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _MULTICALL_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 2: multicall delegatecalls address(this) with
        # the raw sub-call data.
        dm = _DELEGATE_SELF_RE.search(text)
        if not dm:
            continue
        frag = text[dm.start():dm.start() + 400]
        # Re-appending the sender is the protected shape.
        if _SENDER_APPEND_RE.search(frag):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' delegatecalls "
            f"address(this) with the raw sub-call data "
            f"({frag[:90]}) and never re-appends the "
            f"forwarder sender, while '{gated_effect['name']}' "
            f"gates a privileged effect on _msgSender(). "
            f"The sub-call reads attacker-chosen trailing "
            f"bytes as its sender. Gate analysis: "
            f"multicall itself is ungated and the "
            f"_msgSender() gate is the claimed authorization "
            f"being spoofed, so it does not suppress.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated multicall: raw delegatecall to "
                    "address(this), sender never re-appended, "
                    "privileged effect gated on _msgSender()")
        out.append(_finish_recipient(spec, item,
                                     gated_effect["text"]))
    return out


# ---------------------------------------------------------------------------
# 4. Liquidation bonus to borrower (DSCEngine CodeHawks #262)
# ---------------------------------------------------------------------------

_LIQUIDATE_FN_RE = re.compile(r"liquidate", re.I)
# Seize math with a literal multiplier strictly above 100
# over 100: debt * 110 / 100, debt * 105 / 100, ... (100 / 100
# is NO bonus and must not match - the int check below).
_BONUS_FACTOR_RE = re.compile(
    r"\*\s*([1-9]\d{2,})\s*/\s*100\b")
# Additive bonus: (100 + N) / 100, N > 0.
_BONUS_ADD_RE = re.compile(
    r"\(\s*100\s*\+\s*[1-9]\d*\s*\)\s*/\s*100\b")
# A named bonus variable: BONUS / bonusBps / liquidationBonus
# assigned a positive literal in the contract and used in
# the seize math.
_BONUS_VAR_RE = re.compile(
    r"\b([A-Za-z_]*[Bb]onus[A-Za-z_]*|"
    r"[A-Za-z_]*(?:BONUS|Bonus)[A-Za-z_]*)\b")
_BONUS_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_]*[Bb]onus[A-Za-z_]*|[A-Za-z_]*"
    r"(?:BONUS|Bonus)[A-Za-z_]*)\b\s*=\s*([1-9]\d*)")
_SEIZE_VAR_RE = re.compile(
    r"([A-Za-z_]\w*)\s*=\s*[^;]{0,200}?"
    r"(?:collateral|debt|seiz|liquidat)", re.I)
_NO_SELF_RE = re.compile(
    r"require\s*\([^;]*?msg\.sender\s*!=\s*borrower|"
    r"require\s*\([^;]*?borrower\s*!=\s*msg\.sender|"
    r"require\s*\([^;]*?liquidator\s*!=\s*borrower|"
    r"require\s*\([^;]*?borrower\s*!=\s*liquidator")


def _bonus_names(scoped: str) -> List[str]:
    """Named bonus variables assigned a positive literal."""
    return [m.group(1)
            for m in _BONUS_ASSIGN_RE.finditer(scoped)]


def _bonus_proof(fn_text: str, scoped: str
                 ) -> Tuple[bool, str]:
    """Prove bonus > 0 in the seize math, with the evidence."""
    m = _BONUS_FACTOR_RE.search(fn_text)
    if m and int(m.group(1)) > 100:
        return True, f"literal multiplier {m.group(0).strip()} "\
            f"(> 100 / 100)"
    m = _BONUS_ADD_RE.search(fn_text)
    if m:
        return True, f"additive bonus factor {m.group(0).strip()}"
    # Named bonus variable with a positive literal, used in
    # the function's seize math.
    assigned = {}
    for am in _BONUS_ASSIGN_RE.finditer(scoped):
        assigned[am.group(1)] = am.group(2)
    for name, val in assigned.items():
        if re.search(r"\b" + re.escape(name) + r"\b", fn_text):
            return True, (f"named bonus '{name}' = {val} "
                         f"(positive literal) used in the "
                         f"seize math")
    return False, ""


def _analyze_liquidation_bonus(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _LIQUIDATE_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # A liquidator != borrower check is the protected
        # shape: self-liquidation cannot pocket the bonus.
        if _NO_SELF_RE.search(text):
            continue
        # MANDATORY: prove bonus > 0, else this is a
        # legitimate self-repay path and must stay silent.
        proven, proof = _bonus_proof(text, scoped)
        if not proven:
            continue
        # The seized collateral actually leaves the contract.
        calls = cl._external_calls(text)
        if not calls:
            continue
        # The recipient is the CALLER (msg.sender) or a
        # caller-supplied address parameter - not the
        # borrower themself as the named recipient. Prefer
        # the payout call: the one moving a seize var (a
        # local assigned from the bonus math). The debt
        # repayment leg (transferFrom with msg.sender as the
        # SOURCE) must not be mistaken for the payout.
        params = _fn_params(fn)
        addr_params = _fn_addr_params(fn)
        seize_vars = set()
        for am in re.finditer(
                r"([A-Za-z_]\w*)\s*=\s*[^;]{0,220}", text):
            rhs = am.group(0)
            if _BONUS_FACTOR_RE.search(rhs) or \
                    _BONUS_ADD_RE.search(rhs) or any(
                    re.search(r"\b" + re.escape(n) + r"\b", rhs)
                    for n in _bonus_names(scoped)):
                seize_vars.add(am.group(1))
        payout = None
        for c in calls:
            frag = text[c["pos"]:c["pos"] + 220]
            if any(re.search(r"\b" + re.escape(v) + r"\b", frag)
                   for v in seize_vars):
                payout = frag
                break
        dest_ok = False
        dest_txt = ""
        if payout is not None:
            if "msg.sender" in payout:
                dest_ok, dest_txt = True, "msg.sender"
            else:
                for p in addr_params:
                    if p != "borrower" and re.search(
                            r"\b" + re.escape(p) + r"\b", payout):
                        dest_ok, dest_txt = True, p
                        break
                if not dest_ok:
                    state = cl.state_variables(scoped)
                    for sv in state:
                        if re.search(r"\b" + re.escape(sv) +
                                     r"\b", payout):
                            dest_ok, dest_txt = True, sv
                            break
        if not dest_ok:
            for c in calls:
                frag = text[c["pos"]:c["pos"] + 220]
                if "msg.sender" in frag:
                    dest_ok, dest_txt = True, "msg.sender"
                    break
                for p in addr_params:
                    if p != "borrower" and re.search(
                            r"\b" + re.escape(p) + r"\b", frag):
                        dest_ok, dest_txt = True, p
                        break
                if dest_ok:
                    break
        if not dest_ok:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' seizes collateral "
            f"with {proof} and pays it to '{dest_txt}' with "
            f"no liquidator != borrower check, so the "
            f"borrower can liquidate themselves and pocket "
            f"the bonus. Gate analysis: liquidate is "
            f"permissionless (no caller-identity gate) and "
            f"no self-liquidation check bounds the bonus.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "permissionless liquidate: proven bonus > "
                    "0 to caller, no liquidator != borrower "
                    "check")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. EIP-7702 low-slot storage collision (storage layout only)
# ---------------------------------------------------------------------------

_7702_MARKER_RE = re.compile(r"7702|eip-?7702", re.I)
_DELEGATION_NAME_RE = re.compile(r"7702|Delegation", re.I)
_INIT_FN_RE = re.compile(r"^initialize$", re.I)
_DELEGATECALL_RE = re.compile(r"\bdelegatecall\s*\(")
_CALL_RE = re.compile(r"\.\s*call\s*(?:\{[^}]*\})?\s*\(")
# Low-slot delegate state names. Matched ONLY against
# contract-level state variables (cl.state_variables, depth
# 1) - never against locals: a local `address signer` inside
# an execute() is not stored delegate state.
_LOW_SLOT_NAMES = ("owner", "module", "admin", "signer")
_LOW_SLOT_MAP_RE = re.compile(
    r"sessions?|approved\w*|authorized\w*")
_ERC7201_RE = re.compile(
    r"7201|StorageSlot|struct\s+\w+Storage\s*\{|"
    r"\.slot\b|_SLOT\b|_STORAGE_SLOT\b|"
    r"keccak256\s*\(\s*\"[^\"]*\"\s*\)\s*-\s*1|"
    r"ERC7201|erc7201")
_EXECUTE_FN_RE = re.compile(r"^execute", re.I)


def _analyze_eip7702_low_slot(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Leg 1: this is an EIP-7702 delegation contract. The
    # marker must be tight: the literal "7702", or a contract
    # name containing "7702" / "Delegation". (Loose markers
    # misfire: "Delegat" matches every governance Delegator
    # token, and initialize + delegatecall matches any
    # upgradeable token whose bundle includes OZ
    # functionDelegateCall - 15/15 false positives on the
    # 2026-11-05 corpus, all plain Ownable ERC-20s.)
    is_delegate = bool(
        _7702_MARKER_RE.search(scoped) or
        any(_DELEGATION_NAME_RE.search(n)
            for n in scope.contract_names))
    has_init = any(_INIT_FN_RE.match(fn["name"]) for fn in fns)
    # Leg 3 (checked before leg 2 so the protected shape
    # short-circuits): ERC-7201 namespaced storage.
    if _ERC7201_RE.search(scoped):
        return []
    # Leg 2: low, non-namespaced owner / module / session
    # state in plain storage - contract-level state variables
    # only (a local named `signer` is not stored state).
    state = cl.state_variables(scoped)
    low_vars = {v for v in state
                if v in _LOW_SLOT_NAMES or
                _LOW_SLOT_MAP_RE.fullmatch(v)}
    if not low_vars:
        return []
    # The delegate marker must gate the execute path too: an
    # execute() that calls and reads an owner is a multisig /
    # forwarder shape, not a 7702 delegate, unless the
    # contract is a 7702 delegate (literal marker) or an
    # initialized delegate (initialize + delegatecall in
    # execute).
    if not (is_delegate or has_init):
        return []
    # The low-slot state must be read on the delegate's
    # execute path: an execute() that delegatecalls / calls
    # and reads the low-slot state. A bare "7702" marker
    # plus any use also counts (the literal is strong).
    exec_fns = [fn for fn in fns
                if _EXECUTE_FN_RE.match(fn["name"])]
    fire_fn = None
    fire_var = None
    for fn in exec_fns:
        text = fn["text"]
        if not (_DELEGATECALL_RE.search(text) or
                _CALL_RE.search(text)):
            continue
        if is_delegate or _DELEGATECALL_RE.search(text):
            for v in low_vars:
                if re.search(r"\b" + re.escape(v) + r"\b", text):
                    fire_fn, fire_var = fn, v
                    break
        if fire_fn is not None:
            break
    if fire_fn is None and is_delegate:
        for fn in fns:
            if re.search(r"\b(view|pure)\b", fn["signature"]):
                continue
            for v in low_vars:
                if re.search(r"\b" + re.escape(v) + r"\b",
                             fn["text"]):
                    fire_fn, fire_var = fn, v
                    break
            if fire_fn is not None:
                break
    if fire_fn is None:
        return []
    fn, var = fire_fn, fire_var
    detail = spec.detail + (
        f" Observed: delegation contract keeps "
        f"'{var}' in low, non-namespaced storage (plain "
        f"state variable, no ERC-7201 slot) and "
        f"'{fn['name']}' reads it on the execute path, so a "
        f"previous delegate's '{var}' persists into a new "
        f"delegate. Gate analysis: the stored state IS the "
        f"authorization here - its layout, not a caller gate, "
        f"is the defect, so no caller-identity gate "
        f"suppresses it.")
    item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                detail,
                "layout defect: low non-namespaced slot for "
                "delegate state, no ERC-7201 namespacing")
    out = [_finish_recipient(spec, item, fn["text"])]
    return out


ANALYZERS = {
    "withdraw_rounding_drain": _analyze_withdraw_rounding,
    "forwarder_execute_spoof": _analyze_forwarder_spoof,
    "multicall_2771_sender_spoof": _analyze_multicall_2771,
    "liquidation_bonus_to_borrower": _analyze_liquidation_bonus,
    "eip7702_low_slot_collision": _analyze_eip7702_low_slot,
}


def analyze_deep10_source(src: str, spec: DetectorSpec,
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
# proxy resolution; analysis is analyze_deep10_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit10Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 10)"
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
        for item in analyze_deep10_source(
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
                source="deep audit detector batch 10 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit10Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 10) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
