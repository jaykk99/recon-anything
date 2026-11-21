"""Deep-audit detectors, batch 29: a relayer that executes
arbitrary calls with its own trusted identity, a Uniswap v4
hook callback that pays out without checking the caller is
the pool manager, a swap helper that routes through a
caller-supplied pool key with no allowlist, a governance
execute with a zero quorum, and a batch reward assignment
that overwrites duplicates while the total counts them all.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- relay_arbitrary_call_trusted_identity: a relayer /
  arbitrator function (claimMessage / relay / forward /
  deliver) that makes an external CALL to a caller-supplied
  target with caller-supplied calldata, with no allowlist /
  registry check on the target and no verification of the
  message content against a verified digest. Downstream
  contracts trust msg.sender == the relayer, so the call
  executes with the relayer's identity - the zkLink Nova
  shape (Oct 28-29, ~$780k: a forged message relayed
  through the arbitrator drained the bridge). A target
  allowlist, a digest verification, or an owner gate is the
  protected shape. Distinct from
  settlement_swap_executes_caller_target_spends_approvals
  (a swap / settle path spending standing token approvals -
  this one is a relay whose power is the relayer's trusted
  identity, not approvals), from
  multicall_arbitrary_delegatecall (a plain call, not a
  delegatecall), from access_control_arbitrary_call_injection
  (no exec-family function name), and from
  bridge_replay_unbound_digest (there is NO digest here at
  all - the message is never verified, not verified
  against an under-bound digest).
- v4_hook_callback_no_poolmanager_check: a Uniswap v4 hook
  callback (beforeSwap / afterSwap / beforeAddLiquidity /
  afterAddLiquidity / beforeRemoveLiquidity /
  afterRemoveLiquidity / beforeDonate / afterDonate) that
  moves value (pays a rebate / reward, takes a fee, mints,
  transfers, or updates a payout ledger) with NO check that
  msg.sender == poolManager (no onlyPoolManager modifier,
  no require(msg.sender == address(poolManager/manager))) -
  the Cork shape (May 2025, ~$12M: beforeSwap with no
  caller check). A poolManager caller check is the
  protected shape. Distinct from hook_cei_reentrancy (this
  fixture is CEI-clean: state is updated before the
  external transfer), from v4_hook_shared_delta_take_pair
  (no modifyLiquiditiesWithoutUnlock / TAKE_PAIR), and from
  token_sell_hook_burns_pair_reserves_sync (no burn from a
  pair, no pair.sync()).
- swap_helper_caller_supplied_pool_hook_no_allowlist: a
  helper / executor function that performs a swap or
  liquidity operation through a caller-supplied PoolKey (or
  hook / pool address parameter) with no allowlist /
  registry check on the pool / hook, while moving funds the
  contract holds. The call goes to a FIXED pool manager /
  router - the attacker-controlled part is the pool key /
  hook, not the call target - the Safe v4 liquidity module
  shape (Sep 2026, ~$7.73M, 2,900 rsETH: an unchecked hook
  in a caller-supplied pool key). A pool-key / hook
  allowlist, or a key read from contract storage, is the
  protected shape. Distinct from
  settlement_swap_executes_caller_target_spends_approvals
  (a raw CALL to a caller target plus standing approvals -
  here there is no raw call to a caller target at all) and
  from v4_hook_shared_delta_take_pair (no shared-delta take).
- governance_zero_quorum_executes: a governance contract
  with propose / vote / execute where execute() performs
  the proposal's generic call (target + calldata) with NO
  quorum enforcement: quorum() returns a 0 constant, or no
  votes >= quorum-style comparison exists anywhere in the
  contract - the Yapeswap shape (Oct 25, ~$22-40k: a
  zero-quorum union that executed its own proposal). A
  quorum comparison (forVotes >= quorum(), quorum() > 0
  enforced) or an owner-gated execute is the protected
  shape. Distinct from governance_quorum_calculation_flaw
  (quorum from CURRENT totalSupply - this fixture contains
  NO totalSupply() call) and from
  governance_early_execution_race (this fixture HAS a state
  check (Succeeded) and an eta check - the ONLY missing
  piece is quorum).
- duplicate_reward_overwrite_desync: a batch-assignment loop
  (constructor or init / setup) over parallel arrays writing
  mapping[key] = value (OVERWRITE, not +=) with no duplicate
  check, while a total / sum variable accumulates ALL
  entries (total += values[i]), PLUS a claim function paying
  out of the mapping. The mapping sum is less than the
  total, so accounting permanently desyncs (funds locked /
  closePot mis-divides) - the MyCut CodeHawks H-03 shape.
  A += accumulation, a duplicate check
  (require(rewards[key] == 0) / a seen mapping), or no total
  accumulating all entries is the protected shape. This is a
  user-harm / insolvency class, labelled honestly: the
  recipient is HOLDER-SELF, report_class trigger_only, NOT
  stranger-receivable. Distinct from
  gamefi_state_desync_reward_claim (the claim here zeroes
  the recorded reward before paying, and names no pending /
  earned balance), from recipient_unbacked_claim (the claim
  IS bounded by the recorded reward), and from
  share_transfer_cancel_desync (no cancel path, no
  transferable shares).

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. The one
exception is the gated VARIANT of each of the first four
detectors: an owner-gated relay / hook / helper / execute
still fires, as trigger-only at low severity with a FIXED
recipient (the batch-28 variant precedent) - the gated
shape is worth reporting because the gate is the only thing
standing between a stranger and the path, and the
trigger-only label keeps it out of the candidate queue.

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
FAMILY = "deep29"

SPECS = [
    S("relay_arbitrary_call_trusted_identity", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Relay executes arbitrary calls with its trusted "
             "identity: a relayer / arbitrator function "
             "(claimMessage / relay / forward / deliver) makes "
             "an external CALL to a caller-supplied target with "
             "caller-supplied calldata, with no allowlist / "
             "registry check on the target and no verification "
             "of the message content against a verified digest. "
             "Downstream contracts trust msg.sender == the "
             "relayer, so the call executes with the relayer's "
             "identity - the zkLink Nova shape. A target "
             "allowlist, a digest verification, or an owner "
             "gate is the protected shape.",
      fix="Never relay an unchecked caller-supplied call: "
          "allowlist the call targets (or check them against "
          "a registry), verify the message content against a "
          "verified digest before relaying, and require the "
          "downstream contract to authenticate the message "
          "itself, not just msg.sender == the relayer."),
    S("v4_hook_callback_no_poolmanager_check", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Uniswap v4 hook callback pays out with no pool "
             "manager check: a hook callback (beforeSwap / "
             "afterSwap / beforeAddLiquidity / "
             "afterAddLiquidity / beforeRemoveLiquidity / "
             "afterRemoveLiquidity / beforeDonate / "
             "afterDonate) moves value (pays a rebate / reward, "
             "takes a fee, mints, transfers, or updates a "
             "payout ledger) with NO check that msg.sender == "
             "poolManager (no onlyPoolManager modifier, no "
             "require(msg.sender == address(poolManager / "
             "manager))) - the Cork shape. A poolManager "
             "caller check is the protected shape.",
      fix="Check the caller in every hook callback: require "
          "msg.sender == address(poolManager) (or an "
          "onlyPoolManager modifier) before moving any value "
          "or updating any payout ledger."),
    S("swap_helper_caller_supplied_pool_hook_no_allowlist",
      FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Swap helper routes through a caller-supplied pool "
             "key with no allowlist: a helper / executor "
             "function performs a swap or liquidity operation "
             "through a caller-supplied PoolKey (or hook / pool "
             "address parameter) with no allowlist / registry "
             "check on the pool / hook, while moving funds the "
             "contract holds. The call goes to a FIXED pool "
             "manager / router - the attacker-controlled part "
             "is the pool key / hook, not the call target - the "
             "Safe v4 liquidity module shape. A pool-key / "
             "hook allowlist, or a key read from contract "
             "storage, is the protected shape.",
      fix="Allowlist the pools / hooks a helper may touch: "
          "check the caller-supplied PoolKey (or hook) "
          "against a stored allowlist before routing any "
          "swap, or read the key from contract storage "
          "instead of taking it from the caller."),
    S("governance_zero_quorum_executes", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Governance executes with a zero quorum: a "
             "governance contract with propose / vote / execute "
             "lets execute() perform the proposal's generic "
             "call (target + calldata) with NO quorum "
             "enforcement: quorum() returns a 0 constant, or "
             "no votes >= quorum-style comparison exists "
             "anywhere in the contract - the Yapeswap shape. "
             "A quorum comparison (forVotes >= quorum(), "
             "quorum() > 0 enforced) or an owner-gated execute "
             "is the protected shape.",
      fix="Enforce a real quorum before executing: require "
          "the proposal's votes for to be at least quorum() "
          "with quorum() returning a nonzero value, and "
          "never let a proposal execute on a quorum of zero."),
    S("duplicate_reward_overwrite_desync", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Duplicate reward assignment overwrites while the "
             "total counts every entry: a batch-assignment loop "
             "(constructor or init / setup) over parallel "
             "arrays writes mapping[key] = value (OVERWRITE, "
             "not +=) with no duplicate check, while a total / "
             "sum variable accumulates ALL entries (total += "
             "values[i]), PLUS a claim function paying out of "
             "the mapping. The mapping sum is less than the "
             "total, so accounting permanently desyncs (funds "
             "locked / closePot mis-divides) - the MyCut "
             "CodeHawks H-03 shape. A += accumulation, a "
             "duplicate check, or no total accumulating all "
             "entries is the protected shape. User-harm / "
             "insolvency class, NOT stranger-receivable: the "
             "duplicated player loses their earlier reward.",
      fix="Never overwrite a batch assignment: accumulate "
          "with += (or reject duplicates with a seen check / "
          "require(rewards[key] == 0)), and reconcile the "
          "total against the mapping sum before any claim "
          "pays out."),
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
# Shared helpers for the batch-29 analyzers
# ---------------------------------------------------------------------------

def _plain_call_to_param(body: str, addr_params: List[str],
                         bytes_params: List[str]
                         ) -> Optional[Tuple[str, str]]:
    """(target param, calldata param) for a plain `.call(`
    (optionally `.call{value: ...}(`) whose receiver is a
    caller-supplied address parameter and whose arguments
    mention a caller-supplied bytes parameter. A delegatecall
    is NOT this shape (the multicall detector owns it); a
    call to a stored router is NOT this shape."""
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


def _target_checked(text: str, target: str) -> bool:
    """The call target is bound: an allowlist-mapping read on
    it, an isAllowed check on it, or a require / if comparing
    it (==) against something that is not address(0). A
    non-zero check is not a binding."""
    tp = re.escape(target)
    if re.search(
            r"(?:allowlist|whitelist|allowed\w*|approved\w*|"
            r"trusted\w*)\s*\[\s*" + tp + r"\b", text, re.I):
        return True
    if re.search(r"isAllowed\w*\s*\(\s*" + tp + r"\b", text,
                 re.I):
        return True
    for m in re.finditer(
            r"(?:require|if)\s*\(([^;]{0,300})\)", text):
        stmt = m.group(1)
        if not re.search(r"\b" + tp + r"\b\s*==|==\s*\b" + tp +
                         r"\b", stmt):
            continue
        if "address(0)" in stmt or "address(0x0)" in stmt:
            continue
        return True
    return False


def _digest_verified(text: str) -> bool:
    """The message content is verified against a digest: a
    keccak256 digest plus a verified-digest lookup, a Merkle
    proof, or a recovered-signer check."""
    if "keccak256" not in text:
        return False
    return bool(re.search(
        r"verified|MerkleProof|ecrecover|digest\s*==|"
        r"==\s*digest|verifyProof", text, re.I))


def _brace_body(text: str, open_pos: int) -> str:
    """Body text inside the brace group at open_pos."""
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i]
    return text[open_pos + 1:]


def _is_view_or_pure(fn: Dict[str, Any]) -> bool:
    return bool(re.search(r"\b(view|pure)\b", fn["signature"]))


# ---------------------------------------------------------------------------
# 1. relay_arbitrary_call_trusted_identity
# ---------------------------------------------------------------------------

_RELAY_FN_RE = re.compile(
    r"^(?:claimMessage|relay\w*|forward\w*|deliver\w*)$", re.I)


def _analyze_relay(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _RELAY_FN_RE.match(fn["name"]):
            continue
        if _is_view_or_pure(fn):
            continue
        typed = _fn_params_typed(fn)
        addr_params = [n for (t, n) in typed
                       if t == "address"]
        bytes_params = [n for (t, n) in typed
                        if t == "bytes" or
                        t.startswith("bytes")]
        if not addr_params or not bytes_params:
            continue
        body = _fn_body(fn["text"])
        call = _plain_call_to_param(body, addr_params,
                                    bytes_params)
        if call is None:
            continue
        target, data = call
        searched = fn["text"] + "\n" + _called_internal_texts(
            fn["text"], scope)
        if _target_checked(searched, target):
            continue
        if _digest_verified(searched):
            continue
        gated = _caller_gated(fn, scope)
        detail = spec.detail + (
            f" Observed: '{fn['name']}' makes an external plain "
            f"call to the caller-supplied target '{target}' with "
            f"the caller-supplied calldata '{data}', with no "
            f"allowlist / registry check binding the target and "
            f"no verification of the message content against a "
            f"verified digest anywhere on the path (not even in "
            f"an internal helper it calls) - so any stranger "
            f"can make this contract call anything with the "
            f"relayer's trusted identity behind it, and a "
            f"downstream contract that trusts msg.sender == "
            f"this relayer executes it as the relayer. Gate "
            f"analysis: " + (
                "the relay is owner-gated - the gate is the "
                "only thing standing between a stranger and "
                "the relayer's identity"
                if gated else
                "no caller-identity gate, no target allowlist, "
                "no digest verification") + ".")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "owner-gated relay: the gate is the only "
                    "thing standing between a stranger and the "
                    "relayer's identity" if gated else
                    "ungated relay: plain call to a "
                    "caller-supplied target with caller-supplied "
                    "calldata, no allowlist, no digest check")
        if gated:
            out.append(_classify(
                item, "FIXED",
                "the relay path is owner-gated: no stranger "
                "can invoke it, so the relayer's identity is "
                "never stranger-reachable - trigger-only"))
        else:
            out.append(_classify(
                item, "CALLER",
                f"the caller supplies both the call target "
                f"'{target}' and the calldata '{data}': the "
                f"call executes with the relayer's trusted "
                f"identity"))
    return out


# ---------------------------------------------------------------------------
# 2. v4_hook_callback_no_poolmanager_check
# ---------------------------------------------------------------------------

_HOOK_CB_RE = re.compile(
    r"^(?:beforeSwap|afterSwap|beforeAddLiquidity|"
    r"afterAddLiquidity|beforeRemoveLiquidity|"
    r"afterRemoveLiquidity|beforeDonate|afterDonate)$")
_LEDGER_WRITE_RE = re.compile(
    r"\b(?:rebates?|rewards?|pending\w*|owed\w*|payouts?|"
    r"credits?)\s*\[[^\]]*\]\s*(?:\+=|=)(?!=)")


def _has_manager_check(fn: Dict[str, Any], scope) -> bool:
    """A poolManager caller check: an onlyPoolManager
    modifier (the modifier's name IS the check, by the
    Uniswap v4 convention), or a require comparing
    msg.sender against poolManager / manager, in the
    function or in an applied modifier's body."""
    if "onlyPoolManager" in fn["signature"]:
        return True
    searched = fn["text"] + "\n" + _applied_modifier_bodies(
        fn, scope)
    return bool(re.search(
        r"msg\.sender\s*==\s*address\s*\(\s*"
        r"(?:poolManager|manager)\s*\)|"
        r"msg\.sender\s*==\s*(?:poolManager|manager)\b|"
        r"address\s*\(\s*(?:poolManager|manager)\s*\)\s*==\s*"
        r"msg\.sender|"
        r"(?:poolManager|manager)\s*==\s*msg\.sender",
        searched))


def _analyze_hook_manager(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    if "poolManager" not in state and "manager" not in state:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _HOOK_CB_RE.match(fn["name"]):
            continue
        if _is_view_or_pure(fn):
            continue
        text = fn["text"]
        if not (_moves_value(text) or
                _LEDGER_WRITE_RE.search(text)):
            continue
        if _has_manager_check(fn, scope):
            continue
        gated = _caller_gated(fn, scope)
        detail = spec.detail + (
            f" Observed: hook callback '{fn['name']}' moves "
            f"value with NO check that msg.sender == "
            f"poolManager (no onlyPoolManager modifier, no "
            f"require(msg.sender == address(poolManager / "
            f"manager))) - any contract can call this callback "
            f"directly and collect the payout, because the "
            f"pool manager is never authenticated as the "
            f"caller. Gate analysis: " + (
                "the callback is owner-gated - the gate is the "
                "only thing standing between a stranger and "
                "the payout"
                if gated else
                "no caller-identity gate and no poolManager "
                "caller check") + ".")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "owner-gated hook callback: the gate is the "
                    "only thing standing between a stranger and "
                    "the payout" if gated else
                    "ungated hook callback: value moves with no "
                    "poolManager caller check")
        if gated:
            out.append(_classify(
                item, "FIXED",
                "the hook callback is owner-gated: no stranger "
                "can invoke it - trigger-only"))
        else:
            out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. swap_helper_caller_supplied_pool_hook_no_allowlist
# ---------------------------------------------------------------------------

_POOLKEY_TYPE_RE = re.compile(r"\bPoolKey\b")
_HOOK_PARAM_RE = re.compile(
    r"^(?:hook|pool|poolKey|key)$", re.I)
_SWAP_CALL_RE = re.compile(
    r"\b(poolManager|manager|router|swapRouter|pool)\s*\.\s*"
    r"(swap|modifyLiquidities|exactInput|exactOutput)\s*\(")


def _swap_call_with_key(body: str, key_param: str,
                        params: List[str]) -> Optional[str]:
    """A swap / liquidity call on a FIXED manager / router
    whose arguments mention the caller-supplied key. A call
    on a caller-supplied router is not this shape."""
    for m in _SWAP_CALL_RE.finditer(body):
        if m.group(1) in params:
            continue
        i = body.index("(", m.start())
        args, _ = _balanced(body, i)
        if _mentions(args, key_param):
            return m.group(0)
    return None


def _key_allowlisted(text: str, key_param: str) -> bool:
    kp = re.escape(key_param)
    if re.search(
            r"allowed\w*\s*\[\s*" + kp +
            r"(?:\s*\.\s*hooks?)?\s*\]", text, re.I):
        return True
    if re.search(r"isAllowed\w*\s*\(\s*" + kp + r"\b", text,
                 re.I):
        return True
    if re.search(r"require\s*\([^;]{0,200}?allowed", text,
                 re.I) and _mentions(text, key_param):
        return True
    return False


def _analyze_swap_helper(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _is_view_or_pure(fn):
            continue
        typed = _fn_params_typed(fn)
        params = [n for (t, n) in typed]
        key_param = None
        for (t, n) in typed:
            if _POOLKEY_TYPE_RE.search(t):
                key_param = n
                break
        if key_param is None:
            for (t, n) in typed:
                if t == "address" and _HOOK_PARAM_RE.match(n):
                    key_param = n
                    break
        if key_param is None:
            continue
        body = _fn_body(fn["text"])
        swap = _swap_call_with_key(body, key_param, params)
        if swap is None:
            continue
        if not _moves_value(fn["text"]):
            continue
        searched = fn["text"] + "\n" + _called_internal_texts(
            fn["text"], scope)
        if _key_allowlisted(searched, key_param):
            continue
        gated = _caller_gated(fn, scope)
        detail = spec.detail + (
            f" Observed: '{fn['name']}' routes a swap / "
            f"liquidity operation through the caller-supplied "
            f"pool key '{key_param}' ({swap.strip()}), with no "
            f"allowlist / registry check on the pool / hook "
            f"anywhere on the path (not even in an internal "
            f"helper it calls), while moving funds the contract "
            f"holds - so a stranger names a pool whose hook "
            f"they control and the helper executes against it "
            f"with the contract's funds. Gate analysis: " + (
                "the helper is owner-gated - the gate is the "
                "only thing standing between a stranger and "
                "the routing"
                if gated else
                "no caller-identity gate, no pool-key / hook "
                "allowlist") + ".")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "owner-gated swap helper: the gate is the "
                    "only thing standing between a stranger and "
                    "the routing" if gated else
                    "ungated swap helper: caller-supplied pool "
                    "key routes the swap, no allowlist, funds "
                    "move")
        if gated:
            out.append(_classify(
                item, "FIXED",
                "the swap helper is owner-gated: no stranger "
                "can invoke it - trigger-only"))
        else:
            out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 4. governance_zero_quorum_executes
# ---------------------------------------------------------------------------

_GOV_EXEC_RE = re.compile(
    r"^(?:execute|executeProposal|executeTransaction)$")


def _quorum_enforced(text_all: str) -> bool:
    """A real quorum comparison exists AND quorum() does not
    return a 0 constant (a comparison against a zero quorum
    is vacuous - it always passes)."""
    if re.search(
            r"function\s+quorum\s*\([^)]*\)[^{]*\{[^}]{0,200}?"
            r"\breturn\s+0\s*;", text_all, re.S):
        return False
    if re.search(
            r"(?:forVotes|votesFor|yesVotes)\s*>=\s*quorum",
            text_all):
        return True
    if re.search(r">=\s*quorum\s*\(", text_all):
        return True
    if re.search(r"quorum\s*\(\s*\)\s*>\s*0|quorum\s*>\s*0",
                 text_all):
        return True
    if re.search(r"require\s*\([^;]{0,200}?quorum", text_all):
        return True
    return False


def _analyze_governance_quorum(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _GOV_EXEC_RE.match(fn["name"]):
            continue
        if _is_view_or_pure(fn):
            continue
        text = fn["text"]
        body = _fn_body(text)
        if not re.search(r"\.\s*call\s*(?:\{[^}]*\})?\s*\(",
                         body):
            continue
        if "proposals[" not in text and \
                "proposal" not in text.lower():
            continue
        # The early-execution shape is NOT this detector: a
        # state check (Succeeded) and an eta check must be
        # present - the ONLY missing piece is quorum.
        if "ProposalState.Succeeded" not in text and \
                "Succeeded" not in text:
            continue
        if "eta" not in text or not re.search(
                r"block\.timestamp\s*>=", text):
            continue
        if _quorum_enforced(text_all):
            continue
        gated = _caller_gated(fn, scope)
        detail = spec.detail + (
            f" Observed: '{fn['name']}' performs the "
            f"proposal's generic call after a state check "
            f"(Succeeded) and an eta check, but with NO quorum "
            f"enforcement anywhere in the contract (quorum() "
            f"returns 0, and no votes >= quorum-style "
            f"comparison exists) - so a proposal that nobody "
            f"voted for executes as if it had passed. Gate "
            f"analysis: " + (
                "execute is owner-gated - the gate is the only "
                "thing standing between a stranger and "
                "execution"
                if gated else
                "no caller-identity gate and no quorum "
                "enforcement") + ".")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "owner-gated execute: the gate is the only "
                    "thing standing between a stranger and "
                    "execution" if gated else
                    "ungated execute: state + eta checked, "
                    "quorum never enforced")
        if gated:
            out.append(_classify(
                item, "FIXED",
                "execute is owner-gated: no stranger can "
                "invoke it - trigger-only"))
        else:
            out.append(_classify(
                item, "CALLER",
                "the caller executes the proposal's generic "
                "call (target + calldata): the caller chooses "
                "the proposal and receives the call's effect"))
    return out


# ---------------------------------------------------------------------------
# 5. duplicate_reward_overwrite_desync
# ---------------------------------------------------------------------------

_LOOP_FN_RE = re.compile(
    r"^(?:constructor|initialize|init|setup)$")
_DUP_CLAIM_FN_RE = re.compile(r"^(?:claim|collect)\w*$", re.I)
_MAPPING_DECL_RE = re.compile(
    r"mapping\s*\([^)]*\)\s*(?:public\s+|private\s+|internal\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)")


def _has_dup_check(loop_text: str, map_name: str) -> bool:
    """A duplicate guard in the batch loop: a require on the
    mapping slot being empty, or a seen-mapping check."""
    mp = re.escape(map_name)
    if re.search(r"require\s*\([^)]*" + mp + r"\s*\[", loop_text):
        return True
    if re.search(r"\bseen\w*\s*\[", loop_text, re.I):
        return True
    return False


def _analyze_dup_reward(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    maps = set(_MAPPING_DECL_RE.findall(scope.scoped_text))
    if not maps:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _LOOP_FN_RE.match(fn["name"]):
            continue
        if _is_view_or_pure(fn):
            continue
        text = fn["text"]
        for m in re.finditer(r"\bfor\s*\(", text):
            i = text.index("(", m.start())
            _, pend = _balanced(text, i)
            j = text.find("{", pend)
            if j < 0:
                continue
            loop = _brace_body(text, j)
            # Overwrite write: mapping[arrayElem] = value (not
            # +=), keyed by an array element.
            overwrite = None
            for wm in re.finditer(
                    r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*"
                    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]*\])?)"
                    r"\s*\]\s*=(?!=)\s*([^;]{0,120})", loop):
                mapping, key, rhs = (wm.group(1),
                                     wm.group(2).strip(),
                                     wm.group(3))
                if mapping not in maps:
                    continue
                if not re.search(r"\w+\s*\[\s*\w+\s*\]", key):
                    continue
                if _has_dup_check(loop, mapping):
                    continue
                overwrite = (mapping, key, rhs)
                break
            if overwrite is None:
                continue
            mapping, key, rhs = overwrite
            # The total accumulates ALL entries: total +=
            # <the same values array>.
            rhs_base = rhs.strip().split("[")[0].strip()
            total = None
            for tm in re.finditer(
                    r"([A-Za-z_][A-Za-z0-9_]*)\s*\+=\s*"
                    r"([^;]{0,120})", loop):
                if _mentions(tm.group(2), rhs_base):
                    total = (tm.group(1), tm.group(2))
                    break
            if total is None:
                continue
            # A claim function must pay out of the same
            # mapping - the desync is only payable through it.
            claim_fn = None
            for cfn in fns:
                if not _DUP_CLAIM_FN_RE.match(cfn["name"]):
                    continue
                if _is_view_or_pure(cfn):
                    continue
                if mapping in cfn["text"] and \
                        _moves_value(cfn["text"]):
                    claim_fn = cfn
                    break
            if claim_fn is None:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' batch-assigns "
                f"'{mapping}[{key}] = {rhs.strip()}' "
                f"(OVERWRITE, not +=) with no duplicate check, "
                f"while '{total[0]} += {total[1].strip()}' "
                f"accumulates EVERY entry - so a duplicated key "
                f"keeps only its last reward in '{mapping}' "
                f"while '{total[0]}' counts it twice, and "
                f"'{claim_fn['name']}' pays out of that same "
                f"'{mapping}' record. The mapping sum is less "
                f"than the total, so accounting permanently "
                f"desyncs. Gate analysis: no duplicate check in "
                f"the batch loop; the claim pays the recorded "
                f"reward.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        "batch loop overwrites duplicates while "
                        "the total counts every entry; claim pays "
                        "the mapping")
            # User-harm / insolvency class, NOT
            # stranger-receivable: the duplicated player loses
            # their earlier reward. Trigger-only at MEDIUM
            # severity (the _classify low downgrade does not
            # apply here - the desync itself is medium).
            item["recipient"] = "HOLDER-SELF"
            item["report_class"] = "trigger_only"
            item["detail"] += (
                " Recipient analysis: recipient classified "
                "HOLDER-SELF (the claim pays the caller's own "
                "recorded reward) - the duplicated player "
                "loses their earlier reward, so a stranger "
                "receives nothing here: classified "
                "TRIGGER-ONLY under the receive rule. This is "
                "a user-harm / insolvency class, not a "
                "stranger-receivable drain.")
            out.append(item)
            break
    return out


ANALYZERS = {
    "relay_arbitrary_call_trusted_identity": _analyze_relay,
    "v4_hook_callback_no_poolmanager_check":
        _analyze_hook_manager,
    "swap_helper_caller_supplied_pool_hook_no_allowlist":
        _analyze_swap_helper,
    "governance_zero_quorum_executes": _analyze_governance_quorum,
    "duplicate_reward_overwrite_desync": _analyze_dup_reward,
}


def analyze_deep29_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-29 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep29_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit29Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 29)"
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
        for item in analyze_deep29_source(
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
                source="deep audit detector batch 29 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit29Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 29) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
