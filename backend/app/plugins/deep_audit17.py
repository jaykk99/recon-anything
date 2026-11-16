"""Deep-audit detectors, batch 17: the 0-day exploit chain (2026-11-11).

ONE detector: zeroday_exploit_chain. It fires only when the FULL
exploit chain is present in one contract at once - a single
primitive alone never fires, because the existing plugins already
cover those (contract_logic arbitrary_delegatecall, the UUPS
upgrade plugin, recipient_mint_to_caller, the forwarder / multicall
spoof detectors, zeroday_contract_guards' convention break). The
chain:

1. UNGUARDED DANGEROUS PRIMITIVE - a public / external function
   with no caller-identity gate (no only* / auth / ifAdmin
   modifier, no msg.sender identity comparison, no role check, no
   mapping lookup on the caller, no guard helper one hop down,
   no gated super / parent function it delegates to) contains
   one of:
   - .delegatecall() to a caller-controlled target,
   - .call() (any value form) to a caller-controlled target,
   - selfdestruct() with a caller-controlled recipient,
   - upgradeTo() / upgradeToAndCall() with a caller-controlled
     new implementation,
   - _mint() / mint() with a caller-controlled recipient or amount.
2. CALLER CONTROL of the dangerous input - the target /
   recipient / implementation is a function parameter (or a local
   assigned from one, one-hop taint) or msg.sender. A constant,
   immutable, or owner-set storage value is NOT caller control and
   stays silent.
3. REAL VALUE AT STAKE - the same function moves contract value
   to the caller (a fund move to msg.sender / a parameter
   recipient), or is payable and forwards msg.value through the
   primitive, or the primitive itself moves the balance
   (selfdestruct pays address(this).balance to the recipient), or
   the contract holds value (upgrade leg), or the mint creates
   tokens (gated on live pool liquidity at run time). At run time
   the live native balance is also read: a payable-forward-only
   chain on a contract with a KNOWN zero balance is suppressed
   (nothing of the contract's is at stake - the attacker would
   only move their own msg.value).
4. FRESH OR RECENTLY-CHANGED CODE - enforced at run time, not in
   the static analyzer (source cannot know its own age): the
   contract - or its implementation behind a proxy, which is the
   upgrade-window shape - was created within the 30-day window
   (Blockscout getcontractcreation -> receipt block -> current
   block). When the creation lookup fails the age is UNKNOWN and
   the finding is KEPT, never silently dropped: unknown is not
   stale. An old contract (> 30 days) is suppressed and the
   suppression is recorded in the run summary.

The mint leg's value is the minted token's realizable value, so
at run time it is gated on DexScreener pool liquidity (best pair
>= $500, the same dust floor as app/valuation.py): a mint of a
token with no pool is dust, not a lead - the Base-token lesson
(infinite mintable supply, no pool, illusory value). Unknown
liquidity keeps the finding.

Detection only: verified-source static analysis in the fast lane
plus read-only public chain reads (eth_getBalance,
getcontractcreation, eth_getTransactionReceipt, eth_blockNumber,
DexScreener token lookup). Never sends a transaction, never calls
the contract for value, never simulates. Fetch failure is reported
honestly by the shared scaffolding (analyzed 0 / no verified
source - skipped), never dressed up as a clean result.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from . import crypto_drain as cd
from .bsc_common import DetectorSpec, S

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "deep17"

# The 0-day window: code deployed or upgraded within this long is
# fresh enough that an undisclosed bug in it is a live 0-day (no
# audit cycle, no whitehat eyes on it yet). Older code has had its
# window: the same chain on it is a known-shape finding for the
# single-primitive plugins, not a 0-day.
ZERO_DAY_WINDOW_DAYS = 30.0

# A minted token whose best pool holds less than this is dust, not
# a lead (same floor as app/valuation.py DUST_POOL_FLOOR_USD).
DUST_POOL_FLOOR_USD = 500.0

# Approximate seconds per block, per chain (used only to turn a
# creation-block age into days for the freshness window).
_BLOCK_TIME_S = {
    "ethereum": 12.0, "bsc": 3.0, "polygon": 2.0,
    "arbitrum": 0.25, "base": 2.0, "optimism": 2.0,
}

SPECS = [
    S("zeroday_exploit_chain", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="0-day exploit chain: an unguarded public / external "
             "function hands a stranger a dangerous primitive "
             "(delegatecall / arbitrary call to a caller-supplied "
             "target, selfdestruct / upgrade to a caller-supplied "
             "address, or mint to a caller-supplied recipient) "
             "AND the same function moves real contract value to "
             "the caller, AND the code is fresh (deployed or "
             "upgraded within 30 days) - the full chain a live "
             "0-day needs, in one contract. Any single leg alone "
             "is covered by the existing single-primitive "
             "detectors and stays silent here.",
      fix="Gate the dangerous function (onlyOwner / onlyRole, or "
          "an allowlist of targets), never let a caller supply "
          "the delegatecall / call target, the selfdestruct "
          "recipient, the upgrade implementation, or the mint "
          "recipient, and do not move contract value in the same "
          "function that takes caller-controlled addresses."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 11)
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


# TransparentUpgradeableProxy's admin-only modifier. It is not an
# only* name, so the shared gate check below does not see it, but
# it is the same identity gate (only the proxy admin may call).
_ADMIN_MOD_RE = re.compile(r"\bifAdmin\b")

# A role predicate that checks the CALLER's role internally and
# takes only the role as an argument: require(isSenderInRole(
# ROLE_TOKEN_CREATOR), ...) - the call site never mentions
# msg.sender, so the shared gate check (which needs msg.sender
# in the call) does not see it.
_SENDER_ROLE_CALL_RE = re.compile(
    r"(?:require|if)\s*\([^;{]*?\b(?:isSenderInRole|isSenderIn|"
    r"senderHasRole|isCallerInRole|hasSenderRole)\s*\(")


def _has_caller_limit_gate(text: str, params: List[str]) -> bool:
    """A per-caller bridge limit gate (the xERC20 shape): the
    function aliases msg.sender to a local, calls a *LimitOf()
    function with that local (or msg.sender), and reverts when
    the limit is below the requested amount. Only a registered
    bridge has a limit above zero, so a stranger's mint reverts.
    Both halves are required: a limit lookup on the caller, and
    a revert when it is below the amount."""
    aliases = set()
    for m in re.finditer(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"(?:msg\.sender|_msgSender\s*\(\s*\))", text):
        aliases.add(m.group(1))
    callers = [r"msg\.sender", r"_msgSender\s*\(\s*\)"] + \
        [re.escape(a) for a in sorted(aliases)]
    caller_alt = "(?:" + "|".join(callers) + ")"
    if not re.search(
            r"\b[A-Za-z_][A-Za-z0-9_]*LimitOf\s*\(\s*" +
            caller_alt + r"\s*\)", text):
        return False
    amt_alt = "|".join(re.escape(p) for p in params) or "amount"
    # The revert / require compares the limit against the amount
    # in any direction: if (limit < amount) revert, require(limit
    # >= amount), if (amount > limit) revert.
    return bool(re.search(
        r"(?:if|require)\s*\([^;{]*(?:<\s*(?:" + amt_alt + r")\b|"
        r">=\s*(?:" + amt_alt + r")\b|"
        r"(?:" + amt_alt + r")\s*>\s)", text))


def _gated_direct(fn: Dict[str, Any], scope) -> bool:
    """The function's own gate. This mirrors contract_logic
    _gated_deep (the shared discipline: _is_gated on the
    signature / body, on referenced modifier bodies, and on
    internal helpers one hop down) with ONE correction: the
    _authorizeUpgrade name is neutralized before the check. The
    shared _GATE_RE treats the literal name _authorizeUpgrade as
    a gate, so _gated_deep calls every UUPS upgradeTo gated -
    including one whose _authorizeUpgrade override is an empty
    body - before the (D) check on the override ever runs. A call
    to _authorizeUpgrade is the authorization STEP, not the gate:
    the gate lives in the override's modifier / body, which the
    (D) check reads precisely. So here the name is stripped from
    the signature / body and the _authorizeUpgrade helper is
    skipped, and the function is gated only when something ELSE
    gates it. One hop only, never recursive."""
    # The replacement token must not contain "_authorizeUpgrade"
    # as a substring (the shared _GATE_RE would still match it).
    sig = fn["signature"].replace("_authorizeUpgrade",
                                   "_authUpgrade")
    text = fn["text"].replace("_authorizeUpgrade",
                              "_authUpgrade")
    if cd._is_gated(sig, text):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        tail = stripped[cd._matching(stripped, i) + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and cd._is_gated("", body):
                return True
    for name, helper in scope.helpers.items():
        if name == fn["name"] or name in ("_authorizeUpgrade",
                                          "authorizeUpgrade"):
            continue
        if re.search(r"\b" + re.escape(name) + r"\s*\(", text) and \
                cd._is_gated(helper["signature"], helper["text"]):
            return True
    if _ADMIN_MOD_RE.search(fn["signature"]):
        return True
    if _SENDER_ROLE_CALL_RE.search(fn["text"]):
        return True
    if _has_caller_limit_gate(fn["text"], _fn_params(fn)):
        return True
    return False


def _caller_gated(fn: Dict[str, Any], scope,
                  inherit: Optional[Dict[str, List[str]]] = None
                  ) -> bool:
    """Caller-identity gate (see module docstring).

    The gate discipline is the shared one (contract_logic
    _gated_deep / crypto_drain _is_gated): an only* / auth /
    adminOnly modifier, a msg.sender identity comparison, a role
    check, a mapping lookup on the caller (minters[msg.sender],
    isMinter[_msgSender()] - _msgSender() is exactly msg.sender),
    a registry / signature gate, in the function's own body or in
    a referenced modifier's body - or one hop down the internal
    call path, in a guard helper the function calls (_canMint(),
    _requireCallerIsWhitelistedContract()). Three additions on
    top of _gated_deep: the ifAdmin modifier, a sender-role
    predicate call (isSenderInRole), a per-caller bridge limit
    (xERC20 mintingCurrentLimitOf), and super / parent
    delegation - a child mint that only calls super.mint() or
    AliERC20v2Base.mint() inherits the parent mint's gate, so it
    is gated when the parent is. Plus one correction inside
    _gated_direct: the _authorizeUpgrade name is neutralized, so
    a UUPS upgradeTo is gated only when something other than the
    authorization call itself gates it - the (D) check on the
    override decides the upgrade path. One hop only, never
    recursive.
    """
    if _gated_direct(fn, scope):
        return True
    if inherit is None:
        return False
    text = fn["text"]
    ancestors = inherit.get(fn.get("contract", ""), [])
    if not ancestors:
        return False
    for m in re.finditer(
            r"\b(?:super|([A-Za-z_][A-Za-z0-9_]*))\s*\.\s*"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        parent, fname = m.group(1), m.group(2)
        if parent is not None and parent not in ancestors:
            continue
        for cand in scope.functions:
            if cand["name"] == fname and \
                    cand.get("contract") in ancestors and \
                    "{" in cand["text"]:
                if _gated_direct(cand, scope):
                    return True
    return False


def _inheritance_map(src: str) -> Dict[str, List[str]]:
    """contract name -> direct ancestor names, parsed from the
    `contract X is A, B {` declarations (constructor arguments on
    an ancestor, e.g. ERC20("Name", "SYM"), are stripped to the
    base identifier). Used only to resolve super./Parent. calls
    in _caller_gated."""
    out: Dict[str, List[str]] = {}
    for m in re.finditer(
            r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
            r"(?:is\s+([^{]+?))?\{", src):
        parents: List[str] = []
        if m.group(2):
            for part in _split_top(m.group(2)):
                base = re.match(r"[A-Za-z_][A-Za-z0-9_]*",
                                part.strip())
                if base:
                    parents.append(base.group(0))
        out[m.group(1)] = parents
    return out


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


def _skip_fn(fn: Dict[str, Any], scope,
             inherit: Optional[Dict[str, List[str]]] = None) -> bool:
    if re.search(r"\b(view|pure)\b", fn["signature"]):
        return True
    return _caller_gated(fn, scope, inherit)


def _fn_params(fn: Dict[str, Any]) -> List[str]:
    """Parameter names from a function signature."""
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


def _fn_addr_params(fn: Dict[str, Any]) -> List[str]:
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner, _ = _balanced(sig, sig.index("("))
    out: List[str] = []
    for part in _split_top(inner):
        if "address" in part:
            toks = [t for t in part.split()
                    if t not in ("calldata", "memory", "storage",
                                 "payable")]
            if len(toks) >= 2:
                out.append(toks[-1])
    return out


def _is_payable(fn: Dict[str, Any]) -> bool:
    """True when the function itself is payable (mutability in
    the signature tail, not an `address payable` parameter)."""
    sig = fn["signature"]
    i = sig.find("(")
    if i < 0:
        return False
    _, pend = _balanced(sig, i)
    tail = sig[pend + 1:]
    return bool(re.search(r"\bpayable\b", tail))


# ---------------------------------------------------------------------------
# The 0-day chain: primitive + caller control + value
# ---------------------------------------------------------------------------

_DELEGATECALL_RE = re.compile(r"\.delegatecall\s*\(")
_CALL_RE = re.compile(r"\.call\s*(?:\(|\{)")
_SELFDESTRUCT_RE = re.compile(r"\bselfdestruct\s*\(")
_UPGRADE_RE = re.compile(r"\bupgradeTo(?:AndCall)?\s*\(")
_MINT_RE = re.compile(r"\b(?:_mint|mint)\s*\(")

_CALLER_WORD_RE = re.compile(
    r"\bmsg\.sender\b|\bmsg\.data\b|\bcalldata\b")


def _expr_mentions_caller(expr: str, params: List[str],
                          tainted: set) -> bool:
    """True when an expression reads caller-controlled data."""
    if not expr:
        return False
    if _CALLER_WORD_RE.search(expr):
        return True
    for name in list(params) + sorted(tainted):
        if re.search(r"\b" + re.escape(name) + r"\b", expr):
            return True
    return False


def _tainted_locals(text: str, params: List[str]
                    ) -> Tuple[set, set]:
    """Local names assigned from caller-controlled data (one-hop
    taint, fixpoint over two passes so `a = _p; b = a;` chains).
    Returns (tainted, direct): direct aliases are locals assigned
    from EXACTLY one parameter / msg.value / msg.sender (casts
    stripped) - the only taint a minted AMOUNT may rely on, so a
    protocol-computed amount (reserves math) never counts as
    caller-controlled."""
    tainted: set = set()
    direct: set = set()
    for _ in range(2):
        for m in re.finditer(
                r"(?:^|[;{}])\s*(?:(?:address|uint\d*|bytes\d*|"
                r"bool|string)\s+(?:memory\s+|calldata\s+|"
                r"storage\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
                r"([^;{}]+);", text):
            name, expr = m.group(1), m.group(2)
            if name in params:
                continue
            if _expr_mentions_caller(expr, params, tainted):
                tainted.add(name)
            bare = cd._unwrap(expr.strip().strip("()").strip())
            if bare in params or bare in ("msg.value",
                                          "msg.sender"):
                direct.add(name)
    return tainted, direct


def _is_controlled(expr: str, params: List[str],
                   tainted: set) -> bool:
    """The dangerous input is caller-controlled: a parameter, an
    element of a parameter array, a tainted local, or msg.sender.
    A constant, immutable, or storage value set elsewhere is not.
    """
    e = cd._unwrap(expr or "")
    if not e:
        return False
    if e == "msg.sender":
        return True
    if cd._caller_controlled(e, params):
        return True
    base = re.match(r"[A-Za-z_][A-Za-z0-9_]*", e)
    if base and base.group(0) in tainted:
        return True
    return False


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


def _call_data_arg(text: str, call_match) -> str:
    """The data argument of a .call: target.call{...}(data),
    target.call.value(v)(data), or target.call(data). Empty
    string when the call carries no data argument."""
    i = call_match.end()
    while i < len(text) and text[i] in " \t\n":
        i += 1
    if i < len(text) and text[i] == "{":
        _, close = _balanced_brace(text, i)
        j = text.find("(", close)
        if j < 0:
            return ""
        inner, _ = _balanced(text, j)
        return _split_top(inner)[0] if _split_top(inner) else ""
    if text[i:i + 7] == ".value(":
        paren = text.index("(", i)
        _, close = _balanced(text, paren)
        j = text.find("(", close)
        if j < 0:
            return ""
        inner, _ = _balanced(text, j)
        return _split_top(inner)[0] if _split_top(inner) else ""
    if i < len(text) and text[i] == "(":
        inner, _ = _balanced(text, i)
        return _split_top(inner)[0] if _split_top(inner) else ""
    return ""


def _snippet(text: str, pos: int, cap: int = 600) -> str:
    """The source line(s) around a match, for code evidence."""
    lines = text.split("\n")
    off = 0
    for i, line in enumerate(lines):
        if off <= pos < off + len(line) + 1:
            lo = max(0, i - 1)
            hi = min(len(lines), i + 2)
            return "\n".join(lines[lo:hi]).strip()[:cap]
        off += len(line) + 1
    return text.strip()[:cap]


def _analyze_zeroday_exploit_chain(src, spec, compiler,
                                   contract_name):
    scope, fns = _scope_fns(src, contract_name)
    inherit = _inheritance_map(src)
    # Contract-level value: any fund move or payable function
    # anywhere in the contract (the upgrade leg's value basis).
    holds_value = False
    for fn in fns:
        if _is_payable(fn) or cd._fund_moves(fn["text"]):
            holds_value = True
            break
    # A gated _authorizeUpgrade authorizes the upgrade path
    # (the UUPS shape): an upgrade leg never fires on it.
    upgrade_authorized = any(
        fn["name"] in ("_authorizeUpgrade", "authorizeUpgrade")
        and _caller_gated(fn, scope, inherit) for fn in fns)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope, inherit):
            continue
        # Only externally reachable functions: a constructor runs
        # once at deployment (never a live exploit), and internal /
        # private helpers are not callable by a stranger - the
        # OpenZeppelin Address helpers (sendValue,
        # functionCallWithValue) live there and must not fire.
        sig = fn["signature"]
        if fn["name"] == "constructor":
            continue
        if "public" not in sig and "external" not in sig:
            continue
        text = fn["text"]
        params = _fn_params(fn)
        if not params and "msg.sender" not in text:
            continue
        tainted, direct = _tainted_locals(text, params)
        moves = cd._fund_moves(text)
        value_to_caller = False
        for mv in moves:
            rec = (mv.get("recipient") or "").strip()
            amt = (mv.get("amount") or "").strip()
            if amt in ("0", "0x0"):
                continue
            if _is_controlled(rec, params, tainted):
                value_to_caller = True
                break
        payable = _is_payable(fn)
        # (leg, dangerous-input, recipient-class, value-basis, pos)
        prims: List[Tuple[str, str, str, str, int]] = []
        body_at = text.find("{")
        for m in _DELEGATECALL_RE.finditer(text):
            if m.start() < body_at:
                continue  # the signature, not a call
            recv = cd._unwrap(cd._expr_before(text, m.start()))
            if not _is_controlled(recv, params, tainted):
                continue
            if value_to_caller:
                basis = "fund_move"
            elif payable:
                basis = "payable_forward"
            else:
                continue  # no value at stake in this function
            recip = ("CALLER" if recv == "msg.sender"
                     else "CALLER-SUPPLIED")
            prims.append(("delegatecall", recv, recip, basis,
                          m.start()))
        for m in _CALL_RE.finditer(text):
            if m.start() < body_at:
                continue  # the signature, not a call
            recv = cd._unwrap(cd._expr_before(text, m.start()))
            if not recv or recv in ("address", "payable"):
                continue
            if not _is_controlled(recv, params, tainted):
                continue
            # An arbitrary call needs caller-controlled DATA, not
            # just a caller-chosen target: target.call{value:}("")
            # is a plain value transfer (the standard withdraw),
            # not an arbitrary call.
            data = _call_data_arg(text, m)
            if not data or data in ('""', "''", '"0x"', "'0x'"):
                continue
            if not _expr_mentions_caller(data, params, tainted):
                continue
            if value_to_caller:
                basis = "fund_move"
            elif payable:
                basis = "payable_forward"
            else:
                continue
            recip = ("CALLER" if recv == "msg.sender"
                     else "CALLER-SUPPLIED")
            prims.append(("call", recv, recip, basis, m.start()))
        for m in _SELFDESTRUCT_RE.finditer(text):
            if m.start() < body_at:
                continue  # a function named selfdestruct, not a call
            args = _call_args(text, m)
            recip_arg = (args[0].strip() if args else "")
            if not _is_controlled(recip_arg, params, tainted):
                continue  # fixed recipient: griefing, not a steal
            recip = ("CALLER" if recip_arg == "msg.sender"
                     else "CALLER-SUPPLIED")
            prims.append(("selfdestruct", recip_arg, recip,
                          "selfdestruct_balance", m.start()))
        # A function NAMED upgradeTo / upgradeToAndCall IS the
        # primitive: the entry point itself takes the new
        # implementation (its body rarely contains a literal
        # upgradeTo( call). A wrapper that CALLS upgradeTo is
        # caught by the regex below.
        if upgrade_authorized:
            pass  # the upgrade path is authorized, no upgrade leg
        elif fn["name"] in ("upgradeTo", "upgradeToAndCall"):
            for p in _fn_addr_params(fn):
                if not _is_controlled(p, params, tainted):
                    continue
                if not holds_value:
                    continue
                recip = "CALLER-SUPPLIED"
                prims.append(("upgrade", p, recip,
                              "contract_holds_value",
                              text.find(fn["name"])))
                break
        for m in _UPGRADE_RE.finditer(text):
            if m.start() < body_at:
                continue  # the declaration, handled above
            if upgrade_authorized:
                continue  # the upgrade path is authorized
            args = _call_args(text, m)
            impl = (args[0].strip() if args else "")
            if not _is_controlled(impl, params, tainted):
                continue
            if not holds_value:
                continue  # nothing of value under this proxy
            recip = ("CALLER" if impl == "msg.sender"
                     else "CALLER-SUPPLIED")
            prims.append(("upgrade", impl, recip,
                          "contract_holds_value", m.start()))
        for m in _MINT_RE.finditer(text):
            if m.start() < body_at:
                continue  # the declaration, not a call
            args = _call_args(text, m)
            if not args:
                continue
            to_arg = args[0].strip()
            amt_arg = args[1].strip() if len(args) > 1 else ""
            to_ctrl = _is_controlled(to_arg, params, tainted)
            # The amount must be caller-controlled: the parameter
            # itself, a direct alias, msg.value, or an expression
            # built from one (amount * 2, msg.value * 2 - a
            # doubled mint is still the caller's choice). A
            # protocol-computed amount (AMM liquidity from reserve
            # math) is not the caller's choice - the LP mint only
            # returns what the caller already put in.
            amt_bare = cd._unwrap(amt_arg.strip().strip("()").strip())
            amt_ctrl = (amt_bare in params or amt_bare in direct or
                        amt_bare == "msg.value" or
                        bool(re.search(r"\bmsg\.value\b", amt_arg)) or
                        any(re.search(r"\b" + re.escape(p) + r"\b",
                                      amt_arg) for p in params))
            if not amt_ctrl:
                continue  # the amount is protocol-computed (LP
                # liquidity from reserve math), not the caller's
                # choice - the mint only returns what was put in
            # A mint of exactly msg.value is self-funded: the
            # caller pays X and mints X worth (depositTo), so
            # there is nothing to steal. A multiplier (msg.value
            # * 2) is NOT self-funded - the caller profits - and
            # still fires.
            if amt_bare == "msg.value":
                continue
            if to_ctrl:
                recip = ("CALLER" if to_arg == "msg.sender"
                         else "CALLER-SUPPLIED")
            else:
                recip = "FIXED"  # amount controlled, recipient fixed
            prims.append(("mint", to_arg, recip, "mint", m.start()))
        for leg, dangerous, recip, basis, pos in prims:
            code = _snippet(text, pos)
            detail = (
                f"0-day exploit chain ({leg}): unguarded public "
                f"function '{fn['name']}' hands a stranger the "
                f"dangerous input '{dangerous}' (caller-supplied) "
                f"and the same function moves real contract value "
                f"(value basis: {basis}), so one call can both "
                f"seize control and take the funds. Freshness is "
                f"enforced at run time (creation within the "
                f"{ZERO_DAY_WINDOW_DAYS:.0f}-day window, or unknown "
                f"when the creation lookup fails) - this static "
                f"finding is the source chain only.")
            gate = (
                f"No caller-identity gate on '{fn['name']}' (no "
                f"only* modifier, no msg.sender identity "
                f"comparison, no role check). Dangerous input "
                f"'{dangerous}' is a function parameter or a "
                f"local assigned from one (caller-supplied), not "
                f"a constant, immutable, or owner-set value. "
                f"Value basis: {basis}.")
            item = _hit(spec, fn["name"], code, detail, gate)
            item["leg"] = leg
            item["value_basis"] = basis
            item["dangerous_input"] = dangerous
            _classify(item, recip,
                      f"the {leg} input '{dangerous}' is "
                      f"caller-supplied" if recip != "FIXED" else
                      f"the minted tokens land at the fixed "
                      f"recipient '{dangerous}'")
            out.append(item)
            break  # one finding per function: the strongest leg
    return out


ANALYZERS = {
    "zeroday_exploit_chain": _analyze_zeroday_exploit_chain,
}


def analyze_deep17_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run the batch-17 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class, leg,
    value_basis, dangerous_input}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Live legs (run time only): balance, freshness, mint liquidity.
# All read-only public endpoints. Any failure -> unknown, and
# unknown NEVER suppresses a finding (unknown is not stale, not
# dust, not empty) - the gates below only fire on a KNOWN value.
# ---------------------------------------------------------------------------

async def _rpc_call(ctx: Ctx, chain: cc.ChainConfig,
                    method: str, params: list) -> Optional[Any]:
    """One JSON-RPC call via ctx.http, trying the chain's RPCs in
    order. Returns the result, or None when every endpoint fails
    or there is no HTTP client (tests)."""
    http = getattr(ctx, "http", None) if ctx is not None else None
    if http is None:
        return None
    payload = {"jsonrpc": "2.0", "id": 1, "method": method,
               "params": params}
    for rpc in chain.rpc_urls:
        try:
            r = await http.post(rpc, json=payload, timeout=10.0)
            d = r.json()
            if isinstance(d, dict) and d.get("result") is not None:
                return d["result"]
        except Exception:
            continue
    return None


async def _creation_age_days(ctx: Ctx, chain: cc.ChainConfig,
                             addr: str) -> Tuple[Optional[float],
                                                 Optional[int],
                                                 Optional[int]]:
    """(age_days, creation_block, current_block) for a contract,
    or (None, None, None) when the age cannot be determined.
    Blockscout getcontractcreation -> receipt block -> head block.
    """
    http = getattr(ctx, "http", None) if ctx is not None else None
    if http is None or not chain.blockscout_api:
        return (None, None, None)
    try:
        from urllib.parse import urlencode
        params = {"module": "contract",
                  "action": "getcontractcreation",
                  "contractaddresses": addr}
        url = f"{chain.blockscout_api}?{urlencode(params)}"
        r = await http.get(url, timeout=10.0)
        d = r.json()
        res = (d or {}).get("result") or []
        if not res or not isinstance(res, list):
            return (None, None, None)
        tx = (res[0] or {}).get("txHash") or ""
        if not tx:
            return (None, None, None)
        receipt = await _rpc_call(
            ctx, chain, "eth_getTransactionReceipt", [tx])
        if not isinstance(receipt, dict):
            return (None, None, None)
        creation_block = int(receipt.get("blockNumber", "0x0"), 16)
        head = await _rpc_call(ctx, chain, "eth_blockNumber", [])
        if head is None:
            return (None, None, None)
        current_block = int(head, 16)
        if current_block <= creation_block:
            return (0.0, creation_block, current_block)
        secs = ((current_block - creation_block) *
                _BLOCK_TIME_S.get(chain.id, 12.0))
        return (secs / 86400.0, creation_block, current_block)
    except Exception:
        return (None, None, None)


async def _token_liquidity_usd(ctx: Ctx,
                               addr: str) -> Optional[float]:
    """Best DexScreener pair liquidity (USD) for a token, or None
    when unknown (no HTTP client, fetch failure, no pairs)."""
    http = getattr(ctx, "http", None) if ctx is not None else None
    if http is None:
        return None
    try:
        r = await http.get(
            f"https://api.dexscreener.com/latest/dex/tokens/{addr}",
            timeout=10.0)
        d = r.json()
        best: Optional[float] = None
        for p in (d or {}).get("pairs") or []:
            usd = ((p or {}).get("liquidity") or {}).get("usd")
            if usd is None:
                continue
            if best is None or float(usd) > best:
                best = float(usd)
        return best
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-11 collection / fetch /
# proxy resolution; analysis is analyze_deep17_source per spec,
# plus the live legs applied only after the static chain fires)
# ---------------------------------------------------------------------------

class DeepAudit17Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 12)"
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
        self._gate_notes: List[str] = []
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
        summary = (
            f"{spec.id}: analyzed {analyzed} contract address(es) "
            f"({no_source} without verified source - skipped, no "
            f"guess made), {hits} finding(s)")
        if self._gate_notes:
            summary += "; live gates: " + "; ".join(self._gate_notes)
        res = self._ok(findings, summary)
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
        got = await self._analyze_contract(ctx, chain, addr, src,
                                           findings, role=role,
                                           impl_addr=impl)
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
        return await self._analyze_contract(
            ctx, chain, impl, impl_src, findings,
            role="implementation", proxy_addr=addr) or got

    async def _analyze_contract(self, ctx: Ctx,
                                chain: cc.ChainConfig,
                                addr: str,
                                src: Optional[Dict[str, Any]],
                                findings: List[Finding], role: str,
                                proxy_addr: str = "",
                                impl_addr: str = "") -> bool:
        spec = self._spec
        if spec is None or not src:
            return False
        items = analyze_deep17_source(
            src["source"], spec, src.get("compiler", ""),
            contract_name=src.get("contract_name", ""))
        if not items:
            return True  # source analyzed, static chain absent
        # Live legs, only now that the static chain already fired.
        balance = await cc.rpc_get_balance(ctx, chain, addr)
        age_days, creation_block, current_block = \
            await _creation_age_days(ctx, chain, addr)
        liquidity: Optional[float] = None
        if any(it.get("leg") == "mint" for it in items):
            liquidity = await _token_liquidity_usd(ctx, addr)
        kept: List[Dict[str, Any]] = []
        for item in items:
            leg = item.get("leg")
            basis = item.get("value_basis")
            if age_days is not None and \
                    age_days > ZERO_DAY_WINDOW_DAYS:
                self._gate_notes.append(
                    f"{addr} on {chain.id}: {leg} chain "
                    f"suppressed - code is {age_days:.0f} days old "
                    f"(window {ZERO_DAY_WINDOW_DAYS:.0f}d)")
                continue
            if basis == "payable_forward" and balance == 0:
                self._gate_notes.append(
                    f"{addr} on {chain.id}: {leg} chain "
                    f"suppressed - native balance is 0 and the "
                    f"value leg was payable-forwarding only")
                continue
            if leg == "mint" and liquidity is not None and \
                    liquidity < DUST_POOL_FLOOR_USD:
                self._gate_notes.append(
                    f"{addr} on {chain.id}: mint chain "
                    f"suppressed - token pool liquidity "
                    f"${liquidity:,.0f} is dust "
                    f"(floor ${DUST_POOL_FLOOR_USD:,.0f})")
                continue
            item["native_balance_wei"] = balance
            item["creation_age_days"] = age_days
            item["creation_block"] = creation_block
            item["current_block"] = current_block
            item["freshness"] = (
                "fresh" if age_days is not None and
                age_days <= ZERO_DAY_WINDOW_DAYS else "unknown")
            if leg == "mint":
                item["token_liquidity_usd"] = liquidity
            kept.append(item)
        if not kept:
            return True
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
        for item in kept:
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
                "leg": item.get("leg"),
                "value_basis": item.get("value_basis"),
                "dangerous_input": item.get("dangerous_input"),
                "native_balance_wei": item.get("native_balance_wei"),
                "creation_age_days": item.get("creation_age_days"),
                "creation_block": item.get("creation_block"),
                "current_block": item.get("current_block"),
                "freshness": item.get("freshness"),
            })
            if item.get("leg") == "mint":
                ev["token_liquidity_usd"] = item.get(
                    "token_liquidity_usd")
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
                source="deep audit detector batch 17 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit17Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 17) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
