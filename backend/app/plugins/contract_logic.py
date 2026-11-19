"""Smart Contract Logic Analyzer: analyze HOW a contract's code
behaves, not just who can call it.

The other web3 plugins map surface: privileged functions, secret
strings, drain shapes, infra exposure. This one reads the logic of
the verified source (and falls back to bytecode heuristics when no
source is verified) for the classic contract bug classes:

- Reentrancy (key "reentrancy"): an external call - low-level
  .call{value:}, .call.value(), ETH transfer/send, token
  safe-transfer hooks, calls into external token contracts - that
  happens BEFORE the state update that should precede it
  (checks-effects-interactions violation), plus cross-function
  hints when state written after a call in one function is read
  before a call in another.
- Integer overflow / underflow (key "integer_overflow"):
  Solidity <0.8 raw arithmetic on state values with no SafeMath;
  Solidity >=0.8 `unchecked {}` blocks doing arithmetic on
  balances / supply; inline assembly arithmetic touching stored
  balances. The compiler version comes from the pragma or the
  explorer metadata.
- Access-control flaws (key "access_control_flaw"): sensitive
  functions (mint, withdraw, setOwner, upgrade, setFee, pause,
  ...) with NO gate that actually perform the sensitive action;
  tx.origin used for authorization; an unprotected initialize()
  (public, no initializer modifier); arbitrary delegatecall to a
  caller-supplied target.

False-positive discipline is the SAME as the drain analyzer and
the bridge critical watch, shared by importing its gate logic:
only* modifiers of any name, msg.sender comparisons in either
direction (including the BNB `if (msg.sender != owner) throw;`
shape), role checks, and signature verification all count as
gated; interface declarations, internal/private, and view/pure
functions are skipped; ReentrancyGuard (nonReentrant) suppresses
the reentrancy lane; CEI-ordered functions (state written before
the call) do not flag.

2026-11-02 FP fixes (adjudicated regression set: 99 false
positives out of 103 hand-validated candidates across the
10,000-contract sweep):
1. Overflow lane: arithmetic inside internal/private functions,
   arithmetic whose bound is require/if-revert checked earlier in
   the same function (the canonical OpenZeppelin shape: balance
   checked, THEN the unchecked block), and msg.value-bounded
   arithmetic (WETH9 deposit) no longer flag.
2. Gate detection reads the full body and the internal call path:
   _msgSender() comparisons, boolean role-mapping lookups
   (require(isMinter[msg.sender])), role predicate calls, custom
   gate modifiers by name AND by definition body, registry-
   indirect gates (bridges[msg.sender] + require on the struct),
   and gates enforced by an internal helper the function calls.
3. Compilation scoping: only the target contract and its
   ancestors are analyzed. Sibling contracts bundled in the same
   verified compilation, test/mock files, and free functions are
   not methods of the deployed target and never flag.
4. Recipient dataflow (the receive rule): an ungated sensitive
   function whose moved value lands at a FIXED destination
   (owner(), a stored project address, a literal) or back with
   the caller metered by their own balance is emitted as
   TRIGGER-ONLY at low severity, never as a candidate-grade flaw.

Bytecode lane (key "bytecode_opcode_risk"): when no verified
source exists, the runtime bytecode is analyzed per selector by
bytecode_paths: an EIP-1167 minimal proxy surfaces its
implementation address; a recognized solc dispatcher yields one
finding per selector whose walked path reaches a sensitive
opcode (SELFDESTRUCT / DELEGATECALL paths at medium, CALL-only
at low), with the path opcodes, storage slots, and an inert
eth_call probe sketch for the validator; with no dispatcher
recognized, the legacy aggregate SELFDESTRUCT / DELEGATECALL /
CALLCODE presence finding is emitted unchanged. Everything in
this lane is explicitly labeled a bytecode-only heuristic -
never a confirmed logic flaw.

Detection only. Never sends a transaction, never calls the
contract; the deepest access is eth_getCode and public explorer
reads, exactly like contract_recon and the drain analyzer. When a
target is a proxy, the implementation behind it is resolved (one
level) and analyzed too, with findings tagged by contract role.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import bytecode_paths as bp
from . import chain_data
from . import crypto_drain as cd

MAX_ADDRESSES = 4       # addresses analyzed per run
MAX_CHAIN_PAIRS = 4     # (chain, address) pairs analyzed per run

_REMEDIATIONS = {
    "reentrancy": (
        "Reorder the function to checks-effects-interactions "
        "(update all state BEFORE any external call) and/or add a "
        "reentrancy guard (e.g. OpenZeppelin ReentrancyGuard). As "
        "written, a caller contract can re-enter during the "
        "external call and repeat the operation against stale "
        "state."),
    "integer_overflow": (
        "Compile with Solidity >=0.8 checked arithmetic (or use "
        "SafeMath on pre-0.8 compilers) and remove unchecked / "
        "assembly arithmetic on balances and supply unless every "
        "operation is provably bounded. Over/underflow lets an "
        "attacker wrap a balance or the total supply."),
    "access_control_flaw": (
        "Put this function behind real access control (an "
        "owner/role check enforced in the function or a modifier; "
        "an initializer modifier for initialize()), and never "
        "authorize on tx.origin. As deployed, any caller can use "
        "it."),
    "bytecode_opcode_risk": (
        "Get the contract source verified so the logic can be "
        "audited properly. The bytecode alone contains opcodes "
        "that deserve a manual audit (selfdestruct / delegatecall "
        "capability); this is a heuristic, not a confirmed flaw."),
}

_UNGATED_BASIS = cd._UNGATED_BASIS


# ---------------------------------------------------------------------------
# Source model helpers
# ---------------------------------------------------------------------------

def solc_version(src: str, compiler: str = "") -> Optional[Tuple[int, ...]]:
    """Solidity version from the pragma, falling back to the
    explorer's compiler string ("v0.8.20+commit...", "0.6.12")."""
    m = re.search(r"pragma\s+solidity[^;]*?(\d+)\.(\d+)(?:\.(\d+))?", src)
    if not m and compiler:
        m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", compiler)
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None)


def _depth_array(src: str) -> List[int]:
    """Brace depth before each character index."""
    depths = [0] * (len(src) + 1)
    d = 0
    for i, ch in enumerate(src):
        depths[i] = d
        if ch == "{":
            d += 1
        elif ch == "}":
            d -= 1
    depths[len(src)] = d
    return depths


_DECL_RES = [
    # Nested mappings: mapping(address => mapping(address =>
    # LockInfo)) - the key type may itself contain parens, so
    # the value type allows one level of nested parens
    # (TokenHub lockInfoMap was missed entirely before this).
    re.compile(r"mapping\s*\((?:[^()]|\([^()]*\))*\)\s*"
               r"(?:(?:public|private|internal)\s+)?([A-Za-z_]\w*)"),
    re.compile(r"\b(?:uint\d*|int\d*|address|bool|bytes32)\s+"
               r"(?:(?:public|private|internal|constant|immutable)\s+)*"
               r"([A-Za-z_]\w*)\s*(?:=[^;]*)?;"),
]


def state_variables(src: str) -> set:
    """Names of contract-level (depth-1) state variables."""
    depths = _depth_array(src)
    out = set()
    for pat in _DECL_RES:
        for m in pat.finditer(src):
            if depths[m.start()] == 1:
                out.add(m.group(1))
    return out


_ASSIGN_RE = re.compile(
    r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(\+=|-=|\*=|=(?!=))")
_DELETE_RE = re.compile(r"\bdelete\s+([A-Za-z_]\w*)")


def _state_writes(text: str, state: set) -> List[Tuple[int, str]]:
    """(position, variable) for writes to state variables."""
    out: List[Tuple[int, str]] = []
    for m in _ASSIGN_RE.finditer(text):
        if m.group(1) in state:
            out.append((m.start(), m.group(1)))
    for m in _DELETE_RE.finditer(text):
        if m.group(1) in state:
            out.append((m.start(), m.group(1)))
    return sorted(out)


def _reads_var(text: str, var: str) -> bool:
    return re.search(r"\b" + re.escape(var) + r"\b", text) is not None


# ---------------------------------------------------------------------------
# External calls (for the reentrancy lane)
# ---------------------------------------------------------------------------

_CALL_RES = [
    ("call", re.compile(r"\.call\s*\{")),
    ("call", re.compile(r"\.call\s*\.value\s*\(")),
    ("call", re.compile(r"\.call\s*\(")),
    ("delegatecall", re.compile(r"\.delegatecall\s*\(")),
    ("callcode", re.compile(r"\.callcode\s*\(")),
    ("send", re.compile(r"\.send\s*\(")),
    ("safe_transfer", re.compile(r"\.safeTransfer(?:From)?\s*\(")),
    ("hook", re.compile(
        r"\.(?:onERC721Received|onERC1155Received|"
        r"onERC1155BatchReceived|tokensReceived)\s*\(")),
]


def _external_calls(text: str) -> List[Dict[str, Any]]:
    """External call sites: {pos, end, kind, receiver, args}."""
    out: List[Dict[str, Any]] = []
    seen_pos = set()
    for kind, pat in _CALL_RES:
        for m in pat.finditer(text):
            if m.start() in seen_pos:
                continue
            seen_pos.add(m.start())
            recv = cd._expr_before(text, m.start())
            if cd._base_ident(cd._unwrap(recv)) in ("super", "this"):
                continue
            out.append({"pos": m.start(), "kind": kind,
                        "receiver": recv, "args": ""})
    # ETH transfer (1 arg) and token transfer / transferFrom (2-3
    # args) into an external contract both hand control or value
    # outward; the contract's OWN token API is a definition, not a
    # `.transfer(` call site, so call sites are what matters here.
    for m in re.finditer(r"\.(transferFrom|transfer)\s*\(", text):
        recv = cd._expr_before(text, m.start())
        if cd._base_ident(cd._unwrap(recv)) in ("super", "this"):
            continue
        paren = m.end() - 1
        args = cd._split_top(text[paren + 1:cd._matching(text, paren)])
        out.append({"pos": m.start(),
                    "kind": "transferFrom" if m.group(1) == "transferFrom"
                    else "transfer",
                    "receiver": recv, "args": args})
    return sorted(out, key=lambda c: c["pos"])


# ---------------------------------------------------------------------------
# Compilation scope (FP fix 3): findings must map to the deployed
# target contract's OWN code. Verified bundles routinely ship
# sibling contracts (a DepositHandler next to the token), library
# test fixtures (contracts/test/...), and free functions; none of
# those are methods of the deployed target.
# ---------------------------------------------------------------------------

_FILE_MARKER_RE = re.compile(r"^//\s*====\s*(.+?)\s*====\s*$", re.M)
_TEST_SEGMENT_RE = re.compile(
    r"(?:^|/)(?:test|tests|mock|mocks)(?:/|$)", re.I)
_CONTRACT_DECL_RE = re.compile(
    r"\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:is\s+([^{;]+?))?\s*\{")
_MODIFIER_DECL_RE = re.compile(
    r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{")


def _split_units(src: str) -> List[Tuple[str, str]]:
    """Split a flattened verified source on its `// ==== path ====`
    file markers (kept by _unwrap_source / Sourcify flattening).
    A markerless source is a single unit with an empty path."""
    marks = list(_FILE_MARKER_RE.finditer(src))
    if not marks:
        return [("", src)]
    units: List[Tuple[str, str]] = []
    head = src[:marks[0].start()].strip()
    if head:
        units.append(("", head))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(src)
        units.append((m.group(1).strip(), src[m.end():end]))
    return units


def _brace_span(text: str, open_pos: int) -> int:
    """Index just past the brace matching text[open_pos] == '{'."""
    depth = 0
    j = open_pos
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(text)


def _contract_spans(clean: str) -> List[Dict[str, Any]]:
    """Contract/library/interface declarations with body spans:
    {name, kind, ancestors, start, end} on comment-stripped text."""
    spans: List[Dict[str, Any]] = []
    for m in _CONTRACT_DECL_RE.finditer(clean):
        brace = clean.index("{", m.start())
        ancestors: List[str] = []
        if m.group(3):
            for part in m.group(3).split(","):
                am = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", part)
                if am:
                    ancestors.append(am.group(1))
        spans.append({"name": m.group(2), "kind": m.group(1),
                      "ancestors": ancestors, "start": m.start(),
                      "end": _brace_span(clean, brace)})
    return spans


def _extract_functions_pos(clean: str) -> List[Dict[str, Any]]:
    """cc.extract_functions with start/end offsets into `clean`,
    so scope membership is testable per function."""
    out: List[Dict[str, Any]] = []
    for m in cc._FUNC_START.finditer(clean):
        name = m.group(2) or m.group(3) or m.group(4) or \
            m.group(5) or ""
        start = m.start()
        i = m.end()
        while i < len(clean) and clean[i] not in "{;":
            i += 1
        if i >= len(clean):
            continue
        signature = clean[start:i].strip()
        if clean[i] == ";":
            out.append({"name": name, "signature": signature,
                        "text": clean[start:i + 1].strip(),
                        "start": start, "end": i + 1})
            continue
        end = _brace_span(clean, i)
        out.append({"name": name, "signature": signature,
                    "text": clean[start:end].strip(),
                    "start": start, "end": end})
    return out


class _Scope:
    """The analysis scope of one verified compilation: the target
    contract plus its inheritance chain, or (when the target name
    is unknown / unmatched) every contract outside test/mock
    files. Free functions are never in scope: they are not methods
    of any deployed contract."""

    def __init__(self, src: str, contract_name: str = ""):
        self.functions: List[Dict[str, Any]] = []
        self.modifiers: Dict[str, str] = {}
        self.helpers: Dict[str, Dict[str, Any]] = {}
        self.scoped_text = ""
        self.target_found = False
        self.contract_names = set()
        units = []
        all_spans: List[Dict[str, Any]] = []
        for path, raw in _split_units(src):
            clean = cc._strip_comments(raw)
            spans = _contract_spans(clean)
            for s in spans:
                s["path"] = path
                s["unit"] = len(units)
            if not spans:
                # Unparseable unit: keep it whole (legacy behavior)
                # rather than blinding the analyzer.
                spans = [{"name": "", "kind": "contract",
                          "ancestors": [], "start": 0,
                          "end": len(clean), "path": path,
                          "unit": len(units)}]
            units.append({"path": path, "clean": clean,
                          "spans": spans,
                          "functions": _extract_functions_pos(clean)})
            all_spans.extend(spans)
            self.contract_names.update(
                s["name"] for s in spans if s["name"])
        # Transitive ancestors per contract (for resolving a bare
        # call to a function the entry's contract inherits from a
        # sibling base: fTokenEIP2612Deposits.mintWithSignature
        # calls mint(...) defined in fTokenActions).
        self.contract_ancestors: Dict[str, set] = {}
        _by_name_all = {s["name"]: s for s in all_spans
                        if s["name"]}
        for _name in self.contract_names:
            _seen_anc: set = set()
            _stack = list(_by_name_all.get(_name, {}).get(
                "ancestors", []))
            while _stack:
                _a = _stack.pop()
                if _a in _seen_anc:
                    continue
                _seen_anc.add(_a)
                _stack.extend(_by_name_all.get(_a, {}).get(
                    "ancestors", []))
            self.contract_ancestors[_name] = _seen_anc
        pool = [s for s in all_spans
                if not _TEST_SEGMENT_RE.search(s["path"])] or all_spans
        kept = pool
        if contract_name:
            by_name = {s["name"]: s for s in pool if s["name"]}
            if contract_name in by_name:
                self.target_found = True
                keep_names = set()
                stack = [contract_name]
                while stack:
                    n = stack.pop()
                    if n in keep_names:
                        continue
                    keep_names.add(n)
                    sp = by_name.get(n)
                    if sp:
                        stack.extend(sp["ancestors"])
                kept = [s for s in pool if s["name"] in keep_names]
        kept_ids = {id(s) for s in kept}
        texts: List[str] = []
        for unit in units:
            clean = unit["clean"]
            unit_kept = [s for s in unit["spans"] if id(s) in kept_ids]
            for s in unit_kept:
                texts.append(clean[s["start"]:s["end"]])
            for m in _MODIFIER_DECL_RE.finditer(clean):
                owner = next((s for s in unit["spans"]
                              if s["start"] <= m.start() < s["end"]),
                             None)
                if owner is not None and id(owner) in kept_ids:
                    brace = clean.index("{", m.start())
                    self.modifiers[m.group(1)] = \
                        clean[m.start():_brace_span(clean, brace)]
            for fn in unit["functions"]:
                owner = next((s for s in unit["spans"]
                              if s["start"] <= fn["start"] < s["end"]),
                             None)
                if owner is not None and id(owner) in kept_ids:
                    fn["contract"] = owner["name"]
                    self.functions.append(fn)
                    if re.search(r"\b(internal|private)\b",
                                 fn["signature"]):
                        self.helpers[fn["name"]] = fn
        self.scoped_text = "\n".join(texts)


def _gated_deep(fn: Dict[str, Any], scope: _Scope,
                _depth: int = 0, _seen=None) -> bool:
    """Gate check over the function, its custom modifiers'
    DEFINITIONS, the internal helpers it calls, AND the
    implementations it delegates to via super.<fn>,
    <Parent>.<fn> or a same-contract public overload (FP fix,
    2026-11-19: the gate may live in the parent implementation
    an override delegates to - Tranche.mint -> ERC20.mint `auth`,
    VANRY 3-arg mint -> super.mint hasRole, PToken 2-arg mint ->
    4-arg mint `require(_msgSender() == pNetwork)`, Shares
    mintAndCall -> Shares.mint onlyOwner, DripToken.mint ->
    MintableToken.mint onlyWhitelisted)."""
    if _depth > 2:
        return False
    if _seen is None:
        _seen = set()
    if id(fn) in _seen:
        return False
    _seen.add(id(fn))
    sig, text = fn["signature"], fn["text"]
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
        if name == fn["name"]:
            continue
        if re.search(r"\b" + re.escape(name) + r"\s*\(", text) and \
                cd._is_gated(helper["signature"], helper["text"]):
            return True
    for _key, impl in _called_impls(text, fn, scope):
        if _gated_deep(impl, scope, _depth + 1, _seen):
            return True
    return False


# ---------------------------------------------------------------------------
# Depth fix 2 (2026-11-05): guard-aware path tracing.
#
# path_trace walks the actual execution path of an entry function
# (entry -> modifiers -> internal helper calls -> first value
# transfer) and guard_inventory lists every guard found on that
# path with its evidence, so a finding can say WHICH guard closes
# a path instead of a flat gated=True/False. The reentrancy lane
# additionally recognizes hand-rolled storage locks, and looks
# through internal helper calls for CEI violations split across
# the entry/helper boundary.
# ---------------------------------------------------------------------------

def _modifier_names(fn: Dict[str, Any]) -> List[str]:
    """Modifier tokens named on a function signature, in order."""
    sig = re.sub(r"returns\s*\([^)]*\)", "", fn["signature"])
    i = sig.find("(")
    if i < 0:
        return []
    tail = sig[cd._matching(sig, i) + 1:]
    return [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail)
            if t not in cd._SIG_KEYWORDS]


def _ordered_helpers(text: str, scope: _Scope, entry_name: str,
                     max_depth: int = 2) -> List[Dict[str, Any]]:
    """Internal helpers called from `text`, in call order, each
    {name, fn, depth, via, entry_pos} - entry_pos is the offset
    of the (depth-1) call site in the ENTRY text, so state
    writes can be ordered against the call point."""
    order: List[Dict[str, Any]] = []
    seen = set()

    def walk(t: str, owner: str, depth: int, entry_pos: int):
        if depth >= max_depth:
            return
        sites = []
        for hname, helper in scope.helpers.items():
            if hname == entry_name:
                continue
            for m in re.finditer(r"\b" + re.escape(hname) +
                                 r"\s*\(", t):
                sites.append((m.start(), hname, helper))
        for pos, hname, helper in sorted(sites):
            if hname in seen:
                continue
            seen.add(hname)
            here = pos if depth == 0 else entry_pos
            order.append({"name": hname, "fn": helper,
                          "depth": depth + 1, "via": owner,
                          "entry_pos": here})
            walk(helper["text"], hname, depth + 1, here)

    walk(text, entry_name, 0, 0)
    return order


def path_trace(scope: _Scope, fn: Dict[str, Any]
               ) -> List[Dict[str, Any]]:
    """Ordered steps of the function's execution path: entry,
    its modifiers, the internal helpers it calls (depth <= 2,
    call order), and the first value-transfer site on the path
    (in the entry, or in the first helper that makes one)."""
    steps: List[Dict[str, Any]] = [{
        "kind": "entry", "function": fn["name"],
        "signature": fn["signature"][:200]}]
    for tok in _modifier_names(fn):
        steps.append({"kind": "modifier", "function": fn["name"],
                      "name": tok})
    helpers = _ordered_helpers(fn["text"], scope, fn["name"])
    for h in helpers:
        steps.append({"kind": "internal_call",
                      "function": h["name"], "via": h["via"],
                      "depth": h["depth"]})
    calls = _external_calls(fn["text"])
    owner, first = fn["name"], (calls[0] if calls else None)
    if first is None:
        for h in helpers:
            hc = _external_calls(h["fn"]["text"])
            if hc:
                owner, first = h["name"], hc[0]
                break
    if first is not None:
        steps.append({"kind": "value_transfer", "function": owner,
                      "call_kind": first["kind"],
                      "receiver": str(first.get("receiver", ""))[:120]})
    return steps


def _guards_in_text(text: str, signature: str, where: str,
                    add) -> None:
    """Enumerate the guards visible in one body of text (an
    entry function, a modifier definition, or a helper)."""
    for m in cd._CMP_RE.finditer(text):
        op = m.group(1) or m.group(4)
        other = (m.group(2) or m.group(3) or "").strip()
        if op == "==" or (op == "!=" and
                          other not in ("address(0)", "0")):
            add("sender_comparison", where, m.group(0))
    if cd._MAP_GATE_RE.search(text):
        add("membership_check", where,
            cd._MAP_GATE_RE.search(text).group(0))
    if cd._ROLE_CALL_RE.search(text):
        add("role_check", where,
            cd._ROLE_CALL_RE.search(text).group(0))
    m = re.search(r"_checkOwner|_checkRole|hasRole\s*\([^)]*\)",
                  text)
    if m:
        add("role_check", where, m.group(0))
    reg = cd._registry_gate_evidence(text)
    if reg:
        add("registry_gate", where, reg)
    sig_ev = cd._signature_gate_evidence(text, signature)
    if sig_ev:
        add("signature_gate", where, sig_ev)


def _reentrancy_lock_var(text: str, state: set,
                         call_pos: Optional[int] = None
                         ) -> Optional[str]:
    """Name of a hand-rolled reentrancy lock variable, or None.

    The shape: a state variable require-checked at function
    start (its unlocked value), assigned a locked value BEFORE
    the external call (or the given call point), and restored
    to a different value after it - the same standing as the
    nonReentrant modifier, without the keyword."""
    if call_pos is None:
        calls = _external_calls(text)
        if not calls:
            return None
        call_pos = calls[0]["pos"]
    head, tail = text[:call_pos], text[call_pos:]
    assign = r"(?:\[[^\]]*\])?\s*=(?!=)\s*([^;]+);"
    for var in sorted(state):
        v = re.escape(var)
        if not re.search(r"(?:require|assert)\s*\(\s*!?\s*" + v +
                         r"\b|if\s*\(\s*!?\s*" + v + r"\b", head):
            continue
        sets = re.findall(v + assign, head)
        if not sets:
            continue
        locked = sets[-1].strip()
        restores = [r for r in re.findall(v + assign, tail)
                    if r.strip() != locked]
        if restores:
            return var
    return None


def guard_inventory(scope: _Scope, fn: Dict[str, Any]
                    ) -> List[Dict[str, Any]]:
    """Every guard on the function's execution path, as
    {kind, where, evidence} dicts. Kinds: modifier_gate,
    sender_comparison, membership_check, role_check,
    registry_gate, signature_gate, helper_gate,
    reentrancy_lock."""
    guards: List[Dict[str, Any]] = []
    seen = set()

    def add(kind: str, where: str, evidence: str) -> None:
        ev = " ".join(str(evidence).split())[:200]
        key = (kind, where, ev)
        if key in seen:
            return
        seen.add(key)
        guards.append({"kind": kind, "where": where,
                       "evidence": ev})

    for tok in _modifier_names(fn):
        if tok == "nonReentrant":
            add("reentrancy_lock", f"modifier:{tok}",
                "nonReentrant modifier")
        body = scope.modifiers.get(tok)
        if body and cd._is_gated("", body):
            add("modifier_gate", f"modifier:{tok}",
                f"modifier {tok} definition enforces a gate")
            _guards_in_text(body, "", f"modifier:{tok}", add)
    _guards_in_text(fn["text"], fn["signature"], "entry", add)
    if "nonReentrant" in fn["signature"] or \
            "nonReentrant" in fn["text"]:
        add("reentrancy_lock", "entry", "nonReentrant")
    state = state_variables(scope.scoped_text)
    lock = _reentrancy_lock_var(fn["text"], state)
    if lock:
        add("reentrancy_lock", "entry",
            f"hand-rolled storage lock on '{lock}': checked at "
            "entry, set before the external call, restored after")
    for h in _ordered_helpers(fn["text"], scope, fn["name"]):
        helper = h["fn"]
        if cd._is_gated(helper["signature"], helper["text"]):
            add("helper_gate", f"helper:{h['name']}",
                f"{h['name']}() enforces a gate on the call path")
        _guards_in_text(helper["text"], helper["signature"],
                        f"helper:{h['name']}", add)
        hlock = _reentrancy_lock_var(helper["text"], state)
        if hlock:
            add("reentrancy_lock", f"helper:{h['name']}",
                f"hand-rolled storage lock on '{hlock}' in "
                f"helper {h['name']}")
    return guards


def _helper_split_cei(fn: Dict[str, Any], scope: _Scope,
                      state: set) -> Optional[Dict[str, Any]]:
    """CEI violation split across the entry/helper boundary:
    the external call sits in an internal helper the entry
    calls, and state is written after that call point (in the
    entry, or in a helper called later). Returns {var, helper,
    call_kind, lock} or None."""
    text = fn["text"]
    helpers = _ordered_helpers(text, scope, fn["name"])
    if not helpers:
        return None
    writes = _state_writes(text, state)
    for idx, h in enumerate(helpers):
        hcalls = _external_calls(h["fn"]["text"])
        if not hcalls:
            continue
        call_point = h["entry_pos"]
        written_before = {v for p, v in writes if p < call_point}
        late = [(p, v) for p, v in writes
                if p > call_point and v not in written_before]
        for later in helpers[idx + 1:]:
            for _p, v in _state_writes(later["fn"]["text"], state):
                if v not in written_before:
                    late.append((call_point + 1, v))
        if not late:
            continue
        lock = _reentrancy_lock_var(text, state,
                                    call_pos=call_point) or \
            _reentrancy_lock_var(h["fn"]["text"], state)
        first = hcalls[0]
        for _pos, var in late:
            before = text[:call_point]
            if _reads_var(before, var) or \
                    _reads_var(h["fn"]["text"][:first["pos"]],
                               var) or \
                    first["kind"] in ("call", "send",
                                      "safe_transfer", "hook",
                                      "delegatecall", "callcode"):
                return {"var": var, "helper": h["name"],
                        "call_kind": first["kind"],
                        "receiver": str(first.get("receiver", "")),
                        "lock": lock}
    return None


# ---------------------------------------------------------------------------
# Overflow suppression (FP fix 1): canonical checked shapes
# ---------------------------------------------------------------------------

_OZ_INTERNAL_NAMES = {
    "_transfer", "_mint", "_burn", "_update", "_increaseBalance",
    "_decreaseBalance", "_spendAllowance", "_writeCheckpoint",
    "_approve", "_beforeTokenTransfer", "_afterTokenTransfer",
}


def _bounds_checked_before(text: str, pos: int, var: str) -> bool:
    """A require/assert/if-revert BEFORE pos compares the flagged
    variable (or the balanceOf / totalSupply views over it)
    against a bound: the canonical checked-then-unchecked shape
    (OZ ERC20 require(fromBalance >= amount) before the unchecked
    subtraction; WETH9 require(balanceOf >= wad) before `-=`)."""
    head = text[:pos]
    alts = [re.escape(var)] if var else []
    alts += ["balanceOf", "totalSupply", "_totalSupply", "_balances"]
    names = "|".join(alts)
    cmpop = r"(?:>=|<=|>|<|==|!=)"
    pat = re.compile(
        r"(?:require|assert)\s*\([^;]*?\b(?:" + names + r")\b"
        r"[^;]*?" + cmpop +
        r"|(?:require|assert)\s*\([^;]*?" + cmpop +
        r"[^;]*?\b(?:" + names + r")\b" +
        r"|if\s*\([^)]*?\b(?:" + names + r")\b[^)]*?" + cmpop +
        r"[^)]*\)\s*(?:\{[^}]*?)?revert")
    return pat.search(head) is not None


def _msgvalue_bounded(rhs: str, var: str, state: set,
                      params: List[str]) -> bool:
    """The operation's only external influence is msg.value: the
    moved quantity is bounded by the value the caller actually
    sent, and total ETH supply (~2^67 wei) can never push a sum
    to 2^256 (WETH9 `balanceOf[msg.sender] += msg.value`)."""
    if "msg.value" not in rhs:
        return False
    if any(re.search(r"\b" + re.escape(p) + r"\b", rhs)
           for p in params):
        return False
    return not any(v != var and
                   re.search(r"\b" + re.escape(v) + r"\b", rhs)
                   for v in state)


def _overflow_suppression(fn: Dict[str, Any], text: str, pos: int,
                          var: str, snippet: str, state: set,
                          params: List[str]) -> Optional[str]:
    """Reason the flagged arithmetic is a known-safe shape, or
    None when it stays a finding (FP fix 1)."""
    sig = fn["signature"]
    if re.search(r"\b(internal|private)\b", sig):
        tag = ("canonical library internal pattern"
               if fn["name"] in _OZ_INTERNAL_NAMES else
               "internal/private function")
        return f"{tag}: not an external entry point"
    if _bounds_checked_before(text, pos, var):
        return ("bounds checked by a require/if-revert earlier in "
                "the function")
    rhs = re.split(r"\+=|-=|\*=|=(?!=)", snippet, maxsplit=1)
    if len(rhs) == 2 and _msgvalue_bounded(rhs[1], var, state,
                                           params):
        return "arithmetic bounded by msg.value (physically capped)"
    return None


# ---------------------------------------------------------------------------
# Recipient dataflow (FP fix 4, the receive rule): where does the
# moved value LAND? Ported from the adjudication harness
# (recon-10k/recipient.py), which hand-validated the regression
# set with exactly this classification.
# ---------------------------------------------------------------------------

_RECIP_SENDER = re.compile(r"msg\.sender|_msgSender\(\)|caller\(\)|tx\.origin")
_RECIP_SELF_METER = re.compile(
    r"balanceOf\[\s*msg\.sender|balances?\[\s*msg\.sender|"
    r"shares?\[\s*msg\.sender|userInfo\[\s*msg\.sender|"
    r"deposits?\[\s*msg\.sender|staked\[\s*msg\.sender|"
    r"pending\w*\(\s*msg\.sender|earned\(\s*msg\.sender|"
    r"dividend\w*\(\s*msg\.sender|withdrawable\w*\(\s*msg\.sender|"
    r"_withdrawDividendOfUser\(\s*msg\.sender|"
    r"withdrawableDividendOf|dividendOf\(", re.I)
_RECIP_CALLS = re.compile(
    r"(?P<recv>[A-Za-z_][\w]*(?:\s*\([^()]*\))?(?:\s*\.\s*[A-Za-z_]\w*"
    r"(?:\s*\([^()]*\))?)*)\s*\.\s*"
    r"(?P<method>transferFrom|safeTransferFrom|transfer|send|call|"
    r"withdrawTo|withdraw|redeemFor|redeem|claimFor|releaseTo|"
    r"payoutTo|disperse|harvestTo|unstakeTo|collectTo)\s*"
    r"(?P<brace>\{[^}]*\})?\s*\(")
_RECIP_DIRECT = re.compile(r"(?P<fn>selfdestruct|_mint|mint|safeTransfer)\s*\(")

# External methods whose NAME declares a recipient argument
# (the To/For argument pays a third party). The destination is
# extracted only when exactly one argument is unambiguously an
# address expression - see _recip_pick_address_arg.
_RECIP_NAMED_METHODS = frozenset({
    "withdrawTo", "redeemFor", "claimFor", "releaseTo",
    "payoutTo", "disperse", "harvestTo", "unstakeTo",
    "collectTo"})


def _recip_addr_param_names(code: str) -> set:
    """Address-typed parameter names across every function
    signature in `code` (entry + helpers on a bound path)."""
    names = set()
    for m in re.finditer(r"function\s+\w+\s*\(([^)]*)\)", code):
        for p in m.group(1).split(","):
            toks = [t for t in p.strip().split()
                    if t not in cd._PARAM_ATTRS]
            if len(toks) >= 2 and "address" in p:
                names.add(toks[-1])
    return names


def _recip_pick_address_arg(args: List[str], addr_names: set
                            ) -> Optional[str]:
    """The recipient argument of a named-recipient external
    call, or None when no position is unambiguous.

    An argument qualifies when it is a sender expression, an
    address literal, a cast expression, a member/index
    expression, or a bare identifier that is an address-typed
    parameter in scope. Exactly one qualifying argument is a
    classification; zero or several is a guess, and this
    classifier does not guess."""
    hits = []
    for a in args:
        e = a.strip()
        if _RECIP_SENDER.search(e) or \
                re.fullmatch(r"0x[0-9a-fA-F]{40}", e) or \
                re.match(r"(?:payable|address)\s*\(", e) or \
                "[" in e or "." in e:
            hits.append(e)
            continue
        base = re.split(r"[.\[(]", e)[0].strip()
        if re.fullmatch(r"[A-Za-z_]\w*", e) and base in addr_names:
            hits.append(e)
    return hits[0] if len(hits) == 1 else None


def _recip_destinations(code: str) -> List[str]:
    dests: List[str] = []
    addr_names = _recip_addr_param_names(code)
    for m in _RECIP_CALLS.finditer(code):
        recv, method = m.group("recv").strip(), m.group("method")
        paren = m.end() - 1
        args = cd._split_top(code[paren + 1:cd._matching(code, paren)])
        if method in ("transfer", "send"):
            dests.append(args[0] if len(args) >= 2 else recv)
        elif method == "call":
            dests.append(recv)
        elif method in ("withdraw", "redeem"):
            # ERC4626: withdraw(assets, receiver, owner) /
            # redeem(shares, receiver, owner) - the receiver
            # is args[1]. Shorter arities are not the 4626
            # shape and are not guessed at.
            if len(args) >= 3:
                dests.append(args[1])
        elif method in _RECIP_NAMED_METHODS:
            pick = _recip_pick_address_arg(args, addr_names)
            if pick is not None:
                dests.append(pick)
        elif len(args) >= 2:  # transferFrom / safeTransferFrom
            dests.append(args[1])
    for m in _RECIP_DIRECT.finditer(code):
        paren = m.end() - 1
        args = cd._split_top(code[paren + 1:cd._matching(code, paren)])
        if not args:
            continue
        if m.group("fn") == "safeTransfer" and len(args) >= 3:
            dests.append(args[1])
        else:
            dests.append(args[0])
    return dests


def _recip_locals(body: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in re.finditer(r"(?:address(?:\s+payable)?|uint\w*|bool)\s+"
                         r"([A-Za-z_]\w*)\s*=\s*([^;]+);", body):
        out[m.group(1)] = m.group(2).strip()
    return out


def _recip_all_params(code: str) -> set:
    names = set()
    for m in re.finditer(r"function\s+\w+\s*\(([^)]*)\)", code):
        for p in m.group(1).split(","):
            toks = p.strip().split()
            if toks:
                names.add(toks[-1].lstrip("_"))
    return names


_RECIP_CASTS = ("payable", "address", "uint160", "uint128",
                "uint96", "uint64", "uint32", "uint", "int160",
                "int", "bytes32")


def _recip_unwrap_cast(e: str) -> str:
    """Unwrap whole-expression casts: payable(X), address(X),
    address(uint160(X)), uint160(X), ... classify the inner
    expression (payable(operator) is the FIXED project wallet,
    address(uint160(to)) is the caller's address parameter)."""
    e = (e or "").strip()
    for _ in range(8):
        m = re.match(r"([A-Za-z_]\w*)\s*\(", e)
        if not m or m.group(1) not in _RECIP_CASTS:
            return e
        open_paren = m.end() - 1
        if cd._matching(e, open_paren) != len(e) - 1:
            return e
        e = e[open_paren + 1:-1].strip()
    return e


def _recip_split_ternary(e: str):
    """Split a top-level `cond ? a : b` expression into (a, b),
    or None. Only the branches carry the destination; the
    condition never does."""
    depth = 0
    qpos = None
    nested = 0
    for i, ch in enumerate(e):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and ch == "?":
            if qpos is None:
                qpos = i
            else:
                nested += 1
        elif depth == 0 and ch == ":" and qpos is not None:
            if nested == 0:
                return e[qpos + 1:i].strip(), e[i + 1:].strip()
            nested -= 1
    return None


def _recip_combine(classes: List[str]) -> str:
    """Combine branch classes of a ternary destination:
    caller-controlled beats fixed (CALLER-SUPPLIED beats
    CALLER/SENDER beats FIXED); an unresolved branch keeps
    the whole expression unresolved unless a caller-controlled
    branch already settles it."""
    if "CALLER-SUPPLIED" in classes:
        return "CALLER-SUPPLIED"
    if "SENDER" in classes:
        return "SENDER"
    if classes and all(c == "FIXED" for c in classes):
        return "FIXED"
    return "UNRESOLVED"


def _recip_expand_locals(expr: str, locals_: Dict[str, str],
                         _rounds: int = 4) -> str:
    """Substitute known locals into `expr` (bounded rounds, so a
    self-referential definition cannot loop). Used to see what an
    index expression is really made of: `rand` in
    `participants[rand % n]` expands to its keccak256(...)
    definition, which carries msg.sender."""
    out = expr
    for _ in range(_rounds):
        names = [n for n in locals_ if re.search(
            r"\b" + re.escape(n) + r"\b", out)]
        if not names:
            return out
        pat = re.compile(r"\b(" + "|".join(
            re.escape(n) for n in sorted(names, key=len,
                                         reverse=True)) + r")\b")
        new = pat.sub(lambda m: "(" + locals_[m.group(1)] + ")",
                      out)
        if new == out:
            return out
        out = new
    return out


def _recip_index_sender(expr: str,
                        locals_: Dict[str, str]) -> Optional[str]:
    """How the index of a state-array/mapping destination relates
    to the caller: "derived" when an index is built from
    msg.sender inside a larger expression (a draw the caller
    influences), else None. A BARE msg.sender index is NOT
    caller-controlled here: `users[msg.sender].wallet` is a
    stored wallet looked up by the caller key, and the repo's
    adjudicated convention (test_validator_v2_recipient) keeps
    that FIXED - the caller cannot redirect it in this call."""
    for m in re.finditer(r"\[([^\]]*)\]", expr):
        idx = _recip_expand_locals(m.group(1), locals_).strip()
        if re.fullmatch(r"msg\.sender|_msgSender\(\)|caller\(\)|"
                        r"tx\.origin", idx):
            continue  # bare caller key: stored entry, FIXED
        if _RECIP_SENDER.search(idx):
            return "derived"
    return None


def _recip_class_expr(expr: str, params: List[str],
                      addr_params: List[str], locals_: Dict[str, str],
                      all_params: set, _depth: int = 0) -> str:
    if _depth > 8:
        return "UNRESOLVED"
    e = _recip_unwrap_cast(cd._unwrap(expr))
    # Ternary destination: classify both branches and combine.
    tern = _recip_split_ternary(e)
    if tern is not None:
        return _recip_combine([
            _recip_class_expr(b, params, addr_params, locals_,
                              all_params, _depth + 1)
            for b in tern])
    if re.fullmatch(r"msg\.sender|_msgSender\(\)|caller\(\)|"
                    r"tx\.origin", e):
        return "SENDER"
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", e):
        return "FIXED"
    # A nullary getter call (owner(), treasury(), ...) resolves to
    # whatever the contract stored - a fixed destination, never
    # caller-controlled.
    m = re.fullmatch(r"([A-Za-z_]\w*)\(\)", e)
    if m:
        e = m.group(1)
    # Member / index destinations (users[x].wallet, payees[i],
    # info[to].addr): the value lands at an address READ THROUGH
    # the base, so resolve the BASE - a caller-supplied base is
    # caller-controlled, a msg.sender-derived base is the
    # caller, a state-variable base is a stored (fixed) address,
    # and a local base recurses into its definition.
    if "[" in e or "." in e:
        bm = re.match(r"([A-Za-z_]\w*)", e)
        if bm:
            base = bm.group(1)
            rest = e[bm.end():].lstrip()
            if base in ("msg", "tx") or _RECIP_SENDER.search(
                    e.split("[", 1)[0].split(".", 1)[0]):
                return "SENDER"
            if rest.startswith("("):
                return "FIXED"  # call result's member: stored
            if base in addr_params or base in params:
                return "CALLER-SUPPLIED"
            if base in locals_:
                return _recip_class_expr(
                    locals_[base], params, addr_params, locals_,
                    all_params, _depth + 1)
            if base in all_params:
                return "SENDER"
            # State array / mapping indexed by a caller-DERIVED
            # value: the picked entry is not a stored project
            # wallet. `participants[rand % n]` where rand is
            # seeded from msg.sender (lottery / raffle draw)
            # lands value at whichever participant the draw
            # picks - a stranger can be that participant and
            # the caller influences the draw, so this is not
            # FIXED; the recipient is unresolved (candidate,
            # not proven caller). A bare msg.sender index stays
            # FIXED per the stored-wallet convention above.
            if "[" in e:
                if _recip_index_sender(e, locals_) == "derived":
                    return "UNRESOLVED"
            return "FIXED"  # state struct / array / mapping
    if _RECIP_SENDER.search(e):
        return "SENDER"
    base = re.split(r"[.\[(]", e)[0].strip()
    if base in addr_params or base in params:
        return "CALLER-SUPPLIED"
    if base in locals_:
        return _recip_class_expr(locals_[base], params, addr_params,
                                 locals_, all_params, _depth + 1)
    if base in all_params:
        # an internal helper's address parameter that entry
        # functions feed - fed msg.sender at the call site in the
        # adjudicated shapes, i.e. the caller's own payout channel
        return "SENDER"
    if base in ("address", "this"):
        return "FIXED"
    if re.fullmatch(r"[A-Za-z_]\w*", e):
        return "FIXED"  # state variable / stored project address
    if "msg.sender" in e:
        return "SENDER"
    return "UNRESOLVED"


_LEDGER_CREDIT_RE = re.compile(
    r"\b(balanceOf|balances|_balances)\s*\[\s*([^\]]+?)\s*\]\s*"
    r"(?:\+=|=(?!=))")
_SUPPLY_UP_RE = re.compile(
    r"\b_?totalSupply\s*(?:\+=|=\s*_?totalSupply\s*\+)")


_SELF_CREDIT_RE = re.compile(
    r"\b(?:balanceOf|balances|_balances)\s*\[\s*msg\.sender\s*\]"
    r"\s*(?:\+=|=(?!=))")


def _self_metered(code: str) -> bool:
    """The payout to the caller is metered by the caller's own
    recorded position (a balance/entitlement READ keyed by
    msg.sender). A ledger CREDIT write to the caller's own
    entry (balanceOf[msg.sender] += amount) is not a meter -
    it is the issuance itself, and on an argument-bound call
    path every helper credit to a caller-bound parameter
    lands in exactly that shape - so credit writes are
    stripped before the meter search."""
    return bool(_RECIP_SELF_METER.search(
        _SELF_CREDIT_RE.sub("", code)))


def _ledger_credit_exprs(code: str) -> List[str]:
    """Token-ledger CREDIT destinations of a mint-shaped
    function. A mint that writes the ledger directly
    (balanceOf[to] += amount, _balances[to] = ...) performs no
    transfer / _mint call for _recip_destinations to see, so the
    credited key expression IS the value destination. Only
    fires when the function is mint-named or itself increases
    totalSupply - the shapes where a ledger credit is newly
    issued value rather than bookkeeping. The `code` seen here
    is the whole bound call path on the path-classification
    route (entry + helpers), so the gate scans EVERY function
    signature in it: a mint-named helper, or a supply increase
    anywhere on the path, enables the credit read just as a
    mint-named entry does."""
    mint_named = any(
        "mint" in m.group(1).lower()
        for m in re.finditer(r"function\s+([A-Za-z_]\w*)", code))
    if not mint_named and not _SUPPLY_UP_RE.search(code):
        return []
    return [m.group(2).strip()
            for m in _LEDGER_CREDIT_RE.finditer(code)]


def classify_recipient(code: str) -> Tuple[str, str]:
    """-> (recipient, detail). Recipient in CALLER,
    CALLER-SUPPLIED, FIXED, HOLDER-SELF, UNRESOLVED."""
    if not code or "{" not in code:
        return "UNRESOLVED", "no function body in evidence"
    sig = code.split("{", 1)[0]
    body = code.split("{", 1)[1]
    params = cd._param_names(sig)
    addr_params = []
    i = sig.find("(")
    if i >= 0:
        inner = sig[i + 1:cd._matching(sig, i)]
        for part in cd._split_top(inner):
            toks = [t for t in part.split()
                    if t not in cd._PARAM_ATTRS]
            if len(toks) >= 2 and "address" in part:
                addr_params.append(toks[-1])
    locals_ = _recip_locals(body)
    all_params = _recip_all_params(code)
    dests = _recip_destinations(code)
    dests += _ledger_credit_exprs(code)
    if not dests:
        return "UNRESOLVED", "no value destination found in function"
    classes = []
    for d in dests:
        c = _recip_class_expr(d, params, addr_params, locals_,
                              all_params)
        if c == "SENDER":
            c = "HOLDER-SELF" if _self_metered(code) \
                else "CALLER"
        classes.append(c)
    for want in ("CALLER-SUPPLIED", "CALLER", "FIXED",
                 "HOLDER-SELF"):
        if want in classes:
            return want, f"destinations={classes}"
    return "UNRESOLVED", f"destinations={classes}"


def _recipient_reclassify(item: Dict[str, Any], fn_text: str) -> None:
    """Apply the receive rule to a finding in place: FIXED /
    HOLDER-SELF destinations become TRIGGER-ONLY at low severity;
    caller-reachable destinations stay candidate-grade."""
    recipient, detail = classify_recipient(fn_text)
    item["recipient"] = recipient
    if recipient in ("FIXED", "HOLDER-SELF"):
        item["report_class"] = "trigger_only"
        item["severity"] = "low"
        item["detail"] += (
            f" Recipient analysis: moved value lands at a "
            f"{recipient} destination ({detail}), so a stranger "
            "can trigger this but receives nothing - classified "
            "TRIGGER-ONLY under the receive rule.")
    else:
        item["report_class"] = "candidate"


# ---------------------------------------------------------------------------
# Bound call-path recipient classification (depth fix 1): the
# destination a function pays is routinely decided one or two
# internal hops down (withdraw() -> _payout(amount), and the
# helper transfers to msg.sender). Concatenating helper text and
# classifying parameter NAMES guesses wrong whenever the entry
# passes something other than the helper's own parameter name;
# expanding WITH argument binding writes each helper body in
# the caller's frame, so the classification reads the actual
# call path.
# ---------------------------------------------------------------------------

def _positional_params(signature: str) -> List[Optional[str]]:
    """Parameter names in declaration order (None for unnamed
    parameters, which no call site can bind by name)."""
    i = signature.find("(")
    if i < 0:
        return []
    inner = signature[i + 1:cd._matching(signature, i)]
    out: List[Optional[str]] = []
    for part in cd._split_top(inner):
        toks = [t for t in part.split() if t not in cd._PARAM_ATTRS]
        name = None
        if len(toks) >= 2 and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*", toks[-1]):
            name = toks[-1]
        out.append(name)
    return out


_SIMPLE_EXPR_RE = re.compile(
    r"(?:[A-Za-z_][\w]*(?:\s*\.\s*[A-Za-z_]\w*)*"
    r"(?:\s*\[[^\]]*\])?|0x[0-9a-fA-F]{40}|\d+"
    r"|msg\.sender|_msgSender\(\s*\)|address\(this\))$")


def _bind_substitute(text: str, bindings: Dict[str, str]) -> str:
    """Replace bound parameter names in `text` with the actual
    argument expressions from the call site, in ONE simultaneous
    pass (sequential passes corrupt swaps like (x, y) -> (y, x)).
    Simple atoms substitute bare; complex expressions are
    parenthesized so the result stays one expression."""
    if not bindings:
        return text

    def rep(m: "re.Match") -> str:
        e = bindings[m.group(1)].strip()
        return e if _SIMPLE_EXPR_RE.fullmatch(e) else f"({e})"

    names = sorted(bindings, key=len, reverse=True)
    pat = re.compile(r"\b(" + "|".join(re.escape(n) for n in names)
                     + r")\b")
    return pat.sub(rep, text)


def _call_args(text: str, open_paren: int) -> List[str]:
    inner = text[open_paren + 1:cd._matching(text, open_paren)]
    return [a.strip() for a in cd._split_top(inner)]


def _called_impls(text: str, entry_fn: Dict[str, Any],
                  scope: _Scope) -> List[Tuple[str, Dict[str, Any]]]:
    """Implementations reached from `text` through calls that are
    NOT internal helpers: `super.<name>(...)`, `<Parent>.<name>(...)`
    and same-contract public `<name>(...)` (overload delegation).

    An override that delegates to a gated parent implementation
    (Tranche.mint -> ERC20.mint `auth`, VANRY 3-arg mint ->
    super.mint hasRole, PToken 2-arg mint -> 4-arg mint
    `require(_msgSender() == pNetwork)`, Shares.mintAndCall ->
    Shares.mint onlyOwner) IS gated, but the old code only ever
    looked at internal helpers, so the parent's gate was invisible.
    Returns (key, fn) pairs; the first same-named implementation
    in scope order wins for `super.` (parents precede children in
    a flattened source), while a qualified `<Parent>.<name>` is
    resolved exactly by contract name.
    """
    out: List[Tuple[str, Dict[str, Any]]] = []
    entry_contract = entry_fn.get("contract")
    ancestors = set()
    try:
        ancestors = scope.contract_ancestors.get(
            entry_contract, set())
    except AttributeError:
        ancestors = set()

    # Index once: first bodied implementation per (contract,
    # name), so the per-call-site lookup is O(1).
    by_contract_name: Dict[Tuple[str, str], Dict[str, Any]] = {}
    same_contract_public: Dict[str, Dict[str, Any]] = {}
    ancestor_public: Dict[str, Dict[str, Any]] = {}
    ancestor_named: Dict[str, Dict[str, Any]] = {}
    for cand in scope.functions:
        if cand is entry_fn or "{" not in cand["text"]:
            continue
        by_contract_name.setdefault(
            (cand.get("contract"), cand["name"]), cand)
        if cand.get("contract") in ancestors:
            # super.<name> may target an internal base function
            # (ERC4626._deposit), so this index is not
            # visibility-filtered.
            ancestor_named.setdefault(cand["name"], cand)
        if re.search(r"\b(internal|private)\b",
                     cand["signature"]):
            continue
        if cand.get("contract") == entry_contract:
            same_contract_public.setdefault(cand["name"], cand)
        elif cand.get("contract") in ancestors:
            ancestor_public.setdefault(cand["name"], cand)

    # super.<name> resolves to a base contract's implementation.
    for m in re.finditer(r"\bsuper\s*\.\s*(\w+)\s*\(", text):
        cand = ancestor_named.get(m.group(1))
        if cand is not None:
            out.append(("super:" + m.group(1), cand))
    for m in re.finditer(
            r"\b([A-Za-z_]\w*)\s*\.\s*(\w+)\s*\(", text):
        qual, name = m.group(1), m.group(2)
        if qual in ("super", "msg", "address", "this"):
            continue
        if qual not in scope.contract_names:
            continue
        cand = by_contract_name.get((qual, name))
        if cand is not None:
            out.append((qual + ":" + name, cand))
    # Bare calls resolve in the entry contract, then in its
    # bases (a call in fTokenEIP2612Deposits to mint(...) is the
    # fTokenActions.mint it inherits, not an unrelated same-named
    # function elsewhere in the compilation). Skip names that are
    # internal helpers (handled by the helpers loop) and the entry
    # itself (recursion).
    for m in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*\(", text):
        name = m.group(1)
        if name in scope.helpers:
            continue
        cand = same_contract_public.get(name) or \
            ancestor_public.get(name)
        if cand is not None:
            out.append((name, cand))
    return out


def bound_path_text(scope: _Scope, fn: Dict[str, Any],
                    max_depth: int = 3) -> str:
    """The flagged function's text plus the bodies of the
    internal helpers it calls, transitively (depth <= 3), WITH
    argument binding: at every call site the helper's parameters
    are replaced by the actual argument expressions, so each
    appended helper body is written in its caller's frame.

    Super / parent-qualified / same-contract-public calls are
    followed the same way: the bound path is the actual execution
    path, so a parent ERC4626 _deposit that pulls the caller's
    assets (sNUSD/fToken mint) and a parent mint that carries the
    role gate both belong in it.
    """
    parts = [fn["text"]]
    seen = {fn["name"]}
    seen_impls = {id(fn)}

    def expand(text: str, depth: int) -> None:
        if depth > max_depth:
            return
        for name, helper in scope.helpers.items():
            if name in seen:
                continue
            cm = re.search(r"\b" + re.escape(name) + r"\s*\(", text)
            if not cm:
                continue
            seen.add(name)
            args = _call_args(text, cm.end() - 1)
            params = _positional_params(helper["signature"])
            child = {p: args[i] for i, p in enumerate(params)
                     if p is not None and i < len(args)}
            htext = helper["text"]
            brace = htext.find("{")
            if brace >= 0 and child:
                # Substitute in the BODY only: the signature
                # keeps the helper's own parameter names, which
                # the classifier's parameter bookkeeping expects.
                htext = htext[:brace + 1] + _bind_substitute(
                    htext[brace + 1:], child)
            parts.append(htext)
            expand(htext, depth + 1)
        for key, impl in _called_impls(text, fn, scope):
            if id(impl) in seen_impls:
                continue
            seen_impls.add(id(impl))
            cm = re.search(r"(?:super\s*\.\s*|"
                           r"(?:[A-Za-z_]\w*\s*\.\s*)?)" +
                           re.escape(impl["name"]) + r"\s*\(",
                           text)
            if not cm:
                continue
            args = _call_args(text, cm.end() - 1)
            params = _positional_params(impl["signature"])
            child = {p: args[i] for i, p in enumerate(params)
                     if p is not None and i < len(args)}
            itext = impl["text"]
            brace = itext.find("{")
            if brace >= 0 and child:
                itext = itext[:brace + 1] + _bind_substitute(
                    itext[brace + 1:], child)
            parts.append(itext)
            expand(itext, depth + 1)

    expand(fn["text"], 1)
    return "\n".join(parts)


def classify_recipient_path(scope: _Scope, fn: Dict[str, Any]
                            ) -> Tuple[str, str, str]:
    """classify_recipient over the argument-bound internal call
    path of `fn`. Returns (recipient, detail, path_text)."""
    text = bound_path_text(scope, fn)
    recipient, detail = classify_recipient(text)
    return recipient, detail, text


_SELF_FUNDED_RE = re.compile(r"msg\.value\s*==|==\s*msg\.value")


# ---------------------------------------------------------------------------
# Logic analysis over verified source (pure, testable)
# ---------------------------------------------------------------------------

_SENSITIVE_NAME_RE = re.compile(
    r"mint|withdraw|sweep|drain|rescue|setowner|transferownership|"
    r"renounceownership|setfee|settax|setadmin|setcontroller|"
    r"setminter|setimplementation|upgrade|pause|setprice|setwallet|"
    r"setrouter|setoracle|settreasury|destroy|kill|setconfig|"
    r"setaddress|burnfrom", re.I)

_BALANCEY_RE = re.compile(r"balance|supply|totalminted|minted", re.I)


def _performs_sensitive_action(text: str, state: set) -> bool:
    if _state_writes(text, state):
        return True
    if cd._fund_moves(text):
        return True
    if "_mint(" in text or "selfdestruct" in text or \
            ".delegatecall(" in text:
        return True
    return False


def _overflow_ops(text: str, state: set, params: List[str]
                  ) -> List[Tuple[int, str, str]]:
    """Raw arithmetic ops on state values: (pos, var, snippet_src).

    Compound assignments to state, and plain assignments whose
    right-hand side does binary arithmetic involving state or a
    parameter / msg.value. SafeMath method calls (.add/.sub/.mul)
    are not raw ops and never match.
    """
    out: List[Tuple[int, str, str]] = []

    def influenced(rhs: str) -> bool:
        if "msg.value" in rhs:
            return True
        if any(re.search(r"\b" + re.escape(p) + r"\b", rhs)
               for p in params):
            return True
        return any(re.search(r"\b" + re.escape(v) + r"\b", rhs)
                   for v in state)

    for m in re.finditer(
            r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(\+=|-=|\*=)\s*([^;]+);",
            text):
        var = m.group(1)
        if var in state and influenced(m.group(3)):
            out.append((m.start(), var, m.group(0)))
    for m in re.finditer(
            r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=(?!=)\s*([^;]+);",
            text):
        var, rhs = m.group(1), m.group(2)
        if var not in state:
            continue
        if not re.search(r"(?<![\w.])[-+*](?![\w])|\s[-+*]\s", rhs):
            if not re.search(r"\w\s*[-+*]\s*\w", rhs):
                continue
        if influenced(rhs):
            out.append((m.start(), var, m.group(0)))
    return out


def _balanced_local(text: str, open_pos: int):
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
        i += 1
    return text[open_pos + 1:], len(text)


def _expand_helpers_local(text: str, scope: _Scope,
                          max_depth: int = 2) -> str:
    """Entry text + in-scope internal helper bodies (bounded).

    Local copy of the validator's expansion pattern (the
    validator imports this module, so the dependency cannot
    run the other way)."""
    parts = [text]
    seen = set()
    frontier = [text]
    for _ in range(max_depth):
        nxt = []
        for t in frontier:
            for hname, helper in scope.helpers.items():
                if hname in seen:
                    continue
                if re.search(r"\b" + re.escape(hname) +
                             r"\s*\(", t):
                    seen.add(hname)
                    parts.append(helper["text"])
                    nxt.append(helper["text"])
            # super.<fn>(...) reaches the base-contract
            # implementation (ERC4626 mint/deposit overrides
            # in vault contracts): include that body too.
            for sm in re.finditer(r"\bsuper\s*\.\s*(\w+)"
                                  r"\s*\(", t):
                base_name = sm.group(1)
                if ("super:" + base_name) in seen:
                    continue
                for cand in scope.functions:
                    if cand["name"] == base_name and \
                            "{" in cand["text"] and \
                            cand["text"] not in parts:
                        seen.add("super:" + base_name)
                        parts.append(cand["text"])
                        nxt.append(cand["text"])
                        break
        if not nxt:
            break
        frontier = nxt
    return "\n".join(parts)


_CALLER_PULL_RE = re.compile(
    r"(?:safeTransferFrom|transferFrom|_transfer|_burn|"
    r"safeTransfer)\s*\(\s*(msg\.sender|[A-Za-z_]\w*)")
_EXT_AUTH_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*(\w*(?:check|allowed|"
    r"verif|valid|authori|qualified)\w*)\s*\(",
    re.I)


def _operate_callback_funded(text: str) -> str:
    """External operate-with-callback deposit (Fluid fToken shape):
    the mint calls LIQUIDITY.operate(asset, amount, ...,
    abi.encode(msg.sender)) and mints shares computed from that
    same amount. The external contract pulls the caller's assets
    through the callback, so the shares are caller-funded even
    though no transferFrom appears in this source. Returns a
    reason string or "".
    """
    cb_vars = set()
    for m in re.finditer(
            r"(\w+)\s*=\s*[^;]*abi\.encode\s*\([^;]*?"
            r"(msg\.sender|_msgSender\s*\(\s*\))", text):
        cb_vars.add(m.group(1))
    for m in re.finditer(r"\.operate\s*\(", text):
        paren = text.find("(", m.start())
        if paren < 0:
            continue
        args, _ = _balanced_local(text, paren)
        arg_list = [a.strip() for a in cd._split_top(args)]
        has_cb = any(
            "abi.encode" in a and
            ("msg.sender" in a or "_msgSender()" in a)
            for a in arg_list) or any(
            a.strip("() ") in cb_vars for a in arg_list)
        if not has_cb:
            continue
        amt_vars = set()
        for a in arg_list:
            if "abi.encode" in a:
                continue
            for v in re.findall(r"[A-Za-z_]\w*", a):
                # lowercase/mixed-case locals only: all-caps
                # names are token/constant identifiers, not
                # the operated amount.
                if v not in ("address", "SafeCast", "toInt256",
                             "toUint256", "uint256", "int256") and \
                        not v.isupper():
                    amt_vars.add(v)
        if not amt_vars:
            continue
        derived = set(amt_vars)
        for v in list(amt_vars):
            for am in re.finditer(
                    r"(\w+)\s*=\s*[^;]*\b" + re.escape(v) + r"\b",
                    text):
                derived.add(am.group(1))
        for mm in re.finditer(
                r"_safeMint\s*\(\s*\w+\s*,\s*(\w+)|"
                r"_mint\s*\(\s*\w+\s*,\s*(\w+)", text):
            amt = mm.group(1) or mm.group(2)
            if amt in derived:
                return ("caller-funded: the mint deposits "
                        "through an external operate() call "
                        "whose callback data encodes the caller, "
                        "and the minted shares are computed from "
                        "the operated amount, so the payout is "
                        "backed by the caller's own assets pulled "
                        "through the callback")
    return ""


def _fp_downgrade_reason(text: str, scope: _Scope,
                         state: set) -> str:
    """Structural reasons an ungated sensitive function is
    NOT a stranger-reachable access flaw (FP elimination,
    2026-11-05). Returns a reason string or "".

    - caller-funded: the function pulls value FROM the
      caller (transferFrom / internal _transfer / burn of
      the caller's own tokens or shares, possibly one
      helper hop away with msg.sender passed through), so
      the payout is backed by the caller's own money
      (ERC4626 deposit/mint, share-burning vault withdraw,
      fee-collecting minter application).
    - self-balance accounting: the function meters the
      payout from the contract's own token balance delta
      (AMM pair mint against reserves).
    - external authorization: execution is gated by an
      authorization call on a state-held external contract
      (Comptroller.mintAllowed(...) == 0 required, or a
      checkQualified(msg.sender) call that reverts for
      unqualified callers).
    """
    expanded = _expand_helpers_local(text, scope)
    caller_ids = {"msg.sender"}
    # NOTE: no trailing \b - it never matches after the closing
    # paren of _msgSender() (')' followed by ';' has no word
    # boundary), so `address user = _msgSender();` never
    # registered `user` as a caller alias and the DOG8004
    # caller-funded pull was missed (2026-11-19). The negative
    # lookahead keeps `msg.senderFoo` from matching instead.
    for m in re.finditer(
            r"(\w+)\s*=\s*(?:_msgSender\s*\(\s*\)|"
            r"msg\.sender)(?![A-Za-z0-9_])", expanded):
        caller_ids.add(m.group(1))
    # helper params bound to the caller at a call site
    for hname, helper in scope.helpers.items():
        for cm in re.finditer(
                r"\b" + re.escape(hname) + r"\s*\(",
                text):
            args, _ = _balanced_local(text, cm.end() - 1)
            sig_inner = ""
            if "(" in helper["signature"]:
                sig_inner, _ = _balanced_local(
                    helper["signature"],
                    helper["signature"].index("("))
            params = []
            for part in cd._split_top(sig_inner):
                words = re.findall(r"[A-Za-z_]\w*",
                                   part)
                if words:
                    params.append(words[-1])
            arg_list = [a.strip() for a in
                        cd._split_top(args)]
            for i, a in enumerate(arg_list):
                if a in ("msg.sender", "_msgSender()") \
                        and i < len(params):
                    caller_ids.add(params[i])
    # Recipients of _mint in this path: a pull whose FROM is the
    # mint recipient is funded by the recipient, not the contract
    # (ERC20Plus mintManyERC20: transferFrom(_to, address(this),..)
    # then _mint(_to, ..)). A stranger can only mint to an address
    # that pays for the tokens itself.
    mint_recipients = set()
    for mm in re.finditer(r"_safeMint\s*\(\s*(\w+)|"
                          r"_mint\s*\(\s*(\w+)", expanded):
        mint_recipients.add(mm.group(1) or mm.group(2))
    for m in _CALLER_PULL_RE.finditer(expanded):
        # Determine the FROM argument positionally:
        # transferFrom(from, to, amt) / _transfer(from, ...)
        # / _burn(from, amt) take it first, while
        # SafeERC20.safeTransferFrom(token, from, to, amt)
        # takes it second.
        paren = expanded.find("(", m.start())
        if paren < 0:
            continue
        args, _ = _balanced_local(expanded, paren)
        arg_list = [a.strip() for a in cd._split_top(args)]
        from_args = arg_list[:1]
        if "safeTransferFrom" in m.group(0) and \
                len(arg_list) >= 4:
            from_args = arg_list[1:2]
        if any(a in caller_ids or a.rstrip(")") in
               caller_ids for a in from_args):
            return ("caller-funded: value is pulled from "
                    "the caller (or the caller's own shares "
                    "burned) inside the function, so the "
                    "payout is backed by the caller's own "
                    "money")
        if any(a in mint_recipients for a in from_args):
            return ("recipient-funded: value is pulled from "
                    "the mint recipient itself inside the "
                    "function, so the payout is backed by the "
                    "recipient's own money, not the contract's")
    _op_cb = _operate_callback_funded(expanded)
    if _op_cb:
        return _op_cb
    if "balanceOf(address(this))" in expanded:
        return ("self-balance accounting: the payout is "
                "metered from the contract's own token "
                "balance against recorded reserves (AMM "
                "pair surface)")
    for m in _EXT_AUTH_RE.finditer(text):
        obj = m.group(1)
        # state-held external contract: either in the
        # elementary state set or declared at contract
        # level with a contract/interface type (Comptroller,
        # reserve, ...) - state_variables() only captures
        # elementary declarations.
        declared = obj in state or re.search(
            r"\b[A-Za-z_]\w*\s+(?:public\s+|private\s+|"
            r"internal\s+|immutable\s+)*" +
            re.escape(obj) + r"\s*[;=]", scope.scoped_text)
        if declared:
            return (f"external authorization: execution "
                    f"is gated by {obj}."
                    f"{m.group(2)}(...) on a state-held "
                    f"external contract")
    return ""


def _caller_aliases(text: str) -> set:
    """Local names bound to the caller: msg.sender, _msgSender(),
    and variables assigned from either."""
    out = {"msg.sender", "_msgSender()"}
    for m in re.finditer(
            r"(\w+)\s*=\s*(?:_msgSender\s*\(\s*\)|"
            r"msg\.sender)(?![A-Za-z0-9_])", text):
        out.add(m.group(1))
    return out


def _guarded_cmp(text: str, pattern: str) -> bool:
    """True when `pattern` (a comparison shape) appears inside a
    require(...) condition, or inside an if(...) whose body
    reverts/returns. require() is a guard by construction; an
    if() only guards when the failing branch exits."""
    for m in re.finditer(
            r"require\s*\(\s*(?:" + pattern + r")", text):
        return True
    for m in re.finditer(
            r"\bif\s*\(\s*(?:" + pattern + r")", text):
        paren = text.find("(", m.start())
        if paren < 0:
            continue
        _inner, close = _balanced_local(text, paren)
        tail = text[close + 1:close + 120]
        if re.search(r"\brevert\b|\breturn\b", tail):
            return True
    return False


def _live_gate_reason(text: str, state: set, compiler: str = "",
                      for_claim: bool = False) -> str:
    """Live gates a path text models that _gated_deep misses
    (they live in a helper / parent body on the bound path, or
    are state-based rather than modifier-based). Returns a reason
    string or "". Silent-gate shapes only: a stranger cannot pass
    them at all.

    - minter/whitelist membership: require(<map>[caller]) as a
      boolean, <set>.contains(caller), require(minters[caller]).
    - caller-keyed limit: a local assigned from a caller-keyed
      limit read compared against the amount (XERC20
      mintingCurrentLimitOf, GravityTokenG _minterMint,
      BridgedToken bridgeSupply cap).
    - role-helper calls in require/if (isSenderInRole, hasRole).
    - caller-vs-stored-address require / if-revert
      (USSD stakingContract, E2EssenceToken _masterAccount).
    - ownership of the claimed item: require(ownerOf(x) ==
      msg.sender) (Gold8V2 Goose claim).
    - caller-balance bound: require(<balance-var> >= amount)
      where the var reads the caller's balance (THREEHUNDRED).
    - PoW / challenge digest: a keccak256 digest compared
      against a stored target with revert/require (AutumnToken).
    - minter-allowance underflow (0.8+ checked arithmetic):
      <map>[caller] -= amount (HATToken).

    With for_claim=True only the access shapes apply
    (membership, role-helper, caller-vs-authority, ownership):
    limit / balance / PoW shapes are entitlements for a claim,
    and the claim detector adjudicates those by payout
    derivation, not by silencing here.
    """
    callers = _caller_aliases(text)
    caller_alt = r"(?:" + "|".join(
        re.escape(c) for c in sorted(callers, key=len,
                                      reverse=True)) + r")"

    def _membership():
        # require(<map>[caller]) as a boolean, or == true, or
        # <set>.contains(caller)
        if re.search(
                r"(?:require|if)\s*\([^;]*?[A-Za-z_]\w*\s*\[\s*" +
                caller_alt + r"\s*\]\s*(?:\)|,|==\s*true\b|"
                r"&&|\|\|)", text):
            return True
        if re.search(
                r"(?:require|if)\s*\([^;]*?\.\s*contains\s*\(\s*" +
                caller_alt + r"\s*\)", text):
            return True
        return False

    def _role_helper():
        return bool(re.search(
            r"(?:require|if)\s*\(\s*!?\s*[A-Za-z_]\w*[Rr]ole\w*"
            r"\s*\(", text))

    def _caller_vs_stored():
        stored_alt = r"(?:" + "|".join(
            re.escape(s) for s in sorted(state, key=len,
                                          reverse=True)) + r")"
        if not state:
            return False
        pat = (r"(?:" + caller_alt + r")\s*(==|!=)\s*" +
               stored_alt + r"\b|" + stored_alt +
               r"\s*(==|!=)\s*(?:" + caller_alt + r")")
        return _guarded_cmp(text, pat)

    def _ownership():
        return bool(re.search(
            r"(?:require|if)\s*\([^;]*?ownerOf\s*\([^)]*\)\s*"
            r"(==|!=)\s*(?:" + caller_alt + r")|"
            r"(?:require|if)\s*\([^;]*?(?:" + caller_alt +
            r")\s*(==|!=)\s*ownerOf\s*\(", text))

    if _membership():
        return ("minter/whitelist membership: the caller must be "
                "recorded in a minter/allowlist mapping or set")
    if _role_helper():
        return ("role-helper gate: a require/if on a role check "
                "call (isSenderInRole / hasRole)")
    if _caller_vs_stored():
        return ("caller-vs-stored-address gate: the caller must "
                "equal a stored authorized address")
    if _ownership():
        return ("ownership gate: the caller must own the item "
                "being claimed against (ownerOf == caller)")
    if for_claim:
        return ""
    # --- mint-only shapes below (entitlements for a claim) ---
    # Caller-keyed limit: a local assigned from a caller-keyed
    # limit read, compared against an amount.
    limit_vars = set()
    for m in re.finditer(
            r"(\w+)\s*=\s*[^;]*?(?:[Ll]imit\w*|"
            r"[A-Za-z_]\w*)\s*\(\s*(?:" + caller_alt + r")",
            text):
        limit_vars.add(m.group(1))
    for m in re.finditer(
            r"(\w+)\s*=\s*[^;]*?[A-Za-z_]\w*\s*\[\s*" +
            caller_alt + r"\s*\]\s*\.\s*[Ll]imit\b", text):
        limit_vars.add(m.group(1))
    for v in limit_vars:
        if _guarded_cmp(
                text, r"\b" + re.escape(v) +
                r"\b\s*(>=|>|<=|<|==|!=)|"
                r"(>=|>|<=|<|==|!=)\s*\b" + re.escape(v) + r"\b"):
            return ("caller-keyed minter limit: the mint amount "
                    "is checked against the caller's recorded "
                    "minter limit")
    # Caller-keyed mapping read compared against an amount
    # (bridge cap, minter allowance).
    if _guarded_cmp(
            text, r"[A-Za-z_]\w*\s*\[\s*" + caller_alt +
            r"\s*\]\s*(>=|>|<=|<|==|!=)"):
        return ("caller-keyed cap: the mint amount is checked "
                "against the caller's recorded cap")
    # Record-field guard: a require/if-revert on a field of a
    # local bound to a caller-keyed mapping read (BridgedToken:
    # Supply storage b = bridgeSupply[msg.sender];
    # require(b.cap > 0); require(b.total <= b.cap)). The record
    # is zero/absent for a stranger, so the require is the gate.
    record_vars = set()
    for m in re.finditer(
            r"(\w+)\s*=\s*[^;]*?\[[^\];]*?" + caller_alt +
            r"\b[^\];]*?\]", text):
        record_vars.add(m.group(1))
    for v in record_vars:
        if _guarded_cmp(
                text, r"\b" + re.escape(v) +
                r"\.\w+\s*(>=|>|<=|<|==|!=)|"
                r"(>=|>|<=|<|==|!=)\s*\b" + re.escape(v) +
                r"\.\w+|\b" + re.escape(v) +
                r"\b\s*(>=|>|<=|<|==|!=)"):
            return ("record-field gate: the mint amount is "
                    "checked against the caller's stored record")
    # Caller-balance bound.
    bal_vars = set()
    for m in re.finditer(
            r"(\w+)\s*=\s*[^;]*?(?:balanceOf|[A-Za-z_]*[Bb]alance\w*)"
            r"\s*\(\s*(?:" + caller_alt + r")\s*\)", text):
        bal_vars.add(m.group(1))
    for v in bal_vars:
        if _guarded_cmp(
                text, r"\b" + re.escape(v) +
                r"\b\s*(>=|>|<=|<|==|!=)|"
                r"(>=|>|<=|<|==|!=)\s*\b" + re.escape(v) + r"\b"):
            return ("caller-balance bound: the mint amount is "
                    "checked against the caller's own balance")
    if _guarded_cmp(
            text, r"balanceOf\s*\(\s*(?:" + caller_alt +
            r")\s*\)\s*(>=|>|<=|<|==|!=)"):
        return ("caller-balance bound: the mint amount is "
                "checked against the caller's own balance")
    # PoW / challenge digest.
    digest_vars = set()
    for m in re.finditer(
            r"(\w+)\s*=\s*[^;]*?keccak256\s*\(", text):
        digest_vars.add(m.group(1))
    for v in digest_vars:
        if _guarded_cmp(
                text, r"(?:uint256\s*\(\s*)?\b" + re.escape(v) +
                r"\b\s*\)?\s*(>=|>|<=|<|==|!=)\s*[A-Za-z_]|"
                r"[A-Za-z_]\w*\s*(>=|>|<=|<|==|!=)\s*"
                r"(?:uint256\s*\(\s*)?\b" + re.escape(v) +
                r"\b\s*\)?"):
            return ("proof-of-work / challenge gate: the mint "
                    "requires a digest below a stored target or "
                    "matching a challenge")
    # Minter-allowance underflow (0.8+ checked arithmetic only:
    # pre-0.8 the subtraction wraps instead of reverting).
    if compiler:
        mver = re.search(r"(\d+)\.(\d+)", compiler)
        if mver and (int(mver.group(1)), int(mver.group(2))) >= (0, 8):
            if re.search(
                    r"[A-Za-z_]\w*\s*\[\s*" + caller_alt +
                    r"\s*\]\s*-=\s*[A-Za-z_]\w*", text):
                return ("minter-allowance underflow: the caller's "
                        "recorded minter allowance is decremented "
                        "by the mint amount (0.8 checked "
                        "arithmetic reverts for a non-minter)")
    return ""


def _priced_mint_reason(text: str) -> str:
    """The mint charges the caller: a msg.value comparison
    against a non-zero price expression. A bare `msg.value > 0`
    does NOT count (1 wei is not a price). Returns a reason
    string or ""."""
    for m in re.finditer(
            r"(?:require|if)\s*\(([^;]*)msg\.value([^;]*)\)", text):
        lhs, rhs = m.group(1), m.group(2)
        other = (lhs + rhs).strip()
        other = re.sub(r"^(>=|<=|==|!=|>|<)\s*", "", other)
        other = re.sub(r"\s*(>=|<=|==|!=|>|<)$", "", other)
        if other and other not in ("0", "0x0", "0.0"):
            return ("priced mint: the caller must pay msg.value "
                    "against a non-zero price for the minted "
                    "amount")
    return ""


def _entitlement_bounded_reason(text: str,
                                mint_only: bool = False) -> str:
    """The payout amount derives from a caller/recipient-keyed
    recorded position, so a stranger with no record gets zero.
    Modelled as a small dataflow fixpoint over the bound path:

    - bound values start as the caller and the payout
      recipients; a require/if-equality against a bound value
      binds the other side (Hedron: require(hsiAddress ==
      _hsiAddress) where _hsiAddress came from
      hsiLists(msg.sender, ...)).
    - a local assigned from a key-keyed mapping read (incl.
      storage pointers and nested keys) is an entitlement
      record; a local loaded by a call fed a bound value whose
      fields a require/if then guards is one too (Hedron:
      share = _hsiLoad(hsiAddress), guarded by
      share._stake.lockedDay / share._isLoaned checks).
    - a local assigned from an expression mentioning an
      entitlement record derives from it.
    - a payout amount that is a call to a helper whose body
      reads a caller-keyed record and gates on it is bounded
      too (HELIOS: _mint(..., _claimMint(_msgSender(), id, ...))
      where _claimMint reverts when the caller's mint record
      does not exist or is not mature).

    Returns a reason string or ""."""
    keys = _caller_aliases(text)
    for m in re.finditer(
            r"_safeMint\s*\(\s*(\w+)|_mint\s*\(\s*(\w+)|"
            r"(?:safeTransfer|transfer)\s*\(\s*(\w+)", text):
        for g in m.groups():
            if g:
                keys.add(g)
    bound = set(keys)
    ent = set()
    # Helpers whose return is a value read from a
    # caller/recipient-keyed record (computed once; the fixpoint
    # below only looks the set up).
    loader_helpers = set()
    for _fm in re.finditer(r"function\s+(\w+)\s*\(", text):
        if _helper_loads_caller(text, _fm.group(1), keys):
            loader_helpers.add(_fm.group(1))
    changed = True
    while changed:
        changed = False
        # Require / if-equality binding.
        for m in re.finditer(
                r"require\s*\([^;]*?(\w+)\s*==\s*(\w+)[^;]*?\)|"
                r"\bif\s*\(\s*(\w+)\s*!=\s*(\w+)[^;]*?\)", text):
            a, b = m.group(1) or m.group(3), \
                m.group(2) or m.group(4)
            if a in bound and b not in bound:
                bound.add(b)
                changed = True
            elif b in bound and a not in bound:
                bound.add(a)
                changed = True
        # Assignments.
        for m in re.finditer(
                r"(?:^|[;{}])\s*(?:\w+\s+)?(?:storage\s+|memory\s+)?"
                r"(\w+)\s*=\s*([^;{}]+)", text):
            var, rhs = m.group(1), m.group(2)
            if var in ent:
                continue
            # Key-keyed mapping read.
            keyed = False
            for k in bound:
                if re.search(r"\[\s*" + re.escape(k) + r"\b",
                             rhs):
                    keyed = True
                    break
            if keyed:
                ent.add(var)
                bound.add(var)
                changed = True
                continue
            # Call to a helper that loads the caller's record
            # (Hedron mintNative: stake =
            # _hexStakeLoad(stakeIndex), where _hexStakeLoad
            # returns _hx.stakeLists(msg.sender, stakeIndex)).
            for cm in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", rhs):
                if cm.group(1) in loader_helpers:
                    ent.add(var)
                    bound.add(var)
                    changed = True
                    keyed = True
                    break
            if keyed:
                continue
            # Call fed a bound value: the result is bound to the
            # caller too (Hedron: _hsiAddress =
            # _hsim.hsiLists(msg.sender, hsiIndex)); when the
            # result is a record whose fields a require/if then
            # guards, it is an entitlement record (share =
            # _hsiLoad(hsiAddress), guarded by
            # share._stake.lockedDay / share._isLoaned).
            if re.search(r"\b[A-Za-z_]\w*\s*\(", rhs):
                fed = any(re.search(
                    r"\b" + re.escape(b) + r"\b", rhs)
                    for b in bound)
                if fed:
                    if var not in bound:
                        bound.add(var)
                        changed = True
                    if re.search(
                            r"(?:require|if)\s*\([^;]*\b" +
                            re.escape(var) + r"\.\w+", text):
                        if var not in ent:
                            ent.add(var)
                            changed = True
            # Derivation from an entitlement record.
            for e in ent:
                if re.search(r"\b" + re.escape(e) + r"\b", rhs):
                    ent.add(var)
                    bound.add(var)
                    changed = True
                    break
    if not ent and not _helper_is_entitlement(text, None, keys):
        return ""
    for m in re.finditer(
            r"_safeMint\s*\([^;]*?\)|_mint\s*\([^;]*?\)|"
            r"(?:safeTransfer|transfer)\s*\([^;]*?\)", text):
        call = m.group(0)
        if mint_only and not re.match(
                r"_safeMint\s*\(|_mint\s*\(", call):
            # A transfer payout is bounded only by consumption
            # (_record_debit_bounded): an entitlement read with
            # no debit is the double-claim shape, which must
            # still fire. Only mint-shaped payouts (newly
            # minted value gated by record existence) downgrade
            # here.
            continue
        for e in ent:
            if re.search(r"\b" + re.escape(e) + r"\b", call):
                return ("entitlement-bounded payout: the minted / "
                        "paid amount derives from the caller or "
                        "recipient's recorded position, so a "
                        "stranger with no record receives zero")
        # Payout amount is a call to an entitlement helper.
        paren = call.find("(")
        if paren >= 0:
            inner, _ = _balanced_local(call, paren)
            for a in _split_top(inner):
                a = a.strip()
                hm = re.match(r"([A-Za-z_]\w*)\s*\(", a)
                if hm and _helper_is_entitlement(text, hm.group(1),
                                                 keys):
                    return ("entitlement-bounded payout: the "
                            "minted / paid amount is the return of "
                            "a helper that reads the caller or "
                            "recipient's recorded position and "
                            "gates on it, so a stranger with no "
                            "record receives zero")
    return ""


def _helper_is_entitlement(text: str, name, keys: set) -> bool:
    """True when the named helper's body (in the bound path)
    reads a caller/recipient-keyed record and gates on it.
    With name=None, true when ANY function chunk in the text
    does (used as a fast pre-check)."""
    for m in re.finditer(r"function\s+(\w+)\s*\(", text):
        if name is not None and m.group(1) != name:
            continue
        start = text.find("{", m.start())
        if start < 0:
            continue
        nxt = text.find("\nfunction ", start)
        body = text[start:nxt if nxt >= 0 else len(text)]
        keyed = any(re.search(r"\[\s*" + re.escape(k) + r"\b",
                              body) for k in keys)
        if not keyed:
            continue
        # A require/if on a var read from that record.
        rec_vars = set()
        for am in re.finditer(
                r"(\w+)\s*=\s*[^;]*?\[[^\];]*?" +
                r"(?:" + "|".join(re.escape(k) for k in keys) +
                r")\b[^\];]*?\]", body):
            rec_vars.add(am.group(1))
        for v in rec_vars:
            if re.search(
                    r"(?:require|if)\s*\([^;]*\b" +
                    re.escape(v) + r"\b", body):
                return True
    return False


def _helper_loads_caller(text: str, name: str, keys: set) -> bool:
    """True when the named helper's body returns a value read
    from a caller/recipient-keyed record: a mapping read
    [<key>] or an external call with the key as an argument,
    whose result flows into the helper's return (directly, or
    via a single / tuple assignment that the return then
    mentions). Hedron: _hexStakeLoad returns
    _hx.stakeLists(msg.sender, stakeIndex)."""
    for m in re.finditer(r"function\s+" + re.escape(name) +
                         r"\s*\(", text):
        start = text.find("{", m.start())
        if start < 0:
            continue
        nxt = text.find("\nfunction ", start)
        body = text[start:nxt if nxt >= 0 else len(text)]

        def _keyed(expr: str) -> bool:
            for k in keys:
                if re.search(r"\[\s*" + re.escape(k) + r"\b",
                             expr):
                    return True
                if re.search(r"\b\w+\s*\([^;]*\b" +
                             re.escape(k) + r"\b[^;]*\)", expr):
                    return True
            return False

        # Direct return of a caller-keyed read/call.
        for rm in re.finditer(r"return\b([^;]*)", body):
            if _keyed(rm.group(1)):
                return True
        # Vars assigned from a caller-keyed read/call.
        loaded = set()
        for am in re.finditer(
                r"(?<![=!<>])(\w+)\s*=(?!=)\s*([^;]*)", body):
            if _keyed(am.group(2)):
                loaded.add(am.group(1))
        # Tuple assignment: (a, b, ...) = f(key, ...), or
        # (uint40 a, uint72 b) = f(key, ...) - the component
        # may carry its type, so the var is the last word.
        for tm in re.finditer(
                r"\(([\w\s,]+)\)\s*=\s*([^;]*)", body):
            if _keyed(tm.group(2)):
                for v in tm.group(1).split(","):
                    parts = v.split()
                    if parts:
                        loaded.add(parts[-1])
        # Any loaded var returned?
        for rm in re.finditer(r"return\b([^;]*)", body):
            for v in loaded:
                if re.search(r"\b" + re.escape(v) + r"\b",
                             rm.group(1)):
                    return True
    return False


def analyze_logic_source(src: str, compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Static logic analysis over verified Solidity source.

    Returns finding dicts {kind, logic_kind, severity, function,
    code, detail} (access-control findings that move value also
    carry recipient + report_class). Detection only - nothing
    here interacts with the contract.

    Analysis is scoped to the deployed target contract and its
    inheritance chain when `contract_name` identifies it in the
    compilation (FP fix 3); test/mock files, sibling contracts
    and free functions never produce findings.
    """
    clean = cc._strip_comments(src)
    version = solc_version(clean, compiler)
    scope = _Scope(src, contract_name)
    state = state_variables(scope.scoped_text)
    # Pre-0.5 contracts name their constructor after the contract
    # itself; those functions run once, at deploy time, with
    # deployer-supplied arguments - not live logic. (USDT's
    # RequestToken-style hit in the 2026-11-02 live smoke was
    # exactly this shape.)
    contract_names = scope.contract_names or set(
        re.findall(r"\bcontract\s+([A-Za-z_]\w*)", clean))
    out: List[Dict[str, Any]] = []
    fns = [fn for fn in scope.functions if fn["name"]
           and fn["name"] not in ("constructor",)
           and fn["name"] not in contract_names]
    writes_after_call: Dict[str, List[str]] = {}

    for fn in fns:
        name, sig, text = fn["name"], fn["signature"], fn["text"]
        if "{" not in text:
            continue  # interface declaration - no logic to analyze
        if re.search(r"\b(view|pure)\b", sig):
            continue
        params = cd._param_names(sig)
        gated = _gated_deep(fn, scope)
        guarded = "nonReentrant" in sig or "nonReentrant" in text
        fn_path = path_trace(scope, fn)
        fn_guards = guard_inventory(scope, fn)

        # ---- tx.origin authorization (any function) ---------------
        if re.search(r"tx\.origin\s*(==|!=)|(==|!=)\s*tx\.origin",
                     text):
            out.append({
                "kind": "access_control_flaw",
                "logic_kind": "tx_origin_auth",
                "severity": "high",
                "function": name,
                "code": cc._snip(text),
                "path": fn_path,
                "guards": fn_guards,
                "detail": (
                    "authorization compares tx.origin; any "
                    "contract the owner is tricked into calling "
                    "inherits the owner's identity. signature: "
                    f"{sig[:200]}"),
            })

        # ---- reentrancy: external call before state update --------
        calls = _external_calls(text)
        writes = _state_writes(text, state)
        cei_fired = False
        lock_var = _reentrancy_lock_var(text, state) if calls \
            else None
        if calls and writes and not gated and not guarded:
            first_call = calls[0]
            # A variable already written BEFORE the call and
            # written again after it is a rollback/compensation
            # write (dividend trackers restore the credit when the
            # payout transfer fails), not a CEI violation.
            written_before = {v for p, v in writes
                              if p < first_call["pos"]}
            late = [(p, v) for p, v in writes
                    if p > first_call["pos"]
                    and v not in written_before]
            for pos, var in late:
                before = text[:first_call["pos"]]
                amount = " ".join(
                    str(a) for a in first_call.get("args") or [])
                if _reads_var(before, var) or \
                        _reads_var(amount, var) or \
                        first_call["kind"] in ("call", "send",
                                               "safe_transfer",
                                               "hook",
                                               "delegatecall",
                                               "callcode"):
                    if lock_var:
                        # Depth fix 2: the path IS guarded - by
                        # a hand-rolled storage lock, not the
                        # nonReentrant keyword. Trigger-only at
                        # low, naming the closing guard.
                        out.append({
                            "kind": "reentrancy",
                            "logic_kind": "cei_violation",
                            "severity": "low",
                            "report_class": "trigger_only",
                            "function": name,
                            "code": cc._snip(text),
                            "path": fn_path,
                            "guards": fn_guards,
                            "detail": (
                                f"external call "
                                f"({first_call['kind']} to "
                                f"{first_call['receiver']}) precedes "
                                f"the update of state variable "
                                f"'{var}', but the path is closed "
                                f"by a hand-rolled reentrancy lock "
                                f"on '{lock_var}' (checked at "
                                "entry, set before the call, "
                                "restored after) - TRIGGER-ONLY. "
                                f"signature: {sig[:200]}"),
                        })
                    else:
                        out.append({
                            "kind": "reentrancy",
                            "logic_kind": "cei_violation",
                            "severity": "high",
                            "function": name,
                            "code": cc._snip(text),
                            "path": fn_path,
                            "guards": fn_guards,
                            "detail": (
                                f"external call ({first_call['kind']} "
                                f"to {first_call['receiver']}) executes "
                                f"before state variable '{var}' is "
                                "updated later in the same function "
                                "(checks-effects-interactions violated); "
                                f"gated=False ({_UNGATED_BASIS}); "
                                "reentrancy guard absent. signature: "
                                f"{sig[:200]}"),
                        })
                        writes_after_call.setdefault(
                            var, []).append(name)
                    cei_fired = True
                    break

        # ---- reentrancy split across a helper call ----------------
        # The external call lives in an internal helper; the
        # state write sits in the entry after the helper call
        # (depth fix 2). CEI-correct-through-helper and locked
        # paths stay non-candidate.
        if not cei_fired and not gated and not guarded:
            split = _helper_split_cei(fn, scope, state)
            if split:
                if split["lock"]:
                    out.append({
                        "kind": "reentrancy",
                        "logic_kind": "cei_violation",
                        "severity": "low",
                        "report_class": "trigger_only",
                        "function": name,
                        "code": cc._snip(text),
                        "path": fn_path,
                        "guards": fn_guards,
                        "detail": (
                            f"external call ({split['call_kind']}) "
                            f"inside internal helper "
                            f"{split['helper']}() precedes the "
                            f"update of state variable "
                            f"'{split['var']}', but the path is "
                            f"closed by a hand-rolled reentrancy "
                            f"lock on '{split['lock']}' - "
                            f"TRIGGER-ONLY. signature: "
                            f"{sig[:200]}"),
                    })
                else:
                    out.append({
                        "kind": "reentrancy",
                        "logic_kind": "cei_violation",
                        "severity": "high",
                        "function": name,
                        "code": cc._snip(text),
                        "path": fn_path,
                        "guards": fn_guards,
                        "detail": (
                            f"external call ({split['call_kind']} "
                            f"to {split['receiver']}) inside "
                            f"internal helper {split['helper']}() "
                            f"executes before state variable "
                            f"'{split['var']}' is updated after "
                            "the helper call returns "
                            "(checks-effects-interactions "
                            "violated across the helper boundary; "
                            f"path: {name} -> {split['helper']}); "
                            f"gated=False ({_UNGATED_BASIS}); "
                            "reentrancy guard absent on the "
                            f"path. signature: {sig[:200]}"),
                    })
                    writes_after_call.setdefault(
                        split["var"], []).append(name)

        # ---- integer overflow / underflow --------------------------
        # Gated functions are skipped here too (2026-11-02 live
        # smoke FP class): USDT's onlyOwner issue()/redeem() do
        # pre-0.8 arithmetic on balances, but the only caller who
        # could push the value to overflow is the privileged
        # account itself - self-harm by the operator, not an
        # attacker-reachable logic flaw. Same gate discipline as
        # the drain analyzer. On top of that, FP fix 1 suppresses
        # the canonical safe shapes (internal functions, bounds
        # checked upstream, msg.value-bounded arithmetic) that
        # produced 63 of the adjudicated FPs.
        if not gated and version is not None and version < (0, 8, 0):
            for pos, var, op in _overflow_ops(text, state, params):
                if _overflow_suppression(fn, text, pos, var, op,
                                         state, params):
                    continue
                out.append({
                    "kind": "integer_overflow",
                    "logic_kind": "pre080_unchecked_arithmetic",
                    "severity": "high",
                    "function": name,
                    "code": cc._line_context(
                        clean, clean.find(text) + pos
                        if clean.find(text) >= 0 else pos,
                        before=2, after=2) or cc._snip(text),
                    "detail": (
                        f"Solidity {'.'.join(map(str, version))} "
                        f"(<0.8) arithmetic on state variable "
                        f"'{var}' with no SafeMath: pre-0.8 "
                        "arithmetic wraps silently on "
                        "over/underflow. signature: "
                        f"{sig[:200]}"),
                })
                break  # one finding per function is enough
        # unchecked {} blocks exist only in >=0.8 sources
        for m in (re.finditer(r"\bunchecked\s*\{", text)
                  if not gated else []):
            brace = text.index("{", m.start())
            block = text[brace + 1:cd._matching(text, brace, "{", "}")]
            for _pos, var, _op in _overflow_ops(block, state,
                                                params):
                if _overflow_suppression(fn, text, brace + 1 + _pos,
                                         var, _op, state, params):
                    continue  # canonical safe shape (FP fix 1)
                sev = "high" if _BALANCEY_RE.search(var) else "medium"
                out.append({
                    "kind": "integer_overflow",
                    "logic_kind": "unchecked_block_arithmetic",
                    "severity": sev,
                    "function": name,
                    "code": cc._snip(text),
                    "detail": (
                        f"unchecked {{}} block does arithmetic on "
                        f"state variable '{var}': the block opts "
                        "out of Solidity >=0.8 overflow checks. "
                        f"signature: {sig[:200]}"),
                })
                break
        # inline assembly arithmetic on stored balances
        for m in (re.finditer(r"\bassembly\s*\{", text)
                  if not gated else []):
            brace = text.index("{", m.start())
            block = text[brace + 1:cd._matching(text, brace, "{", "}")]
            if re.search(r"\b(add|sub|mul)\s*\(", block) and \
                    ("sload" in block or
                     any(_reads_var(block, v) for v in state)):
                if _overflow_suppression(fn, text, brace, "",
                                         "", state, params):
                    continue
                out.append({
                    "kind": "integer_overflow",
                    "logic_kind": "assembly_arithmetic",
                    "severity": "medium",
                    "function": name,
                    "code": cc._snip(text),
                    "detail": (
                        "inline assembly performs add/sub/mul on "
                        "stored state: assembly arithmetic is never "
                        "overflow-checked. signature: "
                        f"{sig[:200]}"),
                })
                break

        # ---- access control ----------------------------------------
        if cd._is_skippable(sig, text):
            continue
        if name == "initialize":
            if "initializer" not in sig and \
                    "reinitializer" not in sig and \
                    _state_writes(text, state):
                out.append({
                    "kind": "access_control_flaw",
                    "logic_kind": "unprotected_initializer",
                    "severity": "high",
                    "function": name,
                    "code": cc._snip(text),
                    "path": fn_path,
                    "guards": fn_guards,
                    "detail": (
                        "public initialize() with no initializer "
                        "modifier sets state: anyone can call it "
                        "first (or again) and seize the contract. "
                        f"signature: {sig[:200]}"),
                })
            continue
        if gated:
            continue
        # arbitrary delegatecall to a caller-supplied target
        for m in re.finditer(r"\.delegatecall\s*\(", text):
            recv = cd._unwrap(cd._expr_before(text, m.start()))
            if cd._caller_controlled(recv, params):
                out.append({
                    "kind": "access_control_flaw",
                    "logic_kind": "arbitrary_delegatecall",
                    "severity": "high",
                    "function": name,
                    "code": cc._snip(text),
                    "path": fn_path,
                    "guards": fn_guards,
                    "detail": (
                        f"delegatecall target '{recv}' is "
                        "caller-supplied and the function has no "
                        f"access gate (gated=False; {_UNGATED_BASIS}):"
                        " the target code runs in this contract's "
                        "storage context. signature: "
                        f"{sig[:200]}"),
                })
                break
        # Self-funded shapes are not access flaws: when the
        # payout is bound to the caller's own payment
        # (msg.value == amount, the POL system-contract withdraw
        # and the crowdsale purchase shape), a stranger can only
        # ever move their own money through the function.
        if _SELF_FUNDED_RE.search(text):
            continue
        # Withdraw-family names are only an access flaw when the
        # caller can take more than their own credited balance: a
        # withdraw bounded by balances[msg.sender] pays out what
        # the caller is owed (the drain analyzer's own-credit
        # rule). Admin-shaped names (set*/mint/upgrade/pause/...)
        # are flaws on any ungated state-changing action.
        _ADMIN_NAME_RE = re.compile(
            r"mint|setowner|transferownership|renounceownership|"
            r"setfee|settax|setadmin|setcontroller|setminter|"
            r"setimplementation|upgrade|pause|setprice|setwallet|"
            r"setrouter|setoracle|settreasury|destroy|kill|"
            r"setconfig|setaddress|burnfrom", re.I)
        if _SENSITIVE_NAME_RE.search(name) and \
                _performs_sensitive_action(text, state) and \
                (_ADMIN_NAME_RE.search(name) or
                 "[msg.sender]" not in text):
            item = {
                "kind": "access_control_flaw",
                "logic_kind": "ungated_sensitive_function",
                "severity": "high",
                "function": name,
                "code": cc._snip(text),
                "path": fn_path,
                "guards": fn_guards,
                "detail": (
                    f"sensitive function '{name}' performs its "
                    "action with NO access gate (gated=False; "
                    f"{_UNGATED_BASIS}). signature: {sig[:200]}"),
            }
            # FP fix 4: recipient dataflow decides whether this
            # is candidate-grade (a stranger can RECEIVE) or
            # trigger-only (value lands at a fixed destination).
            _recipient_reclassify(item, text)
            # FP elimination (2026-11-05): caller-funded,
            # self-balance-metered and externally
            # authorized shapes are public surface, not
            # stranger-reachable access flaws.
            reason = _fp_downgrade_reason(text, scope, state)
            if reason:
                item["report_class"] = "trigger_only"
                item["severity"] = "low"
                item["detail"] += (
                    f" Downgraded to TRIGGER-ONLY: {reason}.")
            out.append(item)

    # ---- cross-function reentrancy hints ----------------------------
    if writes_after_call:
        for fn in fns:
            name, sig, text = fn["name"], fn["signature"], fn["text"]
            if "{" not in text or re.search(r"\b(view|pure)\b", sig):
                continue
            if _gated_deep(fn, scope) or "nonReentrant" in text:
                continue
            calls = _external_calls(text)
            if not calls:
                continue
            first = calls[0]["pos"]
            for var, writers in writes_after_call.items():
                if name in writers:
                    continue
                if _reads_var(text[:first], var):
                    out.append({
                        "kind": "reentrancy",
                        "logic_kind": "cross_function_reentrancy",
                        "severity": "medium",
                        "function": name,
                        "code": cc._snip(text),
                        "path": path_trace(scope, fn),
                        "guards": guard_inventory(scope, fn),
                        "detail": (
                            f"reads state variable '{var}' before "
                            f"its own external call, while "
                            f"{writers[0]}() updates '{var}' only "
                            "after an external call: a re-entrant "
                            "call into this function can act on the "
                            "stale value. signature: "
                            f"{sig[:200]}"),
                    })
                    break
    return out


# The unfunded stranger used in every probe sketch: read-only
# eth_call reachability is judged from an address that holds
# nothing and controls nothing, exactly like the live validator.
_STRANGER = "0x00000000000000000000000000000000deaDBeef"

_MEDIUM_OPCODES = ("SELFDESTRUCT", "DELEGATECALL", "CALLCODE")


def _signature_arg_count(signature: Optional[str]) -> Optional[int]:
    """Number of top-level arguments in a known signature, or
    None when the signature is unknown / unparseable."""
    if not signature or "(" not in signature or \
            not signature.endswith(")"):
        return None
    inner = signature[signature.index("(") + 1:-1].strip()
    if not inner:
        return 0
    depth = 0
    count = 1
    for ch in inner:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count


def _probe_sketch(selector: str, signature: Optional[str]
                  ) -> Dict[str, Any]:
    """An inert eth_call probe sketch (DATA only - this plugin
    never executes it): the selector plus one zero-filled 32-byte
    word per known argument, from the unfunded stranger."""
    argc = _signature_arg_count(signature)
    data = "0x" + selector[2:]
    if argc:
        data += "00" * 32 * argc
    return {
        "selector": selector,
        "signature": signature,
        "from_address": _STRANGER,
        "data": data,
        "purpose": (
            "read-only eth_call reachability probe for the "
            "validator - never executed by this plugin"),
    }


def _legacy_bytecode_finding(info: Dict[str, Any]
                             ) -> List[Dict[str, Any]]:
    """The original aggregate opcode-presence finding, unchanged:
    used when no dispatcher is recognized, so existing consumers
    see exactly the legacy shape."""
    opcodes = info.get("opcodes") or {}
    risky = {k: v for k, v in opcodes.items()
             if k in ("SELFDESTRUCT", "DELEGATECALL", "CALLCODE")}
    if not risky:
        return []
    listed = ", ".join(f"{k} x{v}" for k, v in sorted(risky.items()))
    return [{
        "kind": "bytecode_opcode_risk",
        "logic_kind": "bytecode_opcode_presence",
        "severity": "low",
        "function": "",
        "code": "",
        "detail": (
            f"bytecode-only heuristic (no verified source): the "
            f"runtime bytecode contains {listed}. Opcode presence "
            "shows the capability exists; it does NOT confirm a "
            "logic flaw - the source is needed for that."),
    }]


def analyze_logic_bytecode(code_hex: str) -> List[Dict[str, Any]]:
    """Bytecode-only heuristic lane, v2: per-selector attribution.

    - EIP-1167 minimal proxy: one finding carrying the
      implementation address and a probe sketch directing
      analysis at the IMPLEMENTATION (the proxy has no logic).
    - solc dispatcher recognized: ONE finding per selector whose
      walked path reaches a sensitive opcode (CALL / CALLCODE /
      DELEGATECALL / SELFDESTRUCT / CREATE / CREATE2), with the
      path opcodes, storage slots, and an inert eth_call probe
      sketch. Selectors reaching nothing sensitive stay silent.
    - No dispatcher recognized: the legacy aggregate
      opcode-presence finding, unchanged.
    - No sensitive opcode on any path and none globally: [].

    Every finding is explicitly a bytecode heuristic: a
    capability on a statically reachable path, NOT a confirmed
    flaw.
    """
    info = cc.analyze_bytecode(code_hex)

    impl = info.get("minimal_proxy_impl")
    if impl:
        return [{
            "kind": "bytecode_opcode_risk",
            "logic_kind": "bytecode_minimal_proxy",
            "severity": "low",
            "function": "",
            "code": "",
            "minimal_proxy_impl": impl,
            "selector_paths": [],
            "probe_sketches": [{
                "selector": None,
                "signature": None,
                "from_address": _STRANGER,
                "data": "0x",
                "target": impl,
                "minimal_proxy_impl": impl,
                "purpose": (
                    "this address is an EIP-1167 minimal proxy "
                    "with no logic of its own: direct read-only "
                    "eth_call analysis at the IMPLEMENTATION "
                    f"address {impl}, not the proxy shell - "
                    "never executed by this plugin"),
            }],
            "detail": (
                f"bytecode heuristic (no verified source): this "
                f"contract is an EIP-1167 minimal proxy - it has "
                f"no logic of its own and delegatecalls every "
                f"call to its implementation {impl}. Analyze the "
                f"IMPLEMENTATION contract; the proxy shell alone "
                f"proves nothing about the logic behind it."),
        }]

    paths = bp.analyze(code_hex)
    if paths.get("dispatcher_found"):
        findings: List[Dict[str, Any]] = []
        for entry in paths.get("selectors") or []:
            sensitive = entry.get("sensitive_opcodes") or []
            if not sensitive:
                continue
            selector = entry["selector"]
            signature = entry.get("signature")
            severity = "medium" if any(
                op in sensitive for op in _MEDIUM_OPCODES) \
                else "low"
            findings.append({
                "kind": "bytecode_opcode_risk",
                "logic_kind": "bytecode_selector_capability",
                "severity": severity,
                "function": signature or selector,
                "code": "",
                "selector": selector,
                "signature": signature,
                "opcodes": entry.get("opcodes") or [],
                "sensitive_opcodes": list(sensitive),
                "storage_reads": entry.get("storage_reads") or [],
                "storage_writes": entry.get("storage_writes") or [],
                "selector_paths": [entry],
                "probe_sketches": [
                    _probe_sketch(selector, signature)],
                "detail": (
                    f"bytecode heuristic (no verified source): "
                    f"selector {selector}"
                    + (f" ({signature})" if signature else "")
                    + f" reaches {', '.join(sensitive)} on a "
                    f"statically walked bytecode path. This is a "
                    f"capability on a reachable path, NOT a "
                    f"confirmed flaw - reachability says nothing "
                    f"about gates or call context the bytecode "
                    f"walk cannot see; the probe sketch is for "
                    f"the validator to test read-only."),
            })
        if findings:
            return findings
        # Dispatcher found but no selector path reaches a
        # sensitive opcode: fall through - silence when nothing
        # sensitive exists globally, else the legacy aggregate.
        global_ops = (info.get("opcodes") or {})
        if not any(name in global_ops for name in (
                "SELFDESTRUCT", "DELEGATECALL", "CALLCODE",
                "CALL", "CREATE", "CREATE2")):
            return []
    return _legacy_bytecode_finding(info)


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class ContractLogicPlugin(Plugin):
    id = "contract_logic"
    label = "Smart Contract Logic Analyzer"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # keyless-first: Blockscout + Sourcify + public RPC
    description = ("Analyzes a contract's LOGIC, not just its "
                   "surface: reentrancy (external call before the "
                   "state update, plus cross-function hints), "
                   "integer overflow/underflow (pre-0.8 unchecked "
                   "arithmetic without SafeMath, >=0.8 unchecked{} "
                   "blocks and assembly arithmetic on balances), "
                   "and access-control flaws (ungated sensitive "
                   "functions that perform the action, tx.origin "
                   "authorization, unprotected initialize(), "
                   "arbitrary delegatecall). Same false-positive "
                   "discipline as the drain analyzer; guarded, "
                   "gated, CEI-ordered, internal and view/pure "
                   "code stays silent. With no verified source, "
                   "falls back to a low-confidence bytecode opcode "
                   "heuristic, clearly labeled as such. When the "
                   "target is a proxy, the implementation behind "
                   "it is analyzed too. Read-only, never interacts "
                   "with contracts.")
    phase = 2  # also consumes addresses discovered by phase-1 miners
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None

        work = self._collect(target, ctx)
        if not work:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. bsc:0x...) "
                "or a web target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        pairs_done = 0
        analyzed = 0
        bytecode_only = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs, got_source = await self._scan_address(
                    ctx, key, chain_hint, addr, findings)
            except Exception:
                pairs, got_source = 0, False
                findings.append(self._f(
                    "web3", "contract_logic_failed",
                    f"MEDIUM: {addr}: DEGRADED - logic analysis failed, "
                    "chain data could not be retrieved "
                    "(explorers/RPC unreachable). No conclusion "
                    "drawn.",
                    source="contract logic analyzer",
                    confidence=60, passive=True,
                    evidence={"severity": "medium", "address": addr,
                              "remediation": "Retry the scan; if the "
                                             "chain RPCs stay down, "
                                             "audit this address "
                                             "manually on its block "
                                             "explorer."}))
            pairs_done += pairs
            if pairs:
                analyzed += 1
                if not got_source:
                    bytecode_only += 1

        flaws = sum(1 for f in findings if f.key in (
            "reentrancy", "integer_overflow", "access_control_flaw"))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"logic-analyzed {analyzed} contract address(es) "
            f"({bytecode_only} bytecode-only), {flaws} logic "
            "flaw(s) found")
        res.duration_ms = dur
        return res

    # -- target collection (mirrors contract_recon / drain) ------------
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

    # -- per-address analysis ------------------------------------------
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
        rpc_all_failed = True
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await chain_data.get_code(ctx, chain, addr)
            if code is None:
                continue
            rpc_all_failed = False
            if code == "0x" or len(code) < 4:
                continue
            pairs += 1
            if await self._scan_on_chain(ctx, key, chain, addr, code,
                                         findings):
                got_source = True
            if chain_hint:
                break
        if pairs == 0 and rpc_all_failed:
            findings.append(self._f(
                "web3", "contract_logic_failed",
                f"MEDIUM: {addr}: DEGRADED - every public RPC endpoint "
                "failed, so no chain data could be retrieved. "
                "No conclusion drawn.",
                source="public JSON-RPC eth_getCode",
                confidence=60, passive=True,
                evidence={"severity": "medium", "address": addr,
                          "remediation": "Retry later; the public "
                                         "RPC endpoints for this "
                                         "chain were unreachable."}))
        return pairs, got_source

    async def _scan_on_chain(self, ctx: Ctx, key: Optional[str],
                             chain: cc.ChainConfig, addr: str,
                             code_hex: str,
                             findings: List[Finding]) -> bool:
        ctx.publish("chain_contracts", {
            "address": addr, "chain": chain.id,
            "is_contract": True, "verified": False, "name": ""})

        src = await chain_data.get_source(ctx, chain, addr, key)

        res = {"implementation": "", "via": "", "beacon": ""}
        try:
            res = await chain_data.get_implementation(
                ctx, chain, addr, code_hex,
                {"implementation": (src or {}).get("implementation", "")})
        except Exception:
            pass
        impl = res.get("implementation") or ""
        role = "proxy_shell" if impl else "standalone"
        got = self._analyze_contract(chain, addr, src, code_hex,
                                     findings, role=role,
                                     impl_addr=impl)
        if not impl:
            return got

        impl_code = None
        impl_src = None
        try:
            impl_code = await chain_data.get_code(ctx, chain, impl)
            impl_src = await chain_data.get_source(
                ctx, chain, impl, key)
        except Exception:
            impl_code, impl_src = None, None
        if not impl_code or impl_code == "0x" or len(impl_code) < 4:
            return got
        return self._analyze_contract(chain, impl, impl_src,
                                      impl_code, findings,
                                      role="implementation",
                                      proxy_addr=addr) or got

    def _analyze_contract(self, chain: cc.ChainConfig, addr: str,
                          src: Optional[Dict[str, Any]],
                          code_hex: str,
                          findings: List[Finding], role: str,
                          proxy_addr: str = "",
                          impl_addr: str = "") -> bool:
        """Analyze one contract: verified source when available,
        else the bytecode heuristic lane. Returns True when
        verified source was analyzed."""
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

        if not src:
            for item in analyze_logic_bytecode(code_hex):
                ev = dict(base_ev)
                ev.update({
                    "severity": item["severity"],
                    "check": item["kind"],
                    "logic_kind": item["logic_kind"],
                    "detail": item["detail"],
                    "bytecode_only": True,
                    "remediation": _REMEDIATIONS[item["kind"]],
                })
                # Bytecode lane v2 fields: per-selector
                # attribution, walked-path opcodes, storage
                # slots, inert probe sketches, and the EIP-1167
                # implementation when the target is a minimal
                # proxy. Legacy aggregate findings carry none of
                # these and keep their exact old evidence shape.
                for field in ("function", "selector", "signature",
                              "opcodes", "sensitive_opcodes",
                              "storage_reads", "storage_writes",
                              "selector_paths", "probe_sketches",
                              "minimal_proxy_impl"):
                    if field in item:
                        ev[field] = item[field]
                findings.append(self._f(
                    "web3", item["kind"],
                    f"{item['severity'].upper()}: Bytecode "
                    f"heuristic: contract {addr} on "
                    f"{chain.name} has risky opcodes and no "
                    f"verified source to audit{tag}\n\n"
                    f"{item['detail']}",
                    source="contract logic analyzer (bytecode)",
                    source_url=url, confidence=40, passive=True,
                    evidence=ev))
            return False

        version = solc_version(src["source"],
                               src.get("compiler", ""))
        for item in analyze_logic_source(
                src["source"], src.get("compiler", ""),
                contract_name=src.get("contract_name", "")):
            sev_word = item["severity"].upper()
            ev = dict(base_ev)
            ev.update({
                "severity": item["severity"],
                "check": item["kind"],
                "logic_kind": item["logic_kind"],
                "function": item["function"],
                "code": item["code"],
                "detail": item["detail"],
                "bytecode_only": False,
                "solc_version": ".".join(map(str, version))
                if version else "",
                "source_origin": src.get("origin", ""),
                "contract_name": src.get("contract_name", ""),
                "remediation": _REMEDIATIONS[item["kind"]],
            })
            if item["kind"] == "access_control_flaw":
                ev["gated"] = False
                ev["ungated_basis"] = _UNGATED_BASIS
            if item.get("report_class"):
                # FP fix 4: trigger_only findings are emitted at
                # low severity and are NOT candidate-grade.
                ev["report_class"] = item["report_class"]
                ev["recipient"] = item.get("recipient", "")
            if item.get("path"):
                ev["path"] = item["path"]
            if item.get("guards") is not None:
                ev["guards"] = item["guards"]
            findings.append(self._f(
                "web3", item["kind"],
                f"{sev_word}: {item['logic_kind'].replace('_', ' ')}"
                f": function '{item['function']}' in contract "
                f"{addr} on {chain.name}{tag}\n\n"
                f"Code:\n{item['code']}",
                source="contract logic analyzer",
                source_url=url,
                confidence=85 if item["severity"] == "high" else 65,
                passive=True, evidence=ev))
        return True
