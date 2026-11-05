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
source exists, the runtime bytecode is disassembled through
contract_chain.analyze_bytecode and the presence of SELFDESTRUCT
/ DELEGATECALL / CALLCODE is reported at LOW severity and LOW
confidence, explicitly labeled a bytecode-only heuristic - never
as a confirmed logic flaw.

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
    re.compile(r"mapping\s*\([^)]*\)\s*"
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
                    self.functions.append(fn)
                    if re.search(r"\b(internal|private)\b",
                                 fn["signature"]):
                        self.helpers[fn["name"]] = fn
        self.scoped_text = "\n".join(texts)


def _gated_deep(fn: Dict[str, Any], scope: _Scope) -> bool:
    """Gate check over the function, its custom modifiers'
    DEFINITIONS, and the internal helpers it calls (FP fix 2:
    the gate may live one hop down the internal call path)."""
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
    return False


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
    r"(?P<method>transferFrom|safeTransferFrom|transfer|send|call)\s*"
    r"(?P<brace>\{[^}]*\})?\s*\(")
_RECIP_DIRECT = re.compile(r"(?P<fn>selfdestruct|_mint|mint|safeTransfer)\s*\(")


def _recip_destinations(code: str) -> List[str]:
    dests: List[str] = []
    for m in _RECIP_CALLS.finditer(code):
        recv, method = m.group("recv").strip(), m.group("method")
        paren = m.end() - 1
        args = cd._split_top(code[paren + 1:cd._matching(code, paren)])
        if method in ("transfer", "send"):
            dests.append(args[0] if len(args) >= 2 else recv)
        elif method == "call":
            dests.append(recv)
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


def _recip_class_expr(expr: str, params: List[str],
                      addr_params: List[str], locals_: Dict[str, str],
                      all_params: set) -> str:
    e = cd._unwrap(expr)
    # payable(X) is just a cast of X: classify the inner
    # expression (payable(operator) is the FIXED project wallet,
    # payable(to) is the helper's address parameter).
    pm = re.fullmatch(r"payable\s*\((.*)\)", e, re.S)
    if pm:
        return _recip_class_expr(pm.group(1), params, addr_params,
                                 locals_, all_params)
    # A nullary getter call (owner(), treasury(), ...) resolves to
    # whatever the contract stored - a fixed destination, never
    # caller-controlled.
    m = re.fullmatch(r"([A-Za-z_]\w*)\(\)", e)
    if m:
        e = m.group(1)
    if _RECIP_SENDER.search(e):
        return "SENDER"
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", e):
        return "FIXED"
    base = re.split(r"[.\[(]", e)[0].strip()
    if base in addr_params or base in params:
        return "CALLER-SUPPLIED"
    if base in locals_:
        return _recip_class_expr(locals_[base], params, addr_params,
                                 locals_, all_params)
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
    if not dests:
        return "UNRESOLVED", "no value destination found in function"
    classes = []
    for d in dests:
        c = _recip_class_expr(d, params, addr_params, locals_,
                              all_params)
        if c == "SENDER":
            c = "HOLDER-SELF" if _RECIP_SELF_METER.search(code) \
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
    for m in re.finditer(
            r"(\w+)\s*=\s*(?:_msgSender\s*\(\s*\)|"
            r"msg\.sender)\b", expanded):
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

        # ---- tx.origin authorization (any function) ---------------
        if re.search(r"tx\.origin\s*(==|!=)|(==|!=)\s*tx\.origin",
                     text):
            out.append({
                "kind": "access_control_flaw",
                "logic_kind": "tx_origin_auth",
                "severity": "high",
                "function": name,
                "code": cc._snip(text),
                "detail": (
                    "authorization compares tx.origin; any "
                    "contract the owner is tricked into calling "
                    "inherits the owner's identity. signature: "
                    f"{sig[:200]}"),
            })

        # ---- reentrancy: external call before state update --------
        calls = _external_calls(text)
        writes = _state_writes(text, state)
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
                    out.append({
                        "kind": "reentrancy",
                        "logic_kind": "cei_violation",
                        "severity": "high",
                        "function": name,
                        "code": cc._snip(text),
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
                    writes_after_call.setdefault(var, []).append(name)
                    break

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


def analyze_logic_bytecode(code_hex: str) -> List[Dict[str, Any]]:
    """Bytecode-only heuristic lane: risky opcode presence.

    Returns at most one finding dict, explicitly labeled a
    heuristic - opcode presence says a capability exists in the
    bytecode, never that a logic flaw is confirmed.
    """
    info = cc.analyze_bytecode(code_hex)
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
                findings.append(self._f(
                    "web3", item["kind"],
                    f"LOW: Bytecode heuristic: contract {addr} on "
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
