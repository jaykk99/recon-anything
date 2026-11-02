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


def analyze_logic_source(src: str, compiler: str = ""
                         ) -> List[Dict[str, Any]]:
    """Static logic analysis over verified Solidity source.

    Returns finding dicts {kind, logic_kind, severity, function,
    code, detail}. Detection only - nothing here interacts with
    the contract.
    """
    clean = cc._strip_comments(src)
    version = solc_version(clean, compiler)
    state = state_variables(clean)
    # Pre-0.5 contracts name their constructor after the contract
    # itself; those functions run once, at deploy time, with
    # deployer-supplied arguments - not live logic. (USDT's
    # RequestToken-style hit in the 2026-11-02 live smoke was
    # exactly this shape.)
    contract_names = set(re.findall(r"\bcontract\s+([A-Za-z_]\w*)",
                                    clean))
    out: List[Dict[str, Any]] = []
    fns = [fn for fn in cc.extract_functions(clean) if fn["name"]
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
        gated = cd._is_gated(sig, text)
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
            late = [(p, v) for p, v in writes
                    if p > first_call["pos"]]
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
        # the drain analyzer.
        if not gated and version is not None and version < (0, 8, 0):
            if not re.search(r"\b internal \b|\b private \b", sig):
                for pos, var, _op in _overflow_ops(text, state,
                                                   params):
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
            for _pos, var, _op in _overflow_ops(block, state, params):
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
            out.append({
                "kind": "access_control_flaw",
                "logic_kind": "ungated_sensitive_function",
                "severity": "high",
                "function": name,
                "code": cc._snip(text),
                "detail": (
                    f"sensitive function '{name}' performs its "
                    "action with NO access gate (gated=False; "
                    f"{_UNGATED_BASIS}). signature: {sig[:200]}"),
            })

    # ---- cross-function reentrancy hints ----------------------------
    if writes_after_call:
        for fn in fns:
            name, sig, text = fn["name"], fn["signature"], fn["text"]
            if "{" not in text or re.search(r"\b(view|pure)\b", sig):
                continue
            if cd._is_gated(sig, text) or "nonReentrant" in text:
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
                    f"MEDIUM: {addr}: logic analysis failed - chain "
                    "data could not be retrieved (explorers/RPC "
                    "unreachable). No conclusion drawn.",
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
            code = await cc.rpc_get_code(ctx, chain, addr)
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
                f"MEDIUM: {addr}: every public RPC endpoint failed, "
                "so no chain data could be retrieved. No conclusion "
                "drawn.",
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

        src = await cc.fetch_verified_source(ctx, chain, addr, key)

        res = {"implementation": "", "via": "", "beacon": ""}
        try:
            res = await cc.resolve_implementation(
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
            impl_code = await cc.rpc_get_code(ctx, chain, impl)
            impl_src = await cc.fetch_verified_source(
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
        for item in analyze_logic_source(src["source"],
                                         src.get("compiler", "")):
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
