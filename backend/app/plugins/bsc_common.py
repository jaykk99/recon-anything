"""Shared engine for the 100 BSC/BNB vulnerability detectors.

Jay's Nov 3 order: 100 named vulnerability-detection plugins for
the BNB Chain surface (BEP-20 tokens, PancakeSwap, Venus/lending,
MasterChef staking, governance, proxies, access control, GameFi /
NFTs, MEV / bridges, core math). Each ID is its own registered
plugin with its own pattern set and its own finding type (the
finding key IS the plugin id). This module is the shared routine
they are built on:

- Scope, gate detection, recipient classification and the solc
  version read are IMPORTED from contract_logic / crypto_drain -
  the same false-positive discipline as PR #78 (gated functions,
  CEI ordering, bounds checks, SafeMath / 0.8 checked math,
  trigger-only reclassification under the receive rule).
- A detector is data (DetectorSpec): name/function filters,
  required patterns, absent patterns, suppressors, an optional
  version gate (pre-0.8 or unchecked{} only), an optional CEI
  ordering requirement, or a named custom check for the handful
  of detectors whose logic is not regex-shaped (call-argument
  inspection, storage-layout pairing, CREATE2 / fallback
  routing, decimal/scale comparison, arbitrary-call receiver
  analysis).
- Dedupe: no two of the 100 share a pattern set; where an older
  plugin already covers the generic class, the BSC detector is
  the BSC-specific variant (PancakeSwap / Venus / MasterChef
  constants and interfaces) or runs the shared routine restricted
  to its own pattern (recorded per detector as outcome a/b/c in
  each family module's SPECS and in the PR body).

Detection only, static verified-source analysis in the fast
lane, exactly like contract_logic: never sends a transaction,
never calls the contract; the deepest access is eth_getCode,
public explorer source reads, and proxy implementation
resolution. Unverified source -> a skip note, never a guess.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import chain_data
from . import crypto_drain as cd
from . import contract_logic as cl

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4

# Known-good PancakeSwap routers (misdirection detector allowlist).
PANCAKE_ROUTERS = {
    "0x10ed43c718714eb63d5aa57b78b54704e256024e",  # V2 router
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4",  # V2 router (legacy)
    "0x1b81d678ffb9c0263b24a97847620c99d213eb14",  # V3 SmartRouter
}

FAMILY_FIX = {
    "bep20": "Bring the token in line with the BEP-20 reference "
             "behavior and re-audit the flagged function; BNB "
             "Chain tokens are routinely forked, so check every "
             "fork of the same code.",
    "pancake": "Follow the PancakeSwap integration reference "
               "(official router/factory addresses, TWAP oracles, "
               "non-zero slippage bounds) and re-check the flagged "
               "call path.",
    "lending": "Follow the Venus/Compound integration checks "
               "(comptroller hooks, accrue-before-read, bounded "
               "incentives) and re-audit the flagged function.",
    "staking": "Follow the canonical MasterChef accounting "
               "(accrue before paying, zero user state before "
               "transfers, balance-delta crediting) and re-audit "
               "the flagged function.",
    "governance": "Follow the OpenZeppelin Governor / Timelock "
                  "reference (snapshot voting power, enforced "
                  "delay, state-gated execution) and re-audit "
                  "the flagged function.",
    "proxy": "Follow the EIP-1967 / OpenZeppelin upgradeable "
             "reference (namespaced slots, locked initializers, "
             "gated upgrades) and re-audit the flagged code.",
    "access": "Follow the OpenZeppelin AccessControl / ECDSA "
              "reference (role-admin gating, EIP-712 domains, "
              "nonce-bound signatures) and re-audit the flagged "
              "function.",
    "gamefi": "Follow the OpenZeppelin ERC721/1155 and "
              "marketplace reference patterns (CEI, order "
              "validation, VRF randomness) and re-audit the "
              "flagged function.",
    "mev_bridge": "Follow the bridge / DEX integration reference "
                  "(validator quorum with signer dedup, bound "
                  "recipients, slippage parameters) and re-audit "
                  "the flagged function.",
    "math_system": "Use checked math helpers (SafeCast, "
                   "SafeMath-era patterns), freshness-checked "
                   "oracles and call-based ETH transfers, then "
                   "re-audit the flagged function.",
}


@dataclass
class DetectorSpec:
    id: str
    family: str
    severity: str = "medium"          # high | medium | low
    outcome: str = "a"                # a new | b BSC variant | c shared
    scope: str = "function"           # function | contract
    fn_re: str = ""
    fn_exclude_re: str = ""
    need: Tuple[str, ...] = ()
    need_any: Tuple[str, ...] = ()
    need_absent: Tuple[str, ...] = ()
    forbid: Tuple[str, ...] = ()
    forbid_all: Tuple[str, ...] = ()
    contract_need: Tuple[str, ...] = ()
    contract_need_any: Tuple[str, ...] = ()
    contract_forbid: Tuple[str, ...] = ()
    gated_suppresses: bool = False
    include_view: bool = False
    public_only: bool = False
    version_gate: str = ""            # "" | "pre080_or_unchecked"
    cei: bool = False
    custom: str = ""
    custom_data: Dict[str, Any] = field(default_factory=dict)
    recipient: bool = False
    detail: str = ""
    fix: str = ""

    def __post_init__(self) -> None:
        # A pattern field given as a bare string means ONE
        # pattern, not an iterable of characters.
        for name in ("need", "need_any", "need_absent", "forbid",
                     "forbid_all", "contract_need",
                     "contract_need_any", "contract_forbid"):
            val = getattr(self, name)
            if isinstance(val, str):
                setattr(self, name, (val,))

    @property
    def label(self) -> str:
        words = self.id.replace("_", " ").split()
        pretty = []
        acronyms = {"bep20": "BEP-20", "bep721": "BEP-721",
                    "bep1155": "BEP-1155", "ecdsa": "ECDSA",
                    "mev": "MEV", "lp": "LP", "nft": "NFT"}
        for w in words:
            pretty.append(acronyms.get(w, w.capitalize()))
        return " ".join(pretty)

    @property
    def class_name(self) -> str:
        return "".join(w.capitalize() for w in self.id.split("_")) \
            + "Plugin"


def S(spec_id: str, family: str, **kw: Any) -> DetectorSpec:
    return DetectorSpec(id=spec_id, family=family, **kw)


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _all(pats: Tuple[str, ...], text: str) -> bool:
    return all(re.search(p, text) for p in pats)


def _any(pats: Tuple[str, ...], text: str) -> bool:
    return any(re.search(p, text) for p in pats)


def _version_ok(spec: DetectorSpec, text: str,
                version: Optional[Tuple[int, ...]]) -> bool:
    if not spec.version_gate:
        return True
    if "unchecked" in text:
        return True
    return version is not None and version < (0, 8, 0)


def _cei_hit(fn: Dict[str, Any], state: set) -> bool:
    """External call executes before a later state write (CEI
    violation), the contract_logic reentrancy shape reduced to a
    boolean for the BSC detectors that need ordering."""
    text = fn["text"]
    calls = cl._external_calls(text)
    if not calls:
        return False
    first = calls[0]["pos"]
    written_before = {v for p, v in cl._state_writes(text, state)
                      if p < first}
    return any(p > first and v not in written_before
               for p, v in cl._state_writes(text, state))


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code,
            "detail": detail}


def _finish(spec: DetectorSpec, item: Dict[str, Any],
            fn_text: str) -> Dict[str, Any]:
    if spec.recipient and fn_text:
        recipient, rdetail = cl.classify_recipient(fn_text)
        item["recipient"] = recipient
        if recipient in ("FIXED", "HOLDER-SELF"):
            item["report_class"] = "trigger_only"
            item["severity"] = "low"
            item["detail"] += (
                f" Recipient analysis: moved value lands at a "
                f"{recipient} destination ({rdetail}), so a "
                "stranger can trigger this but receives nothing - "
                "classified TRIGGER-ONLY under the receive rule.")
        else:
            item["report_class"] = "candidate"
    return item


# ---------------------------------------------------------------------------
# Generic spec-driven analysis
# ---------------------------------------------------------------------------

def analyze_bsc_source(src: str, spec: DetectorSpec,
                       compiler: str = "", contract_name: str = ""
                       ) -> List[Dict[str, Any]]:
    """Run ONE detector spec over verified source. Returns finding
    dicts {kind(=spec.id), severity, function, code, detail}."""
    if spec.custom:
        fn = _CUSTOMS.get(spec.custom)
        if fn is None:
            return []
        return fn(src, spec, compiler, contract_name)

    scope = cl._Scope(src, contract_name)
    scoped = scope.scoped_text
    if not _all(spec.contract_need, scoped):
        return []
    if spec.contract_need_any and \
            not _any(spec.contract_need_any, scoped):
        return []
    if _any(spec.contract_forbid, scoped):
        return []

    clean = cc._strip_comments(src)
    version = cl.solc_version(clean, compiler)
    detail = spec.detail

    if spec.scope == "contract":
        if not _all(spec.need, scoped):
            return []
        if spec.need_any and not _any(spec.need_any, scoped):
            return []
        if _any(spec.forbid, scoped):
            return []
        if spec.need_absent and _any(spec.need_absent, scoped):
            return []
        if spec.forbid_all and _all(spec.forbid_all, scoped):
            return []
        m = None
        for p in spec.need:
            m = re.search(p, scoped)
            if m:
                break
        code = cc._snip(scoped[m.start():] if m else scoped)
        return [_finish(spec, _hit(spec, "", code, detail), "")]

    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    seen_fns = set()
    for fn in scope.functions:
        name = fn["name"]
        if not name or name == "constructor" or name in seen_fns:
            continue
        text = fn["text"]
        if "{" not in text:
            continue
        sig = fn["signature"]
        if not spec.include_view and \
                re.search(r"\b(view|pure)\b", sig):
            continue
        if spec.public_only and \
                not re.search(r"\b(public|external)\b", sig):
            continue
        if spec.fn_re and not re.search(spec.fn_re, name, re.I):
            continue
        if spec.fn_exclude_re and \
                re.search(spec.fn_exclude_re, name, re.I):
            continue
        if not _version_ok(spec, text, version):
            continue
        if not _all(spec.need, text):
            continue
        if spec.need_any and not _any(spec.need_any, text):
            continue
        if _any(spec.forbid, text):
            continue
        if spec.need_absent and _any(spec.need_absent, text):
            continue
        if spec.forbid_all and _all(spec.forbid_all, text):
            continue
        if spec.gated_suppresses and cl._gated_deep(fn, scope):
            continue
        if spec.cei and not _cei_hit(fn, state):
            continue
        seen_fns.add(name)
        out.append(_finish(spec, _hit(spec, name, cc._snip(text),
                                      detail), text))
    return out


# ---------------------------------------------------------------------------
# Custom checks (logic that is not regex-shaped)
# ---------------------------------------------------------------------------

def _scope_and_fns(src: str, contract_name: str):
    scope = cl._Scope(src, contract_name)
    return scope, [fn for fn in scope.functions if "{" in fn["text"]]


def _custom_decimal_mismatch(src, spec, compiler, contract_name):
    scope, _ = _scope_and_fns(src, contract_name)
    scoped = scope.scoped_text
    m = re.search(r"function\s+decimals\s*\([^)]*\)[^{]*\{[^}]*?"
                  r"return\s+(\d+)\s*;", scoped)
    if not m:
        m = re.search(r"uint8\s+(?:public\s+)?(?:_)?decimals\s*=\s*"
                      r"(\d+)\s*;", scoped)
    if not m:
        return []
    dec = int(m.group(1))
    exps = {int(x) for x in
            re.findall(r"10\s*\*\*\s*(\d+)", scoped)}
    exps |= {18 for _ in re.findall(r"\b1e18\b", scoped)}
    # Only true decimal-scale constants count: sub-9 exponents
    # are fee / threshold math (1e5-style bounds), not decimal
    # scaling, and a constant within a few orders of decimals()
    # is ordinary unit math.
    bad = sorted(e for e in exps
                 if e != dec and e >= 9 and abs(e - dec) >= 6)
    if not bad:
        return []
    return [_hit(spec, "decimals", cc._snip(scoped[m.start():]),
                 spec.detail +
                 f" Observed: decimals() = {dec} but scaling "
                 f"constants 10**{bad} are used in the same token.")]


def _custom_router_misdirection(src, spec, compiler, contract_name):
    scope, fns = _scope_and_fns(src, contract_name)
    scoped = scope.scoped_text
    if not re.search(r"swapExact|IPancakeRouter|PancakeRouter|"
                     r"swap\w*For\w*\s*\(", scoped):
        return []
    out = []
    for m in re.finditer(r"(\w*[Rr]outer\w*)\s*=\s*(0x[0-9a-fA-F]{40})",
                         scoped):
        if m.group(2).lower() not in PANCAKE_ROUTERS:
            out.append(_hit(
                spec, "", cc._snip(scoped[m.start():]),
                spec.detail +
                f" Observed: router variable '{m.group(1)}' is "
                f"bound to {m.group(2)}, which is not a known "
                "PancakeSwap router address."))
    for fn in fns:
        if re.search(r"set\w*[Rr]outer|set\w*Router", fn["name"]) and \
                re.search(r"[Rr]outer\w*\s*=\s*\w+", fn["text"]) and \
                not cl._gated_deep(fn, scope):
            out.append(_finish(spec, _hit(
                spec, fn["name"], cc._snip(fn["text"]), spec.detail +
                " Observed: an ungated setter rewrites the router "
                "address used for swaps."), fn["text"]))
    return out


def _call_sites(text: str, calls: Dict[str, Tuple[int, ...]]):
    for name, idxs in calls.items():
        for m in re.finditer(r"\." + re.escape(name) + r"\s*\(",
                             text):
            paren = m.end() - 1
            end = cd._matching(text, paren)
            yield name, idxs, cd._split_top(text[paren + 1:end]), \
                m.start()


def _arg_is_zero(arg: str, text: str) -> bool:
    a = arg.strip()
    if a == "0":
        return True
    if re.fullmatch(r"[A-Za-z_]\w*", a):
        return re.search(r"\b" + re.escape(a) + r"\s*=\s*0\s*;",
                         text) is not None
    return False


def _custom_call_args_zero(src, spec, compiler, contract_name):
    """addLiquidity / removeLiquidity / swap* called with a literal
    (or zero-assigned) minimum-out argument."""
    scope, fns = _scope_and_fns(src, contract_name)
    calls = spec.custom_data["calls"]
    out = []
    for fn in fns:
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        for cname, idxs, args, _pos in _call_sites(fn["text"],
                                                   calls):
            if len(args) <= max(idxs):
                continue
            if all(_arg_is_zero(args[i], fn["text"]) for i in idxs):
                out.append(_finish(spec, _hit(
                    spec, fn["name"], cc._snip(fn["text"]),
                    spec.detail +
                    f" Observed: {cname}() is called with "
                    f"minimum-out argument(s) {list(idxs)} set to "
                    "0."), fn["text"]))
                break
    return out


def _custom_swap_amount_underflow(src, spec, compiler, contract_name):
    scope, fns = _scope_and_fns(src, contract_name)
    clean = cc._strip_comments(src)
    version = cl.solc_version(clean, compiler)
    out = []
    for fn in fns:
        text = fn["text"]
        if not re.search(r"\.swap\w*\s*\(", text):
            continue
        if re.search(r"require\s*\([^)]*(>=|<=|>|<)", text) and \
                re.search(r"balanceOf|balance", text):
            continue
        unchecked = "unchecked" in text
        pre = version is not None and version < (0, 8, 0)
        if not (unchecked or pre):
            continue
        derived = False
        for am in re.finditer(r"=\s*([^;]+);", text):
            rhs = am.group(1)
            if "balanceOf" in rhs and \
                    re.search(r"\)\s*-|\w\s*-", rhs):
                derived = True
                break
        if derived:
            out.append(_hit(
                spec, fn["name"], cc._snip(text), spec.detail +
                " Observed: the swap amount is derived by raw "
                "subtraction in unchecked/pre-0.8 arithmetic with "
                "no balance bound checked first."))
    return out


def _contract_bodies(src: str, contract_name: str):
    """(span, body_text) per contract in the scoped compilation."""
    scope = cl._Scope(src, contract_name)
    out = []
    for unit_src in [scope.scoped_text]:
        for span in cl._contract_spans(cc._strip_comments(unit_src)):
            out.append((span, unit_src[span["start"]:span["end"]]))
    return out


def _custom_storage_collision(src, spec, compiler, contract_name):
    scope, _ = _scope_and_fns(src, contract_name)
    scoped = scope.scoped_text
    if "delegatecall(" not in scoped:
        return []
    m = re.search(r"address\s+(?:public\s+|private\s+|internal\s+)?"
                  r"implementation\s*;", scoped)
    if not m:
        m = re.search(r"address\s+(?:public\s+|private\s+|internal"
                  r"\s+)?admin\s*;", scoped)
    if not m:
        return []
    return [_hit(spec, "", cc._snip(scoped[m.start():]),
                 spec.detail +
                 " Observed: the proxy keeps its implementation/"
                 "admin pointer in an ordinary state variable "
                 "(slot-ordered storage) while delegatecalling.")]


def _custom_shadow_var(src, spec, compiler, contract_name):
    bodies = _contract_bodies(src, contract_name)
    watched = {"owner", "admin", "implementation", "_owner",
               "_admin", "governor", "controller"}
    proxy_bodies = [b for _s, b in bodies if "delegatecall(" in b]
    others = [b for _s, b in bodies if "delegatecall(" not in b]
    for pb in proxy_bodies:
        pvars = cl.state_variables(pb) & watched
        for ob in others:
            clash = pvars & (cl.state_variables(ob) & watched)
            if clash:
                return [_hit(spec, "", cc._snip(pb[:800]),
                             spec.detail +
                             f" Observed: variable(s) "
                             f"{sorted(clash)} are declared in both "
                             "the proxy and the implementation, so "
                             "they share storage slots.")]
    return []


def _custom_function_clash(src, spec, compiler, contract_name):
    bodies = _contract_bodies(src, contract_name)
    by_name: Dict[str, int] = {}
    proxy_names = set()
    for span, body in bodies:
        head = body.lstrip()[:80]
        if re.match(r"(?:abstract\s+)?(library|interface)\b",
                    head):
            continue  # libraries/interfaces define no selectors
        names = set()
        for fn in cl._extract_functions_pos(
                cc._strip_comments(body)):
            # Selector clashes only exist for externally
            # reachable functions; internal helpers sharing a
            # name across a flattened bundle are ordinary
            # inheritance, not clashes.
            if fn["name"] and re.search(
                    r"\b(external|public)\b", fn["signature"]):
                names.add(fn["name"])
        if "delegatecall(" in body:
            proxy_names |= names
        for n in names:
            by_name[n] = by_name.get(n, 0) + 1
    clashes = sorted(n for n in proxy_names
                     if by_name.get(n, 0) > 1
                     and n not in ("fallback", "constructor",
                                   "receive"))
    if not clashes:
        return []
    scope, _ = _scope_and_fns(src, contract_name)
    return [_hit(spec, clashes[0], cc._snip(scope.scoped_text),
                 spec.detail +
                 f" Observed: function name(s) {clashes} are "
                 "defined on both the proxy and another contract "
                 "in the same compilation.")]


def _custom_transparent_fallback(src, spec, compiler, contract_name):
    scope, _ = _scope_and_fns(src, contract_name)
    scoped = scope.scoped_text
    m = re.search(r"fallback\s*\([^)]*\)[^{]*\{", scoped)
    if not m:
        return []
    body = scoped[m.start():]
    body = body[:cl._brace_span(body, body.index("{"))]
    if "delegatecall(" not in body:
        return []
    if not re.search(r"\badmin\b", scoped):
        return []  # no admin concept: not a transparent proxy
    # Admin routing counts only when it happens on the fallback
    # path itself (the transparent-proxy separation point); an
    # admin check on some OTHER function does not route calls.
    if re.search(r"ifAdmin|msg\.sender\s*==\s*\w*[Aa]dmin|"
                 r"\w*[Aa]dmin\s*==\s*msg\.sender|onlyAdmin",
                 body):
        return []
    if not re.search(r"upgrade|implementation", scoped):
        return []
    return [_hit(spec, "fallback", cc._snip(body), spec.detail)]


def _custom_arbitrary_call(src, spec, compiler, contract_name):
    scope, fns = _scope_and_fns(src, contract_name)
    if spec.contract_need and \
            not _all(spec.contract_need, scope.scoped_text):
        return []
    if spec.contract_forbid and \
            _any(spec.contract_forbid, scope.scoped_text):
        return []
    out = []
    for fn in fns:
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if spec.fn_re and not re.search(spec.fn_re, fn["name"],
                                        re.I):
            continue
        if _any(spec.forbid, fn["text"]):
            continue
        if cl._gated_deep(fn, scope):
            continue
        params = cd._param_names(fn["signature"])
        text = fn["text"]
        fired = False
        for kind, pat in cl._CALL_RES:
            if kind not in ("call", "delegatecall", "callcode"):
                continue
            for m in pat.finditer(text):
                recv = cd._unwrap(cd._expr_before(text, m.start()))
                if cd._caller_controlled(recv, params):
                    fired = True
                    break
            if fired:
                break
        if fired:
            out.append(_finish(spec, _hit(
                spec, fn["name"], cc._snip(text), spec.detail),
                text))
    return out


def _custom_safe_mint_cei(src, spec, compiler, contract_name):
    scope, fns = _scope_and_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out = []
    for fn in fns:
        if not re.search(spec.fn_re, fn["name"], re.I):
            continue
        if fn["name"] in ("_safeMint", "_mint", "safeTransfer",
                          "_safeTransfer"):
            continue  # the helper itself is not a call site
        text = fn["text"]
        if "nonReentrant" in text or "nonReentrant" in \
                fn["signature"]:
            continue
        brace = text.find("{")
        m = re.search(r"_safeMint\s*\(|safeTransfer\s*\(",
                      text[brace:] if brace >= 0 else text)
        if not m:
            continue
        mstart = (brace if brace >= 0 else 0) + m.start()
        late = [(p, v) for p, v in cl._state_writes(text, state)
                if p > mstart]
        inc = re.search(r"\+\+|\+=\s*1", text[mstart:])
        if late or inc:
            out.append(_hit(spec, fn["name"], cc._snip(text),
                            spec.detail))
    return out


def _custom_signed_unsigned(src, spec, compiler, contract_name):
    scope, fns = _scope_and_fns(src, contract_name)
    scoped = scope.scoped_text
    int_vars = set(re.findall(
        r"\bint\d*\s+(?:public\s+|private\s+|internal\s+)?"
        r"([A-Za-z_]\w*)\s*(?:=[^;]*)?;", scoped))
    if not int_vars:
        return []
    out = []
    for fn in fns:
        for v in int_vars:
            if re.search(r"uint\d*\s*\(\s*" + re.escape(v) +
                         r"\s*\)", fn["text"]):
                out.append(_hit(spec, fn["name"],
                                cc._snip(fn["text"]), spec.detail +
                                f" Observed: signed variable '{v}' "
                                "is cast to an unsigned type."))
                break
    return out


def _custom_asymmetric_lock(src, spec, compiler, contract_name):
    scope, fns = _scope_and_fns(src, contract_name)
    scoped = scope.scoped_text
    locks = set(re.findall(
        r"\b(last\w*Block|cooldown\w*|lockEnd\w*|lastTrade\w*|"
        r"tradeLock\w*)\b", scoped))
    if not locks:
        return []
    movers = [fn for fn in fns
              if re.search(r"transfer|sell|buy|swap", fn["name"],
                           re.I)
              and re.search(r"balances?\s*\[|_transfer|transfer\s*\(",
                            fn["text"])]
    checked = [fn for fn in movers
               if any(re.search(re.escape(l), fn["text"])
                      for l in locks)]
    unchecked_fns = [fn for fn in movers
                     if fn not in checked]
    if checked and unchecked_fns:
        fn = unchecked_fns[0]
        return [_hit(spec, fn["name"], cc._snip(fn["text"]),
                     spec.detail +
                     f" Observed: lock variable(s) {sorted(locks)}"
                     f" are enforced in "
                     f"{[f['name'] for f in checked]} but not in "
                     f"'{fn['name']}'.")]
    return []


def _custom_victim_slippage(src, spec, compiler, contract_name):
    """Victim-side sandwich surface: a swap function whose API
    gives the caller NO slippage parameter, while the router
    call's minimum-out is some fixed internal value. Literal-0
    minimums are owned by the PancakeSwap slippage detector and
    are skipped here so the two never fire on the same call."""
    scope, fns = _scope_and_fns(src, contract_name)
    calls = spec.custom_data["calls"]
    out = []
    for fn in fns:
        if not re.search(r"swap|trade|rebalance", fn["name"],
                         re.I):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        sig = fn["signature"]
        i = sig.find("(")
        params_txt = sig[i:cd._matching(sig, i) + 1] if i >= 0 \
            else ""
        if re.search(r"min|slippage", params_txt, re.I):
            continue
        for cname, idxs, args, _pos in _call_sites(fn["text"],
                                                   calls):
            if len(args) <= max(idxs):
                continue
            min_arg = args[idxs[0]].strip()
            if min_arg == "0":
                continue  # literal-zero lane (pancake detector)
            out.append(_hit(spec, fn["name"], cc._snip(fn["text"]),
                            spec.detail +
                            f" Observed: {cname}() is called "
                            f"with minimum-out fixed internally "
                            f"as '{min_arg}' and the function "
                            "accepts no slippage parameter."))
            break
    return out


_CUSTOMS = {
    "victim_slippage": _custom_victim_slippage,
    "decimal_mismatch": _custom_decimal_mismatch,
    "router_misdirection": _custom_router_misdirection,
    "call_args_zero": _custom_call_args_zero,
    "swap_amount_underflow": _custom_swap_amount_underflow,
    "storage_collision": _custom_storage_collision,
    "shadow_var": _custom_shadow_var,
    "function_clash": _custom_function_clash,
    "transparent_fallback": _custom_transparent_fallback,
    "arbitrary_call": _custom_arbitrary_call,
    "safe_mint_cei": _custom_safe_mint_cei,
    "signed_unsigned": _custom_signed_unsigned,
    "asymmetric_lock": _custom_asymmetric_lock,
}


# ---------------------------------------------------------------------------
# Plugin base + factory
# ---------------------------------------------------------------------------

class BscDetectorPlugin(Plugin):
    """One registered plugin per DetectorSpec. run() mirrors
    contract_logic's collection / source fetch / proxy resolution;
    the analysis itself is analyze_bsc_source with this plugin's
    own spec only."""
    id = ""
    label = "BSC Detector"
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
        degraded = 0
        pairs_done = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs, got, deg = await self._scan_address(
                    ctx, key, chain_hint, addr, findings)
            except Exception:
                pairs, got, deg = 0, False, False
            pairs_done += pairs
            if pairs:
                analyzed += 1
                if not got:
                    no_source += 1
            elif deg:
                degraded += 1
        dur = int((time.monotonic() - t0) * 1000)
        hits = sum(1 for f in findings if f.key == spec.id)
        if analyzed == 0 and degraded:
            # Every route failed: say DEGRADED, never let this read
            # as a clean run (the Nov 3 silent-skip failure shape).
            res = self._degraded(
                f"DEGRADED: {spec.id}: chain data unavailable for "
                f"{degraded} contract address(es) - every RPC/source "
                f"route failed, so nothing was analyzed and the "
                f"contract is NOT cleared")
            res.findings = findings
            res.duration_ms = dur
            return res
        res = self._ok(
            findings,
            f"{spec.id}: analyzed {analyzed} contract address(es) "
            f"({no_source} without verified source - not analyzed, "
            f"not cleared; {degraded} degraded - chain data "
            f"unavailable), {hits} finding(s)")
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
                            ) -> Tuple[int, bool, bool]:
        if chain_hint:
            chain_ids = [chain_hint]
        else:
            chain_ids = ["bsc"] + [c for c in
                                   cc.DEFAULT_CHAIN_ORDER
                                   if c != "bsc"]
        pairs = 0
        got_source = False
        degraded = False
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await chain_data.get_code(ctx, chain, addr)
            if code is None:
                # Every RPC route for this chain failed (shared
                # layer status: degraded). Distinct from "0x",
                # which means the address genuinely holds no code.
                degraded = True
                continue
            if code == "0x" or len(code) < 4:
                continue
            pairs += 1
            if await self._scan_on_chain(ctx, key, chain, addr,
                                         code, findings):
                got_source = True
            if chain_hint:
                break
        return pairs, got_source, degraded

    async def _scan_on_chain(self, ctx: Ctx, key: Optional[str],
                             chain: cc.ChainConfig, addr: str,
                             code_hex: str,
                             findings: List[Finding]) -> bool:
        src = await chain_data.get_source(ctx, chain, addr, key)
        res = {"implementation": "", "via": "", "beacon": ""}
        try:
            res = await chain_data.get_implementation(
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
            impl_code = await chain_data.get_code(ctx, chain, impl)
            impl_src = await chain_data.get_source(
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
        for item in analyze_bsc_source(
                src["source"], spec, src.get("compiler", ""),
                contract_name=src.get("contract_name", "")):
            ev = dict(base_ev)
            ev.update({
                "severity": item["severity"],
                "check": spec.id,
                "detector_outcome": spec.outcome,
                "function": item["function"],
                "code": item["code"],
                "detail": item["detail"],
                "bytecode_only": False,
                "source_origin": src.get("origin", ""),
                "contract_name": src.get("contract_name", ""),
                "remediation": spec.fix or
                FAMILY_FIX.get(spec.family, ""),
            })
            if item.get("report_class"):
                ev["report_class"] = item["report_class"]
                ev["recipient"] = item.get("recipient", "")
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="bsc detector (verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def build_plugin_class(spec: DetectorSpec) -> type:
    """Create the registered Plugin subclass for one spec."""
    cls = type(spec.class_name, (BscDetectorPlugin,), {
        "id": spec.id,
        "label": spec.label + " (BSC)",
        "_spec": spec,
        "description": (
            f"BSC/BNB detector for {spec.label.lower()}: "
            f"{spec.detail} Static verified-source analysis, "
            "fast lane, detection only."),
        "__module__": __name__,
    })
    return cls


def register_family(module_globals: Dict[str, Any],
                    specs: List[DetectorSpec]) -> None:
    """Assign one plugin class per spec into a family module's
    globals so registry.discover() picks them up."""
    for spec in specs:
        module_globals[spec.class_name] = build_plugin_class(spec)
