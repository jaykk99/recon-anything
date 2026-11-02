"""Zero-Day Candidate Hunter: contract guard consistency (EVM).

contract_recon inventories privileged functions against KNOWN
categories (mint, withdraw, pause...). This hunter needs no category
list: it learns the contract's OWN access-control convention from the
source and flags the functions that break it.

- Convention break: group the public/external state-changing
  functions by the guard patterns they use (onlyOwner-style
  modifiers, msg.sender equality checks, role checks, internal guard
  calls). When a contract's convention is clear - a dominant guard
  pattern, or most state-changing siblings guarded - any public
  state-changing function with NO guard at all is a candidate
  unknown access-control bug, quoted next to the sibling pattern it
  breaks. One forgotten modifier is exactly how real contracts lose
  funds, and no signature list contains the function NAME, because
  the name is whatever the developer invented that day.
- Check difference: a public function that spends from an address
  parameter (balances[from], _transfer(from, ...)) without the
  allowance check a sibling function enforces is a candidate of the
  transferFrom-vs-custom-transfer class.

Every flag is a CANDIDATE (see zeroday_util): labeled
candidate_zero_day, confidence-scored, severity capped at high,
evidence = the function's own code plus the guarded siblings it was
compared against. Source is read-only public chain data; nothing is
called, signed or sent - the same boundary as contract_recon.

Self-service standard functions (transfer, approve, deposit, burn of
one's own balance...) are excluded from the convention break: they
are unguarded BY DESIGN because they only touch the caller's own
assets. They still participate as siblings for the allowance
comparison.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from .zeroday_util import candidate_evidence

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
MAX_CANDIDATES_PER_CONTRACT = 6

REMEDIATION = ("Treat this as an unproven lead: confirm by hand (or "
               "on a fork) whether an arbitrary caller can invoke "
               "the function. If it can, add the same guard its "
               "siblings use; if it is intentionally public, document "
               "why next to the function so the next audit skips it.")

# Functions that are public by design: they only move the CALLER's
# own assets, so "no guard" is correct for them.
STANDARD_PUBLIC = {
    "transfer", "transferfrom", "approve", "increaseallowance",
    "decreaseallowance", "permit", "deposit", "depositeth",
    "burn", "withdraw", "redeem", "stake", "unstake", "claim",
    "get", "balanceof", "allowance", "totalsupply",
}

_SIG_KEYWORDS = {
    "public", "external", "internal", "private", "view", "pure",
    "payable", "virtual", "override", "returns", "memory", "calldata",
    "storage", "immutable", "constant",
}


# ---------------------------------------------------------------------
# Pure analysis (unit-tested without any network)
# ---------------------------------------------------------------------

def _body_of(fn: Dict[str, str]) -> str:
    text = fn["text"]
    i = text.find("{")
    return text[i:] if i >= 0 else ""


def _signature_tail(fn: Dict[str, str]) -> str:
    """Signature text after the parameter list (visibility, mods...)."""
    sig = fn["signature"]
    depth = 0
    for i, ch in enumerate(sig):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return sig[i + 1:]
    return ""


def _params_of(fn: Dict[str, str]) -> List[Tuple[str, str]]:
    """[(type, name)] parsed from the signature's parameter list."""
    sig = fn["signature"]
    i, j = sig.find("("), sig.rfind(")")
    if i < 0 or j <= i:
        # parameters live before any 'returns' clause; rfind is fine
        j = sig.find(")", i)
        if j < 0:
            return []
    inner = sig[i + 1:j]
    out: List[Tuple[str, str]] = []
    for part in inner.split(","):
        toks = part.strip().split()
        if len(toks) >= 2:
            out.append((toks[0], toks[-1]))
        elif len(toks) == 1 and toks[0]:
            out.append((toks[0], ""))
    return out


_GUARD_MOD_RE = re.compile(r"only[A-Z_]\w*|[A-Za-z_]\w*[Aa]uth\w*|"
                           r"adminOnly|ownerOnly", re.I)
_SENDER_EQ_RE = re.compile(r"(?:msg\.sender|_msgSender\(\))\s*==\s*"
                           r"([^\s)&|;]+)")
_SENDER_NE_RE = re.compile(r"(?:msg\.sender|_msgSender\(\))\s*!=\s*"
                           r"([^\s)&|;]+)")
_ROLE_RE = re.compile(r"hasRole\s*\(|_checkRole\s*\(|checkRole\s*\(")
_INTERNAL_GUARD_CALL_RE = re.compile(
    r"\b_?(?:check|require|assert|enforce)[A-Z_]\w*\s*\(")


def guards_of(fn: Dict[str, str]) -> Set[str]:
    """The access-guard patterns one function uses, as tokens."""
    guards: Set[str] = set()
    tail = _signature_tail(fn)
    for word in re.findall(r"[A-Za-z_]\w*", tail):
        if word in _SIG_KEYWORDS:
            continue
        if _GUARD_MOD_RE.fullmatch(word):
            guards.add(f"modifier:{word}")
    body = _body_of(fn)
    for m in _SENDER_EQ_RE.finditer(body):
        guards.add(f"sender_check:{m.group(1).strip()}")
    for m in _SENDER_NE_RE.finditer(body):
        guards.add(f"sender_check:{m.group(1).strip()}")
    if _ROLE_RE.search(body):
        guards.add("role_check")
    for m in _INTERNAL_GUARD_CALL_RE.finditer(body):
        name = m.group(0).rstrip("(")
        if any(w in name.lower() for w in ("owner", "admin", "role",
                                           "auth", "access", "permission")):
            guards.add(f"internal_check:{name}")
    return guards


def _state_vars(src_clean: str) -> Set[str]:
    """Contract-level state variable names (functions removed first)."""
    body = src_clean
    for fn in cc.extract_functions(src_clean):
        body = body.replace(fn["text"], " ", 1)
    decl = re.compile(
        r"\b(?:address|uint\d*|int\d*|bool|bytes\d*|string|mapping\s*\([^;]*?\))"
        r"\s+(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+)*"
        r"([A-Za-z_]\w*)\s*(?:=[^;]*)?;")
    return set(decl.findall(body))


_EFFECT_RES = [
    re.compile(r"\.(?:transfer|send)\s*\("),
    re.compile(r"\.call\s*\{"),
    re.compile(r"\.call\s*\("),
    re.compile(r"\bselfdestruct\s*\("),
    re.compile(r"\bdelegatecall\b"),
    re.compile(r"\b_(?:mint|burn)\s*\("),
    re.compile(r"\b\w+\s*\[[^\]]*\]\s*[:+\-]?=(?![=])"),
    re.compile(r"\b\w+\s*\[[^\]]*\]\s*(?:\+\+|--)"),
]


def is_state_changing(fn: Dict[str, str], state_vars: Set[str]) -> bool:
    sig = fn["signature"]
    if re.search(r"\b(view|pure)\b", sig):
        return False
    body = _body_of(fn)
    if not body:
        return False
    for var in state_vars:
        if re.search(rf"\b{re.escape(var)}\s*"
                     rf"(?:\[[^\]]*\])?\s*[:+\-*/]?=(?![=>])", body):
            return True
        if re.search(rf"\b{re.escape(var)}\s*(?:\+\+|--)", body):
            return True
    return any(r.search(body) for r in _EFFECT_RES)


def _has_allowance_check(fn: Dict[str, str]) -> bool:
    body = _body_of(fn)
    return bool(re.search(r"require\s*\([^)]*allowance", body, re.I)
                or re.search(r"allowance\s*\([^)]*\)\s*>=", body)
                or re.search(r"_spendAllowance\s*\(", body))


def _spends_from_param(fn: Dict[str, str]) -> Optional[str]:
    """Name of an address parameter whose balance this function moves."""
    body = _body_of(fn)
    addr_params = [name for typ, name in _params_of(fn)
                   if typ == "address" and name]
    for name in addr_params:
        if name == "msg.sender":
            continue
        pats = (rf"\b\w+\s*\[\s*{re.escape(name)}\s*\]",
                rf"\b_?(?:transfer|transferFrom|safeTransferFrom)\s*"
                rf"\(\s*{re.escape(name)}\b")
        if any(re.search(p, body) for p in pats):
            return name
    return None


def analyze_guard_consistency(src: str) -> List[Dict[str, Any]]:
    """Intra-contract guard-consistency analysis. Pure function.

    Returns candidate dicts: {kind, function, code, detail,
    sibling_pattern, siblings, confidence, severity}.
    """
    clean = cc._strip_comments(src)
    funcs = [f for f in cc.extract_functions(clean) if f["name"]]
    state_vars = _state_vars(clean)

    pub: List[Dict[str, Any]] = []
    for fn in funcs:
        sig = fn["signature"]
        if not re.search(r"\b(public|external)\b", sig):
            continue
        if re.search(r"\b(view|pure)\b", sig):
            continue
        pub.append({"fn": fn, "guards": guards_of(fn),
                    "state_changing": is_state_changing(fn, state_vars)})

    scfs = [p for p in pub if p["state_changing"]]
    candidates: List[Dict[str, Any]] = []

    # --- convention break -------------------------------------------
    guarded = [p for p in scfs if p["guards"]]
    token_users: Dict[str, List[str]] = {}
    for p in guarded:
        for tok in p["guards"]:
            token_users.setdefault(tok, []).append(p["fn"]["name"])
    dominant = {t: names for t, names in token_users.items()
                if len(names) >= 2}
    ratio = (len(guarded) / len(scfs)) if scfs else 0.0
    convention = bool(dominant) or (len(guarded) >= 2 and ratio >= 0.5)

    if convention and dominant:
        pattern_tok = max(dominant, key=lambda t: len(dominant[t]))
        pattern_desc = _describe_token(pattern_tok)
        siblings = dominant[pattern_tok]
    elif convention:
        pattern_tok = ""
        pattern_desc = "an access guard (each guarded sibling uses one)"
        siblings = [p["fn"]["name"] for p in guarded]
    else:
        pattern_tok, pattern_desc, siblings = "", "", []

    if convention:
        conf = 72 if len(siblings) >= 3 else 62
        for p in scfs:
            name = p["fn"]["name"]
            if p["guards"] or name.lower() in STANDARD_PUBLIC:
                continue
            candidates.append({
                "kind": "guard_convention_break",
                "function": name,
                "code": cc._snip(p["fn"]["text"]),
                "detail": (f"public state-changing function '{name}' "
                           f"uses no access guard, breaking the "
                           f"contract's own convention: "
                           f"{len(siblings)} sibling function(s) "
                           f"({', '.join(siblings[:4])}) are guarded "
                           f"by {pattern_desc}"),
                "sibling_pattern": pattern_desc,
                "siblings": siblings[:6],
                "confidence": conf, "severity": "high",
            })

    # --- check difference: spends-from-param without allowance ------
    with_allowance = [p for p in pub if _has_allowance_check(p["fn"])]
    if with_allowance:
        ref = with_allowance[0]["fn"]["name"]
        for p in pub:
            fn = p["fn"]
            if _has_allowance_check(fn):
                continue
            spender = _spends_from_param(fn)
            if spender:
                candidates.append({
                    "kind": "missing_allowance_check",
                    "function": fn["name"],
                    "code": cc._snip(fn["text"]),
                    "detail": (f"function '{fn['name']}' moves value "
                               f"from address parameter '{spender}' "
                               f"but never checks allowance, while "
                               f"sibling '{ref}' enforces an allowance "
                               f"check for the same class of operation"),
                    "sibling_pattern": f"allowance check (in '{ref}')",
                    "siblings": [ref],
                    "confidence": 68, "severity": "high",
                })

    return candidates[:MAX_CANDIDATES_PER_CONTRACT]


def _describe_token(tok: str) -> str:
    if tok.startswith("modifier:"):
        return f"modifier '{tok.split(':', 1)[1]}'"
    if tok.startswith("sender_check:"):
        return f"a msg.sender == {tok.split(':', 1)[1]} check"
    if tok == "role_check":
        return "a role check (hasRole/_checkRole)"
    if tok.startswith("internal_check:"):
        return f"internal guard call '{tok.split(':', 1)[1]}'"
    return tok


# ---------------------------------------------------------------------
# Plugin (mirrors contract_recon's read-only collection pattern)
# ---------------------------------------------------------------------

class ZerodayContractGuardsPlugin(Plugin):
    id = "zeroday_contract_guards"
    label = "Zero-Day Candidate Hunter (Contract Guard Consistency)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True   # read-only public chain data, like contract_recon
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    phase = 2
    timeout_s = 180
    description = ("Learns a contract's own access-control convention "
                   "from its verified source and flags public "
                   "state-changing functions that break it (no guard "
                   "where every sibling has one, allowance checks a "
                   "sibling enforces but a spender skips) as candidate "
                   "zero-days for human review.")

    # -- collection (same sources as contract_recon) ------------------
    def _collect(self, target: Target,
                 ctx: Ctx) -> List[Tuple[Optional[str], str]]:
        out: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(chain_hint: Optional[str], addr: str) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS or addr.lower() in seen:
                return
            seen.add(addr.lower())
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
                add(hint if isinstance(hint, str) and hint in cc.CHAINS
                    else None, str(item.get("address", "")))
        return out[:MAX_ADDRESSES]

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        work = self._collect(target, ctx)
        if not work:
            return self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed) or a web target "
                "whose pages reference one")
        findings: List[Finding] = []
        pairs_done = 0
        analyzed = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs_done += await self._analyze_address(
                    ctx, key, chain_hint, addr, findings)
                analyzed += 1
            except Exception:
                continue
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"guard-consistency analysis on {analyzed} "
                       f"address(es), {len(findings)} candidates")
        res.duration_ms = dur
        return res

    async def _analyze_address(self, ctx: Ctx, key: Optional[str],
                               chain_hint: Optional[str], addr: str,
                               findings: List[Finding]) -> int:
        chain_ids = [chain_hint] if chain_hint \
            else list(cc.DEFAULT_CHAIN_ORDER)
        pairs = 0
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None or code == "0x" or len(code) < 4:
                continue
            pairs += 1
            src = await cc.fetch_verified_source(ctx, chain, addr, key)
            impl = ""
            try:
                res = await cc.resolve_implementation(
                    ctx, chain, addr, code,
                    {"implementation": (src or {}).get(
                        "implementation", "")})
                impl = res.get("implementation") or ""
            except Exception:
                impl = ""
            self._analyze_source(chain, addr, src,
                                 "proxy_shell" if impl else "standalone",
                                 "", findings)
            if impl:
                try:
                    impl_src = await cc.fetch_verified_source(
                        ctx, chain, impl, key)
                except Exception:
                    impl_src = None
                self._analyze_source(chain, impl, impl_src,
                                     "implementation", addr, findings)
            if chain_hint:
                break
        return pairs

    def _analyze_source(self, chain, addr: str,
                        src: Optional[Dict[str, Any]], role: str,
                        proxy_addr: str,
                        findings: List[Finding]) -> None:
        if not src or not src.get("source"):
            return  # bytecode-only: no source, no convention to learn
        for cand in analyze_guard_consistency(src["source"]):
            ev = candidate_evidence(
                "contract_guard_consistency", cand["kind"],
                cand["confidence"], severity=cand["severity"], extra={
                    "chain": chain.id, "address": addr,
                    "contract_role": role,
                    "proxy_address": proxy_addr or None,
                    "function": cand["function"],
                    "code": cand["code"],
                    "sibling_pattern": cand["sibling_pattern"],
                    "guarded_siblings": cand["siblings"],
                    "remediation": REMEDIATION,
                })
            findings.append(self._f(
                "web3", "candidate_zero_day",
                f"CANDIDATE (not yet verified): {cand['detail']} "
                f"[{chain.name} {addr}"
                + (f", {role}" if role != "standalone" else "") + "]",
                source="zero-day guard-consistency hunter",
                source_url=cc.explorer_url(chain, addr),
                confidence=cand["confidence"], passive=True,
                evidence=ev))
