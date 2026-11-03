"""Crypto Contract Drain Analyzer: find functions that let ANYONE
move a contract's funds out.

Given a contract address - as the scan target itself (optionally
chain-prefixed, e.g. "bsc:0x...") or discovered on a web target by
the address miners - this fetches the contract's verified source
READ-ONLY through the same keyless chain layer as contract_recon
(Blockscout / Sourcify; Etherscan only when a key is already
configured) and statically analyzes every function for one question:
can an arbitrary caller move THIS contract's money to themselves or
to an address they supply, with no access gate in the way?

Drain patterns flagged (key "unprotected_drain", severity high):
- full-balance sweeps: address(this).balance sent to msg.sender or
  a caller-supplied address;
- withdraw / emergencyWithdraw / sweep / rescue-style functions
  sending ETH to the caller or a parameter recipient;
- unguarded token rescue: ERC20 transfer / transferFrom pulling
  tokens out of the contract to the caller or a parameter;
- unguarded selfdestruct to a caller-supplied beneficiary.

False-positive discipline is mandatory and mirrors the bridge
critical watch (recon-contract-watch/scan.py): a function is only
called unguarded when it is a real external/public implementation
(interface declarations have no body and are skipped), is not
internal/private, is not view/pure, and shows NO gate the gate
regex might miss - only* modifiers of any name, msg.sender
comparisons in either direction (==, and != against a non-zero
operand, the BNB-style `if (msg.sender != owner) throw;` pattern),
role checks, or signature verification (ecrecover / verifySigs).
Withdrawals of the caller's OWN credited balance (the amount is
read from a mapping indexed by msg.sender), msg.value
pass-throughs, and crowdsale purchase payouts (amounts derived
from msg.value in a payable function - the caller bought what
they receive in the same transaction) are not drains and are
not flagged. Neither are ERC20 transfer/transferFrom overrides
that delegate to super: that is the contract's own token
implementation debiting the caller's balance or enforcing the
caller's allowance, not a rescue of arbitrary tokens.

Detection only. Never sends a transaction, never calls the
contract; the deepest access is eth_getCode and public explorer
reads, exactly like contract_recon. When a target is a proxy, the
implementation behind it is resolved (one level) and analyzed too,
with findings tagged by contract role.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import chain_data

MAX_ADDRESSES = 4       # addresses analyzed per run
MAX_CHAIN_PAIRS = 4     # (chain, address) pairs analyzed per run

_REMEDIATION = (
    "Put this function behind real access control (an owner/role "
    "check enforced in the function or a modifier), or remove it. "
    "As deployed, any caller can move the contract's funds out.")

_UNGATED_BASIS = (
    "no only*/owner/role modifier, no msg.sender comparison, and "
    "no signature verification in the function signature or body")


# ---------------------------------------------------------------------------
# Drain analysis over verified source (pure, testable)
# ---------------------------------------------------------------------------

def _matching(s: str, i: int, op: str = "(", cl: str = ")") -> int:
    """Index of the closer matching s[i] (an opener)."""
    depth = 0
    for j in range(i, len(s)):
        if s[j] == op:
            depth += 1
        elif s[j] == cl:
            depth -= 1
            if depth == 0:
                return j
    return len(s) - 1


def _split_top(s: str) -> List[str]:
    """Split on top-level commas (nesting-aware)."""
    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _expr_before(text: str, pos: int) -> str:
    """The receiver expression immediately before text[pos] == '.'."""
    i = pos - 1
    depth = 0
    while i >= 0:
        c = text[i]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and not (c.isalnum() or c in "_."):
            break
        i -= 1
    return text[i + 1:pos].strip()


def _unwrap(expr: str) -> str:
    """Strip payable(...)/address(...) cast wrappers."""
    e = (expr or "").strip()
    for w in ("payable", "address"):
        if e.startswith(w + "(") and \
                _matching(e, len(w)) == len(e) - 1:
            return _unwrap(e[len(w) + 1:-1])
    return e


def _base_ident(expr: str) -> str:
    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", expr or "")
    return m.group(0) if m else ""


_PARAM_ATTRS = {"memory", "calldata", "storage", "payable", "indexed"}


def _param_names(signature: str) -> List[str]:
    """Named parameters of a function signature."""
    i = signature.find("(")
    if i < 0:
        return []
    inner = signature[i + 1:_matching(signature, i)]
    names: List[str] = []
    for part in _split_top(inner):
        toks = [t for t in part.split() if t not in _PARAM_ATTRS]
        if len(toks) >= 2:
            cand = toks[-1]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cand):
                names.append(cand)
    return names


def _caller_controlled(expr: str, params: List[str]) -> bool:
    e = _unwrap(expr)
    if e == "msg.sender":
        return True
    if e in params:
        return True
    return any(e.startswith(p + "[") for p in params)


_SENDER_RE = r"(?:msg\.sender|_msgSender\(\))"

_CMP_RE = re.compile(
    _SENDER_RE + r"\s*(==|!=)\s*([A-Za-z0-9_.\(\)\[\]]+)|"
    r"([A-Za-z0-9_.\(\)\[\]]+)\s*(==|!=)\s*" + _SENDER_RE)

# Boolean mapping lookup on the caller used AS the condition:
# require(isMinter[msg.sender]), if (!isMinter[msg.sender]) revert.
# A comparison after the bracket (balances[msg.sender] >= amount)
# is a bounds check, not an identity gate, and does not match.
_MAP_GATE_RE = re.compile(
    r"(?:require\s*\(\s*!?|if\s*\(\s*!)\s*[A-Za-z_][A-Za-z0-9_]*\s*"
    r"\[\s*" + _SENDER_RE + r"\s*\]\s*[,\)]")

# Role/permission predicate call on the caller inside a require/if:
# require(isMinter(msg.sender)), require(hasRole(ROLE, msg.sender)).
_ROLE_CALL_RE = re.compile(
    r"(?:require|if)\s*\([^;{]*?\b(?:is|has|can)[A-Z][A-Za-z0-9_]*\s*"
    r"\([^;{]*?" + _SENDER_RE)

# Registry-indirect gate: a storage struct fetched by caller key,
# whose fields a require() then checks (L2DAO bridges[msg.sender]
# + require(b.cap > 0)).
_REGISTRY_LOCAL_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*"
    r"\[\s*" + _SENDER_RE + r"\s*\]")

_SIG_KEYWORDS = {
    "external", "public", "internal", "private", "view", "pure",
    "payable", "virtual", "override", "returns", "memory",
    "calldata", "storage", "indexed", "nonreentrant", "noreenter",
    "initializer", "reinitializer",
}
_GATE_TOKEN_RE = re.compile(
    r"role|owner|admin|auth|minter|pauser|operator|manager|"
    r"controller|whitelist|allowlist|guard|keeper|vault", re.I)


def _signature_gate_modifier(signature: str) -> bool:
    """A custom modifier in the signature whose NAME carries gate
    semantics (hasMinterRole, onlyVault, isOwner, ...). The stock
    only*/_GATE_RE checks miss has*/is* role modifiers (OREO's
    `mint(...) external hasMinterRole` was a 2026-11-02 FP)."""
    sig = re.sub(r"returns\s*\([^)]*\)", "", signature)
    i = sig.find("(")
    if i < 0:
        return False
    tail = sig[_matching(sig, i) + 1:]
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
        if tok.lower() in _SIG_KEYWORDS:
            continue
        if _GATE_TOKEN_RE.search(tok):
            return True
        if re.match(r"(?i)(only|has|is|require|check)[A-Z_]", tok):
            return True
    return False


def _is_gated(signature: str, text: str) -> bool:
    """True when the function shows any access gate, including the
    shapes contract_chain._GATE_RE misses (bridge-watch discipline).
    """
    if cc._GATE_RE.search(signature) or cc._GATE_RE.search(text):
        return True
    if re.search(r"\bonly[A-Z][A-Za-z0-9_]*\b", signature):
        return True  # custom only* gate modifier (onlyRouter, ...)
    if re.search(r"\b(auth|adminOnly|onlyBy)\b", signature):
        return True
    if _signature_gate_modifier(signature):
        return True  # hasMinterRole / isOwner style modifiers
    if re.search(r"_checkOwner|_checkRole|hasRole\s*\(", text):
        return True
    for m in _CMP_RE.finditer(text):
        op = m.group(1) or m.group(4)
        other = (m.group(2) or m.group(3) or "").strip()
        if op == "==":
            return True  # require(owner == msg.sender) and friends
        if op == "!=" and other not in ("address(0)", "0"):
            return True  # if (msg.sender != owner) throw; and kin
    if _MAP_GATE_RE.search(text):
        return True  # require(isMinter[msg.sender]) and kin
    if _ROLE_CALL_RE.search(text):
        return True  # require(isMinter(msg.sender)) and kin
    for m in _REGISTRY_LOCAL_RE.finditer(text):
        var = re.escape(m.group(1))
        if re.search(r"require\s*\([^;]*?\b" + var + r"\b", text):
            return True  # storage struct by caller + require on it
    low = text.lower()
    if "ecrecover" in low or "verifysig" in low:
        return True  # signature-verified (validator quorum etc.)
    return False


def _is_skippable(signature: str, text: str) -> bool:
    """Interface declarations, non-public functions, and read-only
    functions can never drain anything."""
    if "{" not in text:
        return True  # interface declaration - no implementation
    head = text[:400].lower()
    if " internal " in head or " private " in head:
        return True
    if re.search(r"\b(internal|private)\b", signature):
        return True
    if re.search(r"\b(view|pure)\b", signature):
        return True
    return False


_MOVE_RES = [
    ("transferFrom", re.compile(r"\.transferFrom\s*\(")),
    ("transfer", re.compile(r"\.transfer\s*\(")),
    ("send", re.compile(r"\.send\s*\(")),
    ("call_brace", re.compile(r"\.call\s*\{")),
    ("call_dotvalue", re.compile(r"\.call\s*\.value\s*\(")),
    ("selfdestruct", re.compile(r"\b(?:selfdestruct|suicide)\s*\(")),
]


def _fund_moves(text: str) -> List[Dict[str, str]]:
    """All fund-moving expressions in a function body.

    Each move: {kind, recipient, amount, source}. kind is one of
    transferFrom / transfer / send / call / selfdestruct; transfer
    with 2+ args is an ERC20 transfer (erc20=True), with 1 arg an
    ETH send to the receiver expression.
    """
    moves: List[Dict[str, str]] = []
    for kind, pat in _MOVE_RES:
        for m in pat.finditer(text):
            if kind == "selfdestruct":
                paren = m.end() - 1
                args = _split_top(
                    text[paren + 1:_matching(text, paren)])
                moves.append({
                    "kind": kind,
                    "recipient": args[0] if args else "",
                    "amount": "address(this).balance", "source": ""})
            elif kind == "call_brace":
                brace = text.index("{", m.start())
                inner = text[brace + 1:_matching(text, brace, "{", "}")]
                amount = ""
                for part in _split_top(inner):
                    if part.startswith("value:"):
                        amount = part[len("value:"):].strip()
                if not amount:
                    continue  # .call{gas:...} with no value moves no funds
                moves.append({
                    "kind": "call",
                    "recipient": _expr_before(text, m.start()),
                    "amount": amount, "source": ""})
            elif kind == "call_dotvalue":
                paren = m.end() - 1
                args = _split_top(
                    text[paren + 1:_matching(text, paren)])
                moves.append({
                    "kind": "call",
                    "recipient": _expr_before(text, m.start()),
                    "amount": args[0] if args else "", "source": ""})
            else:
                paren = m.end() - 1
                args = _split_top(
                    text[paren + 1:_matching(text, paren)])
                recv = _expr_before(text, m.start())
                if kind == "transferFrom":
                    moves.append({
                        "kind": kind, "token_expr": recv,
                        "recipient": args[1] if len(args) > 1 else "",
                        "amount": args[2] if len(args) > 2 else "",
                        "source": args[0] if args else ""})
                elif kind == "transfer" and len(args) >= 2:
                    moves.append({
                        "kind": kind, "erc20": "1",
                        "token_expr": recv,
                        "recipient": args[0],
                        "amount": args[1], "source": ""})
                else:  # ETH transfer / send: receiver holds the funds
                    moves.append({
                        "kind": kind,
                        "recipient": recv,
                        "amount": args[0] if args else "",
                        "source": ""})
    return moves


def _msg_value_derived(text: str) -> set:
    """Local variables whose value derives from msg.value.

    Crowdsale StandardCrowdsale.buyTokens is the canonical shape:
    weiAmount = msg.value; tokens = weiAmount.mul(rate);
    token.transfer(msg.sender, tokens). The payout is bought and
    paid for in the same transaction - a purchase, not a drain.
    """
    derived = set()
    assigns = re.findall(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*([^;]+);", text)
    changed = True
    while changed:
        changed = False
        for var, rhs in assigns:
            if var in derived:
                continue
            if "msg.value" in rhs or any(
                    re.search(r"\b" + re.escape(d) + r"\b", rhs)
                    for d in derived):
                derived.add(var)
                changed = True
    return derived


def analyze_drain_source(src: str,
                         meta: Optional[Dict[str, Any]] = None
                         ) -> List[Dict[str, Any]]:
    """Static drain analysis over verified Solidity source.

    Returns finding dicts {kind, drain_kind, severity, function,
    code, recipient, detail} - one per (function, drain pattern).
    Detection only - nothing here interacts with the contract.
    """
    clean = cc._strip_comments(src)
    out: List[Dict[str, Any]] = []
    for fn in cc.extract_functions(clean):
        name = fn["name"]
        if not name or name in ("constructor", "fallback", "receive"):
            continue
        sig, text = fn["signature"], fn["text"]
        if _is_skippable(sig, text) or _is_gated(sig, text):
            continue
        params = _param_names(sig)
        # A function that reads the caller's own credited balance
        # (balances[msg.sender] and kin) is paying out what the
        # caller is owed - not a drain - unless it hands over the
        # contract's FULL balance.
        own_credit_read = "[msg.sender]" in text
        # Amounts derived from msg.value in a payable function are
        # purchase payouts / pass-throughs (crowdsale buyTokens),
        # funded by the caller in this same transaction.
        derived = _msg_value_derived(text) if "payable" in sig \
            else set()
        for mv in _fund_moves(text):
            if (mv["kind"] == "transferFrom" or mv.get("erc20")) and \
                    _base_ident(_unwrap(mv.get("token_expr", ""))) \
                    == "super":
                continue  # the contract's OWN ERC20 implementation
                # (USDT transferFrom override shape): super calls
                # debit the caller's balance / enforce the caller's
                # allowance - the standard token API, not a rescue
            recipient = _unwrap(mv["recipient"])
            if not _caller_controlled(recipient, params):
                continue
            amount = mv.get("amount", "")
            if mv["kind"] == "transferFrom":
                source = _unwrap(mv.get("source", ""))
                if source == "msg.sender":
                    continue  # caller moving their own tokens in
                if source != "address(this)" and \
                        _base_ident(source) not in params:
                    continue  # not out of this contract / not arbitrary
            if mv["kind"] != "selfdestruct":
                if "[msg.sender]" in amount:
                    continue  # sends exactly the caller's own credit
                if "msg.value" in amount:
                    continue  # pass-through of funds just sent in
                if derived and any(
                        re.search(r"\b" + re.escape(v) + r"\b",
                                  amount) for v in derived):
                    continue  # purchase payout bought with msg.value
                if own_credit_read and \
                        "address(this).balance" not in amount:
                    continue  # bounded by the caller's own credit
            if mv["kind"] == "selfdestruct":
                drain_kind = "selfdestruct"
            elif "address(this).balance" in amount:
                drain_kind = "full_balance_sweep"
            elif mv["kind"] == "transferFrom" or mv.get("erc20"):
                drain_kind = "token_rescue"
            else:
                drain_kind = "withdraw_sweep"
            out.append({
                "kind": "unprotected_drain",
                "drain_kind": drain_kind,
                "severity": "high",
                "function": name,
                "code": cc._snip(text),
                "recipient": recipient,
                "detail": (
                    f"drain_kind={drain_kind}; recipient={recipient}; "
                    f"gated=False ({_UNGATED_BASIS}); "
                    f"signature: {sig[:200]}"),
            })
    return out


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class CryptoDrainPlugin(Plugin):
    id = "crypto_drain_scanner"
    label = "Crypto Contract Drain Analyzer"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # keyless-first: Blockscout + Sourcify + public RPC
    description = ("Analyzes a contract's verified source for "
                   "unprotected drain functions: public/external "
                   "functions with NO access gate that can move the "
                   "contract's own ETH or tokens to the caller or a "
                   "caller-supplied address (full-balance sweeps, "
                   "withdraw/rescue functions, token rescue, "
                   "selfdestruct). Gated, internal, view/pure and "
                   "interface functions, own-balance withdrawals and "
                   "msg.value pass-throughs are not flagged. When "
                   "the target is a proxy, the implementation behind "
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
        unverified = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs, got_source = await self._scan_address(
                    ctx, key, chain_hint, addr, findings)
            except Exception:
                pairs, got_source = 0, False
                findings.append(self._f(
                    "web3", "crypto_drain_failed",
                    f"MEDIUM: {addr}: DEGRADED - drain analysis failed, "
                    "chain data could not be retrieved "
                    "(explorers/RPC unreachable). No conclusion "
                    "drawn.",
                    source="crypto drain analyzer",
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
                    unverified += 1

        drains = sum(1 for f in findings
                     if f.key == "unprotected_drain")
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"drain-analyzed {analyzed} contract address(es) "
            f"({unverified} without verified source - bytecode-only, "
            f"not cleared), "
            f"{drains} unprotected drain(s) found")
        res.duration_ms = dur
        return res

    # -- target collection (mirrors contract_recon) -------------------
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
        """Drain-analyze one address on its chain (or probe all
        chains). Returns ((chain, address) pairs with code, whether
        any verified source was analyzed)."""
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
                continue  # this chain's RPCs failed; try the next
            rpc_all_failed = False
            if code == "0x" or len(code) < 4:
                continue  # no contract code on this chain
            pairs += 1
            if await self._scan_on_chain(ctx, key, chain, addr, code,
                                         findings):
                got_source = True
            if chain_hint:
                break
        if pairs == 0 and rpc_all_failed:
            findings.append(self._f(
                "web3", "crypto_drain_failed",
                f"MEDIUM: {addr}: DEGRADED - every public RPC "
                "endpoint failed, so no chain data could be "
                "retrieved. No conclusion drawn.",
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
        """Analyze the contract at (chain, addr) plus its proxy
        implementation (one level). Returns True when at least one
        verified source was analyzed."""
        ctx.publish("chain_contracts", {
            "address": addr, "chain": chain.id,
            "is_contract": True, "verified": False, "name": ""})

        src = await chain_data.get_source(ctx, chain, addr, key)

        res = {"implementation": "", "via": "", "beacon": ""}
        try:
            res = await cc.resolve_implementation(
                ctx, chain, addr, code_hex,
                {"implementation": (src or {}).get("implementation", "")})
        except Exception:
            pass
        impl = res.get("implementation") or ""
        role = "proxy_shell" if impl else "standalone"
        got = self._analyze_source(chain, addr, src, findings,
                                   role=role, proxy_addr="",
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
            return got  # pointer resolved but no code there
        return self._analyze_source(chain, impl, impl_src, findings,
                                    role="implementation",
                                    proxy_addr=addr,
                                    impl_addr=impl) or got

    def _analyze_source(self, chain: cc.ChainConfig, addr: str,
                        src: Optional[Dict[str, Any]],
                        findings: List[Finding], role: str,
                        proxy_addr: str, impl_addr: str) -> bool:
        """Run the drain analyzer over one contract's verified
        source and append its findings. False when there is no
        verified source to analyze (bytecode-only contracts are
        contract_recon's beat, not this plugin's)."""
        if not src:
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
        for item in analyze_drain_source(src["source"]):
            recip = item["recipient"]
            who = ("the caller (msg.sender)" if recip == "msg.sender"
                   else f"a caller-supplied address ('{recip}')")
            value = (
                f"HIGH: Unprotected drain: function "
                f"'{item['function']}' in contract {addr} on "
                f"{chain.name} can move this contract's funds to "
                f"{who} with NO access gate{tag}\n\n"
                f"Code:\n{item['code']}")
            ev = dict(base_ev)
            ev.update({
                "severity": "high",
                "check": "unprotected_drain",
                "drain_kind": item["drain_kind"],
                "function": item["function"],
                "code": item["code"],
                "detail": item["detail"],
                "recipient": recip,
                "gated": False,
                "ungated_basis": _UNGATED_BASIS,
                "source_origin": src.get("origin", ""),
                "contract_name": src.get("contract_name", ""),
                "remediation": _REMEDIATION,
            })
            findings.append(self._f(
                "web3", "unprotected_drain", value,
                source="crypto drain analyzer",
                source_url=url, confidence=88, passive=True,
                evidence=ev))
        return True
