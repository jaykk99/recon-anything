"""Auto-validator lane (2026-11-03, Jay's order).

Hand validation was the bottleneck of the whole recon funnel:
detectors produced thousands of candidates and a human (the parent
agent) re-read source, classified the recipient, probed from a
stranger address and checked balances one contract at a time. That
is how 3,148 findings ended up parked as UNVERIFIED.

This module is the machine replacement. validate_candidate() takes
a candidate finding plus whatever evidence lanes could gather and
returns exactly one verdict:

- VERIFIED_REAL: stranger receives, and the receipt is MEASURED:
  a fork/local simulation that records a positive
  stranger_received, a probe whose return data measures a
  nonzero payout amount, or a DECISIVE read-only probe - a call
  at a nonzero amount the stranger provably cannot self-fund
  (the amount exceeds every measured stranger funding balance)
  that succeeds against live state, proving the payout at that
  amount is contract-funded and payable. A probe that merely
  succeeds is never enough on its own (zero-amount boundary
  calls succeed on standard contracts by design), and a
  contract balance is an upper bound on a payout, never a
  receipt: a positive balance alone no longer verifies. A mint
  payout additionally requires evidence the issued token has
  value (a live pair or reserves); without it the candidate
  stays UNVERIFIED with the missing piece named.
- TRIGGER_ONLY: the code is real and ungated, but the value lands
  at a FIXED or HOLDER-SELF destination - a stranger can trigger
  it and receives $0. Token-authority findings (a mint/freeze
  authority held by one fixed issuer principal) land here with
  subclass TOKEN_RISK.
- FALSE_POSITIVE: killed by evidence - a gate found on the deep
  source read, a live stranger probe that reverts, a simulation
  where the stranger receives 0, or a contract balance of 0.
- UNVERIFIED: evidence is missing, and the verdict names exactly
  which piece (verified source / flagged function / recipient
  destination / stranger probe or simulation). Degraded or
  no-source candidates stay UNVERIFIED - they are never cleared
  by default.

Evidence gathered per candidate, in order:
1. Full verified-source gate read incl. modifiers and internal
   calls (contract_logic._gated_deep over _Scope).
2. Recipient classification (contract_logic.classify_recipient).
3. Read-only eth_call probes from the unfunded stranger
   0x00000000000000000000000000000000deaDBeef (contract_sim.eth_call).
4. Balance evidence with time/source stamps: native balance,
   the contract's own-token balanceOf (the live bound for a
   token-denominated payout), and live AMM reserves when the
   contract is itself a pair. Zero-balance kills are
   denomination-aware (see _payout_denominations).
5. Fork/local simulation where a lane provides one (the Part A
   fixture proof runs the vulnerable fixtures on a local anvil
   chain; the fuzz lane's fixed-harness confirmations feed the
   same slot).

Detection only: eth_call is a node-local simulation and cannot
change state; the local simulation runs on a throwaway chain.
No transaction is ever sent on a live chain, and no drain is ever
executed.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import time
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import bytecode_paths as bp
from . import contract_chain as cc
from . import contract_logic as cl
from . import contract_sim as sim

STRANGER = sim.FUZZ_CALLER  # 0x000...deaDBeef, unfunded by design

VERDICTS = ("VERIFIED_REAL", "TRIGGER_ONLY", "FALSE_POSITIVE",
            "UNVERIFIED")

# Per-run candidate cap for the plugin lane. Default 8. Loop-driven
# runs raise it (RECON_VALIDATOR_MAX_CANDIDATES, or the investigator's
# LOOP_MAX_CANDIDATES) so the validator runs on every high-severity
# contract candidate the loop publishes instead of silently dropping
# the 9th and beyond.
DEFAULT_MAX_CANDIDATES = 8


def validator_max_candidates() -> int:
    try:
        return max(1, int(os.environ.get(
            "RECON_VALIDATOR_MAX_CANDIDATES",
            str(DEFAULT_MAX_CANDIDATES))))
    except (TypeError, ValueError):
        return DEFAULT_MAX_CANDIDATES


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _beneficiary_metered(fn: Dict[str, Any]) -> Optional[str]:
    """Is this function's payout metered by the RECEIVING
    address parameter's own recorded entitlement, and consumed?

    Looks for a mapping read keyed by an address parameter of
    the function (locked[holder], balances[to], ...) plus a
    write that consumes that same entry (decrement, zeroing,
    delete, or a consumed-flag set). Returns the mapping name
    when both are present, else None.
    """
    text = fn["text"]
    sig = fn["signature"]
    # Parameter list = up to the paren that closes the opening
    # one. (rindex(")") would run into the returns clause of a
    # multi-part signature and take the return value's name as
    # the last parameter - the FLY unlock shape.)
    try:
        start = sig.index("(")
    except ValueError:
        return None
    depth = 0
    end = None
    for i in range(start, len(sig)):
        if sig[i] == "(":
            depth += 1
        elif sig[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return None
    inner = sig[start + 1:end]
    addr_params = []
    for part in inner.split(","):
        toks = part.strip().split()
        if len(toks) >= 2 and "address" in part:
            addr_params.append(toks[-1])
    # A consumption write on the keyed entry: a decrement, a
    # delete, or an assignment to the entry itself, to a nested
    # entry (locked[holder][reason]), or to one of its fields
    # (locked[holder][reason].claimed = true - the consumed-flag
    # shape). Comparisons (==, >=) must not count.
    nested = r"(?:\s*\[(?:[^[\]]|\[[^\]]*\])*\])*" \
             r"(?:\s*\.\w+)?"
    for param in addr_params:
        for m in re.finditer(
                r"([A-Za-z_]\w*)\s*\[\s*" + re.escape(param) +
                r"\s*\]", text):
            name = m.group(1)
            keyed = re.escape(name) + r"\s*\[\s*" + \
                re.escape(param) + r"\s*\]"
            if re.search(keyed + r"\s*(-=|\+=)", text) or \
                    re.search(keyed + nested + r"\s*=(?!=)",
                              text) or \
                    re.search(r"delete\s+" + keyed, text):
                return name
    return None


def _issuance_shape(fn: Dict[str, Any]) -> bool:
    """The flagged function ISSUES new units (mint-named, or it
    increases totalSupply itself). A beneficiary-keyed ledger
    write inside an issuance is the credit being created, not
    a pre-existing entitlement being consumed, so the
    beneficiary-metered reclassification must not apply: the
    recipient of a mint is whoever the caller names, with
    value that did not exist before the call."""
    if "mint" in fn["name"].lower():
        return True
    return bool(cl._SUPPLY_UP_RE.search(fn["text"]))


def _find_fn(source: str, name: str, contract_name: str = ""):
    scope = cl._Scope(source, contract_name)
    matches = [fn for fn in scope.functions
               if fn["name"] == name and "{" in fn["text"]]
    if not matches:
        return scope, None
    # Detectors flag external entry points. When several
    # definitions share the name (an ancestor's variant, an
    # internal helper), prefer a non-internal/private one over
    # whichever happens to come first in scope order.
    for fn in matches:
        if not re.search(r"\b(internal|private)\b", fn["signature"]):
            return scope, fn
    return scope, matches[0]


def _deployable_contract_names(source: str) -> set:
    """Names of deployable contracts in the compilation:
    kind == "contract" only (libraries and interfaces are not
    deployed surfaces), excluding test/mock files."""
    names = set()
    for path, raw in cl._split_units(source):
        if cl._TEST_SEGMENT_RE.search(path):
            continue
        clean = cc._strip_comments(raw)
        for s in cl._contract_spans(clean):
            if s["kind"] == "contract" and s["name"]:
                names.add(s["name"])
    return names


def _proxy_attribution(source: str, function: str,
                       contract_name: str):
    """Re-scope a flagged function to the bundled implementation
    behind a proxy target. Returns (scope, fn) or None.

    All of these must hold: the target scope was resolved; the
    target is a proxy shell (its fallback performs a
    delegatecall to an implementation variable or address);
    and the flagged function exists in exactly ONE other
    deployable contract in the bundle. Anything less specific
    (zero or several candidate owners, a non-proxy target) is
    the sibling case, not attribution."""
    target = cl._Scope(source, contract_name)
    if not target.target_found:
        return None
    shell = target.scoped_text
    if "delegatecall" not in shell or \
            not re.search(r"\bfallback\s*\(", shell):
        return None
    full = cl._Scope(source, "")
    owners = {f.get("contract") for f in full.functions
              if f["name"] == function and "{" in f["text"]}
    owners.discard(contract_name)
    owners.discard(None)
    owners &= _deployable_contract_names(source)
    if len(owners) != 1:
        return None
    scope, fn = _find_fn(source, function, next(iter(owners)))
    if fn is None:
        return None
    return scope, fn


def _expanded_fn_text(fn: Dict[str, Any], scope: cl._Scope,
                      max_depth: int = 3) -> "tuple[str, List[str]]":
    """Entry function text plus the bodies of the internal
    helpers it calls, transitively (depth-limited).

    Value routinely moves one or two hops down the internal call
    path (withdraw() -> _payout(to, amt) -> to.transfer(amt)).
    classify_recipient on the entry body alone sees no
    destination there and gives up; its own internals
    (_recip_all_params, the helper-parameter rules) were built
    for function+helper text - the validator just never fed it
    any. Returns (expanded_text, helper_names_included)."""
    parts = [fn["text"]]
    included: List[str] = []
    seen = {fn["name"]}
    frontier = [fn["text"]]
    for _ in range(max_depth):
        nxt = []
        for text in frontier:
            for name, helper in scope.helpers.items():
                if name in seen:
                    continue
                if re.search(r"\b" + re.escape(name) + r"\s*\(",
                             text):
                    seen.add(name)
                    included.append(name)
                    parts.append(helper["text"])
                    nxt.append(helper["text"])
        if not nxt:
            break
        frontier = nxt
    return "\n".join(parts), included


_NATIVE_MARKERS = (
    re.compile(r"selfdestruct\s*\("),
    re.compile(r"\.call\s*\{[^}]*\bvalue\b"),
    re.compile(r"\.send\s*\("),
    re.compile(r"payable\s*\([^)]*\)\s*\.\s*transfer\s*\("),
)
_TOKEN_MARKERS = (
    re.compile(r"(?<![\w.])_?mint\s*\("),
    re.compile(r"safeTransfer(From)?\s*\("),
    re.compile(r"\.transferFrom\s*\("),
    # two-argument .transfer(to, amount) is the ERC20 shape;
    # the native shape takes exactly one argument.
    re.compile(r"\.transfer\s*\([^()]*,"),
)


_CALLER_EXPRS = {"msg.sender", "_msgSender()", "caller"}
_TF_CALL_RE = re.compile(r"(safeTransferFrom|transferFrom)\s*\(")
_BURN_CALLER_RE = re.compile(
    r"\b_?burn(?:From)?\s*\(\s*(?:msg\.sender|_msgSender\(\))\s*[,\)]")


def _split_call_args(text: str, open_paren: int) -> List[str]:
    """Top-level argument strings of the call whose '(' sits at
    open_paren (nested parens/brackets tracked)."""
    args: List[str] = []
    cur: List[str] = []
    depth = 0
    for i in range(open_paren, len(text)):
        ch = text[i]
        if ch in "([{":
            depth += 1
            if depth > 1:
                cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                if cur:
                    args.append("".join(cur).strip())
                return args
            cur.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    return args


def _self_funded(text: str) -> bool:
    """The flagged path funds the payout from the caller
    themselves (deposit / wrap shapes). A stranger 'receiving'
    on such a path receives their own money back in another
    form - not a drain, and a successful probe (typically with
    a zero amount) proves nothing about an unbacked payout.

    Shapes: ERC4626 deposits pulling the underlying from the
    caller - token.transferFrom(caller, ...),
    SafeERC20.safeTransferFrom(token, caller, ...) (the caller
    is the SECOND argument in the library form) - WETH wraps
    where the credited amount is the caller's msg.value, and
    burn-funded withdrawals where the payout amount is burned
    out of the caller's own token balance first
    (_burn(msg.sender, amount) funding the native payout - the
    aeWETH withdrawTo shape: the stranger 'receives' exactly
    their own burned stake back, and an unfunded stranger's
    burn of 0 pays out 0).
    """
    if re.search(r"_mint\s*\([^,]+,\s*msg\.value\s*\)", text) or \
            re.search(r"\[\s*msg\.sender\s*\]\s*\+=\s*msg\.value",
                      text):
        return True
    if _BURN_CALLER_RE.search(text):
        return True
    for m in _TF_CALL_RE.finditer(text):
        args = _split_call_args(text, m.end() - 1)
        if not args:
            continue
        if m.group(1) == "safeTransferFrom" and len(args) >= 4:
            src = args[1]  # SafeERC20 library: (token, from, ...)
        else:
            src = args[0]  # direct: (from, to, amount)
        if src in _CALLER_EXPRS:
            return True
    return False


def _payout_denominations(text: str) -> str:
    """Which denomination(s) the flagged value flow pays out:
    "native", "token", "mixed", or "unknown". Used to keep the
    zero-balance kill denomination-aware: a contract holding
    0 wei can still pay out tokens it holds or mints."""
    native = any(p.search(text) for p in _NATIVE_MARKERS)
    token = any(p.search(text) for p in _TOKEN_MARKERS)
    if native and token:
        return "mixed"
    if native:
        return "native"
    if token:
        return "token"
    return "unknown"


def _payout_amount_exprs(text: str) -> List[str]:
    """Amount expressions of every payout call in a function
    body: native (.call{value: X}, 1-arg .transfer/.send),
    token (2-arg .transfer/.safeTransfer, last arg of
    transferFrom shapes), and issuance (last arg of _mint /
    mint). Empty when the body pays nothing out."""
    exprs: List[str] = []
    for m in re.finditer(r"\.call\s*\{\s*value\s*:\s*([^}]+)\}",
                         text):
        exprs.append(m.group(1).strip())
    for m in re.finditer(
            r"\.(transfer|send|safeTransfer|transferFrom|"
            r"safeTransferFrom)\s*\(", text):
        args = _split_call_args(text, m.end() - 1)
        if not args:
            continue
        name = m.group(1)
        if name in ("transfer", "send"):
            exprs.append(args[0] if len(args) == 1 else args[1])
        elif name == "safeTransfer":
            if len(args) >= 2:
                exprs.append(args[1])
        else:
            exprs.append(args[-1])
    for m in re.finditer(r"(?<![\w.])_?mint\s*\(", text):
        args = _split_call_args(text, m.end() - 1)
        if args:
            exprs.append(args[-1])
    return exprs


_ASSIGN_RE = re.compile(
    r"([A-Za-z_]\w*)\s*(?<![=!<>+\-*/%&|^])=(?![=>])\s*([^;]+);")


def _fn_assignments(text: str) -> Dict[str, str]:
    """Simple `name = expr;` assignments in a function body
    (declarations included; compound assignments and
    comparisons excluded). Later assignments win."""
    out: Dict[str, str] = {}
    for m in _ASSIGN_RE.finditer(text):
        out[m.group(1)] = m.group(2).strip()
    return out


_BASIS_BALANCE_RE = re.compile(
    r"balanceOf\s*\(\s*(?:msg\.sender|_msgSender\(\))\s*\)")
_CALLER_KEYED_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\[\s*(?:msg\.sender|_msgSender\(\))\s*\]")


def _ztokenize(s: str):
    toks = []
    i = 0
    while i < len(s):
        if s[i].isspace():
            i += 1
            continue
        m = re.match(r"0[xX][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?",
                     s[i:])
        if m:
            toks.append(("num", m.group(0)))
            i += m.end()
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", s[i:])
        if m:
            toks.append(("ident", m.group(0)))
            i += m.end()
            continue
        if s[i] in "+-*/%()[],.?:!":
            toks.append(("op", s[i]))
            i += 1
            continue
        return None
    return toks


class _ZFail(Exception):
    pass


class _ZParser:
    """Zero-at-basis evaluator over one amount expression.

    parse_* returns (z, raw): z is True when the subexpression
    provably evaluates to 0 whenever the chosen caller-keyed
    basis reads 0, treating every other read as opaque (able
    to be nonzero); raw is the consumed source text, used to
    recognize caller reads inside call arguments. Anything the
    grammar cannot parse raises _ZFail and the caller treats
    the expression as opaque - the conservative direction.
    """

    def __init__(self, toks, basis, assigns, depth=0):
        self.toks = toks
        self.i = 0
        self.basis = basis  # None | ("token_self", None) |
        #                     ("mapping", name)
        self.assigns = assigns
        self.depth = depth

    def peek(self, k=0):
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else (None, None)

    def take(self):
        t = self.peek()
        self.i += 1
        return t

    def parse_expr(self):
        z, raw = self.parse_addsub()
        if self.peek() == ("op", "?"):
            self.take()
            zt, rt = self.parse_expr()
            if self.take() != ("op", ":"):
                raise _ZFail()
            zf, rf = self.parse_expr()
            return (zt and zf), raw + "?" + rt + ":" + rf
        return z, raw

    def parse_addsub(self):
        z, raw = self.parse_muldiv()
        while self.peek() in (("op", "+"), ("op", "-")):
            op = self.take()[1]
            z2, raw2 = self.parse_muldiv()
            z = z and z2
            raw += op + raw2
        return z, raw

    def parse_muldiv(self):
        z, raw = self.parse_unary()
        while self.peek() in (("op", "*"), ("op", "/"),
                              ("op", "%")):
            op = self.take()[1]
            z2, raw2 = self.parse_unary()
            if op == "*":
                z = z or z2
            # / and %: zero numerator stays zero
            raw += op + raw2
        return z, raw

    def parse_unary(self):
        if self.peek() in (("op", "-"), ("op", "+")):
            self.take()
            return self.parse_unary()
        if self.peek() == ("op", "!"):
            raise _ZFail()
        return self.parse_postfix()

    def parse_args(self):
        # Current token is "(". Returns [(z, raw), ...].
        self.take()
        args = []
        if self.peek() == ("op", ")"):
            self.take()
            return args
        while True:
            args.append(self.parse_expr())
            t = self.take()
            if t == ("op", ")"):
                return args
            if t != ("op", ","):
                raise _ZFail()

    def parse_postfix(self):
        z, raw = self.parse_primary()
        while self.peek() == ("op", "."):
            nxt = self.peek(1)
            after = self.peek(2)
            if nxt[0] != "ident" or after == ("op", "("):
                # A method call .name(...) - or a member the
                # primary already folded into its atom.
                if nxt[0] != "ident":
                    raise _ZFail()
                self.take()
                meth = self.take()[1]
                args = self.parse_args()
                a0 = args[0][0] if args else False
                if meth == "mul":
                    z = z or a0
                elif meth == "div":
                    pass  # zero numerator stays zero
                elif meth in ("add", "sub"):
                    z = z and a0
                else:
                    z = False
                raw += "." + meth + "(...)"
            else:
                # Dotted member of a non-call atom the primary
                # did not claim (defensive; primaries fold
                # msg.sender themselves).
                self.take()
                raw += "." + self.take()[1]
                z = False
        return z, raw

    def parse_primary(self):
        kind, val = self.take()
        if kind == "num":
            try:
                z = float(val.replace("_", "")) == 0
            except ValueError:
                z = False
            return z, val
        if (kind, val) == ("op", "("):
            z, raw = self.parse_expr()
            if self.take() != ("op", ")"):
                raise _ZFail()
            return z, "(" + raw + ")"
        if kind != "ident":
            raise _ZFail()
        name = val
        raw = name
        # Fold a dotted atom (msg.sender) when the segment
        # after the dot is not a method call.
        while self.peek() == ("op", ".") and \
                self.peek(1)[0] == "ident" and \
                self.peek(2) != ("op", "("):
            self.take()
            raw += "." + self.take()[1]
        if self.peek() == ("op", "["):
            self.take()
            _iz, iraw = self.parse_expr()
            if self.take() != ("op", "]"):
                raise _ZFail()
            caller_keyed = iraw.strip() in (
                "msg.sender", "_msgSender()")
            if caller_keyed and self.basis is not None and \
                    self.basis[0] == "mapping" and \
                    self.basis[1] == name:
                return True, raw + "[" + iraw + "]"
            return False, raw + "[" + iraw + "]"
        if self.peek() == ("op", "("):
            args = self.parse_args()
            if name == "balanceOf" and args and \
                    args[0][1].strip() in (
                        "msg.sender", "_msgSender()"):
                return (self.basis is not None and
                        self.basis[0] == "token_self"), \
                    raw + "(caller)"
            return False, raw + "(...)"
        if name in self.assigns and self.depth < 8:
            toks = _ztokenize(self.assigns[name])
            if toks is None:
                return False, raw
            sub = _ZParser(toks, self.basis, self.assigns,
                           self.depth + 1)
            z, _r = sub.parse_expr()
            if sub.i < len(toks):
                raise _ZFail()
            return z, raw
        return False, raw


def _zero_at(expr: str, basis, assigns) -> bool:
    """True when `expr` provably evaluates to 0 whenever the
    basis reads 0 (basis None = every caller read opaque, so
    only an unconditionally-zero expression qualifies)."""
    toks = _ztokenize(expr)
    if toks is None:
        return False
    p = _ZParser(toks, basis, assigns, 0)
    try:
        z, _raw = p.parse_expr()
    except _ZFail:
        return False
    return bool(z) and p.i >= len(toks)


def _caller_metered(fn: Optional[Dict[str, Any]]):
    """Is every payout of the flagged function metered by the
    CALLER's own recorded position - their token balance
    (balanceOf(msg.sender)) or a caller-keyed mapping entry -
    so that a caller whose measured basis is 0 provably
    receives 0?

    The MVK claimReward shape: userShare = balanceOf(caller)
    * remainPool / totalSupply, paid only out of the caller's
    own pro-rata share. Recognized by symbolic evaluation:
    every payout amount expression is zero-at-basis (zero
    whenever the basis read is zero) yet not zero regardless
    of the basis. Conservative: anything unparseable, any
    payout with a basis-independent component, and functions
    with no payout at all return None.

    Returns {"basis": "token_self"} or {"basis": "mapping",
    "name": <mapping>} or None."""
    if fn is None:
        return None
    text = fn["text"]
    exprs = _payout_amount_exprs(text)
    if not exprs:
        return None
    assigns = _fn_assignments(text)
    bases = []
    if _BASIS_BALANCE_RE.search(text):
        bases.append(("token_self", None))
    seen = set()
    for m in _CALLER_KEYED_RE.finditer(text):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            bases.append(("mapping", m.group(1)))
    for basis in bases:
        try:
            if all(_zero_at(e, basis, assigns) for e in exprs) \
                    and any(not _zero_at(e, None, assigns)
                            for e in exprs):
                return {"basis": basis[0], "name": basis[1]}
        except Exception:
            continue
    return None


def _decisive_measured(candidate: Dict[str, Any],
                       balances: Dict[str, Any]):
    """(amount, funding_max) when the candidate carries a
    decisive-probe record proving a nonzero payout the
    stranger cannot self-fund, else None.

    A decisive probe is a read-only call from the unfunded
    stranger at a NONZERO amount (in the flagged function's
    amount slot) that exceeds every funding balance measured
    for the stranger (native + the contract's own token). Its
    success against live state proves the payout at that
    amount is contract-funded and payable to the recipient -
    a measured receipt, where a contract balance is only an
    upper bound. The engine re-checks the amount against the
    recorded stranger funding so a lane cannot stamp receipts
    it did not measure."""
    dp = candidate.get("decisive_probe") or {}
    if dp.get("status") != "success":
        return None
    try:
        amt = int(dp.get("amount") or 0)
    except (TypeError, ValueError):
        return None
    if amt <= 0:
        return None
    funding = []
    for k in ("stranger_native_wei", "stranger_token_self_wei"):
        v = balances.get(k)
        if v is not None:
            try:
                funding.append(int(v))
            except (TypeError, ValueError):
                pass
    if not funding:
        return None
    fmax = max(funding)
    if amt > fmax:
        return (amt, fmax)
    return None


_ERC20_SELF_SURFACE = {"transfer", "transferFrom"}
_LEDGER_MOVE_RE = re.compile(
    r"(_transfer\s*\(|_balances\s*\[|balances\s*\[|balanceOf\s*\[)")
_ALLOWANCE_RE = re.compile(r"(_spendAllowance|allowance\s*\()")


def _own_standard_surface(fn: Optional[Dict[str, Any]],
                          scope: Optional[cl._Scope],
                          flow_text: str) -> bool:
    """The flagged function IS the target token's own standard
    ERC20 transfer surface, not an external drain path.

    True only when all of these hold: the function is named
    transfer / transferFrom; the analysis scope (the deployed
    contract plus ancestors) is itself an ERC20 token (it defines
    balanceOf and totalSupply); the function body moves that
    token's own ledger (_transfer / balance writes); and, for
    transferFrom, allowance mechanics are present (a transferFrom
    with NO allowance check is a backdoor shape, not standard
    semantics, and must not be cleared by this rule).

    Such a function moves value only against the sender's own
    balance (transfer) or an existing allowance (transferFrom).
    A stranger probe "succeeding" - the boundary probes use
    zero amounts, which standard tokens accept by design - is
    normal token semantics, and the Nov 4 backlog re-run proved
    the old engine minted VERIFIED_REAL verdicts out of exactly
    this shape."""
    if fn is None or scope is None:
        return False
    if fn["name"] not in _ERC20_SELF_SURFACE:
        return False
    names = {f["name"] for f in scope.functions}
    is_token = {"balanceOf", "totalSupply"} <= names or (
        "balanceOf" in scope.scoped_text
        and "totalSupply" in scope.scoped_text)
    if not is_token:
        return False
    # The ledger move is either in the function body itself or
    # one super-delegation away (the common OpenZeppelin shape:
    # a thin override that calls super.transfer /
    # super.transferFrom into the in-scope ERC20 implementation).
    delegated = bool(re.search(
        r"super\.\s*" + re.escape(fn["name"]) + r"\s*\(",
        fn["text"]))
    if not _LEDGER_MOVE_RE.search(fn["text"]) and not delegated:
        return False
    if fn["name"] == "transferFrom":
        # Allowance mechanics may live in the ancestor's body
        # when the entry only delegates, so the scoped text
        # counts as evidence too.
        if not _ALLOWANCE_RE.search(flow_text) and not (
                delegated and _ALLOWANCE_RE.search(
                    scope.scoped_text)):
            return False
    return True


def _probe_amount_return(fn: Optional[Dict[str, Any]],
                         probe: Dict[str, Any]) -> Optional[int]:
    """The payout amount a successful live probe measured, when
    it can be read: the flagged function declares exactly one
    uint/int return value and the probe's return data carries
    it as the first word. None when the amount cannot be read
    (no declared numeric return, no return data)."""
    if fn is None:
        return None
    m = re.search(r"returns\s*\(([^)]*)\)", fn["signature"])
    if not m:
        return None
    parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
    if len(parts) != 1 or not re.search(r"\bu?int\d*\b", parts[0]):
        return None
    raw = probe.get("result") or probe.get("detail") or ""
    if not isinstance(raw, str):
        return None
    h = raw[2:] if raw.startswith("0x") else raw
    if len(h) < 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", h[:64]):
        return None
    return int(h[:64], 16)


def _reserves_value(balances: Dict[str, Any],
                    key: str) -> Optional[int]:
    r = balances.get(key)
    if not isinstance(r, dict):
        return None
    try:
        return int(r.get("reserve0") or 0) + int(r.get("reserve1") or 0)
    except Exception:
        return None


def _token_value_evidence(candidate: Dict[str, Any],
                          balances: Dict[str, Any]) -> Optional[str]:
    """Evidence that a token this contract can mint actually has
    value: the contract is itself a live AMM pair, the gathering
    lane read live reserves for a pair of this token, or a lane
    supplied explicit token-value evidence. A mint of a token
    with no market is issuance of paper, not a payable payout."""
    total = _reserves_value(balances, "amm_reserves")
    if total:
        return (f"the contract is itself a live AMM pair "
                f"(reserves sum {total} base units)")
    total = _reserves_value(balances, "token_pair_reserves")
    if total:
        return (f"live pair reserves for the token "
                f"(reserves sum {total} base units)")
    tve = candidate.get("token_value_evidence")
    if isinstance(tve, dict) and tve.get("detail"):
        return str(tve["detail"])
    if isinstance(tve, str) and tve:
        return tve
    return None


def _bytecode_recipient_read(findings: Any,
                             flagged_selector: Any) -> Optional[str]:
    """Coarse recipient read from contract_logic.
    analyze_logic_bytecode output for the flagged selector.

    Deliberately narrow: only a value CALL whose walked path
    loads calldata (the CALL target comes from the caller's
    own arguments) classifies CALLER-SUPPLIED, and a value
    CALL on a path that reads the CALLER opcode classifies
    CALLER. Anything else - no matching selector entry, no
    CALL, a target the walk cannot attribute - returns None
    and the caller keeps the named bytecode blocker. When in
    doubt, no classification."""
    if not isinstance(findings, list):
        return None
    sel = str(flagged_selector or "").lower()
    for f in findings:
        if not isinstance(f, dict):
            continue
        fsel = str(f.get("selector") or "").lower()
        if sel:
            if fsel != sel:
                continue
        elif len(findings) != 1:
            continue  # cannot attribute an unnamed selector
        explicit = f.get("recipient") or f.get("recipient_class")
        if explicit in ("CALLER", "CALLER-SUPPLIED"):
            return str(explicit)
        ops = set(f.get("opcodes") or []) | \
            set(f.get("sensitive_opcodes") or [])
        if "CALL" not in ops:
            return None
        if "CALLDATALOAD" in ops:
            return "CALLER-SUPPLIED"
        if "CALLER" in ops:
            return "CALLER"
        return None
    return None


def _validate_bytecode_only(candidate: Dict[str, Any],
                            out: Dict[str, Any],
                            be: Dict[str, Any]) -> Dict[str, Any]:
    """Verdict flow for a bytecode-only contract (no verified
    source, no recipient_override) carrying bytecode evidence.

    Honesty rules mirror the sibling-source logic: a flagged
    selector ABSENT from the deployed bytecode is dead at live
    state (FALSE_POSITIVE); a present selector with a coarse
    calldata/caller recipient read runs the normal measured-
    proof flow (simulation / stranger probe / value evidence,
    denomination unknown); a present-but-unclassifiable
    selector stays UNVERIFIED with exactly one named missing
    piece - the bytecode recipient blocker - unless a
    reverting live probe settles it first."""
    probe = candidate.get("probe") or {}
    simulation = candidate.get("simulation") or {}
    balances = candidate.get("balances") or {}
    out["evidence"]["bytecode_evidence"] = {
        "flagged_selector": be.get("flagged_selector"),
        "selector_present": be.get("selector_present"),
        "minimal_proxy_impl": be.get("minimal_proxy_impl"),
        "deployed_selectors": be.get("deployed_selectors")}
    if balances:
        out["evidence"]["balances"] = balances
    if probe:
        out["evidence"]["probe"] = {
            "status": probe.get("status"),
            "via": probe.get("via", ""),
            "detail": str(probe.get("detail", ""))[:200]}
    sel = be.get("flagged_selector") or "(unknown selector)"
    if be.get("selector_present") is False:
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            f"flagged function selector {sel} absent from "
            "deployed bytecode: the flagged function is not "
            "part of the deployed contract (bytecode-only, no "
            "verified source), so the flagged path is dead at "
            "live state")
        if probe.get("status"):
            out["reason"] += (
                f"; live stranger probe status: "
                f"{probe.get('status')}")
        return out
    if be.get("selector_present") is True:
        recipient = _bytecode_recipient_read(
            candidate.get("bytecode_findings"),
            be.get("flagged_selector"))
        if recipient in ("CALLER", "CALLER-SUPPLIED"):
            out["recipient"] = recipient
            out["evidence"]["bytecode_recipient"] = recipient
            return _finish_bytecode_proven(candidate, out, probe,
                                           simulation, balances)
        if probe.get("status") == "revert":
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                "flagged selector is present in the deployed "
                "bytecode, but the live read-only probe from "
                "the unfunded stranger reverts "
                f"({str(probe.get('detail', ''))[:160]}); the "
                "path is dead at live state")
            return out
    out["missing"] = [
        "recipient destination (bytecode-only contract, "
        "no verified source)"]
    out["reason"] = (
        "no verified source available, and the bytecode "
        "evidence for the flagged selector does not determine "
        "the value destination; the gate and the recipient "
        "cannot be read from bytecode alone")
    if be.get("minimal_proxy_impl"):
        out["reason"] += (
            f"; the contract is an EIP-1167 minimal proxy - "
            f"analyze the implementation "
            f"{be['minimal_proxy_impl']} instead")
    return out


def _finish_bytecode_proven(candidate: Dict[str, Any],
                            out: Dict[str, Any],
                            probe: Dict[str, Any],
                            simulation: Dict[str, Any],
                            balances: Dict[str, Any]
                            ) -> Dict[str, Any]:
    """Measured-proof flow for a bytecode-only candidate whose
    recipient WAS classified from bytecode evidence. Mirrors
    the source flow's unknown-denomination branch: a
    simulation or a successful stranger probe plus positive
    value evidence verifies; measured zeros kill; nothing
    measured stays UNVERIFIED with the gap named."""
    recipient = out.get("recipient")
    if simulation.get("ran"):
        received = simulation.get("stranger_received")
        out["evidence"]["simulation"] = simulation.get("detail", "")
        if received is not None and float(received) > 0:
            out["verdict"] = "VERIFIED_REAL"
            out["value"] = (f"{received} "
                            f"{simulation.get('unit', '')}".strip())
            out["reason"] = (
                "fork/local simulation proves a stranger "
                f"receives {out['value']}; bytecode recipient "
                f"read {recipient} (bytecode-only contract, no "
                "verified source)")
            return out
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "fork/local simulation ran and the stranger "
            "received 0 - the payout does not reach a stranger "
            "in practice")
        return out
    if probe.get("status") == "revert":
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "live read-only probe from the unfunded stranger "
            f"reverts ({str(probe.get('detail', ''))[:160]}); "
            "the bytecode-level path is dead at live state")
        return out
    if probe.get("status") == "success":
        positives: List[str] = []
        native = balances.get("native_wei")
        token_self = balances.get("token_self_wei")
        if native is not None and int(native) > 0:
            positives.append(
                f"contract native balance {native} wei")
        if token_self is not None and int(token_self) > 0:
            positives.append(
                f"contract own-token balance {token_self} "
                "base units")
        for key in ("amm_reserves", "token_pair_reserves"):
            total = _reserves_value(balances, key)
            if total:
                positives.append(
                    f"live reserves ({key}, sum {total} "
                    "base units)")
        measured = _decisive_measured(candidate, balances)
        if candidate.get("decisive_probe"):
            out["evidence"]["decisive_probe"] = \
                candidate["decisive_probe"]
        if positives and measured is not None:
            amt, fmax = measured
            out["verdict"] = "VERIFIED_REAL"
            out["value"] = (
                f"decisive probe proved {amt} payable; "
                + "; ".join(positives))
            out["reason"] = (
                "decisive read-only probe from the unfunded "
                f"stranger at a nonzero amount ({amt}) "
                f"exceeding the stranger's measured funding "
                f"(max {fmax}) succeeds and the bytecode "
                f"recipient read is {recipient} (bytecode-only "
                "contract, no verified source); positive value "
                "evidence: " + "; ".join(positives))
            return out
        if positives:
            out["missing"] = ["measured receipt (decisive "
                              "nonzero probe or fork/local "
                              "simulation)"]
            out["reason"] = (
                "stranger probe succeeds and the bytecode "
                f"recipient read is {recipient}, but a balance "
                "is an upper bound, not a receipt: no decisive "
                "nonzero probe or simulation measured what a "
                "stranger actually receives (positive value "
                "evidence: " + "; ".join(positives) + ")")
            return out
        if native is not None or token_self is not None or \
                _reserves_value(balances, "amm_reserves") \
                is not None or \
                _reserves_value(balances, "token_pair_reserves") \
                is not None:
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                "stranger probe succeeds but there is no "
                "positive value evidence: the contract holds "
                f"{native} wei native and {token_self} of its "
                "own token, with no live reserves")
            return out
        out["missing"] = ["positive value evidence (contract "
                          "balances / reserves)"]
        out["reason"] = (
            "stranger probe succeeds and the bytecode "
            f"recipient read is {recipient}, but no balance "
            "or reserve evidence was measured, so there is "
            "no proof anything payable exists")
        return out
    out["missing"] = ["stranger probe or fork/local simulation"]
    out["reason"] = (
        "bytecode recipient read is candidate-grade "
        f"({recipient}) but no probe or simulation has run, "
        "so the payout is unproven")
    return out


def validate_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Machine verdict for one candidate finding.

    candidate keys (all optional except address/kind):
      address, chain, function, kind, detail,
      source (verified source text) or None,
      contract_name,
      recipient_override (for non-EVM lanes, e.g. Stacks/Clarity,
        where classify_recipient cannot parse the source),
      authority_class (True for token-authority findings: mint /
        freeze / delegate authority held by a fixed principal),
      probe: {"status": "success"|"revert"|"transport_error",
              "detail": str, "via": str},
      decisive_probe: {"status": "success"|"revert"|
              "transport_error", "amount": int, "slot": int,
              "via": str} - a read-only probe at a NONZERO amount
              in the function's amount slot, chosen to exceed
              every funding balance measured for the stranger;
              its success is the measured-receipt evidence the
              probe-success branch requires for VERIFIED_REAL,
      balances: {"native_wei": int|None, "observed_at": str,
                 "source": str,
                 "stranger_native_wei": int|None - the stranger's
                   own native balance (funding bound),
                 "stranger_token_self_wei": int|None - the
                   stranger's balanceOf on the target contract
                   (funding bound AND the caller-metered basis),
                 "stranger_mapping_<name>_wei": int|None - the
                   stranger's entry in a caller-keyed mapping},
      simulation: {"ran": bool, "stranger_received": number|None,
                   "unit": str, "detail": str},
      entitlement_metered: bool - payout amount is metered by the
        caller's own recorded entitlement, so an eth_call success
        alone cannot measure what a stranger would receive.
    """
    out: Dict[str, Any] = {
        "address": candidate.get("address", ""),
        "chain": candidate.get("chain", ""),
        "function": candidate.get("function", ""),
        "kind": candidate.get("kind", ""),
        "verdict": "UNVERIFIED",
        "reason": "",
        "recipient": None,
        "gated": None,
        "value": None,
        "missing": [],
        "evidence": {},
    }

    # Token-authority class: the power sits with one fixed issuer
    # principal. Not stranger-receivable by construction.
    if candidate.get("authority_class"):
        out["verdict"] = "TRIGGER_ONLY"
        out["subclass"] = "TOKEN_RISK"
        out["recipient"] = candidate.get("recipient_override",
                                         "FIXED")
        out["reason"] = (
            "token-authority finding: the flagged power (mint / "
            "freeze / delegate / metadata authority) is held by a "
            "fixed issuer principal; a stranger holds none of it "
            "and receives nothing. Token risk, not a "
            "stranger-receivable drain.")
        return out

    source = candidate.get("source") or ""
    probe = candidate.get("probe") or {}
    simulation = candidate.get("simulation") or {}
    balances = candidate.get("balances") or {}

    if not source and not candidate.get("recipient_override"):
        be = candidate.get("bytecode_evidence")
        if isinstance(be, dict) and be:
            return _validate_bytecode_only(candidate, out, be)
        out["missing"] = ["verified source"]
        out["reason"] = ("no verified source available (fetch "
                         "failed or contract unverified); cannot "
                         "read the gate or the recipient")
        return out

    fn = None
    scope = None
    if source and candidate.get("function"):
        scope, fn = _find_fn(source, candidate["function"],
                             candidate.get("contract_name", ""))
        if fn is None:
            # Proxy attribution: the function is absent from the
            # target's scope, but the target is a proxy shell and
            # the function lives in exactly one bundled
            # implementation contract - that implementation IS
            # the deployed surface behind the proxy, so the
            # normal verdict flow runs on it.
            attributed = _proxy_attribution(
                source, candidate["function"],
                candidate.get("contract_name", ""))
            if attributed is not None:
                scope, fn = attributed
                out["evidence"]["attributed_to"] = \
                    fn.get("contract", "")
                out["evidence"]["attribution"] = (
                    "bundled implementation surface behind "
                    "proxy target")
        if fn is None:
            out_of_scope = bool(
                candidate.get("function_out_of_scope"))
            if not out_of_scope:
                # Automatic sibling detection: the function
                # exists in the verified compilation, just not
                # in the deployed contract or its ancestors.
                # The backlog lane never set the manual flag;
                # the verdict shape is the same either way.
                full = cl._Scope(source, "")
                out_of_scope = any(
                    f["name"] == candidate["function"] and
                    "{" in f["text"] for f in full.functions)
            if out_of_scope:
                # The detector flagged a function that exists
                # in the verified compilation but NOT in the
                # deployed contract or its ancestors (a bundled
                # sibling contract - the axlUSDC / DepositHandler
                # shape from Nov 2). The deployed contract does
                # not expose it; a reverting live probe proves
                # the path is dead at live state.
                out["evidence"]["probe"] = {
                    "status": probe.get("status"),
                    "via": probe.get("via", "")}
                if probe.get("status") == "revert":
                    out["verdict"] = "FALSE_POSITIVE"
                    out["reason"] = (
                        "flagged function is not part of the "
                        "deployed contract or its ancestors - it "
                        "lives in a bundled sibling contract in "
                        "the same verified compilation - and the "
                        "live stranger probe reverts; the path "
                        "is dead at live state")
                    return out
                out["missing"] = ["flagged function in deployed "
                                  "contract scope"]
                out["reason"] = (
                    f"function '{candidate['function']}' exists "
                    "in the verified compilation only in a "
                    "bundled sibling contract, not in the "
                    "deployed contract or its ancestors, and no "
                    "reverting live probe settles it")
                return out
            out["missing"] = ["flagged function in verified source"]
            out["reason"] = (
                f"function '{candidate['function']}' not found in "
                "the verified source for this contract")
            return out

    # 1. Gate read (deep: modifiers + internal calls).
    gated: Optional[bool] = None
    if fn is not None and scope is not None:
        gated = bool(cl._gated_deep(fn, scope))
    out["gated"] = gated

    # Evidence passthrough: balances (native + token + AMM
    # reserves, whatever the gathering lane read) and the probe
    # outcome ride along in every verdict from here on.
    if balances:
        out["evidence"]["balances"] = balances
    if probe:
        out["evidence"]["probe"] = {
            "status": probe.get("status"),
            "via": probe.get("via", ""),
            "detail": str(probe.get("detail", ""))[:200]}

    # 2. Recipient classification over the value flow: the
    # flagged function PLUS the internal helpers it calls, with
    # argument binding (value routinely moves one or two hops
    # down, and the destination is decided by what the entry
    # actually passes to the helper).
    flow_text = fn["text"] if fn is not None else ""
    metered = _caller_metered(fn) if fn is not None else None
    if metered:
        # Every payout of the flagged function is metered by
        # the caller's own recorded position (their token
        # balance or a caller-keyed entitlement entry): the
        # amount a caller receives scales with what they
        # already hold. Measured in the probe branch against
        # the stranger's own basis.
        out["evidence"]["caller_metered"] = metered
    recipient = candidate.get("recipient_override")
    if recipient is None and fn is not None:
        _expanded, helpers = _expanded_fn_text(fn, scope)
        if helpers:
            out["evidence"]["value_flow_helpers"] = helpers
        recipient, rdetail, flow_text = \
            cl.classify_recipient_path(scope, fn)
        out["evidence"]["recipient_detail"] = rdetail
        if recipient == "CALLER-SUPPLIED":
            metered = _beneficiary_metered(fn)
            if metered and _issuance_shape(fn):
                metered = None
            if metered:
                # The destination is a caller-supplied address,
                # but the payout is metered by THAT address's
                # own recorded entitlement and the entitlement
                # is consumed: the classic unlock(holder) /
                # release(holder) shape. The value belongs to
                # the beneficiary's own position - HOLDER-SELF,
                # not a stranger-receivable drain (the FLY
                # adjudication, Nov 2).
                out["evidence"]["beneficiary_metered"] = metered
                recipient = "HOLDER-SELF"
    out["recipient"] = recipient

    if fn is not None and not candidate.get("function_out_of_scope") \
            and _own_standard_surface(fn, scope, flow_text):
        # The token's own standard transfer surface is not a
        # drain candidate: it can only move the sender's own
        # balance or an approved allowance, and the recipient
        # classification of its `to` parameter (CALLER-SUPPLIED)
        # is just the ERC20 interface shape.
        out["evidence"]["own_standard_erc20_surface"] = True
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "the flagged function is the target token's own "
            "standard ERC20 transfer surface: it moves the "
            "token's own ledger only against the sender's "
            "balance (transfer) or an existing allowance "
            "(transferFrom). A stranger probe succeeding - the "
            "boundary probes use zero amounts, which standard "
            "tokens accept by design - is normal token "
            "semantics, not an external drain")
        return out

    if recipient in ("FIXED", "HOLDER-SELF"):
        if gated:
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                "gated: the deep source read finds an access "
                "gate on the flagged function, and its value "
                f"destination is {recipient} besides; a stranger "
                "can neither trigger it nor receive from it")
            return out
        if simulation.get("ran") and \
                float(simulation.get("stranger_received") or 0) > 0:
            out["missing"] = ["reconciliation of recipient read "
                              "vs simulation payout"]
            out["reason"] = (
                "source read classifies the destination as "
                f"{recipient}, but a simulation measured a "
                "stranger receiving value - the lanes disagree, "
                "so no verdict is forced")
            return out
        out["verdict"] = "TRIGGER_ONLY"
        out["reason"] = (
            f"ungated and triggerable by a stranger, but the "
            f"value destination is {recipient}; the stranger "
            "receives $0")
        return out
    if recipient in (None, "UNRESOLVED"):
        if gated and probe.get("status") == "revert":
            # The destination could not be classified, but two
            # independent lanes agree a stranger cannot use the
            # path at all: the deep source read finds a gate AND
            # the live stranger probe reverts. That settles the
            # candidate even without a destination.
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                "gated: the deep source read finds an access "
                "gate on the flagged function and the live "
                "read-only stranger probe reverts; the value "
                "destination could not be classified, but a "
                "stranger can neither trigger the path nor "
                "receive from it")
            return out
        out["missing"] = ["recipient destination"]
        out["reason"] = ("no value destination could be "
                         "classified in the flagged function")
        return out

    # Recipient is CALLER / CALLER-SUPPLIED. Measured proof
    # outranks the static gate read: a simulation that moves
    # value to a stranger is ground truth, and one that moves
    # nothing kills the candidate even if the source read
    # thought the path was open (the gate read can misread
    # entitlement checks as gates and vice versa).
    if simulation.get("ran"):
        received = simulation.get("stranger_received")
        out["evidence"]["simulation"] = simulation.get("detail", "")
        if received is not None and float(received) > 0:
            out["verdict"] = "VERIFIED_REAL"
            out["value"] = (f"{received} "
                            f"{simulation.get('unit', '')}".strip())
            out["reason"] = (
                "fork/local simulation proves a stranger "
                f"receives {out['value']}; recipient "
                f"{recipient}")
            return out
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "fork/local simulation ran and the stranger "
            "received 0 - the payout does not reach a stranger "
            "in practice")
        return out

    if gated:
        if probe.get("status") == "success":
            out["missing"] = ["reconciliation of gate read vs "
                              "successful stranger probe"]
            out["reason"] = (
                "deep source read finds a gate on the flagged "
                "function, but a stranger probe succeeded - the "
                "two evidence lanes disagree, so no verdict is "
                "forced")
            return out
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "gated: the deep source read (function, modifiers "
            "and internal calls) finds an access gate on the "
            "flagged function; a stranger cannot call it")
        return out

    if probe.get("status") == "revert":
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "live read-only probe from the unfunded stranger "
            f"reverts ({probe.get('detail', '')[:160]}); the "
            "source-level path is dead at live state")
        return out

    if probe.get("status") == "success":
        native = balances.get("native_wei")
        token_self = balances.get("token_self_wei")
        denom = _payout_denominations(flow_text)
        out["evidence"]["payout_denomination"] = denom
        if _self_funded(flow_text):
            # Deposit / wrap / burn shape: the payout is funded
            # by the caller (transferFrom from msg.sender, the
            # credited amount is the caller's own msg.value, or
            # the payout amount is burned out of the caller's
            # own token balance first). A stranger receives
            # only their own funds back; a successful probe
            # proves no unbacked payout.
            shape = ("burns the payout amount out of the "
                     "caller's own token balance "
                     "(_burn(msg.sender, ...)) before paying "
                     "out" if _BURN_CALLER_RE.search(flow_text)
                     else "pulls the value from the caller "
                     "themselves (transferFrom from msg.sender, "
                     "or the payout amount is the caller's own "
                     "msg.value) before paying out")
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                f"self-funded path: the flagged function "
                f"{shape}; a stranger receives only their own "
                "funds back, so the probe success proves no "
                "unbacked receipt")
            return out
        # A successful probe is a liveness result, not a value
        # result: the boundary probes use zero amounts, and
        # zero-amount calls succeed on standard contracts by
        # design. When the probe's own return data measures the
        # payout amount and it is zero, the stranger's measured
        # receipt is zero.
        amount = _probe_amount_return(fn, probe)
        if amount is not None:
            out["evidence"]["probe_return_amount"] = amount
            if amount == 0:
                out["verdict"] = "FALSE_POSITIVE"
                out["reason"] = (
                    "live read-only stranger probe succeeds but "
                    "returns a zero payout amount; the measured "
                    "receipt for a stranger is 0, so the probe "
                    "proves no payable payout")
                return out
        if metered or candidate.get("entitlement_metered"):
            # The payout is metered by the caller's own
            # recorded position. When the engine recognized the
            # metering basis in the source AND the gathering
            # lane measured the stranger's own basis, a zero
            # basis is a MEASURED zero receipt (every payout
            # amount is symbolically zero at a zero basis):
            # the MVK claimReward shape - the function does not
            # revert for a stranger, it simply pays them 0.
            basis_val = None
            basis_label = "caller entitlement"
            if metered:
                if metered["basis"] == "token_self":
                    basis_val = balances.get(
                        "stranger_token_self_wei")
                    basis_label = "own-token balance"
                else:
                    basis_val = balances.get(
                        "stranger_mapping_" +
                        str(metered.get("name")) + "_wei")
                    basis_label = (
                        "entry in the caller-keyed mapping " +
                        str(metered.get("name")))
            if metered and basis_val is not None and \
                    int(basis_val) == 0:
                out["verdict"] = "FALSE_POSITIVE"
                out["reason"] = (
                    "caller-metered payout: every payout of "
                    "the flagged function is metered by the "
                    f"caller's own {basis_label}, and the "
                    f"stranger's measured {basis_label} is 0, "
                    "so the measured receipt for an unfunded "
                    "stranger is 0 - the probe succeeds only "
                    "because the function does not revert, not "
                    "because it pays a stranger anything")
                return out
            out["missing"] = ["fork/local simulation (an "
                              "eth_call cannot measure a payout "
                              "metered by caller entitlement)"]
            out["reason"] = (
                "stranger probe succeeds, but the payout is "
                "metered by the caller's own recorded "
                "entitlement, so the amount a stranger would "
                "actually receive is unmeasured")
            return out
        # MEASURED-RECEIPT GATE. From here, VERIFIED_REAL
        # requires a measured receipt: a decisive probe (a
        # nonzero amount the stranger cannot self-fund,
        # succeeding against live state) on top of positive
        # value in the payout's denomination (or, for a mint,
        # evidence the issued token has value). A contract
        # balance is an upper bound, never a receipt - the
        # aeWETH lesson: withdrawTo succeeded on a zero-amount
        # probe against a positive native balance while paying
        # a stranger exactly 0. Zero-balance kills stay
        # denomination-aware: 0 wei only kills a native payout;
        # a token payout is bounded by token state, not wei.
        measured = _decisive_measured(candidate, balances)
        if candidate.get("decisive_probe"):
            out["evidence"]["decisive_probe"] = \
                candidate["decisive_probe"]
        mint_payout = bool(re.search(r"(?<![\w.])_?mint\s*\(",
                                     flow_text))
        if denom == "native":
            if native is None:
                out["missing"] = ["native balance evidence"]
                out["reason"] = (
                    "stranger probe succeeds on a native payout "
                    "path, but no native balance was measured; "
                    "a successful probe alone is not value "
                    "evidence")
                return out
            if int(native) == 0:
                out["verdict"] = "FALSE_POSITIVE"
                out["reason"] = (
                    "stranger probe succeeds but the contract "
                    "holds 0 native balance; there is nothing "
                    "for a stranger to receive")
                return out
            if measured is not None:
                amt, fmax = measured
                out["verdict"] = "VERIFIED_REAL"
                out["value"] = (
                    f"decisive probe proved {amt} wei payable; "
                    f"contract native balance {native} wei")
                out["reason"] = (
                    "decisive read-only probe from the "
                    "unfunded stranger at a nonzero amount "
                    f"({amt} wei) exceeding the stranger's "
                    f"measured funding (max {fmax}) succeeds "
                    "against live state, the function is "
                    f"ungated, and the value destination is "
                    f"{recipient}: the payout at that amount "
                    "is contract-funded and payable to a "
                    "stranger (measured receipt, not a balance "
                    "bound)")
                return out
            out["missing"] = ["measured receipt (decisive "
                              "nonzero probe or fork/local "
                              "simulation)"]
            out["reason"] = (
                "stranger probe succeeds and the contract "
                f"holds a positive native balance ({native} "
                "wei), but a balance is an upper bound, not a "
                "receipt: no decisive nonzero probe or "
                "simulation measured what a stranger actually "
                "receives")
            return out
        if denom == "token":
            if mint_payout:
                tve = _token_value_evidence(candidate, balances)
                if tve is None:
                    out["missing"] = [
                        "evidence the minted token has value "
                        "(live pair / reserves)"]
                    out["reason"] = (
                        "stranger probe succeeds on an ungated "
                        "mint path, but nothing shows the issued "
                        "token has value: no live pair or "
                        "reserve evidence was gathered. Issuance "
                        "of an untraded token is not a payable "
                        "payout")
                    return out
                if measured is not None:
                    amt, fmax = measured
                    out["verdict"] = "VERIFIED_REAL"
                    out["value"] = (
                        "token issuance to the caller-reachable "
                        f"recipient (mint): decisive probe "
                        f"minted {amt} base units to the "
                        f"stranger; token value evidence: {tve}")
                    out["reason"] = (
                        "decisive read-only probe from the "
                        "unfunded stranger at a nonzero amount "
                        f"({amt} base units) exceeding the "
                        f"stranger's measured funding (max "
                        f"{fmax}) succeeds against live state, "
                        "the function is ungated, the value "
                        f"destination is {recipient}, and the "
                        f"minted token has value evidence: {tve}")
                    return out
                out["missing"] = ["measured receipt (decisive "
                                  "nonzero probe or fork/local "
                                  "simulation)"]
                out["reason"] = (
                    "stranger probe succeeds on an ungated "
                    "mint path and the minted token has value "
                    f"evidence ({tve}), but no decisive "
                    "nonzero probe or simulation measured a "
                    "stranger actually receiving the issuance")
                return out
            if token_self is None:
                out["missing"] = ["contract own-token balance "
                                  "evidence"]
                out["reason"] = (
                    "stranger probe succeeds on a token payout "
                    "path, but the contract's own-token balance "
                    "was not measured; a successful probe alone "
                    "is not value evidence")
                return out
            if int(token_self) == 0:
                out["verdict"] = "FALSE_POSITIVE"
                out["reason"] = (
                    "stranger probe succeeds but the contract "
                    "holds 0 of its own token; the token payout "
                    "has nothing to pay out")
                return out
            if measured is not None:
                amt, fmax = measured
                out["verdict"] = "VERIFIED_REAL"
                out["value"] = (
                    f"decisive probe proved {amt} base units "
                    f"payable; contract own-token balance "
                    f"{token_self} base units")
                out["reason"] = (
                    "decisive read-only probe from the "
                    "unfunded stranger at a nonzero amount "
                    f"({amt} base units) exceeding the "
                    f"stranger's measured funding (max {fmax}) "
                    "succeeds against live state, the function "
                    f"is ungated, and the value destination is "
                    f"{recipient}: the payout at that amount "
                    "is contract-funded and payable to a "
                    "stranger (measured receipt, not a balance "
                    "bound)")
                return out
            out["missing"] = ["measured receipt (decisive "
                              "nonzero probe or fork/local "
                              "simulation)"]
            out["reason"] = (
                "stranger probe succeeds and the contract "
                "holds a positive own-token balance "
                f"({token_self} base units), but a balance is "
                "an upper bound, not a receipt: no decisive "
                "nonzero probe or simulation measured what a "
                "stranger actually receives")
            return out
        # mixed / unknown denomination: any measured positive
        # bound counts; measured zeros across the board kill;
        # nothing measured stays UNVERIFIED with the gap named.
        positives: List[str] = []
        if native is not None and int(native) > 0:
            positives.append(
                f"contract native balance {native} wei")
        if token_self is not None and int(token_self) > 0:
            positives.append(
                f"contract own-token balance {token_self} "
                "base units")
        reserves_total = _reserves_value(balances, "amm_reserves")
        if reserves_total:
            positives.append(
                f"live AMM reserves (sum {reserves_total} "
                "base units)")
        if mint_payout:
            tve = _token_value_evidence(candidate, balances)
            if tve is not None:
                positives.append(f"mint value evidence: {tve}")
        if positives and measured is not None:
            amt, fmax = measured
            out["verdict"] = "VERIFIED_REAL"
            out["value"] = (
                f"decisive probe proved {amt} payable; "
                + "; ".join(positives))
            out["reason"] = (
                "decisive read-only probe from the unfunded "
                f"stranger at a nonzero amount ({amt}) "
                f"exceeding the stranger's measured funding "
                f"(max {fmax}) succeeds, the function is "
                f"ungated, and the value destination is "
                f"{recipient}; positive value evidence: "
                + "; ".join(positives))
            return out
        if positives:
            out["missing"] = ["measured receipt (decisive "
                              "nonzero probe or fork/local "
                              "simulation)"]
            out["reason"] = (
                "stranger probe succeeds and positive value "
                "evidence exists (" + "; ".join(positives) +
                "), but a balance or reserve is an upper "
                "bound, not a receipt: no decisive nonzero "
                "probe or simulation measured what a stranger "
                "actually receives")
            return out
        if native is not None or token_self is not None \
                or reserves_total is not None:
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                "stranger probe succeeds but there is no "
                "positive value evidence: the contract holds "
                f"{native} wei native and "
                f"{token_self} of its own token, with no live "
                "reserves; a successful probe (zero-amount "
                "boundary calls succeed by design) does not "
                "prove a payable payout")
            return out
        out["missing"] = ["positive value evidence (contract "
                          "balances / reserves)"]
        out["reason"] = (
            "stranger probe succeeds and the source read is "
            f"candidate-grade (ungated, recipient {recipient}), "
            "but no balance or reserve evidence was measured, "
            "so there is no proof anything payable exists")
        return out

    out["missing"] = ["stranger probe or fork/local simulation"]
    out["reason"] = (
        "source read is candidate-grade (ungated, recipient "
        f"{recipient}) but no probe or simulation has run, so "
        "the payout is unproven")
    return out


# ---------------------------------------------------------------------------
# Live evidence gathering (used by the plugin wrapper)
# ---------------------------------------------------------------------------

async def _native_balance(ctx: Ctx, chain: cc.ChainConfig,
                          address: str) -> Dict[str, Any]:
    from ..ratelimit import fetch
    payload = {"jsonrpc": "2.0", "id": 1,
               "method": "eth_getBalance",
               "params": [address, "latest"]}
    routes = []
    if chain.blockscout_api:
        base = chain.blockscout_api.rsplit("/api", 1)[0]
        routes.append((f"{base}/api/eth-rpc", "Blockscout eth-rpc"))
    for rpc in chain.rpc_urls:
        routes.append((rpc, "public JSON-RPC"))
    for url, label in routes:
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", url,
                            json=payload, timeout=10, max_retries=0)
            if r.status_code != 200:
                continue
            d = r.json()
        except Exception:
            continue
        if isinstance(d, dict) and isinstance(d.get("result"), str):
            try:
                wei = int(d["result"], 16)
            except Exception:
                continue
            return {"native_wei": wei, "observed_at": _now(),
                    "source": label}
    return {"native_wei": None, "observed_at": _now(),
            "source": "all routes failed"}


def _word_at(result_hex: str, idx: int) -> Optional[int]:
    try:
        h = result_hex[2:] if result_hex.startswith("0x") \
            else result_hex
        return int(h[idx * 64:(idx + 1) * 64], 16)
    except Exception:
        return None


async def _token_balance_of(ctx: Ctx, chain: cc.ChainConfig,
                            address: str,
                            holder: str) -> Optional[int]:
    """balanceOf(holder) read on the contract at `address`.
    None when the contract is not an ERC20 or no route
    answers."""
    data = sim.function_selector("balanceOf(address)") + \
        holder[2:].lower().rjust(64, "0")
    res = await sim.eth_call(ctx, chain, address, data, STRANGER)
    if res.get("status") != "success":
        return None
    return _word_at(res.get("result", ""), 0)


async def _token_self_balance(ctx: Ctx, chain: cc.ChainConfig,
                              address: str) -> Optional[int]:
    """balanceOf(address) of the contract on ITSELF - the live
    bound for a payout denominated in the contract's own token.
    None when the contract is not an ERC20 or no route answers."""
    return await _token_balance_of(ctx, chain, address, address)


async def _mapping_entry(ctx: Ctx, chain: cc.ChainConfig,
                         address: str, name: str,
                         key: str) -> Optional[int]:
    """<name>(key) through the public getter of a caller-keyed
    mapping - the stranger's measured entitlement basis for a
    mapping-metered payout. None when no such getter answers
    (private mapping, or no route)."""
    data = sim.function_selector(f"{name}(address)") + \
        key[2:].lower().rjust(64, "0")
    res = await sim.eth_call(ctx, chain, address, data, STRANGER)
    if res.get("status") != "success":
        return None
    return _word_at(res.get("result", ""), 0)


async def _decisive_probe(ctx: Ctx, chain: cc.ChainConfig,
                          addr: str, fn_name: str,
                          types: List[str],
                          balances: Dict[str, Any]
                          ) -> Optional[Dict[str, Any]]:
    """The measured-receipt probe: one read-only call per
    integer amount slot at a NONZERO amount the stranger
    provably cannot self-fund - one more than the largest
    funding balance measured for the stranger (native + the
    contract's own token), capped at the contract's own
    measured bound in the payout denominations.

    A caller-funded path (burn / transferFrom / deposit
    shapes) cannot complete that call: it would have to pull
    more than the stranger holds. A contract-funded payout
    completes it, which proves the payout at that amount is
    payable to the stranger against live state. Zero-amount
    boundary probes can never prove this - they succeed on
    standard contracts by design (the aeWETH lesson).

    Returns the decisive record, or None when no decisive
    case can be constructed (no integer slot, stranger
    funding unmeasured, or the contract bound is 0 - the
    engine's zero-balance kills settle that case)."""
    slots = [i for i, t in enumerate(types)
             if t.startswith(("uint", "int"))
             and "[" not in t and "(" not in t]
    if not slots:
        return None
    funding = [int(balances[k]) for k in
               ("stranger_native_wei", "stranger_token_self_wei")
               if balances.get(k) is not None]
    if not funding:
        return None
    bounds = [int(balances[k]) for k in
              ("native_wei", "token_self_wei")
              if balances.get(k) is not None]
    bound = max(bounds) if bounds else 0
    if bound <= 0:
        return None
    amount = min(max(funding) + 1, bound)
    base: List[Any] = []
    for t in types:
        v = sim._default_value(t)
        if t == "address":
            v = STRANGER
        base.append(v)
    result: Dict[str, Any] = {
        "status": "transport_error",
        "detail": "no decisive case ran", "amount": amount}
    for i in slots:
        values = list(base)
        values[i] = amount
        enc = sim.encode_call_args(types, values)
        if enc is None:
            continue
        data = sim.function_selector(
            sim.canonical_signature(fn_name, types)) + enc
        res = await sim.eth_call(ctx, chain, addr, data, STRANGER)
        if res.get("status") == "success":
            return {"status": "success", "amount": amount,
                    "slot": i, "via": res.get("via", ""),
                    "detail": str(res.get("detail", ""))[:120]}
        if res.get("status") == "revert":
            result = {"status": "revert", "amount": amount,
                      "slot": i, "via": res.get("via", ""),
                      "detail": str(res.get("detail", ""))[:120]}
    return result


async def _pair_reserves(ctx: Ctx, chain: cc.ChainConfig,
                         address: str) -> Optional[Dict[str, Any]]:
    """Live AMM reserves when the contract itself is a
    UniswapV2-style pair (getReserves). Oracle/price candidates
    cannot be judged without live reserve state; None when the
    contract is not a pair or no route answers."""
    data = sim.function_selector("getReserves()")
    res = await sim.eth_call(ctx, chain, address, data, STRANGER)
    if res.get("status") != "success":
        return None
    r0 = _word_at(res.get("result", ""), 0)
    r1 = _word_at(res.get("result", ""), 1)
    if r0 is None or r1 is None:
        return None
    return {"reserve0": r0, "reserve1": r1,
            "observed_at": _now(),
            "source": res.get("via", "eth_call (live)")}


async def _attach_bytecode_evidence(ctx: Ctx, chain: cc.ChainConfig,
                                    addr: str,
                                    candidate: Dict[str, Any]
                                    ) -> None:
    """Populate candidate["bytecode_evidence"] (+ the raw
    analyze_logic_bytecode findings) from deployed bytecode
    when verified source could not be fetched. Read-only
    eth_getCode only; any failure leaves the candidate
    untouched and the verdict engine names the source gap."""
    try:
        code = await cc.rpc_get_code(ctx, chain, addr)
    except Exception:
        return
    if not code or code == "0x":
        return
    try:
        paths = bp.analyze(code)
        findings = cl.analyze_logic_bytecode(code)
    except Exception:
        return
    candidate["bytecode_findings"] = findings
    deployed = [s["selector"] for s in paths.get("selectors") or []
                if s.get("selector")]
    flagged = candidate.get("flagged_selector") or ""
    if not flagged and candidate.get("function"):
        for sel_hex, sig in cc.SELECTOR_TABLE.items():
            if sig and sig.split("(")[0] == candidate["function"]:
                flagged = sel_hex if sel_hex.startswith("0x") \
                    else "0x" + sel_hex
                break
    present: Optional[bool] = None
    if flagged and paths.get("dispatcher_found") and \
            not paths.get("minimal_proxy_impl"):
        # Only a recognized dispatcher settles presence; a
        # minimal proxy delegatecalls everything, so absence
        # from its (empty) dispatch table proves nothing.
        present = flagged.lower() in {d.lower() for d in deployed}
    candidate["bytecode_evidence"] = {
        "flagged_selector": flagged or None,
        "deployed_selectors": deployed,
        "selector_present": present,
        "minimal_proxy_impl": paths.get("minimal_proxy_impl")}


async def gather_and_validate(ctx: Ctx, key: Optional[str],
                              candidate: Dict[str, Any]
                              ) -> Dict[str, Any]:
    """Fetch source, probe and balances for one candidate, then
    run the pure verdict engine. Never sends a transaction."""
    chain_id = candidate.get("chain") or ""
    chain = cc.CHAINS.get(chain_id)
    addr = candidate.get("address", "")
    if chain is None or not cc.ADDRESS_RE.match(addr or ""):
        v = dict(candidate)
        v.update({"verdict": "UNVERIFIED",
                  "reason": "candidate has no resolvable EVM "
                            "chain/address for this lane",
                  "missing": ["EVM chain/address"]})
        return v
    src = await cc.fetch_verified_source(ctx, chain, addr, key)
    if src:
        candidate["source"] = src["source"]
        candidate["contract_name"] = src.get("contract_name", "")
    if not src and not candidate.get("bytecode_evidence"):
        await _attach_bytecode_evidence(ctx, chain, addr, candidate)
    fn_name = candidate.get("function", "")
    fn = None
    types = None
    if src and fn_name:
        scope, fn = _find_fn(src["source"], fn_name,
                             candidate.get("contract_name", ""))
        if fn is None:
            # Not in the deployed contract's scope: if it exists
            # elsewhere in the compilation (bundled sibling),
            # mark it and still probe - a revert settles the
            # verdict in validate_candidate.
            all_scope = cl._Scope(src["source"], "")
            for afn in all_scope.functions:
                if afn["name"] == fn_name and "{" in afn["text"]:
                    fn = afn
                    candidate["function_out_of_scope"] = True
                    break
        if fn is not None:
            types = sim._param_types(fn["signature"])
    # Balances first: the decisive probe's amount is built
    # from the stranger's measured funding and the contract's
    # measured bound.
    balances = await _native_balance(ctx, chain, addr)
    balances["token_self_wei"] = await _token_self_balance(
        ctx, chain, addr)
    stranger_native = await _native_balance(ctx, chain, STRANGER)
    balances["stranger_native_wei"] = stranger_native.get(
        "native_wei")
    balances["stranger_token_self_wei"] = await \
        _token_balance_of(ctx, chain, addr, STRANGER)
    reserves = await _pair_reserves(ctx, chain, addr)
    if reserves is not None:
        balances["amm_reserves"] = reserves
    candidate["balances"] = balances
    if fn is not None:
        # Caller-metered payouts: measure the stranger's basis
        # entry when the metering basis is a caller-keyed
        # mapping with a public getter.
        metered = _caller_metered(fn)
        if metered and metered["basis"] == "mapping":
            balances["stranger_mapping_" +
                     str(metered.get("name")) + "_wei"] = \
                await _mapping_entry(ctx, chain, addr,
                                     str(metered.get("name")),
                                     STRANGER)
    if fn is not None and types is not None:
        cases = sim.boundary_cases(types, addr)
        probe = {"status": "transport_error",
                 "detail": "no probe case ran"}
        for values, _label in cases[:3]:
            enc = sim.encode_call_args(types, values)
            if enc is None:
                continue
            data = sim.function_selector(
                sim.canonical_signature(fn_name, types)) + enc
            res = await sim.eth_call(ctx, chain, addr, data,
                                     STRANGER)
            probe = res
            if res.get("status") in ("success", "revert"):
                break
        candidate["probe"] = probe
        if probe.get("status") == "success":
            decisive = await _decisive_probe(
                ctx, chain, addr, fn_name, types, balances)
            if decisive is not None:
                candidate["decisive_probe"] = decisive
    return validate_candidate(candidate)


# ---------------------------------------------------------------------------
# Plugin wrapper (heavy lane)
# ---------------------------------------------------------------------------

class AutoValidatorPlugin(Plugin):
    id = "auto_validator"
    label = "Auto Validator"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = (
        "Machine validation of candidate findings: deep gate "
        "read, recipient classification, read-only stranger "
        "probes, balance reads and simulation results folded "
        "into VERIFIED_REAL / TRIGGER_ONLY / FALSE_POSITIVE / "
        "UNVERIFIED verdicts with evidence.")
    phase = 2
    lane = "heavy"
    timeout_s = 600

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        candidates: List[Dict[str, Any]] = []
        for item in ctx.consume("validator_candidates"):
            if isinstance(item, dict) and item.get("address"):
                candidates.append(dict(item))
        if not candidates:
            # A bare contract target with no candidate queue has
            # nothing to validate in this lane.
            res = self._skipped(
                "auto_validator: no candidate findings queued on "
                "the discovery bus for this run (validator "
                "candidates are published under "
                "'validator_candidates')")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        counts: Dict[str, int] = {v: 0 for v in VERDICTS}
        for cand in candidates[:validator_max_candidates()]:
            try:
                verdict = await gather_and_validate(ctx, key, cand)
            except Exception as e:
                verdict = {"verdict": "UNVERIFIED",
                           "reason": f"validator error: {e}",
                           "address": cand.get("address", ""),
                           "function": cand.get("function", ""),
                           "kind": cand.get("kind", "")}
            counts[verdict["verdict"]] = \
                counts.get(verdict["verdict"], 0) + 1
            sev = {"VERIFIED_REAL": "high",
                   "TRIGGER_ONLY": "low",
                   "FALSE_POSITIVE": "low",
                   "UNVERIFIED": "medium"}[verdict["verdict"]]
            findings.append(self._f(
                "web3", "validator_verdict",
                f"{verdict['verdict']}: {verdict.get('address', '')} "
                f"{verdict.get('function', '')} - "
                f"{verdict.get('reason', '')}",
                source="auto-validator (source read + stranger "
                       "probe + balances)",
                confidence=90,
                evidence={"severity": sev, "verdict": verdict},
                passive=True))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            "auto_validator: " + ", ".join(
                f"{k}={v}" for k, v in counts.items()))
        res.duration_ms = dur
        return res
