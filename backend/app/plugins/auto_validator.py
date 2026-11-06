"""Auto-validator lane (2026-11-03, Jay's order).

Hand validation was the bottleneck of the whole recon funnel:
detectors produced thousands of candidates and a human (the parent
agent) re-read source, classified the recipient, probed from a
stranger address and checked balances one contract at a time. That
is how 3,148 findings ended up parked as UNVERIFIED.

This module is the machine replacement. validate_candidate() takes
a candidate finding plus whatever evidence lanes could gather and
returns exactly one verdict:

- VERIFIED_REAL: stranger receives, and a read-only stranger probe
  or a fork/local simulation PROVES it, with POSITIVE value
  evidence attached: a nonzero balance bound in the payout
  denomination, a probe that returns a nonzero payout amount, or
  live reserve / pair evidence. A probe that merely succeeds is
  never enough on its own (zero-amount boundary calls succeed on
  standard contracts by design), and a mint payout additionally
  requires evidence the issued token has value (a live pair or
  reserves); without it the candidate stays UNVERIFIED with the
  missing piece named.
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
from . import contract_chain as cc
from . import contract_logic as cl
from . import contract_sim as sim

STRANGER = sim.FUZZ_CALLER  # 0x000...deaDBeef, unfunded by design

VERDICTS = ("VERIFIED_REAL", "TRIGGER_ONLY", "FALSE_POSITIVE",
            "UNVERIFIED")


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
    is the SECOND argument in the library form) - and WETH
    wraps where the credited amount is the caller's msg.value.
    """
    if re.search(r"_mint\s*\([^,]+,\s*msg\.value\s*\)", text) or \
            re.search(r"\[\s*msg\.sender\s*\]\s*\+=\s*msg\.value",
                      text):
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
      balances: {"native_wei": int|None, "observed_at": str,
                 "source": str},
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
            # Deposit / wrap shape: the payout is funded by the
            # caller (transferFrom from msg.sender, or the
            # credited amount is the caller's own msg.value).
            # A stranger receives only their own funds back;
            # a successful probe proves no unbacked payout.
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                "self-funded path: the flagged function pulls "
                "the value from the caller themselves "
                "(transferFrom from msg.sender, or the payout "
                "amount is the caller's own msg.value) before "
                "paying out; a stranger receives only their own "
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
        if candidate.get("entitlement_metered"):
            out["missing"] = ["fork/local simulation (an "
                              "eth_call cannot measure a payout "
                              "metered by caller entitlement)"]
            out["reason"] = (
                "stranger probe succeeds, but the payout is "
                "metered by the caller's own recorded "
                "entitlement, so the amount a stranger would "
                "actually receive is unmeasured")
            return out
        # POSITIVE VALUE EVIDENCE GATE. From here, VERIFIED_REAL
        # requires at least one measured, nonzero value bound in
        # the payout's denomination (or, for a mint, evidence
        # the issued token has value). Zero-balance kills stay
        # denomination-aware: 0 wei only kills a native payout;
        # a token payout is bounded by token state, not wei.
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
            out["verdict"] = "VERIFIED_REAL"
            out["value"] = (
                f"contract native balance {native} wei (upper "
                "bound on the native payout)")
            out["reason"] = (
                "read-only probe from the unfunded stranger "
                "succeeds, the function is ungated, the value "
                f"destination is {recipient}, and the contract "
                f"holds a positive native balance ({native} "
                "wei) bounding the payout")
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
                out["verdict"] = "VERIFIED_REAL"
                out["value"] = (
                    "token issuance to the caller-reachable "
                    f"recipient (mint); token value evidence: "
                    f"{tve}")
                out["reason"] = (
                    "read-only probe from the unfunded stranger "
                    "succeeds, the function is ungated, the "
                    f"value destination is {recipient}, and the "
                    f"minted token has value evidence: {tve}")
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
            out["verdict"] = "VERIFIED_REAL"
            out["value"] = (
                f"contract own-token balance {token_self} "
                "(base units, upper bound on the token payout)")
            out["reason"] = (
                "read-only probe from the unfunded stranger "
                "succeeds, the function is ungated, the value "
                f"destination is {recipient}, and the contract "
                f"holds a positive own-token balance "
                f"({token_self} base units) bounding the payout")
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
        if positives:
            out["verdict"] = "VERIFIED_REAL"
            out["value"] = "; ".join(positives)
            out["reason"] = (
                "read-only probe from the unfunded stranger "
                "succeeds, the function is ungated, and the "
                f"value destination is {recipient}; positive "
                "value evidence: " + "; ".join(positives))
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


async def _token_self_balance(ctx: Ctx, chain: cc.ChainConfig,
                              address: str) -> Optional[int]:
    """balanceOf(address) of the contract on ITSELF - the live
    bound for a payout denominated in the contract's own token.
    None when the contract is not an ERC20 or no route answers."""
    data = sim.function_selector("balanceOf(address)") + \
        address[2:].lower().rjust(64, "0")
    res = await sim.eth_call(ctx, chain, address, data, STRANGER)
    if res.get("status") != "success":
        return None
    return _word_at(res.get("result", ""), 0)


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
    fn_name = candidate.get("function", "")
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
            if types is not None:
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
    balances = await _native_balance(ctx, chain, addr)
    balances["token_self_wei"] = await _token_self_balance(
        ctx, chain, addr)
    reserves = await _pair_reserves(ctx, chain, addr)
    if reserves is not None:
        balances["amm_reserves"] = reserves
    candidate["balances"] = balances
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
        for cand in candidates[:8]:
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
