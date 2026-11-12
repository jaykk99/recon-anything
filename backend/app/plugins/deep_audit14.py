"""Deep-audit detectors, batch 14: AI plugin dev (2026-11-10).

Five more chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-13 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- lending_collateral_price_provider_unvalidated: a borrow /
  valuation function prices collateral by calling an external
  price provider whose address derives from caller-supplied
  market / token input (a raw address parameter, or a provider
  mapping read keyed by a caller parameter) with no allowlist /
  registry check on the provider. The Loopscale shape
  (2025-04-26, ~$5.8M). Distinct from built
  cp_proto_single_source_oracle (single DEX pair reserves) -
  here the provider ADDRESS itself is spoofable. An
  allowlisted / registry-checked provider, or a provider
  mapping whose setter is owner-gated, stays silent.
- callback_token_cei_violation: a deposit / withdraw / mint
  function does token.transfer / transferFrom BEFORE updating
  the accounting mapping it protects, with no nonReentrant
  guard, so an ERC-777 / 1363 / 677 hook fires mid-transfer
  and re-enters. The Cream $130M 2021 via AMP shape; Gauntlet
  audit 2026-10-27 R-3. Distinct from built
  token_callback_caller_unverified (receipt-callback side)
  and from the generic CEI family (which flags .call, not
  token transfers as the external call). Updating the
  accounting first, or a nonReentrant guard, stays silent.
- forwarder_library_msgdata_tail_confusion: a contract using
  ERC-2771 _msgSender() / trusted-forwarder sender resolution
  where a function forwards user-controlled calldata into an
  external library call whose parameter layout reads the
  calldata tail as the sender, and a transfer / withdraw auth
  depends on that resolved sender. The Mezo veBTC shape
  (2026-10-05, ~5.52 BTC). Tight scope: forwarder + external
  library + sender-dependent transfer must ALL be present.
  Distinct from queued multicall_2771_sender_spoof
  (multicall, not library boundary).
- governance_no_snapshot_immediate_seat: vote weight read from
  live balanceOf at election / vote time (no snapshot / block
  checkpoint) AND a newly elected seat / role usable in the
  same block / tx with no timelock or holding period. The X100
  shape (2026-10-24, ~$4.75-4.85M). Overlap adjudication: this
  needs NO flash loan - it is a governance-design check on the
  election contract itself. Built flash_loan_governance_takeover
  fires on live vote weight alone (its narrative needs a flash
  loan); built governance_early_execution_race fires on
  execute() with no proposal-state / eta gate (proposal
  execution, not election / seat). This check requires BOTH
  halves (live weight + immediate seat authority). A snapshot /
  checkpoint, or a timelock / holding period, stays silent.
- vault_underwrites_attacker_created_pool: a vault / strategy
  sends collateral into a pool / market that is caller-supplied
  or freshly created via a permissionless factory, with no
  allowlist / minimum-liquidity / age check; the pool lets the
  creator withdraw the collateral as liquidity. The Premia V3
  shape (2026-11-01, ~$437k). Caveat: no Premia post-mortem;
  the shape is fixtured (caller-supplied / fresh pool +
  collateral in + no allowlist / liquidity / age check), not
  Premia's exact code. A pool-method receiver only counts when
  it is caller-derived (an address parameter, or a local from a
  parameter / factory create): a fixed protocol address
  (MORPHO.supply), a parent-contract call (super.mint), or a
  fixed router stays silent. An allowlisted pool, or a
  minimum-liquidity / age check, stays silent.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. (Same narrowing
of cl._gated_deep as batch 13.) The forwarder detector is the
narrowed exception: a _msgSender() identity comparison IS the
mechanism under analysis (the resolved sender being audited),
so only only* modifiers and role checks suppress there. The
governance detector reads the election contract itself: the
vote function's own gate does not mitigate a live-weight
election, so the seat-grant half is what must be gated or
timelocked.

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
FAMILY = "deep14"

SPECS = [
    S("lending_collateral_price_provider_unvalidated", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Collateral price provider unvalidated: a borrow / "
             "valuation function prices collateral by calling an "
             "external price provider whose address is derived "
             "from caller-supplied market / token input (a raw "
             "address parameter, or a provider mapping read "
             "keyed by a caller parameter) with no allowlist / "
             "registry check on the provider - the Loopscale "
             "shape (~$5.8M, 2025-04-26). An allowlisted / "
             "registry-checked provider, or a provider mapping "
             "whose setter is owner-gated, is the protected "
             "shape.",
      fix="Resolve collateral prices only through an "
          "owner-registered provider registry (allowlist), and "
          "validate every caller-derived provider address "
          "against that registry before using its price; never "
          "let a caller pick the price-feed address."),
    S("callback_token_cei_violation", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Token-transfer hook CEI violation: a deposit / "
             "withdraw / mint function performs a token transfer "
             "(transfer / transferFrom / safeTransfer) BEFORE "
             "updating the accounting mapping it protects, with "
             "no nonReentrant guard, so an ERC-777 / 1363 / 677 "
             "hook fires mid-transfer and re-enters before the "
             "balance is updated - the Cream / AMP shape ($130M, "
             "2021; Gauntlet audit 2026-10-27 R-3). Updating the "
             "accounting first, or a nonReentrant guard, is the "
             "protected shape.",
      fix="Update the accounting mapping before any token "
          "transfer (checks-effects-interactions), or guard the "
          "function with nonReentrant, so a hook firing "
          "mid-transfer cannot re-enter against stale "
          "balances."),
    S("forwarder_library_msgdata_tail_confusion", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Forwarder + library calldata-tail sender "
             "confusion: a contract resolving the sender through "
             "a trusted forwarder (_msgSender()) forwards "
             "user-controlled calldata into an external library "
             "call whose parameter layout reads the calldata "
             "tail as the sender, and a transfer / withdraw in "
             "the same function authorizes against that resolved "
             "sender - the Mezo veBTC shape (~5.52 BTC, "
             "2026-10-05). A forwarder without a library "
             "boundary, a library call with fixed calldata, or "
             "sender-independent authorization is the protected "
             "shape.",
      fix="Never forward user-controlled calldata into a "
          "library call that reads the calldata tail as the "
          "sender; resolve the sender once at the entry point "
          "and pass it explicitly, and authorize transfers "
          "against the entry-point sender, not a value read "
          "back out of forwarded calldata."),
    S("governance_no_snapshot_immediate_seat", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Governance with no snapshot and an immediate seat: "
             "vote weight is read from the live token balance "
             "(balanceOf / getVotes at election time, no "
             "snapshot / checkpoint) AND a newly elected seat / "
             "role is granted with no timelock or holding "
             "period, so tokens held for a single transaction "
             "elect a seat that can act in the same block - the "
             "X100 shape (~$4.75-4.85M, 2026-10-24). No flash "
             "loan is needed: this is a governance-design check "
             "on the election contract itself. A snapshot / "
             "checkpoint for vote weight, or a timelock / "
             "holding period before the seat activates, is the "
             "protected shape.",
      fix="Snapshot vote weight at a past block (getPastVotes / "
          "checkpoints) and put a timelock or holding period "
          "between election and seat activation, so a seat "
          "cannot be bought, won, and used in one transaction."),
    S("vault_underwrites_attacker_created_pool", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Vault underwrites an attacker-created pool: a "
             "vault / strategy sends collateral into a pool / "
             "market that is caller-supplied or freshly created "
             "through a permissionless factory in the same call, "
             "with no allowlist, minimum-liquidity, or age "
             "check, so the pool creator can withdraw the "
             "collateral as liquidity - the Premia V3 shape "
             "(~$437k, 2026-11-01). An allowlisted pool, or a "
             "minimum-liquidity / age check, is the protected "
             "shape.",
      fix="Send collateral only to allowlisted pools, or "
          "require a minimum liquidity and a minimum pool age "
          "before a pool can receive vault collateral; never "
          "let a caller pick or freshly create the pool that "
          "holds vault funds."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 13)
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
    r"_msgSender\s*\(\s*\)\s*(==|!=)|"
    r"(==|!=)\s*_msgSender\s*\(\s*\)|"
    r"hasRole\s*\(|has[A-Z][A-Za-z0-9_]*Role\s*\(|"
    r"_checkOwner|_checkRole")
# For the forwarder detector: a _msgSender() comparison IS the
# mechanism under analysis, so only a plain msg.sender
# identity comparison or a role check suppresses there.
_IDENTITY_GATE_NO_MSGSENDER_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|has[A-Z][A-Za-z0-9_]*Role\s*\(|"
    r"_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(
    r"\bonly[A-Z][A-Za-z0-9_]*\b|\bonly\s*\(")
# Bare allowlist-mapping read as the whole require condition,
# e.g. require(isTxLimitExempt[msg.sender]): an allowlist gate,
# not a balance check (no comparison operator after the read).
_ALLOWLIST_GATE_RE = re.compile(
    r"require\s*\(\s*!?\s*[A-Za-z_][A-Za-z0-9_]*\s*\[\s*"
    r"(?:msg\.sender|_msgSender\s*\(\s*\))\s*\]\s*"
    r"(?:==\s*true|!=\s*false)?\s*\)")


def _modifier_override_gated(scope, tok: str) -> bool:
    """A modifier may be declared abstract (virtual, no body)
    AND overridden with a gate body elsewhere in the source
    (e.g. Withdrawable's protectedWithdrawal overridden with
    _checkRole(DEFAULT_ADMIN_ROLE)). The scope's modifier dict
    can hold the body-less declaration, so scan the scoped
    text for every declaration of the modifier and check each
    body for a gate."""
    for m in re.finditer(
            rf"modifier\s+{re.escape(tok)}\s*\([^)]*\)[^{{;]*\{{",
            scope.scoped_text):
        close = scope.scoped_text.find("}", m.end())
        if close < 0 or close - m.end() > 400:
            continue
        body = scope.scoped_text[m.end():close]
        if (_IDENTITY_GATE_RE.search(body) or
                _ONLY_MOD_RE.search(body)):
            return True
    return False


def _caller_gated(fn: Dict[str, Any], scope,
                  gate_re=_IDENTITY_GATE_RE) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses.
    """
    sig, text = fn["signature"], fn["text"]
    if _ONLY_MOD_RE.search(sig) or gate_re.search(text):
        return True
    if _ALLOWLIST_GATE_RE.search(text):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        _, pend = _balanced(stripped, i)
        tail = stripped[pend + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and (("msg.sender" in body or
                         "_msgSender" in body) and
                         ("==" in body or "!=" in body)):
                return True
            if _modifier_override_gated(scope, tok):
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


def _call_args(text: str, call_match) -> List[str]:
    paren = text.index("(", call_match.start())
    inner, _ = _balanced(text, paren)
    return _split_top(inner)


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


def _fn_addr_params(fn: Dict[str, Any]) -> List[str]:
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        if "address" in part:
            toks = [t for t in part.split()
                    if t not in ("calldata", "memory", "storage",
                                 "payable")]
            if len(toks) >= 2:
                out.append(toks[-1])
    return out

# ---------------------------------------------------------------------------
# 1. Collateral price provider unvalidated (Loopscale shape)
# ---------------------------------------------------------------------------

_PRICE_METHODS = (r"latestAnswer|getPrice|getPriceUnsafe|"
                 r"fetchPrice|getValue|price|quote|getRate")
_PRICE_CAST_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\(\s*([^()]*)\)\s*\.\s*(?:" +
    _PRICE_METHODS + r")\s*\(")
_PRICE_PLAIN_RE = re.compile(
    r"([A-Za-z_]\w*(?:\s*\[[^\]]*\])?(?:\s*\.\s*[A-Za-z_]\w*)*)"
    r"\s*\.\s*(?:" + _PRICE_METHODS + r")\s*\(")
_PROVIDER_ALLOW_RE = re.compile(
    r"approvedProviders|allowlistedProviders|isValidProvider|"
    r"isApprovedProvider|supportedProviders|whitelistedProviders|"
    r"allowedFeeds|allowedProviders|isRegisteredProvider|"
    r"isSupportedFeed|validProviders|isWhitelistedProvider|"
    r"isApprovedFeed")
_REGISTRY_CALL_RE = re.compile(
    r"isRegistered\s*\(|isApproved\s*\(|isWhitelisted\s*\(")


def _resolve_provider(fn_text: str, receiver: str,
                      params: List[str]):
    """(provider_expr, mapping_name or None) for a price-call
    receiver, or (None, None) when the provider is a fixed
    state variable (not caller-derived)."""
    recv = receiver.strip()
    # A mapping / struct read: markets[market].priceProvider
    mm = re.match(r"([A-Za-z_]\w*)\s*\[", recv)
    mapping = mm.group(1) if mm else None
    if recv in params:
        return recv, None
    # Cast-style: IPriceFeed(<expr>).latestAnswer()
    cast = re.match(
        r"([A-Za-z_]\w*)\s*\(\s*([^()]*)\)\s*$", recv)
    if cast:
        inner = cast.group(2).strip()
        mm = re.match(r"([A-Za-z_]\w*)\s*\[", inner)
        return inner, mm.group(1) if mm else None
    # Local assignment: address provider = <expr>; or
    # IPriceFeed provider = IPriceFeed(<expr>);
    am = re.search(
        rf"(?:address(?:\s+payable)?|[A-Za-z_]\w*)\s+"
        rf"{re.escape(recv)}\s*=\s*([^;]+);", fn_text)
    if not am:
        am = re.search(rf"\b{re.escape(recv)}\s*=\s*([^;]+);",
                       fn_text)
    if am:
        rhs = am.group(1).strip()
        cm = re.match(
            r"([A-Za-z_]\w*)\s*\(\s*([^()]*)\)\s*$", rhs)
        if cm:
            rhs = cm.group(2).strip()
        mm = re.match(r"([A-Za-z_]\w*)\s*\[", rhs)
        return rhs, mm.group(1) if mm else None
    if mapping:
        return recv, mapping
    # Bare identifier with no local assignment: a state
    # variable, i.e. a fixed provider, not caller-derived.
    return None, None


def _mapping_registry_managed(scope, fns, mapping: str) -> bool:
    """True when every in-contract write to the provider
    mapping is owner-gated (or in the constructor), or when
    the mapping is never written in-contract at all (set at
    construction / by admin elsewhere): the mapping is a
    registry, not a caller-pickable spoof surface. An ungated
    public setter makes it spoofable."""
    write_re = re.compile(
        rf"\b{re.escape(mapping)}\s*\[[^\]]*\]\s*"
        rf"(?:\.[A-Za-z_]\w*\s*)?=(?!=)")
    writers = [fn for fn in fns if write_re.search(fn["text"])]
    if not writers:
        return True
    for fn in writers:
        if fn["name"] == "constructor":
            continue
        if _caller_gated(fn, scope):
            continue
        return False
    return True


def _price_consumed(text: str, call_pos: int) -> bool:
    """The price-call result flows into a valuation: used in a
    require / if / return / arithmetic, or assigned to a local
    that is read again later in the function."""
    # Statement containing the call.
    start = max(text.rfind(";", 0, call_pos),
                text.rfind("{", 0, call_pos)) + 1
    end = text.find(";", call_pos)
    stmt = text[start:end if end > 0 else len(text)]
    if re.search(r"\b(require|if|return)\b", stmt):
        return True
    # Arithmetic / comparison use in the same statement (a
    # bare `=` assignment alone does NOT count: the assigned
    # variable must be read again, checked below).
    if re.search(r"[\+\-\*/%><!]|==", stmt):
        return True
    am = re.match(
        r"\s*(?:[A-Za-z_][\w<>]*\s+)?([A-Za-z_]\w*)\s*=",
        stmt)
    if am:
        var = am.group(1)
        rest = text[call_pos:]
        if re.search(rf"\b{re.escape(var)}\b", rest):
            return True
    return False


def _analyze_price_provider(src, spec, compiler,
                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        # No view skip here on purpose (Pyth precedent):
        # valuation readers are commonly view, and
        # _price_consumed is the real gate - a function that
        # merely returns an unvalidated provider's price is
        # still the Loopscale surface. Pure functions cannot
        # call an external provider.
        if re.search(r"\bpure\b", fn["signature"]):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        for m in list(_PRICE_CAST_RE.finditer(text)) + \
                list(_PRICE_PLAIN_RE.finditer(text)):
            # Skip the cast regex's inner plain match: a cast
            # call also matches the plain pattern on its
            # interface name; resolve from the cast only.
            if m.re is _PRICE_PLAIN_RE:
                before = text[:m.start()].rstrip()
                if before.endswith(")"):
                    continue
                receiver = m.group(1)
            else:
                receiver = m.group(2)
            provider, mapping = _resolve_provider(
                text, receiver, params)
            if provider is None:
                continue
            # Caller-derived: the provider expression mentions
            # a function parameter (a raw address param, or a
            # mapping / struct read keyed by a parameter).
            if not any(re.search(r"\b" + re.escape(p) + r"\b",
                                 provider) for p in params):
                continue
            # A registry-managed provider mapping is an
            # allowlist: only owner-registered providers are
            # reachable, so the caller cannot spoof one.
            if mapping and _mapping_registry_managed(
                    scope, fns, mapping):
                continue
            # A per-call allowlist / registry check on the
            # provider suppresses: the provider is validated
            # on this path even though it is caller-derived.
            if _PROVIDER_ALLOW_RE.search(text):
                continue
            if _REGISTRY_CALL_RE.search(text) and \
                    re.search(r"\b" + re.escape(provider) +
                             r"\b", text):
                continue
            if re.search(
                    r"require\s*\([^)]*\b" +
                    re.escape(provider.split("[")[0]
                              .split(".")[0]) +
                    r"\b[^)]*==", text):
                continue
            if not _price_consumed(text, m.start()):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' prices collateral "
                f"from provider '{provider}' - derived from "
                f"caller-supplied input "
                f"({mapping + ' mapping' if mapping else 'a raw address parameter'}) "
                f"with no allowlist / registry check on the "
                f"provider address, and uses the returned price "
                f"in a valuation. Gate analysis: no "
                f"caller-identity gate on the valuation path, "
                f"no allowlist / registry validation of the "
                f"provider, no owner-gated setter guarding the "
                f"provider mapping.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        "ungated valuation: caller-derived price "
                        "provider with no allowlist / registry "
                        "check")
            out.append(_finish_recipient(spec, item, text))
            break
    return out


# ---------------------------------------------------------------------------
# 2. Token-transfer hook CEI violation (Cream / AMP shape)
# ---------------------------------------------------------------------------

_ACCT_WRITE_RE = re.compile(
    r"\b(?:balances|_balances|deposits|shares|accountBalances|"
    r"userBalances|credits|stakeBalances|positions|"
    r"userShares|balancesOf)\s*\[[^\]]+\]\s*"
    r"(?:\+=|-=|=(?!=))")
_TOKEN_XFER_RE = re.compile(
    r"([A-Za-z_]\w*(?:\s*\([^()]*\))?)\s*\.\s*"
    r"(transfer|transferFrom|safeTransfer|safeTransferFrom)"
    r"\s*\(")
_REENTRANCY_GUARD_RE = re.compile(
    r"nonReentrant|ReentrancyGuard|_nonReentrant|"
    r"require\s*\(\s*!?\s*locked\b|"
    r"if\s*\(\s*locked\b|_status\s*==|reentrancyLocked")
_FLOW_FN_RE = re.compile(
    r"deposit|withdraw|redeem|mint|burn|unstake|claim|collect",
    re.I)


def _analyze_token_cei(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # The hook fires mid-transfer: find the FIRST token
        # transfer (excluding native .transfer on payable /
        # msg.sender, which carries no token hook) and the
        # FIRST accounting write, and require transfer < write.
        first_xfer = None
        for m in _TOKEN_XFER_RE.finditer(text):
            recv = re.sub(r"\s+", "", m.group(1))
            if recv.startswith("payable(") or \
                    recv in ("msg.sender", "_msgSender()"):
                continue
            first_xfer = m.start()
            break
        if first_xfer is None:
            continue
        wm = _ACCT_WRITE_RE.search(text)
        if wm is None or wm.start() <= first_xfer:
            continue
        # The shape is the deposit / withdraw / mint flow; a
        # transfer-before-write in an unrelated admin function
        # is not the Cream shape.
        if not _FLOW_FN_RE.search(fn["name"]):
            continue
        # A nonReentrant guard (modifier or in-body check)
        # closes the re-entry window.
        if _REENTRANCY_GUARD_RE.search(fn["signature"]) or \
                _REENTRANCY_GUARD_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' performs a token "
            f"transfer before updating the accounting mapping "
            f"('{wm.group(0)[:60]}' is written after the "
            f"transfer), with no nonReentrant guard, so an "
            f"ERC-777 / 1363 / 677 hook firing mid-transfer "
            f"re-enters against the stale balance. Gate "
            f"analysis: no caller-identity gate, no "
            "nonReentrant guard, accounting updated after "
            "the external token call.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated flow: token transfer before the "
                    "accounting write, no nonReentrant guard")
        out.append(_finish_recipient(spec, item, text))
    return out

# ---------------------------------------------------------------------------
# 3. Forwarder + library calldata-tail sender confusion (Mezo veBTC)
# ---------------------------------------------------------------------------

_FORWARDER_RE = re.compile(
    r"function\s+_msgSender\s*\(|isTrustedForwarder|"
    r"trustedForwarder")
_LIB_NAME_RE = re.compile(
    r"librar|target|logic|impl|executor|module|handler|"
    r"extension|facet", re.I)
_LOWLEVEL_CALL_RE = re.compile(
    r"\.(call|delegatecall)\s*(?:\{[^}]*\})?\s*\(")


def _bytes_params(fn: Dict[str, Any]) -> List[str]:
    """Names of bytes / calldata parameters (user-controlled
    calldata the function can forward)."""
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        if "bytes" in part:
            toks = [t for t in part.split()
                    if t not in ("calldata", "memory", "storage",
                                 "payable")]
            if len(toks) >= 2:
                out.append(toks[-1])
    return out


def _library_forward(text: str, data_vars: List[str]):
    """(call_text) when the function forwards user-controlled
    calldata into an external library call, else None. A
    library call is a low-level .call / .delegatecall carrying
    the calldata, or a method call on a library-ish receiver
    carrying it."""
    if not data_vars:
        return None
    for var in data_vars:
        # Low-level forward: <anything>.call(data) /
        # .delegatecall(data), including (bool ok,) = ...call.
        for m in _LOWLEVEL_CALL_RE.finditer(text):
            paren = text.index("(", m.start())
            inner, _ = _balanced(text, paren)
            args = _split_top(inner)
            if any(re.search(r"\b" + re.escape(var) + r"\b",
                             a) for a in args):
                return text[max(0, m.start() - 60):
                            m.start() + 60]
        # Method forward: <library-ish receiver>.method(data)
        for m in re.finditer(
                r"([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)"
                r"\s*\.\s*([A-Za-z_]\w*)\s*\(", text):
            recv, method = m.group(1), m.group(2)
            if method in ("call", "delegatecall"):
                continue
            if not _LIB_NAME_RE.search(recv):
                continue
            paren = text.index("(", m.start())
            inner, _ = _balanced(text, paren)
            args = _split_top(inner)
            if any(re.search(r"\b" + re.escape(var) + r"\b",
                             a) for a in args):
                return text[max(0, m.start() - 60):
                            m.start() + 60]
    return None


def _sender_dependent_transfer(text: str) -> bool:
    """A transfer / withdraw in the function whose
    authorization or destination depends on the resolved
    sender _msgSender(): a transfer to it, a balance read
    keyed by it, or a require on it."""
    if "_msgSender()" not in text:
        return False
    if re.search(r"\.(transfer|transferFrom|safeTransfer|"
                 r"safeTransferFrom|call)\s*\([^;]{0,120}?"
                 r"_msgSender\s*\(\s*\)", text):
        return True
    if re.search(r"\[[^\]]*_msgSender\s*\(\s*\)\s*\]", text):
        return True
    if re.search(r"require\s*\([^)]*_msgSender\s*\(\s*\)",
                 text):
        return True
    return False


def _analyze_forwarder_library(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Leg (a): the contract resolves senders through a trusted
    # forwarder - an _msgSender() override, or a trusted
    # forwarder reference. Plain OZ Context inheritance
    # (no override, _msgSender() == msg.sender) is NOT a
    # forwarder.
    if not _FORWARDER_RE.search(scoped):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        # The _msgSender() comparison IS the mechanism under
        # analysis, so it never suppresses here: only an only*
        # modifier or a role check does.
        if _caller_gated(fn, scope,
                         gate_re=_IDENTITY_GATE_NO_MSGSENDER_RE):
            continue
        text = fn["text"]
        # Leg (b): user-controlled calldata forwarded into an
        # external library call.
        data_vars = _bytes_params(fn)
        if "msg.data" in text:
            data_vars = data_vars + ["msg.data"]
        fwd = _library_forward(text, data_vars)
        if fwd is None:
            continue
        # Leg (c): a transfer / withdraw in the SAME function
        # authorizes against the resolved sender.
        if not _sender_dependent_transfer(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' resolves the sender "
            f"through a trusted forwarder (_msgSender()) and "
            f"forwards user-controlled calldata into an "
            f"external library call ('{fwd.strip()[:80]}'), "
            f"while a transfer / withdraw in the same function "
            f"authorizes against that resolved sender, so a "
            f"crafted calldata tail can stand in as the sender. "
            f"Gate analysis: no only* / role gate on the "
            f"forwarding path; the _msgSender() check IS the "
            f"claimed authorization being audited, so it does "
            f"not suppress.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "forwarder + library forward + sender-"
                    "dependent transfer in one function, no "
                    "only* / role gate")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. Governance: no snapshot + immediate seat (X100 shape)
# ---------------------------------------------------------------------------

_VOTE_FN_RE = re.compile(
    r"vote|castVote|elect|chooseLeader|selectLeader|nominate",
    re.I)
_LIVE_WEIGHT_RE = re.compile(
    r"balanceOf\s*\(|getVotes\s*\(")
_SNAPSHOT_RE = re.compile(
    r"getPastVotes|getPriorVotes|snapshot|checkpoint|"
    r"getVotesAt|balanceOfAt|pastVotes|priorVotes")
_GRANT_FN_RE = re.compile(
    r"elect|appoint|grantRole|grantSeat|assignSeat|setLeader|"
    r"claimSeat|takeSeat|becomeLeader|inaugurat", re.I)
_GRANT_WRITE_RE = re.compile(
    r"grantRole\s*\(|_grantRole\s*\(|"
    r"\b(?:roles|seats|leaders|members|council|"
    r"representatives)\s*\[[^\]]+\]\s*(?:\+=|-=|=(?!=))|"
    r"\b(?:leader|seatHolder|currentLeader|chair)\s*=")
_TIMELOCK_RE = re.compile(
    r"timelock|eta\b|delay|lockUntil|eligibleAfter|"
    r"activationTime|holdingPeriod|waitPeriod|effectiveAt|"
    r"startTime|block\.timestamp\s*\+|cooldown|vestingPeriod|"
    r"minHold|holdingTime", re.I)


def _analyze_governance_seat(src, spec, compiler,
                             contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # A snapshot anywhere in the contract (getPastVotes /
    # getPriorVotes) means vote weight is checkpointed: the
    # live-weight half cannot hold.
    if re.search(r"getPastVotes|getPriorVotes", scoped):
        return []
    # Leg B candidates: seat-granting functions with no
    # timelock / holding period on the grant.
    grants = []
    for fn in fns:
        if not _GRANT_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if not _GRANT_WRITE_RE.search(fn["text"]):
            continue
        if _TIMELOCK_RE.search(fn["text"]):
            continue
        grants.append(fn)
    if not grants:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _VOTE_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg A: live weight read at vote / election time, no
        # snapshot / checkpoint in the voting function.
        if not _LIVE_WEIGHT_RE.search(text):
            continue
        if _SNAPSHOT_RE.search(text):
            continue
        # The seat must be reachable in the same transaction
        # as the vote: the grant is the vote function itself,
        # is called from it, or is itself public and ungated
        # (the winner claims it immediately).
        reachable = None
        for g in grants:
            if g["name"] == fn["name"]:
                reachable = g
                break
            if re.search(r"\b" + re.escape(g["name"]) +
                         r"\s*\(", text):
                reachable = g
                break
            if not _caller_gated(g, scope):
                reachable = g
                break
        if reachable is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' reads vote weight from "
            f"the live balance (no snapshot / checkpoint) and "
            f"the seat grant '{reachable['name']}' carries no "
            f"timelock or holding period, so tokens held for a "
            f"single transaction elect a seat that is usable in "
            f"the same block. Gate analysis: no snapshot on "
            f"the vote-weight path, no timelock / holding "
            f"period on the seat grant, and the grant is "
            f"reachable in the same transaction as the vote.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated election: live vote weight plus an "
                    "immediate, untimelocked seat grant")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. Vault underwrites an attacker-created pool (Premia V3 shape)
# ---------------------------------------------------------------------------

_POOL_PARAM_RE = re.compile(r"pool|market|pair", re.I)
_FACTORY_CREATE_RE = re.compile(
    r"\b(createPool|createMarket|createPair|createVault|"
    r"deployPool|newPool)\s*\(")
_POOL_METHOD_RE = re.compile(
    r"\.(deposit|mint|addLiquidity|provideLiquidity|stake|"
    r"enter|supply)\s*\(")
_POOL_ALLOW_RE = re.compile(
    r"allowedPools|approvedPools|isApprovedPool|"
    r"whitelistedPools|supportedPools|isValidPool|validPools|"
    r"allowedMarkets|approvedMarkets|isApprovedMarket|"
    r"approvedPairs|allowedPairs")
_POOL_LIQ_RE = re.compile(
    r"totalLiquidity|liquidity\s*(>=|>|<=)|MIN_LIQUIDITY|"
    r"minLiquidity|MINIMUM_LIQUIDITY|reserve\s*(>=|>)")
_POOL_AGE_RE = re.compile(
    r"poolAge|createdAt|MIN_AGE|minAge|age\s*(>=|>)|"
    r"block\.timestamp\s*-\s*\S{0,40}?createdAt|deployedAt")
_POOL_TOKEN_XFER_RE = re.compile(
    r"([A-Za-z_]\w*(?:\s*\([^()]*\))?)\s*\.\s*"
    r"(transfer|transferFrom|safeTransfer|safeTransferFrom)"
    r"\s*\(")


def _caller_derived_receiver(fn_text: str, recv: str,
                             params: List[str]) -> bool:
    """True when a pool-method receiver is caller-derived: an
    address parameter, or a local assigned from a parameter /
    a factory-create call. A bare state variable, a constant,
    `super`, `this`, or a parent-contract name (e.g.
    ERC20PresetMinterPauser.mint, MORPHO.supply on the fixed
    Morpho protocol) is NOT caller-derived: the vault supplies
    a fixed, protocol-owned destination, not an
    attacker-picked pool."""
    if recv in ("super", "this"):
        return False
    if recv in params:
        return True
    am = re.search(
        rf"(?:address(?:\s+payable)?|[A-Za-z_]\w*)\s+"
        rf"{re.escape(recv)}\s*=\s*([^;]+);", fn_text)
    if not am:
        am = re.search(rf"\b{re.escape(recv)}\s*=\s*([^;]+);",
                       fn_text)
    if not am:
        return False
    rhs = am.group(1)
    if _FACTORY_CREATE_RE.search(rhs):
        return True
    return any(re.search(r"\b" + re.escape(p) + r"\b", rhs)
               for p in params)


def _analyze_vault_pool(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        addr_params = _fn_addr_params(fn)
        # Pool variables: a caller-supplied address parameter
        # named pool / market / pair; a local created by a
        # permissionless factory call in this function; or the
        # receiver of a pool-method call - but ONLY when that
        # receiver is caller-derived (a fixed protocol address
        # such as MORPHO, a parent-contract call such as
        # super.mint, or a fixed router is not a pool the
        # caller picked).
        pools = set()
        for p in addr_params:
            if _POOL_PARAM_RE.search(p):
                pools.add(p)
        for m in _FACTORY_CREATE_RE.finditer(text):
            before = text[:m.start()]
            am = re.search(
                r"(?:address(?:\s+payable)?|[A-Za-z_]\w*)\s+"
                r"([A-Za-z_]\w*)\s*=\s*[^;]{0,200}$",
                before)
            if am:
                pools.add(am.group(1))
            else:
                am = re.search(
                    r"\b([A-Za-z_]\w*)\s*=\s*[^;]{0,200}$",
                    before)
                if am:
                    pools.add(am.group(1))
        for m in _POOL_METHOD_RE.finditer(text):
            recv = text[:m.start()].rstrip()
            rm = re.search(r"([A-Za-z_]\w*)\s*$", recv)
            if rm and _caller_derived_receiver(
                    text, rm.group(1), params):
                pools.add(rm.group(1))
        if not pools:
            continue
        # Collateral out: a token transfer TO a pool variable,
        # or a pool-method call on one.
        collateral_out = None
        for m in _POOL_TOKEN_XFER_RE.finditer(text):
            recv = re.sub(r"\s+", "", m.group(1))
            if recv.startswith("payable("):
                continue
            paren = text.index("(", m.start())
            inner, _ = _balanced(text, paren)
            args = _split_top(inner)
            method = m.group(2)
            dest = None
            if method in ("transfer", "safeTransfer") and args:
                dest = args[0]
            elif method in ("transferFrom",
                            "safeTransferFrom") and len(args) >= 2:
                dest = args[1]
            if dest and dest.strip() in pools:
                collateral_out = (
                    f"{method} to '{dest.strip()}'")
                break
        if collateral_out is None:
            for m in _POOL_METHOD_RE.finditer(text):
                recv = text[:m.start()].rstrip()
                rm = re.search(r"([A-Za-z_]\w*)\s*$", recv)
                if rm and rm.group(1) in pools:
                    collateral_out = (
                        f"pool call '{m.group(0).strip()}'")
                    break
        if collateral_out is None:
            continue
        # An allowlist, a minimum-liquidity check, or a pool-age
        # check on this path is the protected shape.
        if _POOL_ALLOW_RE.search(text):
            continue
        if _POOL_LIQ_RE.search(text):
            continue
        if _POOL_AGE_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' sends collateral into "
            f"a pool / market ({collateral_out}) that is "
            f"caller-supplied or freshly created via a "
            f"permissionless factory in the same call, with no "
            f"allowlist, minimum-liquidity, or age check on the "
            f"pool, so the pool creator can withdraw the "
            f"collateral as liquidity. Gate analysis: no "
            f"caller-identity gate on the vault path, no "
            f"allowlist / liquidity / age validation of the "
            f"pool.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated vault: collateral into a "
                    "caller-supplied / freshly created pool, no "
                    "allowlist / liquidity / age check")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "lending_collateral_price_provider_unvalidated":
        _analyze_price_provider,
    "callback_token_cei_violation": _analyze_token_cei,
    "forwarder_library_msgdata_tail_confusion":
        _analyze_forwarder_library,
    "governance_no_snapshot_immediate_seat":
        _analyze_governance_seat,
    "vault_underwrites_attacker_created_pool":
        _analyze_vault_pool,
}


def analyze_deep14_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-14 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)

# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-13 collection / fetch /
# proxy resolution; analysis is analyze_deep14_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit14Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 14)"
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
        for item in analyze_deep14_source(
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
                source="deep audit detector batch 14 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit14Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 14) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
