"""Deep-audit detectors, batch 20: claims, bridges, auctions, lending.

Five chain-agnostic EVM detectors from the standing backlog queue,
built to the batch-11 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- merkle_claim_no_claimed_marker: a claim() function verifies a
  Merkle proof (MerkleProof.verify / verifyCalldata /
  processProof) and moves value to the caller, but never writes
  a claimed marker anywhere on the path (no claimed[] write, no
  setClaimed / bitmap mark, no used/redeemed marker). The same
  proof + claim replays forever and drains the distributor - the
  airdrop double-claim shape. A claimed[msg.sender] = true
  (or a bitmap / setClaimed mark) before the payout is the
  protected shape. Distinct from claim_callback_before_claimed_flag
  (batch 15, callback ordering): this one fires when the marker
  write is absent entirely, not merely late.
- lzreceive_no_origin_validation: a LayerZero lzReceive() (or
  CCIP ccipReceive()) entry point executes the cross-chain
  payload - state write or value move - with no origin
  validation anywhere on the path (no _origin / srcEid check,
  no trusted-remote check, no onlyEndpoint / onlyRouter gate).
  Any caller can spoof a message from any chain and drive the
  payload handler. A trusted-remote / srcEid check (or an
  onlyEndpoint / onlyRouter gate, which already suppresses
  under the gate discipline) is the protected shape.
- auction_bid_no_prior_refund: a payable bid() / placeBid()
  overwrites highestBid / highestBidder with no refund leg for
  the previous highest bidder anywhere on the path (no direct
  payout to the previous bidder, no pendingReturns credit for
  them, no refunds mapping write). Every outbid bidder's funds
  lock in the contract forever. A pendingReturns[highestBidder]
  credit (pull pattern) or a direct refund is the protected
  shape. No value moves to a stranger here - the loss is locked
  funds, not a stranger drain - so this detector carries no
  recipient classification, like weak_onchain_randomness.
- borrow_no_collateral_check: a borrow() function moves value
  to the caller with no collateral check anywhere on the path
  (no require on collateral / health factor, no
  getAccountLiquidity / borrowAllowed / comptroller hook, no
  solvency check). The loan is uncollateralized by construction.
  A collateral / health-factor require (or a comptroller
  borrowAllowed call) is the protected shape.
- liquidation_caller_supplied_price: a liquidate*() function
  takes the collateral price as a caller parameter and uses it
  to size the seizure, with no oracle read anywhere in the
  function (no latestRoundData / getPrice / priceFeed /
  AggregatorV3 read). The liquidator prices the collateral
  themselves, so they can seize at a self-chosen price. An
  oracle price read (Chainlink / Pyth / internal TWAP) with no
  price parameter is the protected shape.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path.

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
FAMILY = "deep20"

SPECS = [
    S("merkle_claim_no_claimed_marker", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Merkle claim with no claimed marker: a function "
             "verifies a Merkle proof and moves value to the "
             "caller, but never writes a claimed marker on the "
             "path (no claimed[] write, no setClaimed / bitmap "
             "mark, no used / redeemed marker), so the same "
             "proof and claim replay forever and drain the "
             "distributor - the airdrop double-claim shape. A "
             "claimed[msg.sender] = true (or bitmap / "
             "setClaimed mark) before the payout is the "
             "protected shape.",
      fix="Mark every claim as claimed before paying it out: "
          "write claimed[msg.sender] = true (or set the "
          "claimed bitmap) at the top of the claim function, "
          "and require(!claimed[msg.sender]) before "
          "verifying the proof."),
    S("lzreceive_no_origin_validation", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Cross-chain receive with no origin validation: "
             "lzReceive() / ccipReceive() executes the payload "
             "(state write or value move) with no check on "
             "where the message came from - no _origin / "
             "srcEid check, no trusted-remote check, no "
             "onlyEndpoint / onlyRouter gate - so any caller "
             "can spoof a message from any chain and drive the "
             "payload handler. A trusted-remote / srcEid "
             "check (or an onlyEndpoint / onlyRouter gate) is "
             "the protected shape.",
      fix="Validate the message origin inside lzReceive / "
          "ccipReceive: require the sender equals the "
          "trusted remote for _origin.srcEid (LayerZero) or "
          "that msg.sender is the CCIP router, and revert "
          "otherwise. Never execute a payload from an "
          "unchecked origin."),
    S("auction_bid_no_prior_refund", FAMILY, severity="medium",
      outcome="a", recipient=False,
      detail="Auction bid strands the previous bidder: a "
             "payable bid() / placeBid() overwrites highestBid "
             "/ highestBidder with no refund leg for the "
             "previous highest bidder anywhere on the path "
             "(no direct payout to them, no pendingReturns "
             "credit, no refunds mapping write), so every "
             "outbid bidder's funds lock in the contract "
             "forever. A pendingReturns[highestBidder] credit "
             "(pull pattern) or a direct refund is the "
             "protected shape.",
      fix="Refund the previous highest bidder on every new "
          "bid: credit pendingReturns[highestBidder] += "
          "highestBid (pull pattern) or pay them out "
          "directly, before overwriting highestBid / "
          "highestBidder."),
    S("borrow_no_collateral_check", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Borrow with no collateral check: a borrow() "
             "function moves value to the caller with no "
             "collateral check anywhere on the path (no "
             "require on collateral / health factor, no "
             "getAccountLiquidity / borrowAllowed / comptroller "
             "hook, no solvency check), so the loan is "
             "uncollateralized by construction. A collateral / "
             "health-factor require (or a comptroller "
             "borrowAllowed call) is the protected shape.",
      fix="Check collateral before lending: require the "
          "borrower's collateral value (or health factor) "
          "covers the loan, or route the check through the "
          "comptroller (borrowAllowed / getAccountLiquidity) "
          "and revert when it fails."),
    S("liquidation_caller_supplied_price", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Liquidation priced by the liquidator: a "
             "liquidate*() function takes the collateral "
             "price as a caller parameter and uses it to size "
             "the seizure, with no oracle read anywhere in "
             "the function (no latestRoundData / getPrice / "
             "priceFeed / AggregatorV3 read), so the "
             "liquidator prices the collateral themselves and "
             "can seize at a self-chosen price. An oracle "
             "price read (Chainlink / Pyth / internal TWAP) "
             "with no price parameter is the protected shape.",
      fix="Price liquidations from an oracle, never from a "
          "caller parameter: read the collateral price with "
          "latestRoundData / getPrice (with a staleness "
          "check) inside the liquidation function and drop "
          "the price parameter."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19)
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
    r"hasRole\s*\(|_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]*\b")


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses. The signature check and the
    _msgSender() gate under analysis are NOT gates here.
    """
    sig, text = fn["signature"], fn["text"]
    if _ONLY_MOD_RE.search(sig) or _IDENTITY_GATE_RE.search(text):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        _, pend = _balanced(stripped, i)
        tail = stripped[pend + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and ("msg.sender" in body and
                         ("==" in body or "!=" in body)):
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


def _fn_body(text: str) -> str:
    """The function body (after the first `{`), for searches
    that must not match the signature's own parameter names."""
    i = text.find("{")
    return text[i + 1:] if i >= 0 else text


def _called_internal_texts(fn_text: str, scope) -> str:
    """Text of internal functions this function calls.

    A claimed-marker write, a collateral check, or a refund
    leg may live in a small internal helper (_markClaimed,
    _checkCollateral, _refundPreviousBidder) rather than in
    the entry point itself. A bare `foo(` call whose name
    matches a function defined in this contract is treated
    as an internal call; external calls (obj.foo(), token
    .transfer) and builtins (require, keccak256) never match
    a defined function name, so they are excluded.
    """
    defined = {f["name"]: f["text"] for f in scope.functions}
    out: List[str] = []
    for m in re.finditer(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                         fn_text):
        name = m.group(1)
        if name in defined and defined[name] not in out:
            out.append(defined[name])
    return "\n".join(out)


def _acts_after(text: str, pos: int, state: set) -> bool:
    """A state write or external call after `pos` in the function."""
    for p, _v in cl._state_writes(text, state):
        if p > pos:
            return True
    for c in cl._external_calls(text):
        if c["pos"] > pos:
            return True
    return False


_VALUE_MOVE_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*transferFrom\s*\(|"
    r"safeTransfer\s*\(|safeTransferFrom\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\.\s*send\s*\(|\.\s*transfer\s*\{\s*value")


def _moves_value(text: str) -> bool:
    """A token / ETH payout of some kind in the function."""
    return bool(_VALUE_MOVE_RE.search(text))


# ---------------------------------------------------------------------------
# Claim / bridge / auction / lending patterns
# ---------------------------------------------------------------------------

# A Merkle proof verification call (OZ MerkleProof library).
_MERKLE_VERIFY_RE = re.compile(
    r"MerkleProof\s*\.\s*(?:verify|verifyCalldata|processProof)"
    r"\s*\(")

# A claimed-marker WRITE. A require(!claimed[x]) read is not a
# write: the bracket write needs `=` not followed by `=` (so
# `==` / `!=` comparisons never match) and not preceded by a
# comparison operator.
_CLAIMED_WRITE_RES = (
    re.compile(r"\bclaimed\w*\s*\[[^\]]*\]\s*=(?!=)"),
    re.compile(r"\bredeemed\w*\s*\[[^\]]*\]\s*=(?!=)"),
    re.compile(r"\bused\w*\s*\[[^\]]*\]\s*=\s*true\b"),
    re.compile(r"_?setClaimed\s*\("),
    re.compile(r"claimedBitMap"),
    re.compile(r"\bmarkClaimed\s*\("),
    re.compile(r"\bclaimBitmap\w*\s*\|="),
)


def _claimed_marker_written(text: str) -> bool:
    return any(p.search(text) for p in _CLAIMED_WRITE_RES)


# A cross-chain origin validation, searched in the function
# BODY only: the standard lzReceive / ccipReceive signatures
# themselves declare _origin / srcEid parameters, so the bare
# words in the signature prove nothing - the check has to
# actually use them (a _origin.sender read, a srcEid
# comparison, a trusted-remote lookup).
_ORIGIN_CHECK_RES = (
    re.compile(r"_origin\s*\.\s*(?:sender|srcEid)"),
    re.compile(r"\bsrcEid\s*(?:==|!=)"),
    re.compile(r"trustedRemote\w*\s*\["),
    re.compile(r"allowlisted\w*\s*\["),
    re.compile(r"allowedSource\w*\s*\["),
    re.compile(r"require\s*\([^)]*(?:origin|trusted|srcEid)",
               re.I),
)


def _origin_validated(body: str) -> bool:
    return any(p.search(body) for p in _ORIGIN_CHECK_RES)


# The previous bidder in an auction, by the names contracts use.
_PREV_BIDDER = r"(?:highestBidder|prevBidder|previousBidder|lastBidder)"
_REFUND_LEG_RES = (
    # Direct payout to the previous bidder.
    re.compile(r"payable\s*\(\s*" + _PREV_BIDDER + r"\s*\)\s*\."
               r"\s*(?:transfer|send|call)\s*\("),
    re.compile(_PREV_BIDDER + r"\s*\.\s*(?:transfer|call)\s*\("),
    # Pull-pattern credit for the previous bidder.
    re.compile(r"pendingReturns\s*\[\s*" + _PREV_BIDDER +
               r"\s*\]\s*\+="),
    re.compile(r"pendingReturns\s*\[\s*" + _PREV_BIDDER +
               r"\s*\]\s*="),
    re.compile(r"\brefunds\s*\["),
    re.compile(r"\bpendingRefunds\s*\["),
)


def _prior_refunded(text: str) -> bool:
    return any(p.search(text) for p in _REFUND_LEG_RES)


# A real collateral check on the borrow path: a require /
# comparison on collateral or health, or a comptroller /
# solvency hook call. A bare mention of a collateral token
# parameter is NOT a check - the check has to compare or call.
_COLLATERAL_CHECK_RES = (
    re.compile(r"require\s*\([^)]*(?:collateral|health|"
               r"liquid|solven)", re.I),
    re.compile(r"(?:healthFactor|health_factor)\s*(?:>=|>|<=|<)"),
    re.compile(r"(?:collateral\w*|collateralValue|collateralBalance)"
               r"[^;]{0,80}(?:>=|>|<=|<)"),
    re.compile(r"(?:>=|>|<=|<)[^;]{0,80}"
               r"(?:collateral\w*|healthFactor)"),
    re.compile(r"\bborrowAllowed\s*\("),
    re.compile(r"\bgetAccountLiquidity\s*\("),
    re.compile(r"\bcomptroller\s*\.", re.I),
    re.compile(r"\bisSolvent\s*\("),
    re.compile(r"\bborrowCapacity\s*\("),
    re.compile(r"\bmaxBorrow\w*\s*(?:>=|>|<=|<)"),
)


def _collateral_checked(text: str) -> bool:
    return any(p.search(text) for p in _COLLATERAL_CHECK_RES)


# An oracle price read (a call, not a parameter name): the
# price comes from a feed, not from the caller.
_ORACLE_READ_RES = (
    re.compile(r"latestRoundData\s*\("),
    re.compile(r"\bgetPrice\s*\("),
    re.compile(r"\bgetUnderlyingPrice\s*\("),
    re.compile(r"\bgetAssetPrice\s*\("),
    re.compile(r"\bfetchPrice\s*\("),
    re.compile(r"priceFeed\s*\.", re.I),
    re.compile(r"AggregatorV3Interface"),
    re.compile(r"\boracle\s*\.\s*(?:latestRoundData|getPrice|"
               r"price)\b", re.I),
    re.compile(r"\bChainlink\b"),
    re.compile(r"\bPyth\b"),
)


def _oracle_read(text: str) -> bool:
    return any(p.search(text) for p in _ORACLE_READ_RES)


# ---------------------------------------------------------------------------
# 1. merkle_claim_no_claimed_marker
# ---------------------------------------------------------------------------

def _analyze_merkle_claim(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if "claim" not in fn["name"].lower():
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _MERKLE_VERIFY_RE.search(text):
            continue
        if not _moves_value(text):
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if _claimed_marker_written(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a Merkle proof "
            f"with MerkleProof.verify and pays out value, but "
            f"no claimed marker is written anywhere on the "
            f"path (no claimed[] write, no setClaimed / "
            f"bitmap mark, no used / redeemed marker, not "
            f"even in an internal helper it calls), so the "
            f"same proof and claim replay indefinitely. Gate "
            f"analysis: no caller-identity gate, no claimed "
            f"marker on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated Merkle claim: proof verified, "
                    "value paid, no claimed marker written")
        out.append(_finish_recipient(spec, item, text))
    return out


# An address local decoded from the caller-supplied cross-chain
# payload: `(address to, ...) = abi.decode(payload, ...)` - the
# caller chooses the payload bytes, so they choose the address.
_ABI_DECODE_ADDR_RE = re.compile(
    r"\(\s*address\s+(\w+)[^;]*\)\s*=\s*abi\.decode\s*\(\s*"
    r"(\w+)\s*,")


def _payload_decoded_dest(text: str, params: List[str]
                          ) -> Optional[str]:
    """Address local decoded from a caller parameter, or None.

    The shared recipient classifier reads a payload-decoded
    local as FIXED (it is neither a parameter nor msg.sender),
    but the payload itself is caller-supplied: whoever calls
    lzReceive chooses the bytes, so whoever they decode to is
    a caller-chosen destination - CALLER-SUPPLIED, not FIXED.
    """
    for m in _ABI_DECODE_ADDR_RE.finditer(text):
        dest, src = m.group(1), m.group(2)
        if src in params:
            return dest
    return None

def _analyze_lzreceive(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        # Only the public entry points: the internal _lzReceive
        # helper is supposed to run unchecked behind a gated
        # lzReceive, so it is out of scope by name.
        if fn["name"].lower() not in ("lzreceive", "ccipreceive"):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # The payload must do something: a state write or an
        # external call anywhere in the entry point.
        acts = (bool(list(cl._state_writes(text, state))) or
                bool(cl._external_calls(text)))
        if not acts:
            continue
        if _origin_validated(_fn_body(text)):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' executes the "
            f"cross-chain payload (state write / external "
            f"call) with no origin validation anywhere in "
            f"the function - no _origin / srcEid check, no "
            f"trusted-remote check, no onlyEndpoint / "
            f"onlyRouter gate - so any caller can spoof a "
            f"message from any chain. Gate analysis: no "
            f"caller-identity gate, no origin check on the "
            f"path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated cross-chain receive: payload "
                    "executes with no origin validation")
        recipient, rdetail = cl.classify_recipient(text)
        # Payload-decoded destination: the classifier reads a
        # local decoded from abi.decode(payload) as FIXED, but
        # the payload is caller-supplied, so the decoded
        # address is caller-chosen - a stranger receives here.
        if recipient == "FIXED":
            dest = _payload_decoded_dest(text, _fn_params(fn))
            if dest and _moves_value(text):
                recipient = "CALLER-SUPPLIED"
                rdetail = (f"destination '{dest}' decoded from "
                           f"the caller-supplied cross-chain "
                           f"payload")
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 3. auction_bid_no_prior_refund
# ---------------------------------------------------------------------------

_BID_NAME_RE = re.compile(r"^(?:bid|placeBid)$", re.I)
_HIGHEST_SET_RE = re.compile(
    r"\bhighestBid\w*\s*=(?!=)|\bhighestBidder\s*=(?!=)")


def _analyze_auction_bid(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BID_NAME_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if "payable" not in fn["signature"] and \
                "msg.value" not in text:
            continue
        if not _HIGHEST_SET_RE.search(text):
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if _prior_refunded(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' is payable and "
            f"overwrites highestBid / highestBidder, but no "
            f"refund leg for the previous highest bidder "
            f"exists anywhere on the path (no direct payout "
            f"to them, no pendingReturns credit, no refunds "
            f"mapping write, not even in an internal helper "
            f"it calls), so every outbid bidder's funds lock "
            f"in the contract. Gate analysis: no "
            f"caller-identity gate, no refund on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated auction bid: highest bid "
                    "overwritten, previous bidder never refunded")
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 4. borrow_no_collateral_check
# ---------------------------------------------------------------------------

def _analyze_borrow(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not fn["name"].lower().startswith("borrow"):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _moves_value(text):
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if _collateral_checked(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' moves value to the "
            f"caller with no collateral check anywhere on "
            f"the path (no require on collateral / health "
            f"factor, no getAccountLiquidity / borrowAllowed "
            f"/ comptroller hook, no solvency check, not "
            f"even in an internal helper it calls), so the "
            f"loan is uncollateralized by construction. Gate "
            f"analysis: no caller-identity gate, no "
            f"collateral check on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated borrow: value paid out with no "
                    "collateral check")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. liquidation_caller_supplied_price
# ---------------------------------------------------------------------------

def _analyze_liquidation_price(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not fn["name"].lower().startswith("liquidate"):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        price_params = [p for p in params
                        if "price" in p.lower()]
        if not price_params:
            continue
        body = _fn_body(text)
        used = [p for p in price_params
                if re.search(r"\b" + re.escape(p) + r"\b", body)]
        if not used:
            continue
        if _oracle_read(body):
            continue
        first_use = min(body.find(p) for p in used)
        if not _acts_after(body, first_use, state):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' takes the collateral "
            f"price as a caller parameter ({', '.join(used)}) "
            f"and uses it to size the seizure, with no oracle "
            f"read anywhere in the function, so the liquidator "
            f"prices the collateral themselves. Gate "
            f"analysis: no caller-identity gate, no oracle "
            f"price on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated liquidation: caller-supplied "
                    "price sizes the seizure, no oracle read")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "merkle_claim_no_claimed_marker": _analyze_merkle_claim,
    "lzreceive_no_origin_validation": _analyze_lzreceive,
    "auction_bid_no_prior_refund": _analyze_auction_bid,
    "borrow_no_collateral_check": _analyze_borrow,
    "liquidation_caller_supplied_price": _analyze_liquidation_price,
}


def analyze_deep20_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-20 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep20_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit20Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 20)"
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
        for item in analyze_deep20_source(
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
                source="deep audit detector batch 20 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit20Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 20) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
