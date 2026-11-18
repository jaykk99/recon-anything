"""Deep-audit detectors, batch 25: batch-mint underpayment,
multicall delegatecall, auction deadline, bridge deposit value,
merkle amount binding.

Five chain-agnostic EVM detectors from the standing backlog queue,
built to the batch-11 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- nft_batch_mint_underpayment: a mint / buy / purchase function
  that mints a caller-supplied quantity of tokens (a per-unit
  loop over the quantity, or a batch-mint call sized by it)
  while the msg.value payment check prices ONE token only
  (require(msg.value >= price) with no price * quantity term),
  so quantity tokens mint for the price of one - the canonical
  per-unit underpayment shape (a recurring Code4rena audit
  finding across NFT mints). require(msg.value >= price *
  quantity) is the protected shape; a mint with no payment
  check at all is a free mint, not this shape (covered by
  recipient_mint_to_caller), and stays silent here.
- multicall_arbitrary_delegatecall: a multicall / batch /
  aggregate function that takes an address-array of targets
  and a bytes-array of calldata and delegatecalls a
  caller-supplied target with caller-supplied calldata, with
  no target allowlist anywhere on the path. The delegatecall
  runs in the contract's own context, so the caller executes
  arbitrary code as the contract - storage rewrite, balance
  drain, selfdestruct - the canonical arbitrary-delegatecall
  shape (a critical audit finding wherever a batch entry
  point meets delegatecall). Delegatecalling a stored
  implementation, or require()ing the target against an
  allowlist, is the protected shape. Distinct from
  multicall_value_reuse (batch 8, msg.value reused across
  sub-calls - this one is non-payable and never reads
  msg.value) and from proxy_delegatecall_selfdestruct (the
  delegatecall must reach a selfdestruct there).
- auction_bid_after_deadline: a payable bid() / placeBid()
  that overwrites highestBid / highestBidder while the
  auction HAS a declared deadline (an endTime / auctionEnd /
  deadline term exists in the contract) but no deadline check
  is enforced on the bid path (no require/if comparing
  block.timestamp against the deadline, not even in a helper
  or a modifier the bid carries). Late bids keep landing at
  stale prices after the auction should have closed - the
  canonical unenforced-deadline shape. A bid that enforces
  require(block.timestamp < auctionEnd) is the protected
  shape; an auction with no deadline declared anywhere stays
  silent (nothing to enforce, possibly by design). This one
  is NOT a recipient detector (locked / stale-price funds
  are not a stranger drain, per the batch-20 auction
  precedent): it fires without a candidate classification,
  at medium severity. Distinct from
  auction_bid_no_prior_refund (batch 20, the previous bidder
  is never refunded - this one is the deadline, and the
  fixture refunds the previous bidder via the pull pattern).
- bridge_deposit_value_unbound_to_msgvalue: a payable
  deposit / lock function that credits a caller-supplied
  amount to a ledger (deposits[to] += amount) with NO
  msg.value comparison anywhere on the path, so the caller
  deposits 0 ETH and is credited the full amount - the
  canonical native-deposit accounting flaw. require(msg.value
  == amount), or crediting msg.value itself instead of the
  amount parameter, is the protected shape; a non-payable
  deposit (ERC20 pulled via transferFrom) is out of scope
  and stays silent. Distinct from bridge_deposit_event_spoofing
  (a deposit CLAIM with no proof - this one is a real deposit
  call that takes no native value) and from
  masterchef_deposit_fee_skimming (a fee taken out of the
  transfer - this one takes no value at all).
- merkle_proof_amount_unbound: a claim function that verifies
  a Merkle proof whose leaf is built from the account only
  (keccak256(abi.encodePacked(account)), single- or
  double-hashed) and then pays a caller-supplied amount, so
  any proven account claims ANY amount - the leaf never bound
  the amount, and the proof cannot catch it. The canonical
  unbound-amount Merkle-claim shape. A leaf built as
  keccak256(abi.encodePacked(account, amount)) is the
  protected shape. Distinct from merkle_claim_no_claimed_marker
  (batch 20, the claimed marker is absent entirely - the
  fixture here sets the marker) and from
  merkle_proof_unbounded_leaf_index (batch 24, the leaf
  index is unbound - this one is the amount) and from
  merkle_leaf_single_hash (batch 8, the leaf is hashed once -
  the fixture here double-hashes the leaf).

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
FAMILY = "deep25"

SPECS = [
    S("nft_batch_mint_underpayment", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Batch mint underpays per unit: a mint / buy / "
             "purchase function mints a caller-supplied "
             "quantity of tokens (a per-unit loop over the "
             "quantity, or a batch-mint call sized by it) "
             "while the msg.value payment check prices ONE "
             "token only (require(msg.value >= price) with no "
             "price * quantity term), so quantity tokens mint "
             "for the price of one - the canonical per-unit "
             "underpayment shape (a recurring Code4rena audit "
             "finding across NFT mints). require(msg.value >= "
             "price * quantity) is the protected shape; a mint "
             "with no payment check at all is a free mint, not "
             "this shape, and stays silent here.",
      fix="Price every unit: require(msg.value >= price * "
          "quantity) (or quantity * price) before minting, "
          "and mint exactly quantity tokens for exactly that "
          "payment."),
    S("multicall_arbitrary_delegatecall", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Multicall delegatecalls a caller-supplied "
             "target: a multicall / batch / aggregate function "
             "takes an address-array of targets and a "
             "bytes-array of calldata and delegatecalls a "
             "caller-supplied target with caller-supplied "
             "calldata, with no target allowlist anywhere on "
             "the path, so the caller executes arbitrary code "
             "in the contract's own context (storage rewrite, "
             "balance drain) - the canonical "
             "arbitrary-delegatecall shape. Delegatecalling a "
             "stored implementation, or require()ing the "
             "target against an allowlist, is the protected "
             "shape.",
      fix="Never delegatecall a caller-supplied address: "
          "delegatecall only a stored implementation, or "
          "require the target against an explicit allowlist "
          "before the call, and prefer plain call over "
          "delegatecall for batched sub-calls."),
    S("auction_bid_after_deadline", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="Auction bid lands after the deadline: a payable "
             "bid() / placeBid() overwrites highestBid / "
             "highestBidder while the auction HAS a declared "
             "deadline (an endTime / auctionEnd / deadline "
             "term exists in the contract) but no deadline "
             "check is enforced on the bid path (no require / "
             "if comparing block.timestamp against the "
             "deadline, not even in a helper or a modifier the "
             "bid carries), so late bids keep landing at stale "
             "prices after the auction should have closed - "
             "the canonical unenforced-deadline shape. A bid "
             "that enforces require(block.timestamp < "
             "auctionEnd) is the protected shape; an auction "
             "with no deadline declared anywhere stays silent.",
      fix="Enforce the deadline on every bid: require"
          "(block.timestamp < auctionEnd) (or the contract's "
          "own deadline term) at the top of bid() / "
          "placeBid(), and settle / close the auction when "
          "the deadline passes."),
    S("bridge_deposit_value_unbound_to_msgvalue", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Bridge deposit credits an amount no ETH backs: "
             "a payable deposit / lock function credits a "
             "caller-supplied amount to a ledger (deposits[to] "
             "+= amount) with NO msg.value comparison anywhere "
             "on the path, so the caller deposits 0 ETH and is "
             "credited the full amount - the canonical "
             "native-deposit accounting flaw. require(msg.value "
             "== amount), or crediting msg.value itself "
             "instead of the amount parameter, is the protected "
             "shape; a non-payable deposit (ERC20 pulled via "
             "transferFrom) is out of scope and stays silent.",
      fix="Bind every native deposit to the value actually "
          "sent: require(msg.value == amount) before "
          "crediting the ledger, or credit msg.value itself "
          "instead of the amount parameter."),
    S("merkle_proof_amount_unbound", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Merkle claim pays an amount the proof never "
             "bound: a claim function verifies a Merkle proof "
             "whose leaf is built from the account only "
             "(keccak256(abi.encodePacked(account)), single- "
             "or double-hashed) and then pays a "
             "caller-supplied amount, so any proven account "
             "claims ANY amount - the leaf never bound the "
             "amount, and the proof cannot catch it. A leaf "
             "built as keccak256(abi.encodePacked(account, "
             "amount)) is the protected shape.",
      fix="Bind the amount into the leaf: leaf = keccak256"
          "(abi.encodePacked(account, amount)) (double-hashed "
          "per OpenZeppelin MerkleProof style) so the proof "
          "only verifies for the exact amount the leaf "
          "commits to."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19 / deep24)
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


def _fn_params_typed(fn: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(type, name) parameter pairs from a function signature."""
    sig = fn["signature"]
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    if "(" not in stripped:
        return []
    i = stripped.find("(")
    inner, _ = _balanced(stripped, i)
    out: List[Tuple[str, str]] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append((" ".join(toks[:-1]), toks[-1]))
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


def _applied_modifier_bodies(fn: Dict[str, Any], scope) -> str:
    """Bodies of the modifiers applied to this function.

    A deadline check (or any other enforcement) may live in a
    modifier (auctionOpen, onlyBeforeEnd) rather than in the
    entry point itself.
    """
    sig = fn["signature"]
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i < 0:
        return ""
    _, pend = _balanced(stripped, i)
    tail = stripped[pend + 1:]
    out: List[str] = []
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
        body = scope.modifiers.get(tok)
        if body:
            out.append(body)
    return "\n".join(out)


def _mentions(text: str, param: str) -> bool:
    """A word-boundary mention of a parameter name, excluding
    the `value` inside `msg.value` (a parameter literally named
    `value` must not match the msg.value keyword)."""
    return bool(re.search(r"(?<!msg\.)\b" + re.escape(param) +
                          r"\b", text))


def _dest_class(dest: str, params: List[str],
                state: set) -> Tuple[str, str]:
    """Recipient class of a value destination expression."""
    d = dest.split("[")[0].split(".")[0].strip()
    if d in params:
        return ("CALLER-SUPPLIED",
                f"destination is the caller parameter '{d}'")
    if d == "msg":
        return ("CALLER", "destination is msg.sender")
    if d in state:
        return ("FIXED",
                f"destination is the stored address '{d}'")
    return ("UNRESOLVED", f"destination '{d}'")


_VALUE_MOVE_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*transferFrom\s*\(|"
    r"safeTransfer\s*\(|safeTransferFrom\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\.\s*send\s*\(|\.\s*transfer\s*\{\s*value")


def _moves_value(text: str) -> bool:
    """A token / ETH payout of some kind in the function."""
    return bool(_VALUE_MOVE_RE.search(text))


# ---------------------------------------------------------------------------
# Batch-mint / multicall / auction / bridge-deposit / merkle patterns
# ---------------------------------------------------------------------------

# A Merkle proof verification call (OZ MerkleProof library).
_MERKLE_VERIFY_RE = re.compile(
    r"MerkleProof\s*\.\s*(?:verify|verifyCalldata|processProof)"
    r"\s*\(")


# ---------------------------------------------------------------------------
# 1. nft_batch_mint_underpayment
# ---------------------------------------------------------------------------

_MINT_FN_RE = re.compile(r"mint|buy|purchase", re.I)
_QTY_PARAM_RE = re.compile(
    r"^(?:quantity|count|numTokens|numberToMint|amountToMint|"
    r"amount)$", re.I)
_MINT_CALL_RE = re.compile(r"\b_safeMint\s*\(|\b_mint\s*\(")
_BATCH_MINT_RE = re.compile(
    r"\b(?:_mintBatch|safeMintBatch|_safeMintBatch)\s*\(")


def _qty_priced(expr: str, qty: str) -> bool:
    """The payment expression prices per unit: qty multiplied
    by a price (either order)."""
    return bool(re.search(r"\*\s*" + re.escape(qty) + r"\b|"
                          r"\b" + re.escape(qty) + r"\s*\*",
                          expr))


def _payment_underpaid(body: str, qty: str) -> bool:
    """A msg.value payment require exists and does NOT price
    per unit. No payment require at all is NOT this shape
    (a free mint belongs to recipient_mint_to_caller)."""
    for m in re.finditer(
            r"require\s*\(\s*msg\.value\s*(>=|==)\s*"
            r"([^;]{0,160})\)", body):
        return not _qty_priced(m.group(2), qty)
    for m in re.finditer(
            r"require\s*\(\s*([^;]{0,160}?)\s*(<=|==)\s*"
            r"msg\.value\s*\)", body):
        return not _qty_priced(m.group(1), qty)
    return False


def _mints_quantity(body: str, qty: str) -> bool:
    """A per-unit loop over the quantity that mints, or a
    batch-mint call sized by the quantity."""
    for m in re.finditer(r"\bfor\s*\(", body):
        header, _ = _balanced(body, m.end() - 1)
        if _mentions(header, qty) and _MINT_CALL_RE.search(body):
            return True
    for m in _BATCH_MINT_RE.finditer(body):
        i = body.index("(", m.start())
        inner, _ = _balanced(body, i)
        if _mentions(inner, qty):
            return True
    return False


def _mint_recipient(fn_text: str, params: List[str],
                    state: set) -> Tuple[str, str]:
    """Recipient of the mint: the first argument of the
    _safeMint / _mint call. The shared classifier sees no
    destination in a bare _safeMint(to, id) call, so the
    destination is read here (mirrors batch 24's
    _settle_recipient)."""
    for pat in (r"\b_safeMint\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)",
                r"\b_mint\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)"):
        m = re.search(pat, fn_text)
        if m:
            dest, rdetail = _dest_class(m.group(1), params, state)
            return dest, (f"mint destination: {rdetail}")
    return "UNRESOLVED", "no mint destination found"


def _analyze_nft_mint(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _MINT_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        qty_params = [p for p in params
                      if _QTY_PARAM_RE.match(p)]
        if not qty_params:
            continue
        body = _fn_body(text)
        qty = qty_params[0]
        if not _mints_quantity(body, qty):
            continue
        if not _payment_underpaid(body, qty):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' mints '{qty}' tokens "
            f"(per-unit loop / batch mint over the quantity) "
            f"but its msg.value check prices one token only "
            f"(no price * {qty} term anywhere in the payment "
            f"require), so {qty} tokens mint for the price of "
            f"one. Gate analysis: no caller-identity gate, "
            f"no per-unit pricing on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated batch mint: payment priced for one "
                    "token, quantity minted")
        recipient, rdetail = _mint_recipient(text, params, state)
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 2. multicall_arbitrary_delegatecall
# ---------------------------------------------------------------------------

_MULTICALL_NAME_RE = re.compile(r"multicall|batch|aggregate",
                                re.I)
_ALLOWLIST_RE = re.compile(
    r"allowlist|whitelist|allowedTargets|isAllowed|"
    r"approvedTargets", re.I)


def _analyze_multicall(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _MULTICALL_NAME_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        typed = _fn_params_typed(fn)
        addr_params = [n for (t, n) in typed
                       if t.startswith("address[")]
        bytes_params = [n for (t, n) in typed
                        if t.startswith("bytes[")]
        if not addr_params or not bytes_params:
            continue
        body = _fn_body(fn["text"])
        target_param = None
        data_param = None
        for m in re.finditer(r"\.delegatecall\s*\(", body):
            head = body[:m.start()]
            rm = re.search(
                r"([A-Za-z_][A-Za-z0-9_]*"
                r"(?:\s*\[[^\]]*\])?)\s*$", head)
            if not rm:
                continue
            recv = rm.group(1)
            ap = [p for p in addr_params
                  if _mentions(recv, p)]
            if not ap:
                continue
            i = body.index("(", m.start())
            inner, _ = _balanced(body, i)
            bp = [p for p in bytes_params
                  if _mentions(inner, p)]
            if not bp:
                continue
            target_param, data_param = ap[0], bp[0]
            break
        if target_param is None:
            continue
        searched = fn["text"] + "\n" + _called_internal_texts(
            fn["text"], scope)
        if _ALLOWLIST_RE.search(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' delegatecalls the "
            f"caller-supplied target '{target_param}' with the "
            f"caller-supplied calldata '{data_param}' and no "
            f"target allowlist exists anywhere on the path "
            f"(not even in an internal helper it calls), so "
            f"the caller executes arbitrary code in the "
            f"contract's own context. Gate analysis: no "
            f"caller-identity gate, no target allowlist on "
            f"the path.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "ungated multicall: delegatecall to a "
                    "caller-supplied target with caller-supplied "
                    "calldata")
        out.append(_classify(
            item, "CALLER",
            f"delegatecall target is the caller parameter "
            f"'{target_param}': the caller executes arbitrary "
            f"code in the contract's context and can move its "
            f"balance / rewrite its storage"))
    return out


# ---------------------------------------------------------------------------
# 3. auction_bid_after_deadline
# ---------------------------------------------------------------------------

_BID_NAME_RE = re.compile(r"^(?:bid|placeBid)$", re.I)
_HIGHEST_SET_RE = re.compile(
    r"\bhighestBid\w*\s*=(?!=)|\bhighestBidder\s*=(?!=)")
_DEADLINE_TERM_RE = re.compile(
    r"endTime|auctionEnd|deadline|expiresAt|expiry|"
    r"endTimestamp|biddingEnd|closeTime|auctionDeadline", re.I)
# A deadline actually DECLARED as a timestamp value (a uint
# state variable / parameter named like a deadline). A bare
# word match is not enough: a contract literally named
# "AuctionNoDeadline" must not count as declaring one.
_DEADLINE_DECLARED_RE = re.compile(
    r"\buint\d*\b[^;{]{0,60}\b(?:endTime|auctionEnd|deadline|"
    r"expiresAt|expiry|endTimestamp|biddingEnd|closeTime|"
    r"auctionDeadline)\b", re.I)


def _deadline_enforced(searched: str) -> bool:
    """A require / if / assert that compares block.timestamp
    against a deadline term in the same statement. A bare
    read of the deadline with no timestamp comparison does
    not enforce anything."""
    for m in re.finditer(
            r"(?:require|if|assert)\s*\(([^;]{0,300})\)",
            searched):
        stmt = m.group(1)
        if not _DEADLINE_TERM_RE.search(stmt):
            continue
        if "block.timestamp" not in stmt:
            continue
        if re.search(r"<|<=|>|>=", stmt):
            return True
    return False


def _analyze_auction_deadline(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    if not _DEADLINE_DECLARED_RE.search(scoped):
        # No deadline declared anywhere in the contract: there
        # is nothing to enforce (possibly by design).
        return []
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
        searched = text + "\n" + _called_internal_texts(
            text, scope) + "\n" + _applied_modifier_bodies(
                fn, scope)
        if _deadline_enforced(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' is payable and "
            f"overwrites highestBid / highestBidder, the "
            f"contract declares a deadline, but no require / "
            f"if compares block.timestamp against that "
            f"deadline anywhere on the bid path (not in the "
            f"function, not in an internal helper it calls, "
            f"not in a modifier it carries), so bids keep "
            f"landing after the auction should have closed. "
            f"Gate analysis: no caller-identity gate, no "
            f"deadline enforcement on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated auction bid: highest bid set with "
                    "no deadline enforcement on the path")
        # No recipient classification: locked / stale-price
        # funds are not a stranger drain (batch-20 auction
        # precedent).
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 4. bridge_deposit_value_unbound_to_msgvalue
# ---------------------------------------------------------------------------

_DEPOSIT_NAME_RE = re.compile(r"deposit", re.I)
_LOCK_NAME_RE = re.compile(r"^lock", re.I)
_AMOUNT_PARAM_RE = re.compile(
    r"^(?:amount|depositAmount|value)$", re.I)
_CREDIT_MAP_RE = re.compile(
    r"\b(?:deposits|balances|locked|credits|lockedAmounts|"
    r"deposited)\s*\[([^\]]+)\]\s*(?:\+=|=(?!=))")
_MSGVALUE_CMP_RE = re.compile(
    r"msg\.value\s*(?:==|!=|>=|<=|>|<)|"
    r"(?:==|!=|>=|<=|>|<)\s*msg\.value")


def _credit_of_amount(body: str, amount_params: List[str]
                      ) -> Optional[Tuple[str, str]]:
    """(ledger key, amount param) for a mapping credit of an
    amount parameter, else None. The credit's statement must
    mention the amount parameter itself - crediting msg.value
    is the protected shape, not this one."""
    for m in _CREDIT_MAP_RE.finditer(body):
        stmt_end = body.find(";", m.start())
        stmt = body[m.start():
                    stmt_end if stmt_end >= 0 else len(body)]
        for p in amount_params:
            if _mentions(stmt, p):
                return m.group(1).strip(), p
    return None


def _analyze_bridge_deposit(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not (_DEPOSIT_NAME_RE.search(fn["name"]) or
                _LOCK_NAME_RE.match(fn["name"])):
            continue
        if _skip_fn(fn, scope):
            continue
        if "payable" not in fn["signature"]:
            continue
        text = fn["text"]
        params = _fn_params(fn)
        amount_params = [p for p in params
                         if _AMOUNT_PARAM_RE.match(p)]
        if not amount_params:
            continue
        body = _fn_body(text)
        credit = _credit_of_amount(body, amount_params)
        if credit is None:
            continue
        key, amount_param = credit
        searched = text + "\n" + _called_internal_texts(text, scope)
        if _MSGVALUE_CMP_RE.search(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' is payable and credits "
            f"the caller-supplied amount '{amount_param}' to "
            f"the ledger for '{key}' with no msg.value "
            f"comparison anywhere on the path (not even in an "
            f"internal helper it calls), so the caller "
            f"deposits 0 ETH and is credited the full amount. "
            f"Gate analysis: no caller-identity gate, no "
            f"native-value binding on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated native deposit: ledger credited "
                    "with the amount parameter, msg.value never "
                    "checked")
        recipient, rdetail = _dest_class(key, params, state)
        if recipient == "UNRESOLVED":
            rdetail = (f"deposit credits the ledger for "
                       f"'{key}' ({rdetail})")
        else:
            rdetail = (f"deposit credits the ledger for "
                       f"'{key}': {rdetail}")
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 5. merkle_proof_amount_unbound
# ---------------------------------------------------------------------------

_CLAIM_NAME_RE = re.compile(r"claim", re.I)
_MERKLE_AMOUNT_PARAM_RE = re.compile(
    r"^(?:amount|value|payout|reward|claimAmount)$", re.I)


def _payout_uses_amount(body: str, amount_params: List[str]
                        ) -> Optional[str]:
    """An amount parameter passed into a payout call, else None."""
    for p in amount_params:
        for m in re.finditer(
                r"\.\s*(?:transfer|transferFrom|safeTransfer|"
                r"safeTransferFrom)\s*\(", body):
            i = body.index("(", m.start())
            inner, _ = _balanced(body, i)
            if _mentions(inner, p):
                return p
        for m in re.finditer(r"\b_safeMint\s*\(", body):
            i = body.index("(", m.start())
            inner, _ = _balanced(body, i)
            if _mentions(inner, p):
                return p
        for m in re.finditer(r"\b_mint\s*\(", body):
            i = body.index("(", m.start())
            inner, _ = _balanced(body, i)
            if _mentions(inner, p):
                return p
    return None


def _leaf_amount_bound(text: str, amount_params: List[str]
                       ) -> Optional[bool]:
    """True if every inline leaf construction binds an amount
    parameter, False if some leaf omits it, None if no inline
    leaf construction exists in the function (leaf supplied
    externally - out of scope for this detector)."""
    found = False
    for m in re.finditer(
            r"keccak256\s*\(\s*abi\.(?:encodePacked|encode)"
            r"\s*\(", text):
        found = True
        inner, _ = _balanced(text, m.end() - 1)
        if not any(_mentions(inner, p) for p in amount_params):
            return False
    return True if found else None


def _analyze_merkle_amount(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CLAIM_NAME_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        amount_params = [p for p in params
                         if _MERKLE_AMOUNT_PARAM_RE.match(p)]
        if not amount_params:
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if not _MERKLE_VERIFY_RE.search(searched):
            continue
        body = _fn_body(text)
        used = _payout_uses_amount(body, amount_params)
        if used is None:
            continue
        bound = _leaf_amount_bound(body, amount_params)
        if bound is not False:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a Merkle "
            f"proof and pays the caller-supplied amount "
            f"'{used}', but the leaf is built from the account "
            f"only - no amount parameter appears in any "
            f"keccak256(abi.encodePacked / encode(...)) leaf "
            f"construction in the function - so any proven "
            f"account claims any amount. Gate analysis: no "
            f"caller-identity gate, no amount binding in the "
            f"leaf.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated Merkle claim: proof verified, "
                    "payout amount never bound into the leaf")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "nft_batch_mint_underpayment": _analyze_nft_mint,
    "multicall_arbitrary_delegatecall": _analyze_multicall,
    "auction_bid_after_deadline": _analyze_auction_deadline,
    "bridge_deposit_value_unbound_to_msgvalue":
        _analyze_bridge_deposit,
    "merkle_proof_amount_unbound": _analyze_merkle_amount,
}


def analyze_deep25_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-25 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep25_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit25Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 25)"
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
        for item in analyze_deep25_source(
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
                source="deep audit detector batch 25 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit25Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 25) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
