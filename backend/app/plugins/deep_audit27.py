"""Deep-audit detectors, batch 27: LP mint with no minimum
liquidity lock, merkle claims replayable across chains,
vesting claims that over-release past the duration, permit
deadlines never enforced, bonding-curve prices from raw
balances.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- lp_mint_no_minimum_liquidity_lock: a Uniswap-V2-style mint
  / addLiquidity computes the first liquidity from sqrt
  (amount0 * amount1) (or the proportional min of the two
  amounts against the reserves) and mints ALL of it to the
  caller, with no MINIMUM_LIQUIDITY burn / lock to a dead
  address - the V2 rationale (Nov 2020, the minimum
  liquidity burn exists precisely so the first LP cannot
  donate tokens to inflate the price per liquidity unit and
  steal later LPs' deposits). Burning MINIMUM_LIQUIDITY to
  address(0) / a dead address, or subtracting it from the
  minted amount, is the protected shape. Distinct from
  vault_share_inflation (ERC-4626 deposit shares priced off
  totalAssets / totalSupply - this one is the sqrt LP-mint
  family, no exchange-rate variable) and from
  lp_mint_unverified_caller_supplied (a removeLiquidity /
  withdraw sizing the payout from a caller-supplied LP
  token's supply - this one is the first-mint lock).
- merkle_claim_replayable_across_chains: a claim / airdrop
  function verifies a Merkle proof over a leaf built from
  the account and the amount only - no block.chainid, no
  domain separator, no contract address in the leaf - so
  the same proof and claim are valid on every chain the
  contract is deployed on (the airdrop is claimed once per
  chain instead of once, ever). Including block.chainid (or
  the contract address, or a domain separator) in the leaf
  is the protected shape. Distinct from
  merkle_claim_no_claimed_marker (no claimed marker - a
  replay on the SAME chain; this detector does not care
  about the marker at all) and from
  merkle_proof_amount_unbound (the leaf binds the account
  only, the amount is never bound - here the amount IS
  bound, the chain is not) and from
  ecdsa_signature_replay_cross_chain (signatures, not
  merkle leaves).
- vesting_claim_overrelease_past_duration: a release /
  claimVested function computes the releasable amount
  linearly from the elapsed time - (block.timestamp -
  start) * total / duration - with NO cap at the vesting
  end (no min(now, end), no require that the releasable
  amount never exceeds the total, no end-branch paying the
  total), so after the vesting end the formula keeps
  growing past 100% and a claimer drains more than the
  allocation. Capping the elapsed time at the vesting end
  (or the releasable amount at the total) is the protected
  shape. Distinct from vesting_release_cancel_double_debit
  (a cancel path debiting twice - this one is the release
  formula itself).
- permit_deadline_param_never_enforced: a permit function
  takes a deadline parameter but never compares it against
  block.timestamp anywhere on the path (not in the
  function, not in an internal helper it calls), so a
  signature collected once is usable forever - the
  allowance it grants never expires. Requiring
  block.timestamp <= deadline (or the equivalent) is the
  protected shape. Distinct from permit_no_domain_separator
  (the EIP-712 domain - here the domain IS present) and
  from signature_replay_no_nonce (the nonce - here the
  nonce IS consumed); the fixture carries both protections
  so the deadline is the only missing one.
- bonding_curve_price_from_raw_balance_no_virtual_reserve:
  a buy / buyTokens / purchase function prices the tokens
  from the contract's raw balance - address(this).balance
  (or a token balanceOf(address(this))) - with no virtual
  reserve and no min-out / slippage bound, so anyone can
  force-feed value (a direct transfer, a selfdestruct)
  and move the curve price, then buy underpriced tokens
  or sell at the inflated price. Pricing off virtual
  reserves, or bounding the trade with a min-out check,
  is the protected shape. Distinct from
  lending_accumulator_donation_inflation (a lending rate /
  accumulator computed from a raw balance - this one is
  the buy pricing leg, no rate / accumulator variable)
  and from spot_oracle_payout (an oracle payout leg -
  this one is the curve's own buy function).

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
FAMILY = "deep27"

SPECS = [
    S("lp_mint_no_minimum_liquidity_lock", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="LP mint has no minimum liquidity lock: a mint / "
             "addLiquidity computes the first liquidity from "
             "sqrt(amount0 * amount1) (or the proportional min "
             "of the two amounts against the reserves) and "
             "mints ALL of it to the caller, with no "
             "MINIMUM_LIQUIDITY burn / lock to a dead address, "
             "so the first LP can donate tokens to inflate "
             "the price per liquidity unit and steal later "
             "LPs' deposits - the Uniswap V2 minimum-liquidity "
             "rationale. Burning MINIMUM_LIQUIDITY to "
             "address(0) / a dead address, or subtracting it "
             "from the minted amount, is the protected shape.",
      fix="Lock the minimum liquidity: on the first mint, "
          "burn MINIMUM_LIQUIDITY to address(0) (or subtract "
          "it from the minted amount) so the price per "
          "liquidity unit can never be inflated by a donation "
          "to an empty pool."),
    S("merkle_claim_replayable_across_chains", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Merkle claim is replayable across chains: a claim "
             "/ airdrop function verifies a Merkle proof over "
             "a leaf built from the account and the amount "
             "only - no block.chainid, no domain separator, "
             "no contract address in the leaf - so the same "
             "proof and claim are valid on every chain the "
             "contract is deployed on and the airdrop is "
             "claimed once per chain instead of once, ever. "
             "Including block.chainid (or the contract address, "
             "or a domain separator) in the leaf is the "
             "protected shape.",
      fix="Bind the leaf to the chain: include block.chainid "
          "(or the contract address, or an EIP-712 domain "
          "separator) in the leaf preimage so a proof minted "
          "for one chain verifies on no other chain."),
    S("vesting_claim_overrelease_past_duration", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Vesting claim over-releases past the duration: a "
             "release / claimVested function computes the "
             "releasable amount linearly from the elapsed "
             "time - (block.timestamp - start) * total / "
             "duration - with NO cap at the vesting end (no "
             "min(now, end), no require that the releasable "
             "amount never exceeds the total, no end-branch "
             "paying the total), so after the vesting end "
             "the formula keeps growing past 100% and a "
             "claimer drains more than the allocation. "
             "Capping the elapsed time at the vesting end (or "
             "the releasable amount at the total) is the "
             "protected shape.",
      fix="Cap the release at the vesting end: compute the "
          "elapsed time as min(block.timestamp, end) - start "
          "(or cap the releasable amount at the total "
          "allocation) so the formula can never exceed 100% "
          "of the grant."),
    S("permit_deadline_param_never_enforced", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Permit deadline is never enforced: a permit "
             "function takes a deadline parameter but never "
             "compares it against block.timestamp anywhere on "
             "the path (not in the function, not in an "
             "internal helper it calls), so a signature "
             "collected once is usable forever and the "
             "allowance it grants never expires. Requiring "
             "block.timestamp <= deadline (or the equivalent) "
             "is the protected shape.",
      fix="Enforce the deadline: require(block.timestamp <= "
          "deadline) before recovering the signer, so a "
          "permit signature stops working the moment its "
          "deadline passes."),
    S("bonding_curve_price_from_raw_balance_no_virtual_reserve",
      FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Bonding-curve price comes from the raw balance "
             "with no virtual reserve: a buy / buyTokens / "
             "purchase function prices the tokens from the "
             "contract's raw balance - address(this).balance "
             "(or a token balanceOf(address(this))) - with no "
             "virtual reserve and no min-out / slippage bound, "
             "so anyone can force-feed value (a direct "
             "transfer, a selfdestruct) and move the curve "
             "price, then buy underpriced tokens or sell at "
             "the inflated price. Pricing off virtual "
             "reserves, or bounding the trade with a min-out "
             "check, is the protected shape.",
      fix="Never price off the raw balance: hold a virtual "
          "reserve (or a fixed curve parameter) the contract "
          "itself controls, and bound every buy with a "
          "min-out check so a distorted price reverts "
          "instead of executing."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}
# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19 / deep25)
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


_ALLOWLIST_RE = re.compile(
    r"allowlist|whitelist|allowedTargets|isAllowed|"
    r"approvedTargets|trustedRouter|isTrusted|onlyAllowed",
    re.I)



# ---------------------------------------------------------------------------
# 1. lp_mint_no_minimum_liquidity_lock
# ---------------------------------------------------------------------------

_LP_MINT_FN_RE = re.compile(
    r"^(?:mint|addLiquidity|provideLiquidity)\w*$", re.I)
_MIN_LIQ_RE = re.compile(
    r"MINIMUM_LIQUIDITY|minimumLiquidity|minLiquidity|"
    r"MIN_LIQUIDITY", re.I)
_DEAD_MINT_RE = re.compile(
    r"_mint\s*\(\s*(?:address\s*\(\s*0\s*\)|"
    r"0x000000000000000000000000000000000000dEaD|"
    r"DEAD|dead)", re.I)
_SQRT_LIQ_RE = re.compile(
    r"\bliquidity\s*=\s*[^;]{0,200}?\bsqrt\s*\(")
_FIRST_MINT_RE = re.compile(
    r"totalSupply\s*==\s*0")
_MINT_CALL_RE = re.compile(r"_mint\s*\(")


def _lp_mint_dest(text: str, params: List[str], state: set
                  ) -> Tuple[str, str]:
    """Recipient of the minted liquidity."""
    for m in _MINT_CALL_RE.finditer(text):
        i = text.index("(", m.start())
        inner, _ = _balanced(text, i)
        parts = _split_top(inner)
        if parts:
            return _dest_class(parts[0], params, state)
    if re.search(r"balanceOf\s*\[\s*msg\.sender\s*\]\s*\+=\s*"
                 r"\w*liquidity", text):
        return ("CALLER", "liquidity credited to msg.sender")
    return ("UNRESOLVED", "no mint destination found")


def _analyze_lp_mint(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _LP_MINT_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        searched = text + "\n" + _called_internal_texts(text, scope)
        # The first liquidity must come from a sqrt (or a
        # first-mint branch sizing it from the amounts): the
        # proportional min() form is the later-mint formula,
        # anchored by a nonzero totalSupply.
        has_sqrt = bool(_SQRT_LIQ_RE.search(text))
        has_first_mint = bool(_FIRST_MINT_RE.search(text)) and \
            bool(re.search(r"\bliquidity\s*=", text))
        if not has_sqrt and not has_first_mint:
            continue
        # Protected shape: a minimum-liquidity burn / lock, or
        # the minted amount reduced by it, anywhere on the
        # path (the constant only counts when the mint uses
        # it - a definition elsewhere in the contract does
        # not protect this mint).
        if _MIN_LIQ_RE.search(searched):
            continue
        if _DEAD_MINT_RE.search(searched):
            continue
        params = _fn_params(fn)
        recipient, rdetail = _lp_mint_dest(searched, params, state)
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes the first "
            f"liquidity from sqrt(amount0 * amount1)"
            f"{' (first-mint branch)' if has_first_mint else ''} "
            f"and mints all of it with no MINIMUM_LIQUIDITY "
            f"burn / lock to a dead address and no reduction "
            f"of the minted amount anywhere on the path (not "
            f"in the function, not in an internal helper it "
            f"calls), so the first LP can donate tokens to "
            f"inflate the price per liquidity unit and steal "
            f"later LPs' deposits. Gate analysis: no "
            f"caller-identity gate, no minimum-liquidity lock "
            f"on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated LP mint: first liquidity from sqrt "
                    "with no minimum-liquidity burn / lock")
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 2. merkle_claim_replayable_across_chains
# ---------------------------------------------------------------------------

_MERKLE_CLAIM_FN_RE = re.compile(
    r"^(?:claim|claimAirdrop|redeem|collect)\w*$", re.I)
_MERKLE_VERIFY_RE = re.compile(
    r"MerkleProof\s*\.\s*verify\s*\(")
_CHAIN_BIND_RE = re.compile(
    r"block\.chainid|chainId|CHAIN_ID|DOMAIN_SEPARATOR|"
    r"domainSeparator|address\s*\(\s*this\s*\)")
_ACCOUNT_PARAM_RE = re.compile(
    r"^(?:account|claimer|user|wallet|to|recipient)$", re.I)
_AMOUNT_PARAM_RE = re.compile(
    r"^(?:amount|value|allocation|index)$", re.I)


def _leaf_binds_chain(inner: str) -> bool:
    return bool(_CHAIN_BIND_RE.search(inner))


def _merkle_leaf_unbound(searched: str, params: List[str]
                         ) -> Optional[str]:
    """The leaf preimage (account, amount) with no chain
    binding, or None when every leaf binds a chain."""
    for m in re.finditer(r"keccak256\s*\(", searched):
        i = searched.index("(", m.start())
        inner, _ = _balanced(searched, i)
        if _leaf_binds_chain(inner):
            continue
        mentions_account = any(
            _mentions(inner, p) for p in params
            if _ACCOUNT_PARAM_RE.match(p)) or \
            "msg.sender" in inner
        mentions_amount = any(
            _mentions(inner, p) for p in params
            if _AMOUNT_PARAM_RE.match(p))
        if mentions_account and mentions_amount:
            return inner.strip()
    return None


def _analyze_merkle_cross_chain(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _MERKLE_CLAIM_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _MERKLE_VERIFY_RE.search(text):
            continue
        params = _fn_params(fn)
        searched = text + "\n" + _called_internal_texts(text, scope)
        leaf = _merkle_leaf_unbound(searched, params)
        if leaf is None:
            continue
        if not _moves_value(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a Merkle "
            f"proof over a leaf built from the account and "
            f"the amount only (leaf preimage '{leaf[:120]}') "
            f"with no block.chainid, no domain separator and "
            f"no contract address in the leaf, and pays out "
            f"downstream - so the same proof and claim are "
            f"valid on every chain the contract is deployed "
            f"on and the airdrop is claimed once per chain "
            f"instead of once, ever. Gate analysis: no "
            f"caller-identity gate, no chain binding in the "
            f"leaf.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated merkle claim: leaf binds account "
                    "and amount only, no chain binding")
        out.append(_finish_recipient(spec, item, searched))
    return out


# ---------------------------------------------------------------------------
# 3. vesting_claim_overrelease_past_duration
# ---------------------------------------------------------------------------

_VEST_FN_RE = re.compile(
    r"^(?:release|claimVested|withdrawVested|claim)\w*$", re.I)
_ELAPSED_RE = re.compile(
    r"block\.timestamp\s*-\s*[A-Za-z_][A-Za-z0-9_]*")
_LINEAR_RE = re.compile(
    r"\*\s*\w*(?:total|allocation|amount|grant)\w*")
_DURATION_RE = re.compile(
    r"/\s*\w*(?:duration)\w*")
_VEST_CAP_MIN_RE = re.compile(
    r"\bmin\s*\([^;]{0,80}?\b\w*[Ee]nd\w*\b")
_VEST_CAP_END_RE = re.compile(
    r"block\.timestamp\s*>=?\s*\w*[Ee]nd\w*")
_VEST_CAP_TOTAL_RE = re.compile(
    r"(?:releasable|vested|claimable)\s*(?:>|>=|<=)\s*"
    r"\w*(?:total|allocation)\w*")


def _has_vesting_cap(text: str) -> bool:
    """A cap at the vesting end: min(now, end), an end
    comparison, or a releasable-vs-total bound."""
    if _VEST_CAP_MIN_RE.search(text):
        return True
    if _VEST_CAP_END_RE.search(text):
        return True
    if _VEST_CAP_TOTAL_RE.search(text):
        return True
    return False


def _analyze_vesting_overrelease(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _VEST_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        searched = text + "\n" + _called_internal_texts(text, scope)
        if not _ELAPSED_RE.search(searched):
            continue
        if not _LINEAR_RE.search(searched):
            continue
        if not _DURATION_RE.search(searched):
            continue
        if _has_vesting_cap(searched):
            continue
        if not _moves_value(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes the "
            f"releasable amount linearly from the elapsed "
            f"time ((block.timestamp - start) * total / "
            f"duration) with no cap at the vesting end - no "
            f"min(now, end), no end comparison, no "
            f"releasable-vs-total bound anywhere on the path "
            f"(not in the function, not in an internal helper "
            f"it calls) - so after the vesting end the "
            f"formula keeps growing past 100% and a claimer "
            f"drains more than the allocation. Gate analysis: "
            f"no caller-identity gate, no vesting-end cap on "
            f"the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated vesting release: linear elapsed "
                    "formula with no vesting-end cap")
        out.append(_finish_recipient(spec, item, searched))
    return out


# ---------------------------------------------------------------------------
# 4. permit_deadline_param_never_enforced
# ---------------------------------------------------------------------------

_PERMIT_FN_RE = re.compile(r"permit", re.I)
_SIG_CHECK_RE = re.compile(
    r"ecrecover\s*\(|ECDSA\s*\.\s*recover\s*\(|"
    r"isValidSignature\s*\(|Signature\s*\.\s*recover\s*\(")
_DEADLINE_ENFORCED_RE = re.compile(
    r"block\.timestamp\s*(?:<=|>=|<|>)\s*\bdeadline\b|"
    r"\bdeadline\b\s*(?:<=|>=|<|>)\s*block\.timestamp")
_APPROVE_RE = re.compile(
    r"_approve\s*\(|allowance\s*\[[^\]]+\]\s*=")


def _permit_spender_class(text: str, params: List[str],
                          state: set) -> Tuple[str, str]:
    """Recipient of the allowance the permit grants."""
    if "spender" in params:
        return ("CALLER-SUPPLIED",
                "spender is the caller parameter 'spender'")
    for m in _APPROVE_RE.finditer(text):
        i = text.index("(", m.start()) \
            if "_approve" in m.group(0) else -1
        if i < 0:
            continue
        inner, _ = _balanced(text, i)
        parts = _split_top(inner)
        if len(parts) >= 2:
            return _dest_class(parts[1], params, state)
    if re.search(r"allowance\s*\[\s*msg\.sender\s*\]", text):
        return ("CALLER", "allowance granted to msg.sender")
    return ("UNRESOLVED", "no spender destination found")


def _analyze_permit_deadline(src, spec, compiler,
                             contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _PERMIT_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        typed = _fn_params_typed(fn)
        if not any(n.lower() == "deadline"
                   for (_t, n) in typed):
            continue
        text = fn["text"]
        searched = text + "\n" + _called_internal_texts(text, scope)
        if not _SIG_CHECK_RE.search(text):
            continue
        if not _APPROVE_RE.search(text):
            continue
        if _DEADLINE_ENFORCED_RE.search(searched):
            continue
        params = _fn_params(fn)
        recipient, rdetail = _permit_spender_class(
            searched, params, state)
        detail = spec.detail + (
            f" Observed: '{fn['name']}' takes a deadline "
            f"parameter and recovers a signature over it, but "
            f"never compares the deadline against "
            f"block.timestamp anywhere on the path (not in "
            f"the function, not in an internal helper it "
            f"calls) - so a signature collected once grants "
            f"an allowance that never expires. Gate analysis: "
            f"no caller-identity gate, no deadline enforcement "
            f"on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated permit: deadline parameter never "
                    "compared against block.timestamp")
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 5. bonding_curve_price_from_raw_balance_no_virtual_reserve
# ---------------------------------------------------------------------------

_BUY_FN_RE = re.compile(
    r"^(?:buy|buyTokens|purchase)\w*$", re.I)
_RAW_BALANCE_RE = re.compile(
    r"address\s*\(\s*this\s*\)\s*\.\s*balance|"
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")
_VIRTUAL_RESERVE_RE = re.compile(
    r"virtual\w*(?:reserve|balance|supply)|"
    r"VIRTUAL_\w*RESERVE", re.I)
_MIN_OUT_RE = re.compile(
    r"\bmin\w*[Oo]ut\b|minimumOut|slippage", re.I)
_PRICE_ASSIGN_RE = re.compile(
    r"\b(?:price|cost|amountOut|tokensOut|totalCost)\w*\s*="
    r"[^;]{0,240}?")


def _price_from_raw_balance(text: str) -> bool:
    """A price / cost / payout assignment whose right-hand
    side reads the contract's raw balance."""
    for m in _PRICE_ASSIGN_RE.finditer(text):
        semi = text.find(";", m.start())
        rhs = text[m.start():semi if semi >= 0 else len(text)]
        if _RAW_BALANCE_RE.search(rhs):
            return True
    return False


def _analyze_bonding_curve(src, spec, compiler,
                           contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BUY_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        searched = text + "\n" + _called_internal_texts(text, scope)
        if not _price_from_raw_balance(searched):
            continue
        if _VIRTUAL_RESERVE_RE.search(searched):
            continue
        if _MIN_OUT_RE.search(searched):
            continue
        if not (_moves_value(searched) or
                re.search(r"_mint\s*\(", searched)):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' prices the tokens "
            f"from the contract's raw balance "
            f"(address(this).balance) with no virtual reserve "
            f"and no min-out / slippage bound anywhere on the "
            f"path (not in the function, not in an internal "
            f"helper it calls), so anyone can force-feed value "
            f"and move the curve price, then buy underpriced "
            f"tokens or sell at the inflated price. Gate "
            f"analysis: no caller-identity gate, no virtual "
            f"reserve, no min-out bound on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated bonding-curve buy: price from raw "
                    "balance, no virtual reserve, no min-out")
        out.append(_finish_recipient(spec, item, searched))
    return out


ANALYZERS = {
    "lp_mint_no_minimum_liquidity_lock": _analyze_lp_mint,
    "merkle_claim_replayable_across_chains":
        _analyze_merkle_cross_chain,
    "vesting_claim_overrelease_past_duration":
        _analyze_vesting_overrelease,
    "permit_deadline_param_never_enforced":
        _analyze_permit_deadline,
    "bonding_curve_price_from_raw_balance_no_virtual_reserve":
        _analyze_bonding_curve,
}

def analyze_deep27_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-27 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep27_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit27Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 26)"
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
        for item in analyze_deep27_source(
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
                source="deep audit detector batch 27 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit27Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 27) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
