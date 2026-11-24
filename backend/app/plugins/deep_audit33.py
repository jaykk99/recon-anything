"""Deep-audit detectors, batch 33: a flash loan that lends the
pool's own pricing balance, a per-user cap counter that is never
incremented, a gauge weight that ignores its account parameter,
proof verification with no context binding, and pool units
minted from the unrounded deposit while the collection rounds
down.

Five chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard:
recipient classification computed inside the detector and
carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate), the
exact code plus a gate analysis on every finding, and a
finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

- pool_flashloan_lends_pricing_balance: a pool / AMM contract
  that (a) offers a flash loan transferring tokens out of the
  pool's own reserve vault / balance AND (b) prices swaps from
  that same live balance (balanceOf(address(this)) read in the
  swap path, with arithmetic on it) - the Ociswap Flex Pool v1
  shape (Radix, Oct 27 + Nov 14 2026, ~1.16M + ~1.32M XRD
  drained): the attacker borrows nearly the whole vault via
  flash loan, swaps a small amount back priced against the
  emptied vault, repays, and keeps the difference. A flash
  loan drawn from a separate lending vault, or pricing that
  reads a stored reserve variable updated only by swaps (not
  the raw balance), is the protected shape. Distinct from
  flash_loan_spot_balance_check (that is flash-loan REPAYMENT
  verified by spot balance only - this one is the pool lending
  its own pricing balance) and from cp_proto_single_source_
  oracle / evm_v3_spot_price_oracle (external consumers
  reading spot; this is the pool itself). DOCUMENTED CO-FIRE:
  spot_price_own_balance fires on the same swap leg by design
  (the swap does price from its own balance) - the new
  detector adds the flash-loan dimension it cannot express.
- cap_counter_never_incremented: a state counter is compared
  against a cap in a require (require(count[x] < MAX) /
  require(count + amount <= limit)) in a value-moving function
  (mint / claim / vote / withdraw), but the counter is NEVER
  incremented or written anywhere in the contract, so the cap
  never binds and the action is unlimited - the CodeHawks Hawk
  High #334 pattern (a per-user mint / claim / vote cap that
  cannot bind). A counter written anywhere (increment, +=, =,
  .increment) is the protected shape. Distinct from
  cap_counter_reset_by_setter (there the counter IS reset by a
  setter - here it is never written at all).
- reward_weight_ignores_account_param: an internal view helper
  takes an address account parameter but never uses it,
  returning a weight computed from address(this) / a global
  (e.g. IGaugeController.getGaugeWeight(address(this))), and a
  claim / reward function pays out sized by that weight - so
  users claim rewards from gauges they never voted for or
  staked in. The CodeHawks RAAC #4428 / #3349 shape (High). A
  helper that uses its account parameter is the protected
  shape. Distinct from reward_distribution_manipulation /
  staking_total_shares_mismatch (accumulator shapes, not a
  wrong-argument weight).
- proof_verification_no_context_binding: a proof-verification
  function (verifyProof / verifyStorageProof / verifyStateProof)
  verifies a Merkle / storage proof whose digest does NOT bind
  the proof to the verifying context - no domain separator, no
  contract address, no function selector, no chain id in the
  verified inputs - so a proof meant for one verification
  function / contract replays in another, with a state-changing
  effect downstream of the verification. The CodeHawks Curve
  Storage Proofs #178 shape (High). Any context binding
  (address(this), domain separator, selector, chain id) in the
  verified digest is the protected shape. Distinct from
  bridge_replay_unbound_digest (bridge MESSAGE digests omitting
  chain / origin / nonce - this is proof verification, not
  bridge messages) and from merkle_patricia_trie_state_proof_
  verifier (that plugin is about MPT proof validity, not
  context binding).
- lp_mint_unrounded_shares_rounded_collection: a deposit /
  addLiquidity function computes / mints shares from the
  REQUESTED amount (unrounded) while computing the COLLECTED
  amount with an explicit rounding-down expression (amount -
  amount % unit, amount / unit * unit, or a round-down helper)
  and performing no balance-delta measurement of what actually
  arrived - so every deposit mints slightly more than it pays.
  The Radix native TwoResourcePool rounding shape (Nov 14 2026,
  ~28,500 micro-deposits, a few satoshis each). Shares computed
  from the measured received balance is the protected shape.
  Distinct from fee_on_transfer_overcredit (that fires when a
  FEE-ON-TRANSFER token's nominal deposit is credited with no
  balance-delta check - this shape requires an explicit
  self-rounding computation on the collected amount, not a
  token fee; the fixture uses a plain token with no fee) and
  from amm_scale_rounding_wrong_direction / withdraw_rounding_
  drain / rounding_iterated_drain (scaling-direction and
  share-conversion rounding shapes, not a self-rounding
  collection).

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
FAMILY = "deep33"

SPECS = [
    S("pool_flashloan_lends_pricing_balance", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Flash loan lends the pool's own pricing balance: "
             "a pool / AMM offers a flash loan that transfers "
             "tokens out of the pool's own reserve vault / "
             "balance AND prices swaps from that same live "
             "balance (balanceOf(address(this)) read in the swap "
             "path, with arithmetic on it) - the Ociswap Flex "
             "Pool v1 shape: borrow nearly the whole vault, swap "
             "a small amount back priced against the emptied "
             "vault, repay, and keep the difference. A flash "
             "loan drawn from a separate lending vault, or "
             "pricing that reads a stored reserve variable "
             "updated only by swaps, is the protected shape.",
      fix="Never let a flash loan drain the balance the swap "
          "pricing reads: lend from a separate lending vault, "
          "or price swaps from a stored reserve snapshot "
          "updated only by swaps (never from the live "
          "balanceOf), and re-check the reserve after the "
          "flash-loan callback returns."),
    S("cap_counter_never_incremented", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Cap counter never incremented: a state counter is "
             "compared against a cap in a require in a "
             "value-moving function (mint / claim / vote / "
             "withdraw), but the counter is NEVER incremented or "
             "written anywhere in the contract, so the cap never "
             "binds and the action is unlimited - the CodeHawks "
             "Hawk High #334 pattern. A counter written "
             "anywhere (increment, +=, =, .increment) is the "
             "protected shape.",
      fix="Increment the counter on every capped action (and "
          "decrement it on any undo / burn path that must "
          "restore quota), and add a test that mints / claims "
          "past the cap and expects a revert."),
    S("reward_weight_ignores_account_param", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Reward weight ignores its account parameter: an "
             "internal view helper takes an address account "
             "parameter but never uses it, returning a weight "
             "computed from address(this) / a global, and a "
             "claim / reward function pays out sized by that "
             "weight - so users claim rewards from gauges they "
             "never voted for or staked in. The CodeHawks RAAC "
             "#4428 / #3349 shape. A helper that uses its "
             "account parameter is the protected shape.",
      fix="Use the account parameter in the weight lookup "
          "(gauge weight for THAT account's gauge / stake), "
          "and test that a claim from an account with no "
          "gauge weight pays zero."),
    S("proof_verification_no_context_binding", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Proof verification with no context binding: a "
             "proof-verification function verifies a Merkle / "
             "storage proof whose digest does NOT bind the "
             "proof to the verifying context - no domain "
             "separator, no contract address, no function "
             "selector, no chain id in the verified inputs - so "
             "a proof meant for one verification function / "
             "contract replays in another, with a "
             "state-changing effect downstream of the "
             "verification. The CodeHawks Curve Storage Proofs "
             "#178 shape. Any context binding in the verified "
             "digest is the protected shape.",
      fix="Bind the verifying context into the digest the proof "
          "is checked against: hash address(this), the chain "
          "id, and a domain separator / function selector into "
          "the leaf, and test that a proof generated for a "
          "different contract or function fails verification."),
    S("lp_mint_unrounded_shares_rounded_collection", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Pool units minted from the unrounded deposit while "
             "the collection rounds down: a deposit / "
             "addLiquidity function computes / mints shares "
             "from the REQUESTED amount (unrounded) while "
             "computing the COLLECTED amount with an explicit "
             "rounding-down expression (amount - amount % unit, "
             "amount / unit * unit, or a round-down helper) and "
             "performing no balance-delta measurement of what "
             "actually arrived - so every deposit mints slightly "
             "more than it pays. The Radix native "
             "TwoResourcePool rounding shape. Shares computed "
             "from the measured received balance is the "
             "protected shape.",
      fix="Mint shares from the measured received balance "
          "(balance after minus balance before), never from "
          "the requested amount, and round the collected "
          "amount UP (or reject deposits that do not divide "
          "evenly into the token's smallest unit)."),
]
SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19 / deep25 / deep28)
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
    or a role check suppresses.
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


def _mentions(text: str, param: str) -> bool:
    """A word-boundary mention of a parameter name, excluding
    the `value` inside `msg.value` (a parameter literally named
    `value` must not match the msg.value keyword)."""
    return bool(re.search(r"(?<!msg\.)\b" + re.escape(param) +
                          r"\b", text))


_VALUE_MOVE_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*transferFrom\s*\(|"
    r"safeTransfer\s*\(|safeTransferFrom\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\.\s*send\s*\(|\.\s*transfer\s*\{\s*value")


def _moves_value(text: str) -> bool:
    """A token / ETH payout of some kind in the function."""
    return bool(_VALUE_MOVE_RE.search(text))


_OWN_BALANCE_RE = re.compile(
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")


# ---------------------------------------------------------------------------
# 1. pool_flashloan_lends_pricing_balance
# ---------------------------------------------------------------------------

_FLASH_FN_RE = re.compile(r"flash", re.I)
_SWAP_FN_RE = re.compile(
    r"^(?:swap|swapExact\w*|exchange)\w*$", re.I)


def _analyze_pool_flashloan(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for flash in fns:
        if not _FLASH_FN_RE.search(flash["name"]):
            continue
        if _skip_fn(flash, scope):
            continue
        ftext = flash["text"]
        typed = _fn_params_typed(flash)
        borrower_params = [n for (t, n) in typed
                           if t == "address"]
        if not borrower_params:
            continue
        # The flash loan transfers tokens OUT to a
        # caller-supplied borrower.
        lends = False
        for bp in borrower_params:
            if re.search(
                    r"\.\s*(?:safeTransfer|transfer)\s*\(\s*\b" +
                    re.escape(bp) + r"\b", ftext):
                lends = True
                break
        if not lends:
            continue
        # The loan comes out of the pool's own reserve balance,
        # not a separate vault: the flash function reads
        # balanceOf(address(this)).
        if not _OWN_BALANCE_RE.search(ftext):
            continue
        # A transferFrom whose source is a stored vault address
        # is a separate-vault draw, not the pool's own balance.
        separate = False
        for m in re.finditer(
                r"transferFrom\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,",
                ftext):
            if m.group(1) in state:
                separate = True
                break
        if separate:
            continue
        for swap in fns:
            if swap is flash:
                continue
            if not _SWAP_FN_RE.search(swap["name"]):
                continue
            if _skip_fn(swap, scope):
                continue
            stext = swap["text"]
            if not _moves_value(stext):
                continue
            # The swap prices from the same live balance: a
            # balanceOf(address(this)) read assigned to a local,
            # with arithmetic on that local. Pricing that reads
            # a stored reserve variable instead never matches
            # this leg, so it is the protected shape.
            m = re.search(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]{0,160}?"
                r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
                stext)
            if not m:
                continue
            reserve_var = m.group(1)
            if not re.search(
                    r"\b" + re.escape(reserve_var) +
                    r"\b\s*[*/]|[*/]\s*\b" +
                    re.escape(reserve_var) + r"\b", stext):
                continue
            detail = spec.detail + (
                f" Observed: '{flash['name']}' lends tokens out "
                f"of the pool's own reserve balance to a "
                f"caller-supplied borrower "
                f"({', '.join(borrower_params)}), and "
                f"'{swap['name']}' prices swaps from that same "
                f"live balance ('{reserve_var}' read from "
                f"balanceOf(address(this)) with arithmetic on "
                f"it) and pays the caller - so a stranger "
                f"borrows nearly the whole vault, swaps a small "
                f"amount back priced against the emptied vault, "
                f"repays, and keeps the difference. Gate "
                f"analysis: no caller-identity gate on either "
                f"leg; the flash loan and the pricing read the "
                f"same live balance.")
            item = _hit(spec, swap["name"], cc._snip(swap["text"]),
                        detail,
                        "ungated flash loan lends the pool's own "
                        "reserve; swap prices from that same live "
                        "balance")
            out.append(_finish_recipient(spec, item, stext))
            break
    return out


# ---------------------------------------------------------------------------
# 2. cap_counter_never_incremented
# ---------------------------------------------------------------------------

_COUNTER_NAME_RE = re.compile(
    r"(count|minted|claimed|issued|sold|passes|redeemed|"
    r"distributed|votes|claims|mints)", re.I)
_CAP_NAME_RE = re.compile(r"(max|cap|limit)", re.I)
_VALUE_FN_RE = re.compile(
    r"^(?:mint|claim|vote|withdraw|redeem|issue|buy|"
    r"purchase)\w*$", re.I)


def _is_counter_var(name: str) -> bool:
    lower = name.lower()
    if lower.startswith("max") or "cap" in lower or \
            "limit" in lower:
        return False
    return bool(_COUNTER_NAME_RE.search(name))


def _counter_written(scoped_text: str, counter: str) -> bool:
    """Any write to the counter anywhere in the contract:
    a mapping write (counter[key] += / = / ++), a scalar write
    (counter += / = / ++), or a .increment() call. A comparison
    (==, <=, >=) is NOT a write: the plain `=` must not be
    preceded by = ! < > and must not be followed by = >."""
    c = re.escape(counter)
    plain_assign = r"(?<![=!<>])=(?![=>])"
    if re.search(r"\b" + c + r"\s*\[[^\]]*\]\s*(?:\+\+|\+=|-=|" +
                 plain_assign + r")", scoped_text):
        return True
    if re.search(r"\b" + c + r"\s*(?:\+\+|\+=|-=|" +
                 plain_assign + r")", scoped_text):
        return True
    if re.search(r"\b" + c + r"\s*\.\s*increment\s*\(",
                 scoped_text):
        return True
    return False


def _analyze_cap_counter_never(src, spec, compiler,
                               contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    counters = [v for v in state if _is_counter_var(v)]
    if not counters:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _VALUE_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # A value-moving function: it moves value out, mints /
        # credits value, or writes contract state (a direct
        # ledger credit such as balances[to] += amount is the
        # mint shape - no _mint call is required).
        if not (_moves_value(text) or
                re.search(r"\b_mint\s*\(", text) or
                cl._state_writes(text, state)):
            continue
        for counter in counters:
            c = re.escape(counter)
            # A require / if comparing the counter (optionally
            # plus an amount) against a cap / limit / max.
            cap_hit = None
            for m in re.finditer(
                    r"\b" + c + r"(?:\s*\[[^\]]*\])?\s*"
                    r"(?:\+\s*[A-Za-z_][A-Za-z0-9_]*\s*)?"
                    r"(<=|<)\s*([A-Za-z_][A-Za-z0-9_]*|\d+)",
                    text):
                rhs = m.group(2)
                if _CAP_NAME_RE.search(rhs) or rhs.isdigit():
                    cap_hit = m.group(0)
                    break
            if cap_hit is None:
                continue
            # The cap never binds if the counter is never
            # written anywhere in the contract - not in this
            # function, not in a setter, nowhere.
            if _counter_written(scoped, counter):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' checks "
                f"'{cap_hit.strip()}' - the state counter "
                f"'{counter}' against a cap - but "
                f"'{counter}' is never written anywhere in the "
                f"contract (no +=, =, ++, or .increment), so "
                f"the cap never binds and the action is "
                f"unlimited. Gate analysis: no caller-identity "
                f"gate on the capped function; the cap check "
                f"itself is the only guard, and it reads a "
                f"counter that never moves.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "ungated capped function: the cap counter "
                        "is never written anywhere in the "
                        "contract")
            out.append(_finish_recipient(spec, item, text))
            break
    return out


# ---------------------------------------------------------------------------
# 3. reward_weight_ignores_account_param
# ---------------------------------------------------------------------------

_WEIGHT_HELPER_RE = re.compile(
    r"weight|gauge|votingPower|voteWeight", re.I)
_CLAIM_FN_RE = re.compile(
    r"^(?:claim|getReward|harvest|collectReward)\w*$", re.I)


def _analyze_reward_weight(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for helper in fns:
        if not _WEIGHT_HELPER_RE.search(helper["name"]):
            continue
        sig = helper["signature"]
        if "internal" not in sig or "view" not in sig:
            continue
        typed = _fn_params_typed(helper)
        addr_params = [n for (t, n) in typed if t == "address"]
        if not addr_params:
            continue
        body = _fn_body(helper["text"])
        # An address parameter the body never references.
        ignored = [p for p in addr_params
                   if not _mentions(body, p)]
        if not ignored:
            continue
        # The returned weight is computed from address(this) /
        # a global, not from the ignored parameter.
        if not re.search(r"address\s*\(\s*this\s*\)", body):
            continue
        for claim in fns:
            if not _CLAIM_FN_RE.match(claim["name"]):
                continue
            if _skip_fn(claim, scope):
                continue
            ctext = claim["text"]
            # The claim calls the helper and sizes its payout
            # from the helper's return.
            call = re.search(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]{0,200}?\b" +
                re.escape(helper["name"]) + r"\s*\(", ctext)
            if call is None:
                continue
            weight_var = call.group(1)
            sized = _mentions(ctext, weight_var)
            if not sized:
                continue
            if not _moves_value(ctext):
                continue
            detail = spec.detail + (
                f" Observed: internal helper "
                f"'{helper['name']}' takes an address parameter "
                f"'{ignored[0]}' it never uses, returning a "
                f"weight computed from address(this), and "
                f"'{claim['name']}' sizes its payout from that "
                f"weight ('{weight_var}') - so a caller claims "
                f"rewards sized by a gauge weight that has "
                f"nothing to do with their own gauge or stake. "
                f"Gate analysis: no caller-identity gate on the "
                f"claim; the weight lookup is the only "
                f"entitlement check, and it ignores the "
                f"account.")
            item = _hit(spec, claim["name"],
                        cc._snip(claim["text"]), detail,
                        "ungated claim sized by a gauge weight "
                        "that ignores its account parameter")
            out.append(_finish_recipient(spec, item, ctext))
            break
    return out


# ---------------------------------------------------------------------------
# 4. proof_verification_no_context_binding
# ---------------------------------------------------------------------------

_VERIFY_FN_RE = re.compile(r"^verify\w*[Pp]roof\w*$", re.I)
_PROOF_CHECK_RE = re.compile(
    r"MerkleProof\s*\.\s*verify\s*\(|"
    r"verifyProof\s*\(|verifyStorageProof\s*\(|"
    r"verifyStateProof\s*\(")
_BINDING_RE = re.compile(
    r"address\s*\(\s*this\s*\)|domainSeparator|"
    r"DOMAIN_SEPARATOR|block\.chainid|chainId|"
    r"msg\.sender|msg\.sig|selector|SELECTOR", re.I)


def _digest_inputs(text: str) -> List[str]:
    """Argument strings of every abi.encode / encodePacked call
    that feeds a keccak256 in this function text (the bridge
    detector's extraction, narrowed to this function)."""
    out: List[str] = []
    for m in re.finditer(r"keccak256\s*\(", text):
        inner, _ = _balanced(text, text.index("(", m.start()))
        em = re.search(r"abi\.encode(?:Packed)?\s*\(", inner)
        if em:
            args, _ = _balanced(inner, inner.index("(", em.start()))
            out.append(args)
        else:
            out.append(inner)
    return out


def _analyze_proof_no_binding(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _VERIFY_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _PROOF_CHECK_RE.search(text):
            continue
        # The verified digest: the keccak256 inputs in this
        # function. No keccak256 digest at all means the leaf
        # arrives pre-built from outside - this detector does
        # not guess about its binding.
        inputs = _digest_inputs(text)
        if not inputs:
            continue
        joined = " ".join(inputs)
        if _BINDING_RE.search(joined):
            continue
        # A state-changing effect must sit downstream of the
        # verification: a state write or a value move in the
        # same function.
        writes = cl._state_writes(text, state)
        if not writes and not _moves_value(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a proof over "
            f"a digest of ({joined.strip()[:120]}) which binds "
            f"no verifying context - no contract address, no "
            f"domain separator, no selector, no chain id, no "
            f"caller - while the function has a state-changing "
            f"effect downstream of the verification, so a proof "
            f"meant for one verification function / contract "
            f"replays in another. Gate analysis: no "
            f"caller-identity gate; the verification is the "
            f"only guard, and its digest is unbound.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated proof verification: the verified "
                    "digest binds no context, state changes "
                    "downstream")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. lp_mint_unrounded_shares_rounded_collection
# ---------------------------------------------------------------------------

_DEPOSIT_FN_RE = re.compile(
    r"^(?:deposit|addLiquidity|supply|provideLiquidity)\w*$",
    re.I)
_ROUND_HELPER_RE = re.compile(
    r"\b(?:roundDown|floorToUnit|roundToDecimals|"
    r"toSmallestUnit)\s*\(")
_BEFORE_RE = re.compile(
    r"([A-Za-z_][\w]*)\s*=\s*[^;]*?balanceOf\s*\(\s*address"
    r"\s*\(\s*this\s*\)\s*\)")


def _delta_measured(text: str) -> bool:
    """A balanceOf(address(this)) snapshot followed by a
    subtraction of it - the received-balance delta is
    measured, so shares can be computed from what arrived."""
    m = _BEFORE_RE.search(text)
    if not m:
        return False
    var = m.group(1)
    rest = text[m.end():]
    return bool(re.search(r"-\s*" + re.escape(var) + r"\b", rest)
                or re.search(r"balanceOf\s*\([^)]*\)\s*-\s*" +
                             re.escape(var) + r"\b", rest))


def _rounding_down_assignment(text: str, amount_param: str
                              ) -> Optional[Tuple[str, str]]:
    """(collected var, rhs) for a local computed from the
    requested amount with an explicit rounding-down
    expression: amount - (amount % unit), amount / unit *
    unit, or a round-down helper call."""
    ap = re.escape(amount_param)
    for m in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]{0,200})",
            text):
        var, rhs = m.group(1), m.group(2)
        if re.search(r"\b" + ap + r"\b\s*-\s*\(\s*\b" + ap +
                     r"\b\s*%", rhs):
            return var, rhs.strip()
        if re.search(r"\b" + ap + r"\b\s*/\s*"
                     r"[A-Za-z_][A-Za-z0-9_]*\s*\*\s*"
                     r"[A-Za-z_][A-Za-z0-9_]*", rhs):
            return var, rhs.strip()
        if _ROUND_HELPER_RE.search(rhs) and \
                re.search(r"\b" + ap + r"\b", rhs):
            return var, rhs.strip()
    return None


def _shares_from_requested(text: str, amount_param: str) -> bool:
    """Shares are minted / credited from the REQUESTED amount
    (unrounded): _mint(to, amount) directly, or _mint(to, x)
    / a mapping credit where x is assigned from the amount."""
    ap = re.escape(amount_param)
    if re.search(r"_mint\s*\(\s*[^,]+,\s*\b" + ap + r"\b\s*\)",
                 text):
        return True
    for m in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]{0,200})",
            text):
        var, rhs = m.group(1), m.group(2)
        if not re.search(r"\b" + ap + r"\b", rhs):
            continue
        if re.search(r"_mint\s*\(\s*[^,]+,\s*\b" +
                     re.escape(var) + r"\b\s*\)", text):
            return True
        if re.search(
                r"\b(?:shares|poolUnits|balances|balanceOf)"
                r"\s*\[\s*[^\]]+\s*\]\s*\+=\s*\b" +
                re.escape(var) + r"\b", text):
            return True
    return False


def _analyze_lp_mint_rounding(src, spec, compiler,
                             contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _DEPOSIT_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        if not params:
            continue
        # The requested deposit amount: the first uint256
        # parameter (amount / amountIn / depositAmount ...).
        typed = _fn_params_typed(fn)
        amount_params = [n for (t, n) in typed
                         if t in ("uint256", "uint")]
        if not amount_params:
            continue
        amount = amount_params[0]
        # (c) no balance-delta measurement of what arrived.
        if _delta_measured(text):
            continue
        # (a) shares minted from the REQUESTED amount.
        if not _shares_from_requested(text, amount):
            continue
        # (b) the COLLECTED amount is rounded down explicitly.
        rounded = _rounding_down_assignment(text, amount)
        if rounded is None:
            continue
        collected, rhs = rounded
        # The rounded amount is the amount actually pulled.
        if not re.search(
                r"transferFrom\s*\([^;]{0,120}?\b" +
                re.escape(collected) + r"\b", text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' mints shares from the "
            f"REQUESTED amount '{amount}' (unrounded) while "
            f"collecting only '{collected} = {rhs}' - the "
            f"collected amount rounded down explicitly - and "
            f"measures no balance delta of what actually "
            f"arrived, so every deposit mints slightly more "
            f"than it pays. Gate analysis: no caller-identity "
            f"gate on the deposit; the rounding is in the "
            f"collection itself, not in any token fee.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated deposit: shares from the requested "
                    "amount, collection rounded down, no "
                    "balance-delta measurement")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "pool_flashloan_lends_pricing_balance": _analyze_pool_flashloan,
    "cap_counter_never_incremented": _analyze_cap_counter_never,
    "reward_weight_ignores_account_param": _analyze_reward_weight,
    "proof_verification_no_context_binding": _analyze_proof_no_binding,
    "lp_mint_unrounded_shares_rounded_collection":
        _analyze_lp_mint_rounding,
}


def analyze_deep33_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-33 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep33_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit33Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 33)"
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
        for item in analyze_deep33_source(
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
                source="deep audit detector batch 33 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit33Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 33) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
