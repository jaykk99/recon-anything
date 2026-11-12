"""Business-logic invariant detectors: the manual bug-hunter workflow,
automated where it can be.

Top researchers find $100k+ bugs by auditing business logic and
architecture, not syntax: real critical bugs live where code is
written correctly syntactically but allows an unintended economic
state. These five detectors look for exactly that - economic-state
flaws, not missing modifiers or known signatures:

- rounding_iterated_drain: a share MINT that computes the
  payout by floor division against a stored total (totalSupply /
  totalAssets) with no minimum-shares / minimum-deposit /
  virtual-shares guard, callable repeatedly, so each small
  deposit shaves a unit and the drift compounds into a
  drain. The withdraw-side rounding drain is already covered
  by the built withdraw_rounding_drain detector, so this one
  fires only on the deposit / mint side. Distinct from built
  amm_scale_rounding_wrong_direction (a scaling helper on the
  swap amount-out side) and built
  lending_accumulator_donation_inflation (the rate is computed
  from the RAW token balance, balanceOf(address(this))). This one
  fires only when the rate comes from STORED totals and the
  floor rounding is on the share-mint side with no minimum
  guard. A minimum guard, virtual shares, or round-up on the
  payout side stays silent.
- reward_distribution_manipulation: a reward accumulator
  (rewardPerToken / accRewardPerShare) computed from the raw
  token balance, or a stake/deposit that credits shares BEFORE
  the reward update runs (or never runs it), while a claim
  function pays out from the accumulator - so a deposit inflates
  the rate and the claim harvests it. An accumulator from stored
  accounting with the update run before any share change stays
  silent.
- flashloan_same_block_state_inconsistency: a flash-loan callback
  (or a deposit followed by a withdraw in the same function) that
  recomputes an exchange rate / price from a balance-dependent
  value between the deposit and the withdraw, with no
  block-number guard - so the transient balance moves the rate
  and the withdraw prices off the moved rate in the same block.
  A rate from stored accounting, or a block-number guard, stays
  silent.
- multistep_state_order_violation: a solvency / health check
  that runs BEFORE a write to a state variable the check depends
  on, in the same function, with the check never repeated after
  the write - so the check validates stale state and the later
  write breaks the invariant it just approved. Distinct from
  built batch_deferred_check_flag_reset (a boolean flag set by
  one batch action and cleared by another). A check that runs
  after all state writes, or is repeated after, stays silent.
- oracle_trust_assumption_break: an external price feed
  (latestRoundData / getPrice / getUnderlyingPrice) whose return
  value drives a borrow / mint / liquidate / swap decision with
  no staleness check (updatedAt / heartbeat), no deviation
  bound, and no positivity check - so a stale or manipulated
  feed is trusted blindly. Any of those guards present stays
  silent.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a finding
- a stranger cannot reach the path. View/pure functions never
fire.

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
FAMILY = "bizlogic"

SPECS = [
    S("rounding_iterated_drain", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Rounding iterated drain: a share mint computes "
             "the payout by floor division against a stored total "
             "(totalSupply / totalAssets) with no minimum-shares, "
             "minimum-deposit, or virtual-shares guard, and the "
             "entry is externally callable, so repeated small "
             "deposits shave a unit each time and the "
             "rounding drift compounds into a drain. A minimum "
             "guard, virtual shares, or round-up on the payout "
             "side is the protected shape.",
      fix="Add a minimum first deposit / minimum shares guard (or "
          "virtual shares) so the first depositor cannot inflate "
          "the rate, and round the payout side UP so a user can "
          "never be underpaid by floor division."),
    S("reward_distribution_manipulation", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Reward distribution manipulation: a reward accumulator "
             "(rewardPerToken / accRewardPerShare) is computed from "
             "the raw token balance, or a stake/deposit credits "
             "shares BEFORE the reward update runs (or never runs "
             "it), while a claim function pays out from the "
             "accumulator - so a deposit inflates the rate and the "
             "claim harvests it. An accumulator from stored "
             "accounting with the update run before any share "
             "change is the protected shape.",
      fix="Compute the reward accumulator from stored accounting, "
          "never from the raw token balance, and always run the "
          "reward update BEFORE any share balance changes in the "
          "same function."),
    S("flashloan_same_block_state_inconsistency", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Flash-loan same-block state inconsistency: a "
             "flash-loan callback (or a deposit followed by a "
             "withdraw in the same function) recomputes an "
             "exchange rate / price from a balance-dependent value "
             "between the deposit and the withdraw, with no "
             "block-number guard - so the transient balance moves "
             "the rate and the withdraw prices off the moved rate "
             "in the same block. A rate from stored accounting, or "
             "a block-number guard, is the protected shape.",
      fix="Compute the exchange rate from stored accounting, never "
          "from a transient balance, and guard rate-sensitive "
          "paths with a block-number / last-update check so a "
          "same-block deposit cannot move the rate it withdraws "
          "against."),
    S("multistep_state_order_violation", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Multi-step state order violation: a solvency / health "
             "check runs BEFORE a write to a state variable the "
             "check depends on, in the same function, with the "
             "check never repeated after the write - so the check "
             "validates stale state and the later write breaks the "
             "invariant it just approved. A check that runs after "
             "all state writes, or is repeated after, is the "
             "protected shape.",
      fix="Run every solvency / health check AFTER all state "
          "writes in the function, or repeat the check after the "
          "last write, so the check always validates the final "
          "state."),
    S("oracle_trust_assumption_break", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Oracle trust assumption break: an external price feed "
             "(latestRoundData / getPrice / getUnderlyingPrice) "
             "drives a borrow / mint / liquidate / swap decision "
             "with no staleness check (updatedAt / heartbeat), no "
             "deviation bound, and no positivity check - so a stale "
             "or manipulated feed is trusted blindly. Any of those "
             "guards present is the protected shape.",
      fix="Check the feed's updatedAt against a heartbeat, enforce "
          "a deviation bound against a second source, and require "
          "the price to be positive before using it for any "
          "borrow, mint, liquidate, or swap decision."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors the deep-audit batches)
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


def _is_entry(fn: Dict[str, Any]) -> bool:
    """Externally callable entry point (not an internal helper)."""
    return bool(re.search(r"\b(external|public)\b",
                          fn["signature"]))


# ---------------------------------------------------------------------------
# Shared pattern regexes
# ---------------------------------------------------------------------------

_TOTAL_RE = re.compile(
    r"\b(totalSupply|totalAssets|totalShares|_totalSupply|"
    r"_totalAssets|_totalShares)\b")
_MIN_GUARD_RE = re.compile(
    r"\b(minShares|minimumDeposit|minimumShares|MINIMUM|"
    r"virtualShares|virtual_shares|deadShares|MINIMUM_LIQUIDITY|"
    r"MIN_SHARES|MIN_DEPOSIT)\b|"
    r"require\s*\(\s*(amount|shares|assets)\s*>=|"
    r"firstDeposit|first_deposit")
_RAW_BALANCE_RE = re.compile(
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")
_ROUND_UP_RE = re.compile(
    r"ceilDiv|mulDivUp|roundUp|\(\s*[^;]*\+\s*[^;]*-\s*1\s*\)\s*/")
_ACCUMULATOR_RE = re.compile(
    r"\b(rewardPerToken|accRewardPerShare|accPerShare|"
    r"rewardPerShare|accReward)[A-Za-z0-9_]*")
_UPDATE_REWARD_RE = re.compile(
    r"\b(updateReward|_updateReward|updatePool|_updatePool|"
    r"updateRewards|_updateRewards)\b")
_CLAIM_RE = re.compile(
    r"\b(claim|getReward|harvest|claimRewards|getRewards)\b")
_FLASH_RE = re.compile(
    r"\b(onFlashLoan|executeOperation|flashLoan|flashBorrow)\b")
_BLOCK_GUARD_RE = re.compile(
    r"\b(block\.number|lastUpdate|lastBlock|blockNumber|"
    r"lastUpdated|updatedAt)\b")
_RATE_ASSIGN_RE = re.compile(
    r"\b(exchangeRate|sharePrice|price|rate|_rate)\b\s*=")
_PRICE_FEED_RE = re.compile(
    r"\b(latestRoundData|getPrice|getUnderlyingPrice|"
    r"getLatestPrice|getAnswer|peek)\s*\(")
_FEED_GUARD_RE = re.compile(
    r"\b(updatedAt|HEARTBEAT|heartbeat|stale|answeredInRound|"
    r"roundId|deviation|maxDeviation|MAX_DEVIATION|tolerance|"
    r"HEALTHY|isStale)\b|"
    r"require\s*\(\s*price\s*>\s*0|"
    r"require\s*\(\s*answer\s*>\s*0")
_DECISION_RE = re.compile(
    r"\b(borrow|mint|liquidate|swap|_borrow|_mint|"
    r"_liquidate|redeem|repay)\b")

# ---------------------------------------------------------------------------
# Analyzers
# ---------------------------------------------------------------------------

def _has_min_guard(fn_text: str, scope) -> bool:
    """A minimum-shares / minimum-deposit / virtual-shares guard in
    the function or in a modifier it uses."""
    if _MIN_GUARD_RE.search(fn_text):
        return True
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", fn_text):
        body = scope.modifiers.get(tok)
        if body and _MIN_GUARD_RE.search(body):
            return True
    return False


def _analyze_rounding_iterated_drain(src, spec, compiler,
                                     contract_name):
    """Share mint/burn by floor division on a stored total, no
    minimum guard, externally callable, payout to the caller."""
    scope, fns = _scope_fns(src, contract_name)
    # A minimum-shares / minimum-deposit / virtual-shares guard
    # is a vault-level property: if the contract has one
    # anywhere, the share conversion is protected.
    if _MIN_GUARD_RE.search(scope.scoped_text):
        return []
    out = []
    for fn in fns:
        if _skip_fn(fn, scope) or not _is_entry(fn):
            continue
        text = fn["text"]
        # A share MINT / credit must be present (a mapping credit
        # or a mint call - not a local declaration, and not a
        # burn: the withdraw-side rounding drain is already
        # covered by the built withdraw_rounding_drain detector,
        # this one is the deposit-side iterated drain).
        if not re.search(
                r"\b(_mint|mint)\s*\(|"
                r"\b(shares|balances|balanceOf|_balances)"
                r"\s*\[[^\]]*\]\s*\+=|"
                r"\b(shares|balances|balanceOf|_balances)"
                r"\s*\[[^\]]*\]\s*=\s*[^=]",
                text):
            continue
        # Floor division by a STORED total (not a raw balance).
        if not re.search(
                r"/\s*(?:\([^)]*\))?\s*"
                r"(totalSupply|totalAssets|totalShares|"
                r"_totalSupply|_totalAssets|_totalShares)\b",
                text):
            continue
        # Raw-balance rate is the built lending-accumulator shape,
        # not this one - stay silent there (no cross-talk).
        if _RAW_BALANCE_RE.search(text):
            continue
        # Round-up on the payout side is the protected shape.
        if _ROUND_UP_RE.search(text):
            continue
        # The payout must reach a destination (caller or supplied).
        if not re.search(
                r"\b(transfer|_mint|mint|transferFrom)\s*\(",
                text):
            continue
        detail = (
            f"{spec.detail} Evidence: function "
            f"'{fn['name']}' computes a share payout by floor "
            f"division against a stored total and credits it "
            f"without any minimum-shares / minimum-deposit / "
            f"virtual-shares guard, so repeated small calls "
            f"compound the rounding drift.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "no minimum-shares / minimum-deposit / "
                    "virtual-shares guard on the share conversion; "
                    "floor division on the payout side; externally "
                    "callable")
        out.append(_finish_recipient(spec, item, text))
        break
    return out


def _analyze_reward_distribution_manipulation(src, spec, compiler,
                                              contract_name):
    """Reward accumulator from a raw balance, or shares credited
    before the reward update, with a claim paying from it."""
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    if not _ACCUMULATOR_RE.search(scoped):
        return []
    if not any(_CLAIM_RE.search(fn["name"]) for fn in fns):
        return []
    # Shape (a), contract level: the accumulator is assigned from
    # the raw token balance somewhere in the contract (usually
    # inside the update function, not the deposit).
    shape_a = False
    for fn in fns:
        text = fn["text"]
        for m in _ACCUMULATOR_RE.finditer(text):
            tail = text[m.start():m.start() + 400]
            if _RAW_BALANCE_RE.search(tail):
                shape_a = True
                break
        if shape_a:
            break
    out = []
    for fn in fns:
        if _skip_fn(fn, scope) or not _is_entry(fn):
            continue
        if not re.search(r"\b(deposit|stake|mint|enter|supply)\b",
                         fn["name"]):
            continue
        text = fn["text"]
        # Shape (b): shares credited before (or without) the
        # reward update in this deposit path.
        shape_b = False
        credit = re.search(
            r"\b(_mint|mint)\s*\(|"
            r"\b(balances|shares)\s*\[[^\]]*\]\s*[\+\-]=",
            text)
        if credit:
            upd = _UPDATE_REWARD_RE.search(text)
            if upd is None or credit.start() < upd.start():
                shape_b = True
        if not (shape_a or shape_b):
            continue
        detail = (
            f"{spec.detail} Evidence: function "
            f"'{fn['name']}' "
            f"{'runs against a reward accumulator computed from '
              'the raw token balance' if shape_a else 'credits '
              'shares before the reward update runs (or never '
              'runs it)'}"
            f", while a claim function pays out from that "
            f"accumulator.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "reward accumulator is balance-derived or the "
                    "reward update runs after the share credit; a "
                    "claim pays from the accumulator")
        out.append(_finish_recipient(spec, item, text))
        break
    return out


def _analyze_flashloan_same_block_state_inconsistency(
        src, spec, compiler, contract_name):
    """Flash-loan callback (or deposit+withdraw in one function)
    that recomputes a rate from a transient balance between the
    deposit and the withdraw, with no block guard."""
    scope, fns = _scope_fns(src, contract_name)
    out = []
    for fn in fns:
        if _skip_fn(fn, scope) or not _is_entry(fn):
            continue
        text = fn["text"]
        is_callback = bool(_FLASH_RE.search(fn["name"]) or
                           _FLASH_RE.search(text))
        has_deposit = bool(re.search(
            r"\b(deposit|stake|mint|supply)\b", text))
        has_withdraw = bool(re.search(
            r"\b(withdraw|redeem|burn|exit)\b", text))
        if not (is_callback or (has_deposit and has_withdraw)):
            continue
        # A rate / price recomputed from a balance-dependent value.
        rate_from_balance = False
        for m in _RATE_ASSIGN_RE.finditer(text):
            tail = text[m.start():m.start() + 400]
            if (_RAW_BALANCE_RE.search(tail) or
                    "address(this).balance" in tail):
                rate_from_balance = True
                break
        if not rate_from_balance:
            continue
        # A block-number guard is the protected shape.
        if _BLOCK_GUARD_RE.search(text):
            continue
        # For deposit+withdraw, the recompute must sit between
        # the two; for a flash-loan callback the whole function
        # is the transient window.
        if not is_callback:
            dep = re.search(r"\b(deposit|stake|mint|supply)\b",
                            text)
            wd = re.search(r"\b(withdraw|redeem|burn|exit)\b",
                           text)
            rate = _RATE_ASSIGN_RE.search(text)
            if not (dep and wd and rate and
                    dep.start() < rate.start() < wd.start()):
                continue
        detail = (
            f"{spec.detail} Evidence: function "
            f"'{fn['name']}' recomputes an exchange rate / price "
            f"from a transient balance in the same call that "
            f"moves funds in and out, with no block-number guard.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "rate recomputed from a transient balance "
                    "between deposit and withdraw; no block-number "
                    "guard")
        out.append(_finish_recipient(spec, item, text))
        break
    return out


_CHECK_CALL_RE = re.compile(
    r"\b(require|assert)\s*\(|"
    r"\b(_check\w*|check\w*|isSolvent|healthFactor|"
    r"validate\w*|_validate\w*|requireHealthy|"
    r"checkSolvency)\s*\(")


_HEALTH_FN_RE = re.compile(
    r"^(check|_check|validate|_validate|isSolvent|"
    r"checkSolvency|requireHealthy|healthFactor)")
_HEALTH_WORD_RE = re.compile(
    r"\b(health|solvent|ltv|collateralRatio|healthFactor)\b",
    re.I)


def _analyze_multistep_state_order_violation(src, spec, compiler,
                                             contract_name):
    """A solvency / health check that runs before a write to a
    state variable the check depends on, never repeated after."""
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(src)
    out = []
    # What each function reads (state vars), so a check that
    # calls a helper (require(isSolvent(x))) resolves to the
    # state the helper reads.
    fn_reads = {}
    for other in fns:
        fn_reads[other["name"]] = {
            t for t in re.findall(
                r"[A-Za-z_][A-Za-z0-9_]*", other["text"])
            if t in state}
    for fn in fns:
        if _skip_fn(fn, scope) or not _is_entry(fn):
            continue
        text = fn["text"]
        writes = cl._state_writes(text, state)
        if not writes:
            continue
        # A "check" is a solvency / health check: a call to a
        # health-check function, or a require/assert whose
        # condition names a health-like value. A plain balance
        # comparison (require(balances[x] >= amount)) is NOT a
        # check - deducting after it is the normal pattern.
        checks = []
        for m in _CHECK_CALL_RE.finditer(text):
            try:
                paren = text.index("(", m.start())
                inner, _ = _balanced(text, paren)
            except ValueError:
                continue
            matched = m.group(0)
            cm = re.match(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                          matched)
            called = cm.group(1) if cm else ""
            is_named_check = bool(_HEALTH_FN_RE.match(called))
            is_health_require = bool(
                _HEALTH_WORD_RE.search(inner))
            if not (is_named_check or is_health_require):
                continue
            read = {t for t in re.findall(
                r"[A-Za-z_][A-Za-z0-9_]*", inner) if t in state}
            # Resolve the called function(s): the check reads
            # what the check function reads.
            if called in fn_reads:
                read |= fn_reads[called]
            for ident in re.findall(
                    r"[A-Za-z_][A-Za-z0-9_]*", inner):
                if ident in fn_reads:
                    read |= fn_reads[ident]
            if read:
                checks.append((m.start(), read))
        if not checks:
            continue
        violated = None
        for cpos, read in checks:
            for wpos, var in writes:
                if var in read and wpos > cpos:
                    # Is the check repeated after this write?
                    repeated = any(
                        c2 > wpos and var in r2
                        for c2, r2 in checks)
                    if not repeated:
                        violated = (cpos, var, wpos)
                        break
            if violated:
                break
        if not violated:
            continue
        cpos, var, wpos = violated
        detail = (
            f"{spec.detail} Evidence: function "
            f"'{fn['name']}' runs a solvency / health check that "
            f"reads state variable '{var}' before that variable "
            f"is written later in the same function, and the "
            f"check is never repeated after the write - the "
            f"check validates stale state.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "check reads a state variable that is written "
                    "after the check with no repeat check")
        out.append(_finish_recipient(spec, item, text))
        break
    return out


def _analyze_oracle_trust_assumption_break(src, spec, compiler,
                                           contract_name):
    """An external price feed drives a borrow / mint / liquidate /
    swap decision with no staleness, deviation, or positivity
    check."""
    scope, fns = _scope_fns(src, contract_name)
    out = []
    for fn in fns:
        if _skip_fn(fn, scope) or not _is_entry(fn):
            continue
        text = fn["text"]
        if not _PRICE_FEED_RE.search(text):
            continue
        if not _DECISION_RE.search(text):
            continue
        # Any feed guard is the protected shape.
        if _FEED_GUARD_RE.search(text):
            continue
        detail = (
            f"{spec.detail} Evidence: function "
            f"'{fn['name']}' reads an external price feed and "
            f"uses it for a borrow / mint / liquidate / swap "
            f"decision with no staleness check, no deviation "
            f"bound, and no positivity check.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "price feed used with no staleness, deviation, "
                    "or positivity guard")
        out.append(_finish_recipient(spec, item, text))
        break
    return out


ANALYZERS = {
    "rounding_iterated_drain": _analyze_rounding_iterated_drain,
    "reward_distribution_manipulation":
        _analyze_reward_distribution_manipulation,
    "flashloan_same_block_state_inconsistency":
        _analyze_flashloan_same_block_state_inconsistency,
    "multistep_state_order_violation":
        _analyze_multistep_state_order_violation,
    "oracle_trust_assumption_break":
        _analyze_oracle_trust_assumption_break,
}


def analyze_business_logic_source(src: str, spec: DetectorSpec,
                                  compiler: str = "",
                                  contract_name: str = ""
                                  ) -> List[Dict[str, Any]]:
    """Run ONE business-logic detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the deep-audit batches; analysis is
# analyze_business_logic_source per spec)
# ---------------------------------------------------------------------------

class BusinessLogicPlugin(Plugin):
    id = ""
    label = "Business Logic Invariant Detector"
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
        for item in analyze_business_logic_source(
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
                source="business-logic invariant detector "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (BusinessLogicPlugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Business-logic invariant detector for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
