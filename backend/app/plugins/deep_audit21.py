"""Deep-audit detectors, batch 21: oracle fallback, vault lockbooks,
period buckets, and redeem guards.

Five crypto-only, money-first detectors from the standing backlog
queue and fresh Nov 2026 research, built to the batch-11 /
recipient-first standard: recipient classification computed
inside the detector and carried on the finding (CALLER /
CALLER-SUPPLIED = candidate; FIXED / HOLDER-SELF = trigger-only,
never a candidate), the exact code plus a gate analysis on every
finding, and a finding shape the auto-validator can consume
unchanged (kind, function, recipient, report_class, gate).

- oracle_twap_fallback_to_spot: a price helper has BOTH a TWAP /
  observe path AND a fallback branch that reads spot price
  (getReserves / slot0) when the TWAP window is unpopulated or
  too short, and a redeem / payout / borrow function consumes
  that price. A flash loan moves the spot price inside one tx,
  so the fallback redeems at the distorted price - the
  CoreVault shape (BNB Chain, 2026-11-03, ~$112k / 259 BNB).
  A TWAP-only price, or a fallback that reverts instead of
  pricing, is the protected shape. Distinct from built
  twap_observe_window_short (window length only) and
  evm_v3_spot_price_oracle (pure spot read, no TWAP at all).
- erc4626_lockbook_share_transfer_desync: a staking vault
  enforces time-locks via per-deposit lock entries tracked by
  address, while shares are freely transferable - but the
  transfer path creates no lock entry for the recipient, so
  transferred-in shares are invisible to the unlock logic and
  the balance is stuck (or forced into a penalized emergency
  flow) - the Belong shape (Immunefi #57399 / #57685,
  Critical, permanent freezing of funds). A transfer that
  moves the lock entries with the shares, or non-transferable
  shares, is the protected shape. Distinct from built
  share_transfer_cancel_desync (stored entitlement refunded
  vs live balanceOf burn) - this is lock metadata not
  following shares.
- rescue_marks_future_bucket_claimed: a period-bucketed
  withdrawal system whose claimed mapping is the terminal
  marker for a period, plus a rescue function that sets the
  flag for a period without requiring it to have elapsed.
  _requestWithdraw always books into currentPeriod() + 1, so
  a pending bucket is by construction still open to further
  requests - rescuing it writes a terminal flag onto it, a
  later withdrawal in the same period burns the shares, and
  the bucket can never be claimed again (the flag is never
  cleared) - the Firelight shape (Immunefi #88231, High,
  permanent freezing of funds). A rescue that requires the
  period elapsed, or one that never writes the flag, is the
  protected shape. The rescue is RESCUER_ROLE-gated by
  design, so the gate does not suppress: the finding is the
  state corruption, not the gate.
- period_start_checkpoint_zeroes_payout_cap: a withdraw that
  burns shares and then writes a checkpoint keyed to the
  current period start with the post-withdrawal total, while
  a payout function reads that snapshot at the period start
  through an inclusive lookup and takes a min() against it.
  At block.timestamp == periodStart the inclusive lookup
  admits the post-withdrawal checkpoint, so the snapshot
  meant to bound pre-boundary exposure returns the
  post-withdrawal figure (0 in the PoC) and a settled cover
  obligation closes short while the collateral that answers
  for it stays in the vault - the Firelight shape (Immunefi
  #88287, High, protocol insolvency). A snapshot taken
  BEFORE the burn, or an exclusive lookup on the payout
  side, is the protected shape. The payout is privileged by
  design, so the gate does not suppress: the finding is the
  cap interaction, not the gate. Distinct from built
  cover_capacity_counts_unpaid_prior_period (capacity
  double-counts unpaid prior-period collateral - no
  checkpoint write involved).
- redeem_burns_shares_for_zero_assets: redeem() guards only
  its input (shares == 0) and never checks the assets it
  computes by flooring, while deposit / mint in the same
  contract DO guard zero shares - so after a payout loss
  leaves totalAssets below totalSupply, any share amount
  that floors to zero assets is destroyed with nothing
  queued and nothing later claimable - the Firelight shape
  (Immunefi #88269, Low). A third party spending an
  allowance can do the same to a victim's shares. The
  caller themself is the victim, so this one is HOLDER-SELF
  / trigger-only by construction under the receive rule,
  never a candidate. Distinct from built
  zero_amount_withdrawal_full_balance (zero amount releases
  the full balance - the opposite direction) and
  post_slash_erc4626_offset_inversion (offset inversion
  after a slash).

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding for the oracle, lockbook and redeem detectors - a
stranger cannot reach the path. The rescue and payout
detectors do NOT suppress on the role gate: the rescue is
RESCUER_ROLE-gated and the payout is privileged by design
in the vulnerable shape, and the bug is the state
corruption / cap interaction, not who may call it.

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
FAMILY = "deep21"

SPECS = [
    S("oracle_twap_fallback_to_spot", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="TWAP oracle falls back to spot price: a price "
             "helper has both a TWAP / observe path and a "
             "fallback branch that reads spot price "
             "(getReserves / slot0) when the TWAP window is "
             "unpopulated or too short, and a redeem / payout / "
             "borrow function consumes that price. A flash loan "
             "moves the spot price inside one tx, so the "
             "fallback redeems at the distorted price - the "
             "CoreVault shape (BNB Chain, 2026-11-03, ~$112k). "
             "A TWAP-only price, or a fallback that reverts "
             "instead of pricing, is the protected shape.",
      fix="Never price from spot as a TWAP fallback: revert "
          "when the TWAP window is unpopulated or too short "
          "('TWAP not ready'), or wait for the window to fill "
          "before the first redemption is allowed."),
    S("erc4626_lockbook_share_transfer_desync", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="ERC-4626 lockbook breaks share fungibility: a "
             "staking vault enforces time-locks via per-deposit "
             "lock entries tracked by address, while shares are "
             "freely transferable - but the transfer path "
             "creates no lock entry for the recipient, so "
             "transferred-in shares are invisible to the unlock "
             "logic and the balance is stuck (or forced into a "
             "penalized emergency flow) - the Belong shape "
             "(Immunefi #57399 / #57685, Critical, permanent "
             "freezing of funds). A transfer that moves the lock "
             "entries with the shares, or non-transferable "
             "shares, is the protected shape.",
      fix="Make lock metadata follow the shares: on transfer, "
          "move (or recreate) the sender's lock entries for "
          "the recipient, or make shares non-transferable "
          "while locked."),
    S("rescue_marks_future_bucket_claimed", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Rescue marks a future withdrawal bucket claimed: "
             "a period-bucketed withdrawal system whose claimed "
             "mapping is the terminal marker for a period, plus "
             "a rescue function that sets the flag for a period "
             "without requiring it to have elapsed. "
             "_requestWithdraw always books into "
             "currentPeriod() + 1, so a pending bucket is by "
             "construction still open to further requests - "
             "rescuing it writes a terminal flag onto it, a "
             "later withdrawal in the same period burns the "
             "shares, and the bucket can never be claimed again "
             "(the flag is never cleared) - the Firelight shape "
             "(Immunefi #88231, High, permanent freezing of "
             "funds).",
      fix="Require the rescued period to have elapsed before "
          "marking it claimed, and never write the terminal "
          "flag for a period that still accepts requests; add "
          "an admin path to clear a wrongly-set flag."),
    S("period_start_checkpoint_zeroes_payout_cap", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Period-start checkpoint zeroes the payout cap: a "
             "withdraw burns shares and then writes a "
             "checkpoint keyed to the current period start with "
             "the post-withdrawal total, while a payout function "
             "reads that snapshot at the period start through "
             "an inclusive lookup and takes a min() against it. "
             "At block.timestamp == periodStart the inclusive "
             "lookup admits the post-withdrawal checkpoint, so "
             "the snapshot meant to bound pre-boundary exposure "
             "returns the post-withdrawal figure and a settled "
             "cover obligation closes short while the collateral "
             "that answers for it stays in the vault - the "
             "Firelight shape (Immunefi #88287, High, protocol "
             "insolvency).",
      fix="Snapshot BEFORE the withdrawal (or key the "
          "checkpoint strictly before the period start), and "
          "use an exclusive lookup on the payout side so a "
          "checkpoint written at the boundary can never bound "
          "the period it opens."),
    S("redeem_burns_shares_for_zero_assets", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Redeem burns shares for zero assets: redeem() "
             "guards only its input (shares == 0) and never "
             "checks the assets it computes by flooring, while "
             "deposit / mint in the same contract DO guard zero "
             "shares - so after a payout loss leaves "
             "totalAssets below totalSupply, any share amount "
             "that floors to zero assets is destroyed with "
             "nothing queued and nothing later claimable - the "
             "Firelight shape (Immunefi #88269, Low). The "
             "caller themself is the victim, so this is "
             "HOLDER-SELF / trigger-only under the receive "
             "rule, never a candidate.",
      fix="Mirror the deposit guard in redeem: revert when the "
          "computed assets floor to zero, so shares are never "
          "burned for nothing."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 19 / deep19)
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
            "stranger can trigger this but receives nothing - "
            "classified TRIGGER-ONLY under the receive rule.")
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


# ---------------------------------------------------------------------------
# 1. oracle_twap_fallback_to_spot (CoreVault, 2026-11-03)
# ---------------------------------------------------------------------------

_TWAP_RE = re.compile(
    r"\b(observe|consult)\s*\(|\bTWAP\b|\btwap\b|"
    r"timeWeightedAveragePrice|averagePrice|getAveragePrice|"
    r"getTwap")
_SPOT_RE = re.compile(
    r"\bgetReserves\s*\(|\bslot0\s*\(|getSpotPrice|spotPrice|"
    r"\bspot\s+price\b")
_FALLBACK_WORD_RE = re.compile(r"\bfallback\b", re.I)
_TWAP_ZERO_RE = re.compile(
    r"(twap|average|observe|consult|observations?)[A-Za-z0-9_]*"
    r"\s*(==|<=|<)\s*0", re.I)
_TWAP_SHORT_RE = re.compile(
    r"(observations?|window|secondsAgo)\s*(==|<=|<)\s*\d+", re.I)
_UNPOPULATED_RE = re.compile(
    r"unpopulated|not\s+ready|notReady|too\s+short|insufficient",
    re.I)
_REVERT_RE = re.compile(r"\brevert\s*\(")
_TWAP_WORD_RE = re.compile(r"twap|TWAP|not.?ready|unpopulated|"
                           r"NotReady")


def _finish_oracle_recipient(spec: DetectorSpec,
                             item: Dict[str, Any],
                             fn_text: str) -> Dict[str, Any]:
    """Recipient for a TWAP-fallback consumer.

    The shared classifier reads a redeem of the caller's own
    position as HOLDER-SELF (the payout is metered by the
    caller's recorded balance). That meter bounds the SHARE
    count, not the payout value: the payout is shares x a
    price the caller moves through the spot fallback, so it
    can exceed the caller's own entitlement (CoreVault paid
    ~33x). The distorted price breaks the self-meter, so a
    HOLDER-SELF read on the consumer is CALLER here.
    """
    recipient, rdetail = cl.classify_recipient(fn_text)
    if recipient == "HOLDER-SELF":
        return _classify(
            item, "CALLER",
            "shared classifier reads HOLDER-SELF (payout "
            "metered by the caller's own position), but the "
            "meter bounds the share count, not the payout "
            "value - the payout is shares x a spot-fallback "
            "price the caller moves, so a stranger can receive "
            "more than their own entitlement")
    return _classify(item, recipient, rdetail)


def _analyze_oracle_twap_fallback(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    helpers = []
    for fn in fns:
        text = fn["text"]
        if not _TWAP_RE.search(text):
            continue
        if not _SPOT_RE.search(text):
            continue
        has_fallback = bool(_FALLBACK_WORD_RE.search(text))
        if not has_fallback:
            for m in re.finditer(r"\belse\b", text):
                if _SPOT_RE.search(text[m.end():]):
                    has_fallback = True
                    break
        if not has_fallback and (
                _TWAP_ZERO_RE.search(text)
                or _TWAP_SHORT_RE.search(text)
                or _UNPOPULATED_RE.search(text)):
            has_fallback = True
        if not has_fallback:
            continue
        # Suppress: the fallback reverts instead of pricing
        # (a TWAP-not-ready revert in the same function).
        if _REVERT_RE.search(text) and _TWAP_WORD_RE.search(text):
            continue
        helpers.append(fn)
    if not helpers:
        return []
    out: List[Dict[str, Any]] = []
    for helper in helpers:
        hname = helper["name"]
        consumers = [
            fn for fn in fns
            if fn is not helper
            and re.search(
                r"\b(redeem|payout|borrow|withdraw|claim)\w*\b",
                fn["name"])
            and re.search(r"\b" + re.escape(hname) + r"\s*\(",
                          fn["text"])]
        if consumers:
            for fn in consumers:
                detail = spec.detail + (
                    f" Observed: price helper '{hname}' falls "
                    f"back to spot price when its TWAP window is "
                    f"unpopulated / too short, and value-moving "
                    f"'{fn['name']}' consumes that price - a "
                    f"flash loan moves the spot inside one tx. "
                    f"Gate analysis: no caller-identity gate on "
                    f"the consumer; the helper is a view by "
                    f"design.")
                item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                            detail,
                            "ungated value-moving consumer of a "
                            "TWAP price with a spot fallback; the "
                            "helper is a view by design")
                out.append(_finish_oracle_recipient(spec, item,
                                                    fn["text"]))
        else:
            detail = spec.detail + (
                f" Observed: price helper '{hname}' falls back "
                f"to spot price when its TWAP window is "
                f"unpopulated / too short; no redeem / payout / "
                f"borrow consumer was found in this source, so "
                f"confirm the caller before treating it as a "
                f"live drain path. Gate analysis: the helper is "
                f"a view by design.")
            item = _hit(spec, hname, cc._snip(helper["text"]),
                        detail,
                        "price helper with a spot fallback; no "
                        "value-moving consumer found in source")
            item["recipient"] = "UNRESOLVED"
            item["report_class"] = "candidate"
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# 2. erc4626_lockbook_share_transfer_desync (Belong #57399/#57685)
# ---------------------------------------------------------------------------

_LOCKBOOK_STRUCT_RE = re.compile(
    r"struct\s+(Stake|Lock|LockedDeposit|DepositLock)\b")
_LOCKBOOK_MAP_RE = re.compile(
    r"mapping\s*\(\s*address\s*=>\s*[^;{]*(Stake|Lock|Deposit|"
    r"Entry)[^;{]*\)")
_LOCKBOOK_VAR_RE = re.compile(
    r"\b(stakes|userStakes|locks|userLocks|lockEntries|"
    r"stakeEntries|deposits)\s*\[")
_UNLOCK_CHECK_RE = re.compile(
    r"unlock(Time|At|After)|lockedUntil|unlockTimestamp|"
    r"canWithdraw|isUnlocked|unlockedAmount")
_LOCKBOOK_WRITE_RE = re.compile(
    r"\b(stakes|userStakes|locks|userLocks|lockEntries|"
    r"stakeEntries|deposits)\s*\[[^\]]*\]\s*(\.push\s*\(|=)")
_LEDGER_CREDIT_KEY_RE = re.compile(
    r"\b(?:balances|balanceOf|_balances|shares)\s*\[\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*(?:\+=|=)(?!=)")


def _transfer_recipient(fn: Dict[str, Any]
                        ) -> Tuple[str, str]:
    """Recipient for a share transfer, read directly.

    The shared classifier only sees transfer() / call()
    destinations and mint-shaped ledger credits, so a share
    transfer's destination - the address credited in the
    ledger - is invisible to it. This detector reads it
    directly: a credited caller-supplied `to` parameter is
    CALLER-SUPPLIED (the frozen shares land on an address
    the caller chooses); a credit to a fixed / state address
    only is FIXED.
    """
    params = _fn_params(fn)
    credited = _LEDGER_CREDIT_KEY_RE.findall(fn["text"])
    for key in credited:
        if key in params:
            return ("CALLER-SUPPLIED",
                    "transfer credits the caller-supplied "
                    f"'{key}' address, so the frozen shares "
                    "land on an address the caller chooses")
    return ("FIXED",
            "transfer credits only a fixed / state address, "
            "never a caller-supplied one")


def _analyze_lockbook_desync(src, spec, compiler,
                             contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    has_book = bool(
        _LOCKBOOK_STRUCT_RE.search(scoped)
        or _LOCKBOOK_MAP_RE.search(scoped)
        or _LOCKBOOK_VAR_RE.search(scoped))
    if not has_book:
        return []
    deposit_creates = False
    for fn in fns:
        if (re.search(r"\b(deposit|mint|stake)\w*\b",
                      fn["name"])
                and _LOCKBOOK_WRITE_RE.search(fn["text"])):
            deposit_creates = True
            break
    if not deposit_creates:
        return []
    withdraw_unlocked = False
    for fn in fns:
        if (re.search(r"\b(withdraw|redeem|unlock|claim)\w*\b",
                      fn["name"])
                and _LOCKBOOK_VAR_RE.search(fn["text"])
                and _UNLOCK_CHECK_RE.search(fn["text"])):
            withdraw_unlocked = True
            break
    if not withdraw_unlocked:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] not in ("transfer", "transferFrom"):
            continue
        if _REVERT_RE.search(fn["text"]):
            # Shares are non-transferable in practice: the
            # transfer path always reverts.
            continue
        if _LOCKBOOK_WRITE_RE.search(fn["text"]):
            # Transfer moves the lock entries with the shares:
            # the protected shape.
            continue
        if _skip_fn(fn, scope):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' moves shares but "
            f"writes no lock entry for the recipient, while "
            f"deposit creates per-address lock entries and "
            f"withdraw consumes only unlocked entries - "
            f"transferred-in shares are invisible to the "
            f"unlock logic. Gate analysis: no caller-identity "
            f"gate on the transfer.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "ungated transfer with no lockbook write; "
                    "deposit creates lock entries, withdraw "
                    "consumes only unlocked ones")
        recipient, rdetail = _transfer_recipient(fn)
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 3. rescue_marks_future_bucket_claimed (Firelight #88231)
# ---------------------------------------------------------------------------

_CLAIMED_MAP_RE = re.compile(
    r"\b(isWithdrawClaimed|withdrawClaimed|"
    r"claimedWithdrawals?|isClaimed|withdrawalClaimed)\s*\[")
_FLAG_WRITE_RE = re.compile(
    r"\b(isWithdrawClaimed|withdrawClaimed|"
    r"claimedWithdrawals?|isClaimed|withdrawalClaimed)"
    r"\s*\[[^;=]{0,80}?=\s*true")
_ELAPSED_CHECK_RE = re.compile(
    r"periods?\s*(?:\[[^\]]*\])?\s*<\s*currentPeriod|"
    r"hasElapsed|periodEnded|block\.timestamp\s*>=.*periodEnd|"
    r"require\s*\(\s*period\s*<")
_CLEAR_FLAG_RE = re.compile(
    r"delete\s+(isWithdrawClaimed|withdrawClaimed|"
    r"claimedWithdrawals?|isClaimed)|"
    r"\b(isWithdrawClaimed|withdrawClaimed|"
    r"claimedWithdrawals?|isClaimed)\s*\[[^;=]{0,80}?=\s*false")


def _analyze_rescue_future_bucket(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    if not _CLAIMED_MAP_RE.search(scoped):
        return []
    claim_guarded = any(
        re.search(r"\bclaim\w*\b", fn["name"])
        and re.search(r"AlreadyClaimed|already.?claimed",
                      fn["text"])
        for fn in fns)
    if not claim_guarded:
        return []
    if _CLEAR_FLAG_RE.search(scoped):
        # An admin path clears a wrongly-set flag: the
        # terminal-marker corruption is recoverable.
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not re.search(r"rescue", fn["name"], re.I):
            continue
        if not _FLAG_WRITE_RE.search(fn["text"]):
            continue
        if _ELAPSED_CHECK_RE.search(fn["text"]):
            continue
        detail = spec.detail + (
            f" Observed: rescue '{fn['name']}' writes the "
            f"terminal claimed flag for a period without "
            f"requiring it to have elapsed, while "
            f"_requestWithdraw always books into "
            f"currentPeriod() + 1 - a pending bucket is by "
            f"construction still open to further requests, "
            f"and the flag is never cleared. Gate analysis: "
            f"the rescue is role-gated by design; the finding "
            f"is the state corruption, not the gate.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "rescue is role-gated by design; it writes "
                    "a terminal flag onto a period that still "
                    "accepts requests, and the flag is never "
                    "cleared")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 4. period_start_checkpoint_zeroes_payout_cap (Firelight #88287)
# ---------------------------------------------------------------------------

_CHECKPOINT_WRITE_RE = re.compile(
    r"_logTrace\s*\(|checkpoints\.push|traces\.push|"
    r"snapshots\s*\[|checkpoint\s*\(|_pushCheckpoint|pushTrace")
_CHECKPOINT_KEY_RE = re.compile(
    r"[Pp]eriodStart|currentPeriodStart|block\.timestamp|"
    r"Time\.timestamp")
_BURN_RE = re.compile(
    r"_burn\s*\(|_update\s*\(\s*\w+\s*,\s*address\(0\)")
_INCLUSIVE_LOOKUP_RE = re.compile(
    r"upperLookupRecent|upperLookup|"
    r"totalAssetsAt\s*\(\s*[^)]*[Pp]eriodStart|snapshotAt\s*\(")
_EXCLUSIVE_LOOKUP_RE = re.compile(r"lowerLookup")
_MIN_CAP_RE = re.compile(r"\bmin\s*\(")


def _analyze_period_checkpoint_cap(src, spec, compiler,
                                   contract_name):
    scope, fns = _scope_fns(src, contract_name)
    bad_withdraw = None
    for fn in fns:
        if not re.search(r"\b(withdraw|requestWithdraw)\w*\b",
                         fn["name"]):
            continue
        text = fn["text"]
        burn_m = _BURN_RE.search(text)
        if not burn_m:
            continue
        cp_m = None
        for m in _CHECKPOINT_WRITE_RE.finditer(text):
            window = text[max(0, m.start() - 120):
                          m.start() + 200]
            if _CHECKPOINT_KEY_RE.search(window):
                cp_m = m
                break
        if cp_m and cp_m.start() > burn_m.start():
            bad_withdraw = fn
            break
    if bad_withdraw is None:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not re.search(r"\b(payout|settle|payClaim)\w*\b",
                         fn["name"]):
            continue
        text = fn["text"]
        if not _INCLUSIVE_LOOKUP_RE.search(text):
            continue
        if _EXCLUSIVE_LOOKUP_RE.search(text):
            continue
        if not _MIN_CAP_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: withdraw '{bad_withdraw['name']}' "
            f"burns shares and THEN writes a checkpoint keyed "
            f"to the current period start with the "
            f"post-withdrawal total, while payout "
            f"'{fn['name']}' reads that snapshot at the period "
            f"start through an inclusive lookup and takes a "
            f"min() against it - at block.timestamp == "
            f"periodStart the post-withdrawal checkpoint bounds "
            f"the period it opens. Gate analysis: the payout "
            f"is privileged by design; the finding is the cap "
            f"interaction, not the gate.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "payout is privileged by design; withdraw "
                    "writes a period-start checkpoint after "
                    "burning, payout caps on it inclusively")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 5. redeem_burns_shares_for_zero_assets (Firelight #88269)
# ---------------------------------------------------------------------------

_SHARES_ZERO_GUARD_RE = re.compile(
    r"require\s*\(\s*shares\w*\s*>\s*0|"
    r"if\s*\(\s*shares\w*\s*==\s*0\s*\)\s*revert|"
    r"require\s*\(\s*shares\w*\s*!=\s*0")
_ASSETS_ZERO_GUARD_RE = re.compile(
    r"require\s*\(\s*assets\w*\s*>\s*0|"
    r"if\s*\(\s*assets\w*\s*==\s*0\s*\)\s*revert|"
    r"require\s*\(\s*assets\w*\s*!=\s*0")
_BOOK_ASSETS_RE = re.compile(
    r"withdrawAssets\s*\[|withdrawShares\s*\[|pendingWithdraw")


def _analyze_redeem_zero_assets(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    deposit_guards = False
    for fn in fns:
        if (re.search(r"\b(deposit|mint)\w*\b", fn["name"])
                and _SHARES_ZERO_GUARD_RE.search(fn["text"])):
            deposit_guards = True
            break
    if not deposit_guards:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] != "redeem":
            continue
        text = fn["text"]
        if not _SHARES_ZERO_GUARD_RE.search(text):
            continue
        if _ASSETS_ZERO_GUARD_RE.search(text):
            continue
        if not _BURN_RE.search(text):
            continue
        if not _BOOK_ASSETS_RE.search(text):
            continue
        if _skip_fn(fn, scope):
            continue
        detail = spec.detail + (
            " Observed: 'redeem' guards only its input "
            "(shares == 0) and never checks the assets it "
            "computes by flooring, while deposit / mint in "
            "the same contract DO guard zero shares - after a "
            "payout loss leaves totalAssets below totalSupply, "
            "any share amount that floors to zero assets is "
            "burned with nothing queued and nothing later "
            "claimable. Gate analysis: redeem is "
            "caller-initiated on the caller's own shares; the "
            "finding is the missing zero-assets guard, not "
            "the gate.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "redeem is caller-initiated on the caller's "
                    "own shares; deposit guards zero shares, "
                    "redeem does not guard zero assets")
        # The caller themself is the victim (and a third party
        # spending an allowance can burn a victim's shares the
        # same way): HOLDER-SELF / trigger-only by
        # construction, never a candidate.
        out.append(_classify(
            item, "HOLDER-SELF",
            "redeem burns the caller's own shares for the "
            "assets it computes - zero when the share price "
            "floors to zero; the caller themself is the "
            "victim, and an allowance spender can burn a "
            "victim's shares the same way"))
    return out


ANALYZERS = {
    "oracle_twap_fallback_to_spot": _analyze_oracle_twap_fallback,
    "erc4626_lockbook_share_transfer_desync":
        _analyze_lockbook_desync,
    "rescue_marks_future_bucket_claimed":
        _analyze_rescue_future_bucket,
    "period_start_checkpoint_zeroes_payout_cap":
        _analyze_period_checkpoint_cap,
    "redeem_burns_shares_for_zero_assets":
        _analyze_redeem_zero_assets,
}


def analyze_deep21_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-21 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-19 / deep19 collection /
# fetch / proxy resolution; analysis is analyze_deep21_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit21Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 21)"
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
        for item in analyze_deep21_source(
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
                source="deep audit detector batch 21 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit21Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 21) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
