"""Deep-audit detectors, batch 11: AI plugin dev (2026-11-06).

Five more chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-10 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- amm_scale_rounding_wrong_direction: a scaling helper that
  rounds DOWN unconditionally (mulDown / floor division) when
  scaling the EXACT_OUT output amount, where round-up is
  required, applied by a swap function to the amount-out side,
  so the protocol systematically undercharges and micro-swaps
  compound the drift into a drain. The Balancer V2 Nov 2025
  shape (~$116-128M). Distinct from built
  inverted_division_zero_collapse (a division collapsing to 0)
  and vault_share_inflation (4626 share conversion) and
  cp_proto_rounding_order (ordering). Rounding the output scale
  up, or scaling only the amount-in side, stays silent.
- lending_accumulator_donation_inflation: a lending market
  exchange rate / accumulator computed from the market raw token
  balance (balanceOf(address(this)), donation-sensitive)
  divided by the share supply, with deposit / withdraw minting
  and burning by dividing by that rate and no virtual-shares /
  minimum-deposit guard, so a small donation into an empty
  market inflates the rate and deposit / withdraw rounding grows
  raw balance for free. The zkLend Feb 2025 shape (~$9.5M).
  The EVM analogue of the cToken / zToken exchange-rate shape,
  NOT ERC-4626 (built vault_share_inflation is 4626-only). A
  rate from stored accounting (totalCash / totalAssets), or a
  virtual-shares / minimum-deposit guard, stays silent.
- batch_deferred_check_flag_reset: a multi-action batch
  (cook-style) where a borrow action sets a boolean
  solvency-check flag and a later no-op action clears it, so the
  end-of-batch solvency check gated on the flag never runs and
  undercollateralized debt is minted. The Abracadabra cook()
  Oct 2025 shape (~$1.8M). Shape: boolean deferred-validation
  flag set true by a sensitive action and set false by another
  action handler, final check gated on the flag. A final check
  that always runs, or a no-op that never touches the flag,
  stays silent.
- liquidation_residual_collateral_reborrow: a liquidate /
  self-liquidation path that zeroes the debt but leaves the
  collateral / order record that borrow() reads, so a later
  borrow sizes itself against collateral that no longer backs a
  position and mints undercollateralized debt. The Abracadabra
  GM cauldron Mar 2025 shape (~$13M). Clearing the record in
  the same liquidate path stays silent.
- transient_slot_reuse_auth_bypass: the same transient storage
  slot written with two meanings - an auth-critical pool address
  for the swap callback check, then an attacker-influenced
  amount (cast to address) - so the callback auth passes for an
  attacker CREATE2 vanity contract. The SIR.trading Mar 2025
  shape (~$355k). Distinct from built transient_latch_unconsumed
  (latch never cleared). One slot per meaning, or clearing the
  slot after the callback, stays silent.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. The mechanism
under analysis itself does NOT count as such a gate: the
callback auth check in the transient-slot shape is the claimed
authorization being audited, so it never suppresses. (Same
narrowing of cl._gated_deep as batch 10.)

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
FAMILY = "deep11"

SPECS = [
    S("amm_scale_rounding_wrong_direction", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="AMM scale rounding wrong direction: a scaling "
             "helper rounds DOWN (mulDown / floor division) when "
             "scaling the EXACT_OUT output amount, where round-up "
             "is required, and a swap function applies it to the "
             "amount-out side, so the protocol systematically "
             "undercharges and micro-swaps at low liquidity "
             "compound the drift into a drain - the Balancer V2 "
             "shape. Rounding the output scale UP, or scaling "
             "only the amount-in side, is the protected shape.",
      fix="Round the output-side scale UP (mulUp / ceil "
          "division) so the amount out can never be "
          "undercharged, and never reuse a round-down scaler on "
          "the EXACT_OUT leg."),
    S("lending_accumulator_donation_inflation", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Lending accumulator donation inflation: a lending "
             "market exchange rate / accumulator is computed from "
             "the market raw token balance "
             "(balanceOf(address(this)), donation-sensitive) "
             "divided by the share supply, and deposit / withdraw "
             "mint and burn by dividing by that rate, with no "
             "virtual-shares or minimum-deposit guard, so a small "
             "donation into an empty market inflates the rate and "
             "deposit / withdraw rounding grows raw balance for "
             "free - the zkLend shape. A rate computed from stored "
             "accounting (totalCash / totalAssets), or a "
             "virtual-shares / minimum-deposit guard, is the "
             "protected shape.",
      fix="Compute the exchange rate from stored accounting, "
          "never from the raw token balance, and add virtual "
          "shares (or a minimum first deposit) so an empty market "
          "cannot be inflated by a donation."),
    S("batch_deferred_check_flag_reset", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Batch deferred-check flag reset: a multi-action "
             "batch (cook-style) sets a boolean solvency-check "
             "flag in one action handler (borrow) and a later "
             "action handler (no-op) clears it, so the "
             "end-of-batch solvency check gated on the flag never "
             "runs and undercollateralized debt is minted - the "
             "Abracadabra cook() shape. A final check that always "
             "runs, or a no-op that never touches the flag, is the "
             "protected shape.",
      fix="Run the solvency check unconditionally at the end of "
          "every batch, or make the flag write-once per batch "
          "(set-only, never cleared by another action) so a later "
          "action cannot cancel it."),
    S("liquidation_residual_collateral_reborrow", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Liquidation residual collateral reborrow: a "
             "liquidate / self-liquidation path zeroes the debt "
             "but leaves the collateral / order record that "
             "borrow() reads, so a later borrow sizes itself "
             "against collateral that no longer backs a position "
             "and mints undercollateralized debt - the Abracadabra "
             "GM cauldron shape. Clearing the collateral / order "
             "record in the same liquidate path is the protected "
             "shape.",
      fix="Clear (delete / zero) the collateral and order record "
          "in the same transaction that zeroes the debt, and have "
          "borrow() re-read the live position rather than a stale "
          "record."),
    S("transient_slot_reuse_auth_bypass", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Transient slot reuse auth bypass: the same transient "
             "storage slot is written with two meanings - an "
             "auth-critical pool address that a swap callback "
             "checks against msg.sender, then an "
             "attacker-influenced amount (cast to address) - so "
             "the callback auth passes for an attacker-controlled "
             "CREATE2 vanity contract - the SIR.trading shape. One "
             "slot per meaning, or clearing the slot after the "
             "callback, is the protected shape.",
      fix="Give the auth address and the amount separate "
          "transient slots, never reuse a slot across meanings, "
          "and clear the auth slot at the end of the callback."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 3)
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
# 1. AMM scale rounding wrong direction (Balancer V2 shape)
# ---------------------------------------------------------------------------

_UPSCALE_FN_RE = re.compile(r"upscale|scaleUp|scale.*Up|toScaled",
                            re.I)
_MULDOWN_RE = re.compile(r"\bmulDown\b|\bdivDown\b")
_MULUP_RE = re.compile(r"\bmulUp\b|\bdivUp\b|Rounding\.Up|ceilDiv|"
                       r"mulDivRoundingUp")
_CEIL_ADD_RE = re.compile(
    r"\+\s*(?:1e18|10\s*\*\*\s*18|PRECISION|SCALE|"
    r"[A-Za-z_]\w*)\s*-\s*1\s*\)\s*/")
_SCALE_FACTOR_RE = re.compile(
    r"\bscalingFactor\b|\bSCALING_FACTOR\b|\bscale\b")
_SCALE_DIV_RE = re.compile(
    r"\*\s*[^;]{0,100}?\b(?:scalingFactor|SCALING_FACTOR|scale)\b"
    r"[^;]{0,40}?/\s*(?:1e18|10\s*\*\*\s*18|PRECISION|SCALE)")
_SWAP_FN_RE = re.compile(r"swap|batchSwap|onSwap|givenOut|exactOut",
                         re.I)
_OUT_ARG_RE = re.compile(
    r"\b(amountOut|amountsOut|outAmount|outputAmount|exactOut|"
    r"givenOut|amountOutScaled|scaledOut)\b")
_OUT_KIND_RE = re.compile(
    r"GIVEN_OUT|EXACT_OUT|givenOut|exactOut|SwapKind\.GIVEN_OUT")


def _is_down_scaling_helper(fn: Dict[str, Any]) -> bool:
    """A scaling helper that rounds DOWN unconditionally.

    Name hit (upscale / scaleUp) or a mulDown body, plus real
    scaling math (mulDown / divDown call, or amount * factor /
    denominator floor division), and no round-up anywhere in
    the helper (mulUp / divUp / ceil / +denominator-1).
    """
    text = fn["text"]
    name_hit = bool(_UPSCALE_FN_RE.search(fn["name"]))
    body_hit = bool(_MULDOWN_RE.search(text) and
                    _SCALE_FACTOR_RE.search(text))
    if not (name_hit or body_hit):
        return False
    if _MULUP_RE.search(text) or _CEIL_ADD_RE.search(text):
        return False
    if _MULDOWN_RE.search(text):
        return True
    return bool(_SCALE_DIV_RE.search(text))


def _analyze_amm_scale_rounding(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # Down-rounding scalers, plus one-hop wrappers (e.g. an
    # _upscaleArray that loops over the leaf _upscale).
    down = {fn["name"] for fn in fns if _is_down_scaling_helper(fn)}
    if not down:
        return []
    changed = True
    while changed:
        changed = False
        for fn in fns:
            if fn["name"] in down:
                continue
            if any(re.search(r"\b" + re.escape(d) + r"\s*\(",
                             fn["text"]) for d in down):
                down.add(fn["name"])
                changed = True
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SWAP_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # The swap must apply a down-scaler to the OUT side:
        # called with an amount-out argument, or inside a
        # GIVEN_OUT / EXACT_OUT leg. Scaling only the amount-in
        # side is the protected direction and stays silent.
        out_side = False
        out_arg = ""
        call_pos = -1
        for d in down:
            for m in re.finditer(r"\b" + re.escape(d) +
                                 r"\s*\(", text):
                paren = text.index("(", m.start())
                inner, _ = _balanced(text, paren)
                args = _split_top(inner)
                for a in args:
                    if _OUT_ARG_RE.search(a):
                        out_side = True
                        out_arg = a.strip()
                        call_pos = m.start()
                        break
                if out_side:
                    break
            if out_side:
                break
        if not out_side and _OUT_KIND_RE.search(text):
            for d in down:
                m = re.search(r"\b" + re.escape(d) + r"\s*\(",
                              text)
                if m:
                    out_side = True
                    call_pos = m.start()
                    break
        if not out_side:
            continue
        # Value actually leaves the contract after the scaling.
        if not [c for c in cl._external_calls(text)
                if c["pos"] > call_pos]:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' scales the amount-out "
            f"side ('{out_arg}'"
            f"{'' if out_arg else ' via a GIVEN_OUT / EXACT_OUT leg'}) "
            f"with a round-down scaler "
            f"({sorted(down)[0] if len(down) == 1 else 'one of ' + ', '.join(sorted(down))}) "
            f"and pays the scaled amount out, so the protocol "
            f"undercharges on every EXACT_OUT swap and "
            f"micro-swaps compound the drift. Gate analysis: no "
            f"caller-identity gate, no round-up on the output "
            f"leg, no amount-in-only scaling.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated swap: round-down scaler on the "
                    "amount-out leg, no mulUp / ceil on that leg")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. Lending accumulator donation inflation (zkLend shape)
# ---------------------------------------------------------------------------

_RATE_VAR_RE = re.compile(
    r"\b(exchangeRate|accumulator|exchangeAccumulator|"
    r"ratePerShare|pricePerShare|_exchangeRate|_accumulator)\b")
_BALANCE_OF_THIS_RE = re.compile(
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")
_MINT_FN_RE = re.compile(r"^(deposit|mint|supply|subscribe)$", re.I)
_BURN_FN_RE = re.compile(
    r"^(withdraw|redeem|burn|unsupply|unsubscribe)$", re.I)
# Virtual-shares / minimum-deposit guards. Bare "virtual" is
# NOT a guard: most contracts mark functions virtual.
_ACC_GUARD_RE = re.compile(
    r"virtualShares|virtual_shares|VIRTUAL_SHARES|"
    r"VirtualShares|MINIMUM_SHARES|MIN_DEPOSIT|minimumDeposit|"
    r"MINIMUM_DEPOSIT|MINIMUM_LIQUIDITY")
_SUPPLY_TOTAL_RE = re.compile(r"\b(?:totalSupply|totalShares)\b")


def _analyze_lending_accumulator(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Leg 1: a rate / accumulator computed from the market raw
    # token balance (donation-sensitive) divided by the share
    # supply - either a rate-named function returning that
    # expression, or an assignment to a rate-named variable.
    rate_names: set = set()
    for fn in fns:
        if _RATE_VAR_RE.search(fn["name"]):
            text = fn["text"]
            if _BALANCE_OF_THIS_RE.search(text) and \
                    re.search(r"/[^;]*?", text) and \
                    _SUPPLY_TOTAL_RE.search(text):
                rate_names.add(fn["name"])
    for m in re.finditer(
            r"\b([A-Za-z_]\w*)\s*=\s*[^;]{0,240}", scoped):
        rhs = m.group(0)
        if _RATE_VAR_RE.search(m.group(1)) and \
                _BALANCE_OF_THIS_RE.search(rhs) and \
                re.search(r"/[^;]*?\b(?:totalSupply|totalShares)"
                         r"\b", rhs):
            rate_names.add(m.group(1))
    if not rate_names:
        return []
    # A rate from stored accounting (totalCash / totalAssets)
    # is not donation-sensitive: leg 1 already requires the
    # raw balanceOf(address(this)) in the rate expression.
    # Leg 2 guard: virtual shares / minimum deposit anywhere
    # in scope blocks the empty-market inflation.
    if _ACC_GUARD_RE.search(scoped):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not (_MINT_FN_RE.match(fn["name"]) or
                _BURN_FN_RE.match(fn["name"])):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 3: mint / burn divides an amount by the
        # donation-sensitive rate.
        div_name = None
        for rn in sorted(rate_names):
            if re.search(r"/[^;]{0,60}?\b" + re.escape(rn) +
                         r"\b", text):
                div_name = rn
                break
        if div_name is None:
            continue
        # Value actually moves: shares minted / assets paid.
        if not cl._external_calls(text) and \
                "totalSupply" not in text and \
                "balanceOf" not in text:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' divides by "
            f"'{div_name}', an exchange rate computed from "
            f"balanceOf(address(this)) / totalSupply, with no "
            f"virtual-shares or minimum-deposit guard, so a small "
            f"donation into an empty market inflates the rate and "
            f"deposit / withdraw rounding grows raw balance for "
            f"free. Gate analysis: no caller-identity gate, no "
            f"virtual-shares offset, no minimum-deposit guard.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated mint/burn: divides by a "
                    "donation-sensitive rate, no virtual-shares "
                    "or minimum-deposit guard")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. Batch deferred-check flag reset (Abracadabra cook() shape)
# ---------------------------------------------------------------------------

_BOOL_DECL_RE = re.compile(
    r"\bbool\s+(?:public\s+|private\s+|internal\s+)?"
    r"([A-Za-z_]\w*)\s*(?:;|=)")
_BATCH_FN_RE = re.compile(
    r"^(cook|batch|multicall|executeBatch|batchExecute|"
    r"cookActions)$", re.I)
_SOLVENCY_RE = re.compile(
    r"solven|healthFactor|isSolvent|checkSolvency|"
    r"health\b", re.I)


def _analyze_batch_flag_reset(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    bool_vars = {m.group(1)
                 for m in _BOOL_DECL_RE.finditer(scoped)}
    if not bool_vars:
        return []
    # Which function sets the flag true, which sets it false.
    # The two writes must be in DIFFERENT handlers: a flag
    # set and cleared inside one handler cannot cancel a
    # batch-level check.
    setters: Dict[str, Dict[str, set]] = {}
    for fn in fns:
        for var in bool_vars:
            if re.search(r"\b" + re.escape(var) +
                         r"\s*=\s*true\b", fn["text"]):
                setters.setdefault(var, {}).setdefault(
                    fn["name"], set()).add(True)
            if re.search(r"\b" + re.escape(var) +
                         r"\s*=\s*false\b", fn["text"]):
                setters.setdefault(var, {}).setdefault(
                    fn["name"], set()).add(False)
    flag = None
    true_fn = None
    false_fn = None
    for var, by_fn in setters.items():
        true_fns = [n for n, v in by_fn.items() if True in v]
        false_fns = [n for n, v in by_fn.items() if False in v]
        for tf in true_fns:
            for ff in false_fns:
                if tf != ff:
                    flag, true_fn, false_fn = var, tf, ff
                    break
            if flag is not None:
                break
        if flag is not None:
            break
    if flag is None:
        return []
    true_fn_text = ""
    for fn in fns:
        if fn["name"] == true_fn:
            true_fn_text = fn["text"]
            break
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BATCH_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # The batch dispatches actions in a loop and both
        # handlers are reachable from it.
        if not re.search(r"\bfor\s*\(|\bwhile\s*\(", text):
            continue
        if true_fn not in text and false_fn not in text:
            continue
        # The end-of-batch check is gated on the flag.
        m = re.search(r"if\s*\(\s*" + re.escape(flag) +
                      r"\s*\)", text)
        if not m:
            continue
        tail = text[m.start():m.start() + 400]
        if not _SOLVENCY_RE.search(tail):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' batches actions in a "
            f"loop; '{true_fn}' sets '{flag}' true and "
            f"'{false_fn}' clears it, so a later no-op action "
            f"cancels the flag and the end-of-batch check "
            f"'if ({flag})' guarding the solvency check never "
            f"runs. Gate analysis: the batch itself is ungated "
            f"and the flag IS the deferred check, so no "
            f"caller-identity gate suppresses it.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated batch: solvency check deferred "
                    "behind a flag that another action clears")
        out.append(_finish_recipient(spec, item, true_fn_text))
    return out


# ---------------------------------------------------------------------------
# 4. Liquidation residual collateral reborrow (GM cauldron shape)
# ---------------------------------------------------------------------------

_LIQUIDATE_FN_RE = re.compile(r"liquidat", re.I)
_BORROW_FN_RE = re.compile(r"^borrow", re.I)
_DEBT_ZERO_RE = re.compile(
    r"\b(?:[A-Za-z_]*[Dd]ebt[A-Za-z_]*|[A-Za-z_]*[Bb]orrow\w*)"
    r"\s*(?:\[[^\]]+\])?\s*=\s*0\b")
_DEBT_DELETE_RE = re.compile(
    r"\bdelete\s+(?:[A-Za-z_]*[Dd]ebt[A-Za-z_]*|"
    r"[A-Za-z_]*[Bb]orrow\w*)")
_RECORD_NAME_RE = re.compile(
    r"[Cc]ollateral|[Oo]rder|[Pp]osition")


def _analyze_liquidation_residual(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    records = {v for v in state if _RECORD_NAME_RE.search(v)}
    if not records:
        return []
    # borrow() must read the record to size the loan.
    borrow_reads = None
    for fn in fns:
        if not _BORROW_FN_RE.match(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        for rec in sorted(records):
            if re.search(r"\b" + re.escape(rec) + r"\b",
                         fn["text"]):
                borrow_reads = (fn, rec)
                break
        if borrow_reads:
            break
    if borrow_reads is None:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _LIQUIDATE_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Leg 1: liquidate zeroes the debt (assignment to 0
        # or delete on a debt / borrow balance).
        if not (_DEBT_ZERO_RE.search(text) or
                _DEBT_DELETE_RE.search(text)):
            continue
        # Leg 2: liquidate does NOT clear the record borrow()
        # reads - no delete, no zeroing, no other write to it.
        rec = borrow_reads[1]
        cleared = bool(
            re.search(r"\bdelete\s+" + re.escape(rec) + r"\b",
                      text)
            or re.search(r"\b" + re.escape(rec) +
                         r"\s*(?:\[[^\]]+\])?\s*"
                         r"(?:=\s*0\b|-\=|=\s*[^=])", text))
        if cleared:
            continue
        # The stale position has value: seized collateral
        # leaves the contract on this path.
        if not cl._external_calls(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' zeroes the debt but "
            f"never clears '{rec}', the record "
            f"'{borrow_reads[0]['name']}' reads to size a loan, "
            f"so a later borrow mints against collateral that no "
            f"longer backs a position. Gate analysis: liquidate "
            f"is permissionless (no caller-identity gate) and "
            f"nothing in the liquidate path clears the record.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "permissionless liquidate: debt zeroed, "
                    "collateral / order record left standing")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. Transient slot reuse auth bypass (SIR.trading shape)
# ---------------------------------------------------------------------------

_TSTORE_RAW_RE = re.compile(
    r"\btstore\s*\(\s*([^,]+?)\s*,\s*([^)]+)\)")
_TSTORE_METHOD_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*tstore\s*\(\s*([^)]+)\)")
_CALLBACK_FN_RE = re.compile(
    r"callback|onSwap|mintCallback|swapCallback", re.I)
_AMOUNT_WORD_RE = re.compile(
    r"amount|minted|shares|mintAmount|supply|balance|output",
    re.I)
_ADDR_WORD_RE = re.compile(
    r"pool|callback|poolAddress|address\s*\(", re.I)


def _slot_key(expr: str) -> str:
    return re.sub(r"\s+", "", expr)


def _value_meaning(value: str) -> str:
    """ADDR vs AMOUNT for one tstore value. An
    attacker-influenced amount wins: an amount cast to
    address is still the amount meaning (the SIR shape)."""
    if _AMOUNT_WORD_RE.search(value):
        return "AMOUNT"
    if _ADDR_WORD_RE.search(value):
        return "ADDR"
    return "OTHER"


def _analyze_transient_slot_reuse(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # All transient writes, grouped by slot. Raw assembly
    # tstore(slot, value) and method-style slot.tstore(value)
    # both count; a method receiver is its own slot key.
    writes: Dict[str, List] = {}

    def _add(slot, value):
        writes.setdefault(slot, []).append(
            (_value_meaning(value), value.strip()))

    for m in _TSTORE_RAW_RE.finditer(scoped):
        _add(_slot_key(m.group(1)), m.group(2))
    for m in _TSTORE_METHOD_RE.finditer(scoped):
        _add("method:" + m.group(1), m.group(2))
    # A slot is reused when it holds BOTH meanings. A clear
    # (tstore(slot, 0)) after use closes the window, so a
    # slot with a clear write is not reused.
    reused: Dict[str, List] = {}
    for slot, ws in writes.items():
        meanings = {w[0] for w in ws}
        if "ADDR" in meanings and "AMOUNT" in meanings:
            if any(v == "0" for _, v in ws):
                continue
            reused[slot] = ws
    if not reused:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CALLBACK_FN_RE.search(fn["name"]):
            continue
        # The callback's msg.sender comparison IS the
        # mechanism under analysis (the claimed authorization
        # being audited), so it never suppresses - same
        # narrowing as the forwarder signature check in
        # batch 10. Only view / pure functions are skipped.
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        for slot in reused:
            if slot.startswith("method:"):
                recv = slot[len("method:"):]
                slot_hit = bool(re.search(
                    r"\b" + re.escape(recv) +
                    r"\s*\.\s*tload\s*\(", text))
            else:
                slot_hit = bool(re.search(
                    r"\btload\s*\(\s*" + re.escape(slot) +
                    r"\s*\)", text))
            if not slot_hit:
                continue
            if not re.search(r"msg\.sender\s*(==|!=)", text):
                continue
            detail = spec.detail + (
                f" Observed: transient slot '{slot}' is written "
                f"with two meanings - an auth-critical pool "
                f"address and an attacker-influenced amount - and "
                f"'{fn['name']}' authenticates the callback by "
                f"comparing msg.sender to tload of that slot, so "
                f"an attacker-crafted amount cast to address "
                f"passes the check. Gate analysis: the callback "
                f"auth check IS the claimed authorization being "
                f"audited, so it does not suppress; no slot clear "
                f"closes the reuse window.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "callback auth reads a transient slot "
                        "reused for an attacker-influenced amount, "
                        "no clear after use")
            out.append(_finish_recipient(spec, item, text))
            break
    return out

ANALYZERS = {
    "amm_scale_rounding_wrong_direction": _analyze_amm_scale_rounding,
    "lending_accumulator_donation_inflation": _analyze_lending_accumulator,
    "batch_deferred_check_flag_reset": _analyze_batch_flag_reset,
    "liquidation_residual_collateral_reborrow": _analyze_liquidation_residual,
    "transient_slot_reuse_auth_bypass": _analyze_transient_slot_reuse,
}


def analyze_deep11_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-10 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-3 collection / fetch /
# proxy resolution; analysis is analyze_deep11_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit11Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 11)"
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
        for item in analyze_deep11_source(
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
                source="deep audit detector batch 11 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit11Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 11) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
