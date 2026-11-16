"""Inline static validation gates (2026-11-08, Jay's order).

Validator v2 (auto_validator.validate_candidate) settles the two
classic false-positive shapes only AFTER the gathering lane has
spent its live reads: the function probe, the decisive probe,
native + token balances, the stranger's funding balances and the
pair-reserve reads. Both shapes, however, are decided by the same
pure source-level detectors v2 already carries -
auto_validator._self_funded (burn / pull funded payouts) and
auto_validator._caller_metered (payouts symbolically zero at a
zero caller basis). This module runs those exact detectors
earlier, fused into the candidate path, at local parse cost
(microseconds to milliseconds per contract, no RPC), and
annotates the candidate so the lane can skip the live probe
suite for the shapes the statics already settle:

- GATED_SELF_FUNDED: every payout of the flagged function is
  funded by the caller themselves - burned out of the caller's
  own token balance first (_burn(msg.sender, ...), the aeWETH
  withdrawTo shape), pulled from the caller (transferFrom /
  safeTransferFrom with the caller as source), or credited from
  the caller's own msg.value. The stranger's receipt on such a
  path is identically their own input; an unfunded stranger's
  input is 0, so the receipt is 0 by construction. This is a
  full fast path: no live read can change it.
- GATED_CALLER_METERED: every payout amount expression of the
  flagged function is symbolically zero whenever the caller's
  own recorded position reads 0 (their balanceOf on the target
  token, or a caller-keyed mapping entry) - the MVK claimReward
  shape. The shape alone does not mint the false positive (that
  is validator v2's standing regression rule): the gate names
  the basis, and the lane confirms the stranger's basis is 0
  with the SINGLE basis read (one balanceOf / mapping getter
  call) instead of the full probe suite. A nonzero or
  unreadable basis falls through to the full v2 path untouched.
- PASS: no static evidence of either shape, or anything about
  the candidate is ambiguous. The candidate flows into
  validator v2 exactly as before.

Hard limits (by construction, not by convention):

- The gates NEVER stamp VERIFIED_REAL and never clear a
  candidate as anything but the two false-positive shapes
  above, recorded as FALSE_POSITIVE with the gate decision and
  its reason in the result row (the FP fast path).
- The gates NEVER override validator v2: any candidate
  carrying measured-receipt evidence (a simulation with a
  positive stranger receipt, a successful decisive probe) is
  passed through untouched, as is every candidate whose
  recipient is not a stranger-receivable class, whose function
  carries an access gate (v2's gated branch precedes the shape
  branches), which is the token's own standard ERC20 surface,
  which belongs to the token-authority class, or which arrives
  with a recipient override from a non-EVM lane.
- A gated candidate is never dropped silently: gate_verdict()
  emits the full verdict row with the gate decision, the
  detector evidence and the reason.
- Bytecode-only candidates PASS: the detectors are source
  level, and a bytecode shape guess would be exactly the kind
  of ambiguity that must fall through to v2's bytecode lane.

The gate reuses v2's own detector functions and the same
function scoping / recipient classification v2 uses, so the
static decision cannot drift from the verdict v2 would reach
on the same source: _find_fn (+ _proxy_attribution fallback),
contract_logic.classify_recipient_path for the flow text,
contract_logic._gated_deep for the access-gate read,
auto_validator._own_standard_surface, _self_funded and
_caller_metered themselves.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from . import contract_logic as cl
from .auto_validator import (
    _BURN_CALLER_RE,
    _caller_metered,
    _find_fn,
    _own_standard_surface,
    _proxy_attribution,
    _self_funded,
)

GATE_PASS = "PASS"
GATE_SELF_FUNDED = "GATED_SELF_FUNDED"
GATE_CALLER_METERED = "GATED_CALLER_METERED"

GATES = (GATE_PASS, GATE_SELF_FUNDED, GATE_CALLER_METERED)

_STRANGER_RECEIVABLE = ("CALLER", "CALLER-SUPPLIED")


def _pass(reason: str, **kw: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"gate": GATE_PASS, "reason": reason,
                           "recipient": None, "evidence": {}}
    out.update(kw)
    return out


def gate_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Static pre-gate for one candidate finding.

    candidate keys mirror validate_candidate's: address, chain,
    function, kind, source, contract_name, plus the optional
    evidence slots (probe / decisive_probe / simulation /
    balances), authority_class and recipient_override.

    Returns {"gate": GATE_*, "reason": str, "recipient": ...,
    "evidence": {...}}; for GATED_CALLER_METERED the result
    also carries "basis": {"basis": "token_self"|"mapping",
    "name": ...} and "requires_basis_zero": True.
    """
    # Measured-receipt evidence outranks statics, always: a
    # simulation that moved value to a stranger, or a decisive
    # probe that succeeded, belongs to validator v2 alone.
    simulation = candidate.get("simulation") or {}
    if simulation.get("ran") and \
            float(simulation.get("stranger_received") or 0) > 0:
        return _pass("candidate carries a simulation with a "
                     "positive stranger receipt; measured "
                     "evidence is validator v2's alone")
    decisive = candidate.get("decisive_probe") or {}
    if decisive.get("status") == "success":
        return _pass("candidate carries a successful decisive "
                     "probe; measured evidence is validator "
                     "v2's alone")
    # Classes v2 settles in its own early branches.
    if candidate.get("authority_class"):
        return _pass("token-authority class is validator v2's "
                     "own branch")
    if candidate.get("recipient_override"):
        return _pass("recipient override from a non-EVM lane; "
                     "source-level gates do not apply")

    source = candidate.get("source") or ""
    function = candidate.get("function") or ""
    if not source:
        return _pass("no verified source; static gates are "
                     "source-level and bytecode-only candidates "
                     "belong to validator v2's bytecode lane")
    if not function:
        return _pass("no flagged function named")

    scope, fn = _find_fn(source, function,
                         candidate.get("contract_name", ""))
    attributed_to = None
    if fn is None:
        attributed = _proxy_attribution(
            source, function, candidate.get("contract_name", ""))
        if attributed is not None:
            scope, fn = attributed
            attributed_to = fn.get("contract", "")
    if fn is None or scope is None:
        # Missing from the deployed scope (or only in a bundled
        # sibling): v2 settles that with the live probe; the
        # statics must not guess.
        return _pass("flagged function not found in the "
                     "deployed contract scope; validator v2's "
                     "missing-function path decides")

    # v2's access-gate branch precedes the shape branches: a
    # gated function is v2's to settle (gated + probe success
    # is a lane disagreement, not a shape kill).
    if bool(cl._gated_deep(fn, scope)):
        return _pass("deep source read finds an access gate on "
                     "the flagged function; validator v2's "
                     "gated branch decides",
                     recipient=None)

    recipient, rdetail, flow_text = \
        cl.classify_recipient_path(scope, fn)
    if recipient not in _STRANGER_RECEIVABLE:
        # FIXED / HOLDER-SELF land at TRIGGER_ONLY in v2 and
        # UNRESOLVED at UNVERIFIED; the gates never pre-empt
        # either.
        return _pass(f"value destination classifies as "
                     f"{recipient}, not stranger-receivable; "
                     f"validator v2 decides", recipient=recipient)

    if _own_standard_surface(fn, scope, flow_text):
        return _pass("the token's own standard ERC20 transfer "
                     "surface; validator v2's own static rule "
                     "decides", recipient=recipient)

    evidence: Dict[str, Any] = {"recipient_detail": rdetail}
    if attributed_to:
        evidence["attributed_to"] = attributed_to

    # Shape 1: self-funded (v2 checks it first in its
    # probe-success branch; same precedence here).
    if _self_funded(flow_text):
        burn = bool(_BURN_CALLER_RE.search(flow_text))
        shape = ("burns the payout amount out of the "
                 "caller's own token balance "
                 "(_burn(msg.sender, ...)) before paying out"
                 if burn else
                 "pulls the value from the caller themselves "
                 "(transferFrom from msg.sender, or the payout "
                 "amount is the caller's own msg.value) before "
                 "paying out")
        evidence["self_funded"] = {"burn_funded": burn}
        return {
            "gate": GATE_SELF_FUNDED,
            "reason": (
                f"inline gate (static, no live probe): "
                f"self-funded path - the flagged function "
                f"{shape}; a stranger receives only their own "
                f"funds back, so an unfunded stranger's receipt "
                f"is 0 by construction"),
            "recipient": recipient,
            "evidence": evidence,
        }

    # Shape 2: caller-metered. Acted on only for a CALLER
    # recipient, mirroring v2: for CALLER-SUPPLIED payouts v2
    # re-reads metering against the beneficiary's entitlement
    # (_beneficiary_metered) and can land at TRIGGER_ONLY,
    # which the gates never pre-empt.
    if recipient == "CALLER":
        metered = _caller_metered(fn)
        if metered:
            evidence["caller_metered"] = metered
            label = ("own-token balance"
                     if metered["basis"] == "token_self" else
                     "entry in the caller-keyed mapping " +
                     str(metered.get("name")))
            return {
                "gate": GATE_CALLER_METERED,
                "reason": (
                    f"inline gate (static shape; stranger "
                    f"basis confirmed 0 by a single basis "
                    f"read): caller-metered payout - every "
                    f"payout of the flagged function is "
                    f"metered by the caller's own {label}, and "
                    f"every payout amount is symbolically zero "
                    f"at a zero basis, so the measured receipt "
                    f"for an unfunded stranger is 0"),
                "recipient": recipient,
                "evidence": evidence,
                "basis": metered,
                "requires_basis_zero": True,
            }

    return _pass("no static evidence of a self-funded or "
                 "caller-metered payout shape",
                 recipient=recipient, evidence=evidence)


def gate_verdict(candidate: Dict[str, Any],
                 gate_result: Dict[str, Any],
                 basis_measured_zero: Optional[bool] = None
                 ) -> Dict[str, Any]:
    """The verdict row for a gated candidate, in
    validate_candidate's output shape.

    Only callable for a non-PASS gate. For
    GATED_CALLER_METERED the caller must pass
    basis_measured_zero=True (the lane's single basis read of
    the unfunded stranger returned 0); anything else raises,
    because the metering shape alone never mints this row.
    GATED_SELF_FUNDED needs no live fact: the receipt is the
    caller's own input by construction.
    """
    gate = gate_result.get("gate")
    if gate not in (GATE_SELF_FUNDED, GATE_CALLER_METERED):
        raise ValueError(f"gate_verdict on a non-gate result: "
                         f"{gate!r}")
    if gate == GATE_CALLER_METERED and \
            basis_measured_zero is not True:
        raise ValueError(
            "GATED_CALLER_METERED requires the stranger basis "
            "to be measured 0 before the fast-path row is "
            "written; the shape alone does not settle it")
    evidence = dict(gate_result.get("evidence") or {})
    evidence["inline_gate"] = {
        "gate": gate,
        "decided": "static source analysis (inline gate); "
                   "live probe suite skipped",
    }
    if gate == GATE_CALLER_METERED:
        evidence["inline_gate"]["basis"] = \
            gate_result.get("basis")
        evidence["inline_gate"]["stranger_basis_measured"] = 0
    return {
        "address": candidate.get("address", ""),
        "chain": candidate.get("chain", ""),
        "function": candidate.get("function", ""),
        "kind": candidate.get("kind", ""),
        "verdict": "FALSE_POSITIVE",
        "reason": gate_result.get("reason", ""),
        "recipient": gate_result.get("recipient"),
        "gated": False,
        "value": None,
        "missing": [],
        "evidence": evidence,
        "gate": gate,
    }
