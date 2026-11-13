"""Validator bus wiring: detectors and fork findings publish candidates.

Before this module, the auto-validator read only from the
``validator_candidates`` discovery bus, and nothing in the codebase
published to it - the validator was starved by construction. These
helpers are the publisher side. Any lane (the loop's detection step,
the fork step, a future detector plugin) builds candidates from its
findings and publishes them; the validator consumes them.

A candidate is the shape auto_validator.validate_candidate expects:
address / chain / function / kind / detail, plus the verified source
when the lane has it. Only high/critical findings become candidates,
and trigger_only findings never do - the value lands at a fixed
destination, so there is no stranger payout to validate.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from .hypothesis import DRAIN_KINDS

CANDIDATE_SEVERITIES = ("critical", "high")


def candidates_from_findings(findings: List[Dict[str, Any]],
                             address: str, chain: str,
                             source: Optional[str] = None,
                             contract_name: str = "") -> List[Dict[str, Any]]:
    """Build validator candidates from detection findings.

    A candidate is a high/critical finding of a drain/takeover kind:
    the validator's job is stranger-receivable payout, so a high
    finding that is not a payout path (e.g. privileged_function, a
    low-level audit note) is a lead for the report, not a candidate
    for a live probe. Order: drain kinds first, then severity.
    Deduped on (kind, function).
    """
    out: List[Dict[str, Any]] = []
    seen = set()
    ranked = sorted(
        findings,
        key=lambda f: (
            0 if str(f.get("kind") or f.get("check") or "")
            in DRAIN_KINDS else 1,
            {"critical": 0, "high": 1, "medium": 2, "low": 3,
             "info": 4}.get(str(f.get("severity") or "info").lower(), 4),
        ))
    for f in ranked:
        ev = f.get("evidence") or {}
        if isinstance(ev, dict) and ev.get("report_class") == "trigger_only":
            continue
        if str(f.get("severity") or "info").lower() not in CANDIDATE_SEVERITIES:
            continue
        kind = str(f.get("kind") or f.get("check") or f.get("key") or "")
        if kind not in DRAIN_KINDS:
            continue
        fn = str(f.get("function") or "")
        key = (kind, fn)
        if key in seen:
            continue
        seen.add(key)
        cand: Dict[str, Any] = {
            "address": address,
            "chain": chain,
            "function": fn,
            "kind": kind,
            "detail": str(f.get("detail") or f.get("title") or ""),
            "source": source or "",
            "contract_name": contract_name,
        }
        # Token-authority findings are a fixed-principal class, not a
        # stranger drain: carry the marker so the validator lands them
        # in TRIGGER_ONLY / TOKEN_RISK instead of chasing a probe.
        if isinstance(ev, dict) and ev.get("authority_class"):
            cand["authority_class"] = True
        out.append(cand)
    return out


def filter_metered(candidates: List[Dict[str, Any]],
                   source: Optional[str] = None,
                   contract_name: str = "") -> tuple:
    """Drop candidates whose payout is not stranger-receivable.

    Two static tests, both borrowed from the validator's own
    discipline so the loop and the validator agree:
    - recipient class (contract_logic.classify_recipient): a payout
      to the caller that is metered by the caller's own recorded
      balance (WETH9 withdraw) classifies HOLDER-SELF - the stranger
      receives only their own money, so there is no drain to validate.
      CALLER / CALLER-SUPPLIED / UNRESOLVED are kept.
    - caller metering (auto_validator._caller_metered): every payout
      amount provably zero when the caller's basis is zero.
    A candidate that cannot be assessed (no source, function not
    found, unparseable payout) is KEPT, never filtered.
    Returns (kept, skipped).
    """
    if not source:
        return list(candidates), []
    try:
        from ..plugins.auto_validator import _caller_metered, _find_fn
        from ..plugins import contract_logic as cl
    except Exception:  # noqa: BLE001 - discipline unavailable: keep all
        return list(candidates), []
    kept, skipped = [], []
    for cand in candidates:
        fn_name = cand.get("function") or ""
        skip_reason = None
        try:
            _, fn = _find_fn(source, fn_name, contract_name)
            if fn is not None:
                recipient, detail = cl.classify_recipient(fn["text"])
                if recipient in ("HOLDER-SELF", "FIXED"):
                    skip_reason = (
                        f"recipient {recipient} ({detail}): payout is "
                        f"the caller's own entitlement, not a stranger "
                        f"receivable")
                elif _caller_metered(fn) is not None:
                    skip_reason = ("caller-metered payout: amount is "
                                   "zero when the caller's basis is zero")
        except Exception:  # noqa: BLE001 - unassessable: keep
            skip_reason = None
        if skip_reason is not None:
            skipped.append({**cand, "skip_reason": skip_reason})
        else:
            kept.append(cand)
    return kept, skipped


def publish_validator_candidates(bus_or_ctx: Any,
                                 candidates: List[Dict[str, Any]]) -> int:
    """Publish candidates onto the validator_candidates bus.

    Accepts a plugin Ctx (has .publish), a plain list (appended to),
    or a dict with a "validator_candidates" list. Returns how many
    were published. Never raises: a publish failure is recorded by
    the caller as a note, not a crash.
    """
    if not candidates:
        return 0
    try:
        publish = getattr(bus_or_ctx, "publish", None)
        if callable(publish):
            for c in candidates:
                publish("validator_candidates", dict(c))
            return len(candidates)
        if isinstance(bus_or_ctx, list):
            bus_or_ctx.extend(dict(c) for c in candidates)
            return len(candidates)
        if isinstance(bus_or_ctx, dict):
            bucket = bus_or_ctx.setdefault("validator_candidates", [])
            bucket.extend(dict(c) for c in candidates)
            return len(candidates)
    except Exception:  # noqa: BLE001 - bus failures must not kill a run
        return 0
    return 0
