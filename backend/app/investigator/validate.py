"""Loop validator runner: the validator, fed, with a raised cap.

The plugin lane caps at 8 candidates/run (AutoValidatorPlugin.run
slices ``candidates[:8]``). Loop-driven runs validate every
high-severity contract candidate the loop publishes, up to
LOOP_MAX_CANDIDATES (32) - the loop is one target at a time, so the
cap is per investigation, not per sweep.

Two paths:
- Live (a plugin Ctx is supplied): gather_and_validate fetches source,
  balances and runs the read-only stranger probes, then the pure
  verdict engine decides. No transaction is ever sent.
- Offline (no Ctx): the pure validate_candidate runs on the candidate
  as supplied (source included when the loop has it). With no live
  probe it honestly returns UNVERIFIED naming the missing piece.

The loop NEVER attaches ``simulation`` evidence to a candidate it
sends to the validator: fork simulation stays UNVERIFIED by design,
and only the validator's own live-probe bar can stamp VERIFIED_REAL.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional

# Raised cap for loop-driven runs (plugin default is 8).
LOOP_MAX_CANDIDATES = int(
    os.environ.get("RECON_LOOP_VALIDATOR_MAX", "32") or "32")


def _run_gather(ctx: Any, key: Optional[str],
                candidate: Dict[str, Any]) -> Dict[str, Any]:
    from ..plugins.auto_validator import gather_and_validate
    return asyncio.run(gather_and_validate(ctx, key, dict(candidate)))


def validate_candidates(candidates: List[Dict[str, Any]],
                        ctx: Any = None,
                        key: Optional[str] = None,
                        max_candidates: int = LOOP_MAX_CANDIDATES
                        ) -> List[Dict[str, Any]]:
    """Validate loop-published candidates, up to max_candidates.

    Never attaches simulation evidence. A validator error on one
    candidate becomes an UNVERIFIED verdict for that candidate, never
    a crash of the whole run.
    """
    from ..plugins.auto_validator import validate_candidate

    out: List[Dict[str, Any]] = []
    for cand in (candidates or [])[:max_candidates]:
        cand = dict(cand)
        # The loop's hard line: simulation evidence is analysis signal
        # only. Strip it if a caller ever attached it, so a fork result
        # can never be laundered into a VERIFIED_REAL stamp.
        cand.pop("simulation", None)
        try:
            if ctx is not None:
                verdict = _run_gather(ctx, key, cand)
            else:
                verdict = validate_candidate(cand)
        except Exception as e:  # noqa: BLE001
            verdict = {"address": cand.get("address", ""),
                       "chain": cand.get("chain", ""),
                       "function": cand.get("function", ""),
                       "kind": cand.get("kind", ""),
                       "verdict": "UNVERIFIED",
                       "reason": f"validator error: {e}",
                       "missing": ["validator run"]}
        if not isinstance(verdict, dict) or "verdict" not in verdict:
            verdict = {"address": cand.get("address", ""),
                       "chain": cand.get("chain", ""),
                       "function": cand.get("function", ""),
                       "kind": cand.get("kind", ""),
                       "verdict": "UNVERIFIED",
                       "reason": "validator returned no verdict",
                       "missing": ["validator verdict"]}
        out.append(verdict)
    return out


def aggregate_verdict(verdicts: List[Dict[str, Any]]) -> str:
    """One verdict for the investigation from the per-candidate ones."""
    if not verdicts:
        return "CLEAN"
    vs = [str(v.get("verdict", "UNVERIFIED")) for v in verdicts]
    if "VERIFIED_REAL" in vs:
        return "VERIFIED_REAL"
    if "TRIGGER_ONLY" in vs and all(
            v in ("TRIGGER_ONLY", "FALSE_POSITIVE") for v in vs):
        return "TRIGGER_ONLY"
    if all(v == "FALSE_POSITIVE" for v in vs):
        return "FALSE_POSITIVE"
    return "UNVERIFIED"
