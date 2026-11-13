"""Value-first target picker.

The old hunters ordered by severity, so a critical on a $0 contract
outranked a high on a $2M contract. The loop orders by realizable value
first (valuation.realizable_value_usd), severity second. A target whose
value is unknown is never dropped on value grounds - it sorts after
known-value targets but ahead of known dust.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..valuation import is_dust, realizable_value_usd, value_band
from .state import BOUNTY_FLOOR_USD


def target_value_usd(target: Dict[str, Any]) -> Optional[float]:
    """Realizable USD for one target dict.

    Accepts either a precomputed ``value_usd`` or the raw inputs
    (``native_usd`` + ``token_positions``) and runs the valuation.
    Returns None when the value cannot be assessed.
    """
    if target.get("value_usd") is not None:
        try:
            return float(target["value_usd"])
        except (TypeError, ValueError):
            return None
    if target.get("native_usd") is None and not target.get("token_positions"):
        return None
    try:
        return realizable_value_usd(
            target.get("native_usd"), target.get("token_positions"))
    except Exception:  # noqa: BLE001 - a bad target never kills the queue
        return None


def meets_live_floor(value_usd: Optional[float],
                     floor_usd: float = BOUNTY_FLOOR_USD) -> bool:
    """True when a target may enter the live path.

    Unknown value passes (never filtered as dust); a known value must
    clear the floor. This is the $100k realizable-value floor, enforced
    in the live path only - offline / fixture runs pass live=False.
    """
    if value_usd is None:
        return True
    return not is_dust(value_usd, floor_usd)


def order_targets(targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort a target queue value-first.

    Known high value first, then unknown value (unassessed, never dust),
    then known dust last. Ties break on worst severity (critical first).
    Returns new dicts with ``value_usd`` and ``value_band`` filled in.
    """
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def key(t: Dict[str, Any]):
        v = target_value_usd(t)
        # (bucket, -value, severity): bucket 0 = known value, 1 = unknown,
        # 2 = known dust. Within a bucket, higher value first.
        if v is None:
            bucket, neg = 1, 0.0
        elif is_dust(v, BOUNTY_FLOOR_USD):
            bucket, neg = 2, 0.0
        else:
            bucket, neg = 0, -v
        sev = sev_rank.get(str(t.get("severity") or "info").lower(), 4)
        return (bucket, neg, sev)

    out = []
    for t in sorted(targets, key=key):
        t = dict(t)
        v = target_value_usd(t)
        t["value_usd"] = v
        t["value_band"] = value_band(v)
        out.append(t)
    return out
