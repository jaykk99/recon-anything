"""Known set + hunt memory: the shared store every hunter reads and
writes through. All functions take an open SQLAlchemy session and a
`system` namespace (default "recon") so other agent systems can keep
their own sets and memories in the same tables later.

Hunters MUST go through here: no private per-hunter state, no ad-hoc
file reads. A confirmed asset written by one hunter is immediately
visible to all of them, and dead ends recorded by one hunter save all
of them from re-walking the same branch.
"""
from __future__ import annotations

import datetime as dt
from typing import Dict, List, Optional, Set, Tuple

from ..models import HuntAction, HuntMemory, KnownAsset

DEFAULT_SYSTEM = "recon"


def _now():
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------
# Known set
# ---------------------------------------------------------------------------

def add_known_asset(session, system: str, target_key: str, asset_type: str,
                    value: str, found_by: str = "", run_id: str = "",
                    depth: int = 0, meta: Optional[Dict] = None) -> Tuple[KnownAsset, bool]:
    """Insert a confirmed asset. Returns (row, created). Idempotent:
    an existing asset only gets its last_run_id/depth refreshed."""
    value = (value or "").strip()
    row = (session.query(KnownAsset)
           .filter_by(system=system, target_key=target_key,
                      asset_type=asset_type, value=value).first())
    if row is not None:
        if run_id:
            row.last_run_id = run_id
        row.updated_at = _now()
        session.commit()
        return row, False
    row = KnownAsset(system=system, target_key=target_key,
                     asset_type=asset_type, value=value,
                     found_by=found_by, first_run_id=run_id or "",
                     last_run_id=run_id or "", depth=depth, meta=meta or {})
    session.add(row)
    session.commit()
    return row, True


def get_known_set(session, system: str, target_key: str) -> List[Dict]:
    rows = (session.query(KnownAsset)
            .filter_by(system=system, target_key=target_key)
            .order_by(KnownAsset.asset_type, KnownAsset.value).all())
    return [{"type": r.asset_type, "value": r.value, "found_by": r.found_by,
             "first_run_id": r.first_run_id, "last_run_id": r.last_run_id,
             "depth": r.depth, "meta": r.meta or {}} for r in rows]


def known_values(session, system: str, target_key: str,
                 asset_type: Optional[str] = None) -> Set[str]:
    q = session.query(KnownAsset.value).filter_by(
        system=system, target_key=target_key)
    if asset_type:
        q = q.filter_by(asset_type=asset_type)
    return {v for (v,) in q.all()}


def known_counts(session, system: str, target_key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for (t,) in session.query(KnownAsset.asset_type).filter_by(
            system=system, target_key=target_key).all():
        counts[t] = counts.get(t, 0) + 1
    return counts


def known_total(session, system: str, target_key: str) -> int:
    return (session.query(KnownAsset)
            .filter_by(system=system, target_key=target_key).count())


# ---------------------------------------------------------------------------
# Hunt actions (audit) + recent finds
# ---------------------------------------------------------------------------

def record_action(session, system: str, target_key: str, hunter: str,
                  action: str, run_id: str = "", asset_type: str = "",
                  asset_value: str = "", detail: Optional[Dict] = None) -> None:
    session.add(HuntAction(run_id=run_id or "", system=system,
                           target_key=target_key, hunter=hunter,
                           action=action, asset_type=asset_type,
                           asset_value=asset_value, detail=detail or {}))
    session.commit()


def recent_finds(session, system: str, limit: int = 50,
                 target_key: Optional[str] = None,
                 hunter: Optional[str] = None) -> List[Dict]:
    """What hunters found lately, across targets: the shared feed every
    hunter reads before expanding so fresh leads propagate."""
    q = (session.query(HuntAction)
         .filter_by(system=system, action="asset_found"))
    if target_key:
        q = q.filter_by(target_key=target_key)
    if hunter:
        q = q.filter_by(hunter=hunter)
    rows = q.order_by(HuntAction.id.desc()).limit(limit).all()
    return [{"hunter": r.hunter, "run_id": r.run_id,
             "target_key": r.target_key, "asset_type": r.asset_type,
             "asset_value": r.asset_value,
             "at": r.created_at.isoformat() if r.created_at else None}
            for r in rows]


def hunter_stats(session, system: str) -> Dict[str, Dict]:
    """Lifetime per-hunter counters from the audit trail."""
    stats: Dict[str, Dict] = {}
    for r in session.query(HuntAction).filter_by(system=system).all():
        s = stats.setdefault(r.hunter, {"assets_discovered": 0,
                                        "jobs_enqueued": 0,
                                        "dead_ends": 0, "passes": 0})
        if r.action == "asset_found":
            s["assets_discovered"] += 1
        elif r.action == "job_enqueued":
            s["jobs_enqueued"] += 1
        elif r.action == "dead_end":
            s["dead_ends"] += 1
        elif r.action == "expand_pass":
            s["passes"] += 1
    # findings attributed: known assets carry found_by = hunter name
    for (fb,) in session.query(KnownAsset.found_by).filter_by(
            system=system).all():
        if fb:
            s = stats.setdefault(fb, {"assets_discovered": 0,
                                       "jobs_enqueued": 0, "dead_ends": 0,
                                       "passes": 0})
            s.setdefault("assets_in_known_set", 0)
            s["assets_in_known_set"] += 1
    return stats


# ---------------------------------------------------------------------------
# Hunt memory
# ---------------------------------------------------------------------------

def _memory_row(session, system: str, target_key: str) -> HuntMemory:
    row = (session.query(HuntMemory)
           .filter_by(system=system, target_key=target_key).first())
    if row is None:
        row = HuntMemory(system=system, target_key=target_key,
                         assets_by_type={}, finding_counts={},
                         dead_ends=[], runs=[], notes=[])
        session.add(row)
        session.commit()
    return row


def get_memory(session, system: str, target_key: str) -> Dict:
    row = _memory_row(session, system, target_key)
    return {
        "system": system, "target_key": target_key,
        "assets_by_type": row.assets_by_type or {},
        "finding_counts": row.finding_counts or {},
        "dead_ends": row.dead_ends or [],
        "runs": row.runs or [],
        "notes": row.notes or [],
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "last_hunt": (row.runs or [{}])[-1] if row.runs else None,
    }


def dead_end_values(session, system: str, target_key: str) -> Set[str]:
    row = (session.query(HuntMemory)
           .filter_by(system=system, target_key=target_key).first())
    if row is None:
        return set()
    return {(d.get("value") or "") for d in (row.dead_ends or [])}


def add_dead_end(session, system: str, target_key: str, asset_type: str,
                 value: str, run_id: str = "", reason: str = "") -> bool:
    """Record a branch that produced nothing. Returns True if new."""
    row = _memory_row(session, system, target_key)
    dead = list(row.dead_ends or [])
    if any(d.get("value") == value and d.get("type") == asset_type
           for d in dead):
        return False
    dead.append({"type": asset_type, "value": value, "run_id": run_id,
                 "reason": reason, "at": _now().isoformat()})
    row.dead_ends = dead[-500:]  # keep memory bounded
    row.updated_at = _now()
    session.commit()
    return True


def add_note(session, system: str, target_key: str, note: str,
             hunter: str = "") -> None:
    row = _memory_row(session, system, target_key)
    notes = list(row.notes or [])
    notes.append({"note": note, "hunter": hunter, "at": _now().isoformat()})
    row.notes = notes[-200:]
    row.updated_at = _now()
    session.commit()


def record_run_summary(session, system: str, target_key: str, run_id: str,
                       known_before: int, known_after: int,
                       finding_counts: Dict[str, int]) -> None:
    """Persist the after-action summary hunters read on the next visit:
    known-set size before/after (growth is the visible score), and the
    run's finding counts folded into the cumulative totals."""
    row = _memory_row(session, system, target_key)
    row.assets_by_type = known_counts(session, system, target_key)
    cumulative = dict(row.finding_counts or {})
    for k, v in (finding_counts or {}).items():
        cumulative[k] = cumulative.get(k, 0) + int(v)
    row.finding_counts = cumulative
    runs = list(row.runs or [])
    runs.append({"run_id": run_id, "at": _now().isoformat(),
                 "known_before": known_before, "known_after": known_after,
                 "findings": sum((finding_counts or {}).values())})
    row.runs = runs[-50:]
    row.updated_at = _now()
    session.commit()
