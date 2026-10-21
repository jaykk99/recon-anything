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
import os
from typing import Dict, List, Optional, Set, Tuple

from ..models import (HuntAction, HuntMemory, KnownAsset, PluginJob,
                      Run, Target as TargetRow)

DEFAULT_SYSTEM = "recon"

# Dead ends expire: a branch that produced nothing once (a plugin
# timeout, a host briefly down) must not be blocked forever, or the
# known set stops compounding. Entries older than the TTL are
# ignored by dead_end_values and the branch may be re-hunted.
DEAD_END_TTL_DAYS = float(
    os.environ.get("RECON_HUNTER_DEAD_END_TTL_DAYS", "7"))


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
# Agent activity feed (per run): the audit trail made readable
# ---------------------------------------------------------------------------

# Pseudo-agents that act in a run without being hunter roles.
_AGENT_LABELS = {
    "seed": "Seed targets",
    "hunter_engine": "Expansion engine",
    "chain_engine": "Finding-driven chaining",
    "known_set": "Known set (earlier scans)",
}


def describe_action(row) -> str:
    """Plain-language line for one audit row, built from the stored
    fields so the activity feed reads like 'dns_hunter found ip
    1.2.3.4 from an A-record finding' instead of raw codes. Works for
    rows written before this helper existed - nothing new had to be
    stored."""
    hunter = row.hunter or "hunter"
    action = row.action or ""
    atype = row.asset_type or ""
    aval = row.asset_value or ""
    d = row.detail if isinstance(row.detail, dict) else {}
    if action == "asset_found":
        via = d.get("via") or ""
        if via == "known_set":
            how = "re-seeded from the known set"
        elif via == "target":
            how = "seed target"
        elif via == "shape":
            how = "spotted in finding text"
        elif via:
            how = f"from a '{via}' finding"
        else:
            how = "from scan findings"
        return f"{hunter} found {atype} {aval} ({how})".strip()
    if action == "job_enqueued":
        plugin = d.get("plugin") or "a plugin"
        target = d.get("target") or aval
        if d.get("via") == "finding_chain":
            signals = ", ".join(d.get("signals") or []) or "a finding"
            return (f"{hunter} queued {plugin} on {target} because of "
                    f"{signals} findings (finding-driven chain)")
        depth = d.get("depth")
        suffix = f" at depth {depth}" if depth is not None else ""
        return (f"{hunter} queued {plugin} on {target} to verify "
                f"{atype} {aval}{suffix}").strip()
    if action == "expand_pass":
        chained = d.get("chained_jobs") or 0
        chain_note = (f", {chained} chained from findings"
                      if chained else "")
        return (f"Expansion pass at depth {d.get('depth', 0)}: "
                f"{d.get('new_assets', 0)} new assets, "
                f"{d.get('jobs_enqueued', 0)} jobs queued{chain_note}")
    if action == "dead_end":
        return (f"{hunter} closed {atype} {aval} as a dead end "
                f"(produced no findings)").strip()
    if action == "note":
        return f"{hunter}: {d.get('note') or aval or 'note'}"
    return f"{hunter} {action} {atype} {aval}".strip()


def run_agent_activity(session, system: str, run_id: str,
                       limit: int = 500) -> Dict:
    """One run's agent activity: the chronological feed plus a
    per-agent rollup (actions, assets found, jobs queued, findings
    those jobs produced, current status).

    Status is derived, not stored: an agent is "working" while any
    job it queued is queued/running (or the run is live and the agent
    is the engine itself), "done" when the run is finished, and
    "abandoned" when every job it queued ended failed/skipped with
    none completing - the watchdog/stale-claim sweep dropped its
    work."""
    from ..hunters.roles import HUNTERS
    specialties = {h["name"]: h["specialty"] for h in HUNTERS}
    run = session.query(Run).filter_by(id=run_id).first()
    run_status = run.status if run else ""
    rows = (session.query(HuntAction)
            .filter_by(system=system, run_id=run_id)
            .order_by(HuntAction.id.asc()).all())
    targets = (session.query(TargetRow).filter_by(run_id=run_id).all())
    target_id_by_norm = {t.normalized: t.id for t in targets}
    jobs = (session.query(PluginJob).filter_by(run_id=run_id).all())
    job_by_key = {(j.target_id, j.plugin_id): j for j in jobs}

    feed: List[Dict] = []
    agents: Dict[str, Dict] = {}

    def agent(name: str) -> Dict:
        return agents.setdefault(name, {
            "name": name,
            "specialty": specialties.get(name)
            or _AGENT_LABELS.get(name, ""),
            "actions": 0, "assets_found": 0, "jobs_enqueued": 0,
            "chained_jobs": 0, "dead_ends": 0,
            "findings_contributed": 0, "last_action_at": None,
            "status": "done", "_job_states": []})

    for r in rows:
        feed.append({
            "id": r.id, "run_id": r.run_id, "agent": r.hunter,
            "action": r.action, "asset_type": r.asset_type,
            "asset_value": r.asset_value,
            "description": describe_action(r),
            "detail": r.detail or {},
            "at": r.created_at.isoformat() if r.created_at else None})
        a = agent(r.hunter)
        a["actions"] += 1
        a["last_action_at"] = feed[-1]["at"]
        d = r.detail if isinstance(r.detail, dict) else {}
        if r.action == "asset_found":
            a["assets_found"] += 1
        elif r.action == "dead_end":
            a["dead_ends"] += 1
        elif r.action == "job_enqueued":
            a["jobs_enqueued"] += 1
            if d.get("via") == "finding_chain":
                a["chained_jobs"] += 1
            tid = target_id_by_norm.get(d.get("target") or "")
            job = job_by_key.get((tid, d.get("plugin") or ""))
            if job is not None:
                a["_job_states"].append(job.status)
                if job.status == "done":
                    result = job.result if isinstance(job.result, dict) \
                        else {}
                    a["findings_contributed"] += int(
                        result.get("findings") or 0)
    out_agents = []
    for a in agents.values():
        states = a.pop("_job_states")
        if states and all(s in ("failed", "skipped") for s in states):
            a["status"] = "abandoned"
        elif run_status == "done":
            a["status"] = "done"
        elif any(s in ("queued", "running") for s in states):
            a["status"] = "working"
        elif run_status in ("running", "finalizing"):
            a["status"] = "working" if a["name"] in (
                "hunter_engine", "chain_engine") else "idle"
        else:
            a["status"] = "done"
        out_agents.append(a)
    out_agents.sort(key=lambda a: (-a["actions"], a["name"]))
    return {"run_id": run_id, "run_status": run_status,
            "total_actions": len(feed),
            "actions": feed[-max(1, int(limit)):],
            "agents": out_agents}


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
    cutoff = _now() - dt.timedelta(days=DEAD_END_TTL_DAYS)
    out: Set[str] = set()
    for d in (row.dead_ends or []):
        at = d.get("at")
        if at:
            try:
                ts = dt.datetime.fromisoformat(str(at))
            except ValueError:
                ts = None
            # Unparseable or timezone-naive stamps are treated as
            # fresh (kept): expiring on a guess could reopen a branch
            # that was deliberately closed.
            if ts is not None and ts.tzinfo is not None and ts < cutoff:
                continue
        out.add(d.get("value") or "")
    return out


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
