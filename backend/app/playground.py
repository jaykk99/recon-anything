"""Findings playground: re-test ONE finding on demand.

Given a stored finding, re-run ONLY the plugin that produced it,
against ONLY the target that finding belongs to, through the exact
same execution path a queued scan job uses (runner._run_plugin:
missing-key gate, hang protection, timeout caps, graceful degrade).
The fresh result is compared with the stored finding and reported as
unchanged / changed / gone / error, with the full fresh finding list
so the UI can show original vs fresh side by side.

Safety rails (this must never become a general request tool):
  - The caller names a run + finding id, never a URL or a plugin.
    The plugin and target are read back from the stored finding's own
    rows, so a retest can only ever re-check what a scan already ran.
  - No payloads, no parameters, no persistence: nothing is written
    back to the run; the fresh findings are returned, not stored.
  - Rate limited: a per-finding cooldown plus a global concurrency
    cap, on top of the plugin's own timeout (runner caps it at
    MAX_PLUGIN_TIMEOUT_S) and the shared per-host RateLimiter.
  - Events emitted during the retest go to a scratch stream
    ("playground-<run>-<finding>") so a completed run's SSE log is
    never polluted; those rows age out with the normal 3-day prune.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import os
import time
from typing import Dict, List, Optional, Tuple

from . import config
from . import net
from .cache import Cache
from .models import Finding as FindingRow
from .models import Run, Target as TargetRow, get_session
from .plugins.base import Ctx, Target
from .plugins.registry import discover
from .ratelimit import RateLimiter
from .runner import _run_plugin

COOLDOWN_S = float(os.environ.get("RECON_PLAYGROUND_COOLDOWN_S", "10"))
MAX_CONCURRENT = int(os.environ.get("RECON_PLAYGROUND_CONCURRENCY", "4"))

_sem = asyncio.Semaphore(MAX_CONCURRENT)
_last_retest: Dict[Tuple[str, int], float] = {}


class PlaygroundError(Exception):
    def __init__(self, status_code: int, detail: str,
                 retry_after: Optional[float] = None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.retry_after = retry_after


def _serialize_original(row: FindingRow) -> Dict:
    return {
        "id": row.id, "target_id": row.target_id, "plugin": row.plugin_id,
        "category": row.category, "key": row.key, "value": row.value,
        "source": row.source, "source_url": row.source_url,
        "evidence": row.evidence, "confidence": row.confidence,
        "passive": row.passive,
        "bounty_value": getattr(row, "bounty_value", "low"),
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
    }


def _serialize_fresh(f) -> Dict:
    ev = dict(f.evidence or {})
    out = {
        "plugin": f.plugin_id, "category": f.category, "key": f.key,
        "value": f.value, "source": f.source, "source_url": f.source_url,
        "evidence": ev, "confidence": f.confidence, "passive": f.passive,
        "bounty_value": getattr(f, "bounty_value", "low"),
    }
    impact = ev.get("attacker_impact")
    if impact:
        out["attacker_impact"] = impact
    return out


def _verdict(orig_key: str, orig_value: str, status: str,
             fresh: List) -> str:
    """unchanged: same key+value still produced. changed: same key,
    different value. gone: plugin ran fine but the finding is no
    longer produced. error: the re-check itself failed."""
    if status == "error":
        return "error"
    same_key = [f for f in fresh if f.key == orig_key]
    if any(f.value == orig_value for f in same_key):
        return "unchanged"
    if same_key:
        return "changed"
    return "gone"


async def retest_finding(run_id: str, finding_id: int) -> Dict:
    """Re-run the producing plugin for one stored finding.

    Raises PlaygroundError for unknown run/finding/plugin and for
    cooldown violations; otherwise always returns a result dict.
    """
    # -- load (session closed before any network work, like _run_one_job)
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise PlaygroundError(
                404, f"run {run_id} not found (see /api/runs for why runs "
                     "can disappear on ephemeral storage)")
        row = (session.query(FindingRow)
               .filter_by(id=finding_id, run_id=run_id).first())
        if not row:
            raise PlaygroundError(
                404, f"finding {finding_id} not found in run {run_id}")
        trow = session.query(TargetRow).filter_by(id=row.target_id).first()
        if not trow:
            raise PlaygroundError(
                404, "the target this finding belongs to is gone")
        from .keys import load_all
        keys = load_all(session)
        meta = (run.summary or {}).get("queue_meta", {})
        original = _serialize_original(row)
        orig_key, orig_value = row.key, row.value
        plugin_id = row.plugin_id
        mode = run.mode or "passive"
        source_type = run.source_type or "website"
        overrides = dict(meta.get("module_overrides", {}) or {})
        target = Target(raw=trow.raw, type=trow.type,
                        normalized=trow.normalized)
        target.id = trow.id
    finally:
        session.close()

    plugin_cls = discover().get(plugin_id)
    if plugin_cls is None:
        raise PlaygroundError(
            422, f"plugin {plugin_id!r} no longer exists in the registry; "
                 "this finding cannot be re-tested")

    # -- rate limit: per-finding cooldown (only when previously tested;
    # a missing entry is not "tested at monotonic 0" - on a fresh boot
    # that would block every first retest)
    now = time.monotonic()
    last = _last_retest.get((run_id, finding_id))
    if COOLDOWN_S > 0 and last is not None and now - last < COOLDOWN_S:
        raise PlaygroundError(
            429, f"playground cooldown: this finding was re-tested "
                 f"{now - last:.0f}s ago; wait {COOLDOWN_S:.0f}s between "
                 "re-tests of the same finding",
            retry_after=COOLDOWN_S - (now - last))
    _last_retest[(run_id, finding_id)] = now

    plugin = plugin_cls()
    async with net.async_client(
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.DEFAULT_TIMEOUT,
            follow_redirects=True) as http:
        ctx = Ctx(run_id=f"playground-{run_id}-{finding_id}", mode=mode,
                  http=http, cache=Cache(), keys=keys,
                  limiter=RateLimiter(),
                  module_overrides=overrides,
                  evidence_dir=config.EVIDENCE_DIR,
                  source_type=source_type)
        async with _sem:
            if plugin.accepts and target.type not in plugin.accepts:
                result = plugin._skipped(
                    f"not applicable to target type '{target.type}'")
                result.duration_ms = 0
            else:
                result = await _run_plugin(plugin, target, ctx)

    fresh = [_serialize_fresh(f) for f in result.findings]
    status = (result.status.value if hasattr(result.status, "value")
              else str(result.status))
    return {
        "run_id": run_id,
        "finding_id": finding_id,
        "plugin": plugin_id,
        "plugin_label": plugin.label,
        "target": target.normalized,
        "target_type": target.type,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "reason": result.reason or "",
        "duration_ms": result.duration_ms or 0,
        "verdict": _verdict(orig_key, orig_value, status, result.findings),
        "original": original,
        "fresh_findings": fresh,
        "fresh_count": len(fresh),
    }
