"""Retest a stored finding by re-running the action that produced it.

The verdict is deliberately conservative: only a clean negative becomes
``fixed``. A transport failure, a missing approval, or an action that
cannot be re-executed is ``unconfirmed`` - never ``fixed``.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from ..exploit_probes import PROBES, default_fetch
from .engine import _execute
from .graph import Graph
from .models import Budget, Intent
from .scope import Scope
from .workers import DEFAULT_WORKERS, WorkerContext


def _intent_for(finding: Dict[str, Any]) -> Optional[Intent]:
    action = str(finding.get("action") or "")
    target = str(finding.get("target") or "")
    if not target:
        return None
    if action == "surface":
        return Intent(kind="recon", action="surface", target=target,
                      goal="recon")
    if action in PROBES:
        return Intent(kind="probe", action=action, target=target,
                      goal="retest")
    if action.startswith("enumerate:"):
        console = action.split(":", 1)[1]
        return Intent(kind="impact", action=action, target=target,
                      goal="impact", requires_approval=True, cost=2,
                      meta={"console": console})
    if action == "bucket-list":
        return Intent(kind="verify", action="bucket-list", target=target,
                      goal="exposure")
    return None


def _same_finding(original: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
    """Same action and tags, and the same title or console identity."""
    if candidate.get("action") != original.get("action"):
        return False
    if set(candidate.get("tags") or []) != set(original.get("tags") or []):
        return False
    if candidate.get("title") == original.get("title"):
        return True
    console = (original.get("meta") or {}).get("console")
    return bool(console) and (
        (candidate.get("meta") or {}).get("console") == console)


def retest_finding(result: Dict[str, Any], finding_id: str, *,
                   fetch: Optional[Callable] = None,
                   workers: Optional[Dict[str, Callable]] = None,
                   clock: Callable[[], float] = time.time) -> Dict[str, Any]:
    """Re-run one finding's action; append and return the retest record."""
    graph = Graph.from_snapshot(result.get("graph") or {})
    scope = Scope.from_dict(result.get("scope") or {})
    finding = graph.findings.get(finding_id)
    if finding is None:
        raise KeyError(f"unknown finding {finding_id!r}")

    intent = _intent_for(finding)
    record: Dict[str, Any] = {
        "finding_id": finding_id,
        "title": finding.get("title", ""),
        "action": finding.get("action", ""),
        "target": finding.get("target", ""),
        "at": clock(),
    }
    if intent is None:
        record.update(verdict="unconfirmed",
                      reason="no re-runnable action for this finding")
        result.setdefault("retests", []).append(record)
        return record

    allowed, reason = scope.allows_intent(intent)
    if not allowed:
        record.update(verdict="unconfirmed", reason=reason)
        result.setdefault("retests", []).append(record)
        return record
    if (scope.needs_approval(intent)
            and intent.key not in set(result.get("approved") or ())):
        record.update(
            verdict="unconfirmed",
            reason="impact retest needs the original approval")
        result.setdefault("retests", []).append(record)
        return record

    budget = Budget(max_requests=6, max_intents=1, max_seconds=30.0,
                    started=clock())
    ctx = WorkerContext(scope=scope, budget=budget, graph=graph,
                        fetch=fetch or default_fetch, log=lambda _m: None)
    work = dict(DEFAULT_WORKERS)
    work.update(workers or {})
    attempt = _execute(intent, work, ctx)
    record["receipt"] = attempt.evidence[0] if attempt.evidence else {}

    if attempt.status != "ok" or attempt.error:
        record.update(verdict="unconfirmed",
                      reason=attempt.error or f"worker status {attempt.status}")
    elif any(_same_finding(finding, row) for row in attempt.findings):
        record.update(verdict="reproducible",
                      reason="the same condition was observed again")
    else:
        record.update(verdict="fixed",
                      reason="the check ran cleanly and the condition was gone")

    result.setdefault("retests", []).append(record)
    result["updated"] = clock()
    return record
