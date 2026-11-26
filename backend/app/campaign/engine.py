"""The campaign loop: plan -> gate -> execute -> write back -> replan.

This is the engine that makes ReconAnything behave like an autonomous
pentest orchestrator instead of a one-shot scanner:

1. seed the asset graph from the authorized roots and any imported scan
   findings,
2. ask the planner for the next intents,
3. gate each one (scope, capability, approval),
4. run it through its worker, capturing evidence,
5. write the result back into the dual graph,
6. replan from the new graph.

The loop ends when a goal is proven by evidence, the scope has nothing
left to try, a human approval is outstanding, or the budget is spent -
and the result says which one it was. It never ends ambiguously.

Determinism: without a model, no wall-clock or randomness enters the
plan; the clock is injectable, which is also how tests exercise the
time budget. With a model configured, its proposals are validated but
not reproducible, so the deterministic plan remains the fallback.

Planning, budget spending and graph writes stay on the calling thread;
``max_parallel`` only overlaps the I/O inside workers, which keeps the
budget and the write-back order deterministic. Per-host pacing is
enforced where each request is issued (``HostPacer``), so it also holds
across round boundaries and for the several requests one worker makes.
"""
from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from . import llm_planner, planner
from .evidence import EvidenceRecorder
from .graph import Graph, import_findings
from .models import Attempt, Budget, Intent
from .scope import Scope, host_of
from .workers import DEFAULT_WORKERS, WorkerContext


def _campaign_id() -> str:
    return "cmp_" + uuid.uuid4().hex[:12]


def _seed(graph: Graph, scope: Scope, seeds: Sequence[str]) -> List[Dict[str, str]]:
    """Add scope roots and caller seeds; return the out-of-scope refusals."""
    refused: List[Dict[str, str]] = []
    for raw in list(scope.roots) + list(seeds or ()):
        target = (raw or "").strip()
        if not target:
            continue
        ok, reason = scope.allows(target)
        if not ok:
            refused.append({"target": target, "reason": reason})
            continue
        if "://" in target:
            graph.add_asset("url", target, source="seed")
        else:
            graph.add_asset("host", target, source="seed")
    return refused


class HostPacer:
    """Per-host request spacing that survives wave boundaries.

    Pacing sleeps used to live in the wave's dispatch loop with the
    last-hit map local to that wave. A new round then started from an
    empty map and could hit a host immediately after the previous
    round's last request, and a queued job could issue its request later
    than the slot measured at submission. Both are bursts past
    ``per_host_rps``, so the gate is taken here instead: every request is
    spaced from the last request actually issued to that host, on any
    thread, for the whole campaign.

    The clock and sleep are injectable so tests can prove the interval
    without waiting for it.
    """

    def __init__(self, rps: float, *,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        try:
            rate = float(rps or 0)
        except (TypeError, ValueError):
            rate = 0.0
        self.interval = 1.0 / max(0.1, rate) if rate > 0 else 0.0
        self._clock = clock
        self._sleep = sleep
        self._guard = threading.Lock()
        self._slots: Dict[str, Dict[str, Any]] = {}

    def _slot(self, host: str) -> Dict[str, Any]:
        with self._guard:
            slot = self._slots.get(host)
            if slot is None:
                slot = self._slots[host] = {"lock": threading.Lock(),
                                            "last": None}
            return slot

    def wait(self, target: str) -> None:
        """Block until one more request to ``target``'s host is allowed."""
        if self.interval <= 0:
            return
        host = host_of(target)
        if not host:
            return
        slot = self._slot(host)
        # One lock per host: waiting on one target never stalls another
        # host's workers, and the slot is reserved before the request
        # leaves, so concurrent callers cannot share one interval.
        with slot["lock"]:
            now = self._clock()
            last = slot["last"]
            if last is not None:
                delay = self.interval - (now - last)
                if delay > 0:
                    self._sleep(delay)
                    now = self._clock()
            slot["last"] = now

    def wrap(self, fetch: Callable[..., Any]) -> Callable[..., Any]:
        """Return ``fetch`` with the per-host gate in front of it."""
        if self.interval <= 0:
            return fetch

        def paced(url: str, *args: Any, **kwargs: Any) -> Any:
            self.wait(url)
            return fetch(url, *args, **kwargs)

        return paced


def run_campaign(objective: str, scope: Scope, *,
                 seeds: Sequence[str] = (),
                 findings: Iterable[Dict[str, Any]] = (),
                 graph: Optional[Graph] = None,
                 workers: Optional[Dict[str, Callable]] = None,
                 approved: Iterable[str] = (),
                 fetch: Optional[Callable] = None,
                 llm: Optional[Callable[[str], str]] = None,
                 evidence: Optional[EvidenceRecorder] = None,
                 campaign_id: Optional[str] = None,
                 created: Optional[float] = None,
                 spent_requests: int = 0,
                 spent_intents: int = 0,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 log: Callable[[str], None] = lambda _m: None) -> Dict[str, Any]:
    """Run (or resume) one campaign and return its complete state."""
    graph = graph or Graph()
    goals = planner.goals_for(objective)
    refused = _seed(graph, scope, seeds)
    if findings:
        import_findings(graph, findings)

    work = dict(DEFAULT_WORKERS)
    if workers:
        work.update(workers)

    if fetch is None:
        from ..exploit_probes import default_fetch
        fetch = default_fetch
    if evidence is not None:
        fetch = evidence.wrap(fetch)
    # Pace every request, not every dispatch: the gate is shared by all
    # waves of this campaign and by every thread in a wave.
    fetch = HostPacer(scope.per_host_rps, clock=clock, sleep=sleep).wrap(fetch)

    budget = Budget(max_requests=scope.max_requests,
                    max_intents=scope.max_intents,
                    max_seconds=scope.max_seconds, started=clock())
    budget.requests_used = max(0, int(spent_requests))
    budget.intents_used = max(0, int(spent_intents))
    ctx = WorkerContext(scope=scope, budget=budget, graph=graph,
                        fetch=fetch, log=log, sleep=sleep)
    approvals = set(approved or ())
    awaiting: Dict[str, Dict[str, Any]] = {}
    executed = 0
    stop_reason = ""
    llm_rounds: List[Dict[str, Any]] = []

    for round_no in range(max(1, int(scope.max_rounds))):
        if budget.exhausted(clock()):
            stop_reason = budget.stop_reason or "budget exhausted"
            break
        proven = planner.goal_proven(goals, graph)
        # Proven stops the loop, but never before approved work that is
        # still unexecuted (a resumed approval must be allowed to run).
        outstanding = {k for k in approvals if k not in graph.attempted_keys()}
        if proven["proven"] and not awaiting and not outstanding:
            stop_reason = "goal proven"
            break

        intents = planner.next_intents(
            graph, scope, goals,
            pending=set(awaiting.keys()))
        if llm is not None:
            proposed, llm_meta = llm_planner.propose_intents(
                llm, graph, scope, goals,
                limit=planner.MAX_INTENTS_DEFAULT,
                pending=set(awaiting.keys()))
            llm_rounds.append(llm_meta)
            if proposed:
                intents = llm_planner.merge(
                    intents, proposed, limit=planner.MAX_INTENTS_DEFAULT)
        if not intents:
            stop_reason = ("awaiting approval" if awaiting
                           else "no untried in-scope actions remain")
            break

        runnable: List[Intent] = []
        for intent in intents:
            if budget.exhausted(clock()):
                stop_reason = budget.stop_reason or "budget exhausted"
                break
            ok, reason = scope.allows_intent(intent)
            if not ok:
                _record_blocked(graph, intent, reason)
                continue
            if scope.needs_approval(intent) and intent.key not in approvals:
                if intent.key not in awaiting:
                    awaiting[intent.key] = intent.to_dict()
                continue
            runnable.append(intent)
        ran = _run_wave(runnable, work, ctx, scope, graph, clock)
        executed += ran
        round_progress = ran > 0

        if not round_progress and not awaiting:
            stop_reason = "no untried in-scope actions remain"
            break
        if not round_progress and awaiting:
            stop_reason = "awaiting approval"
            break

    # Surface gated work the planner would take next even when the goal
    # is already proven: the operator can approve it and resume, and the
    # report then shows the whole chain instead of stopping at the door.
    for it in planner.next_intents(graph, scope, goals,
                                   pending=set(awaiting.keys())):
        if scope.needs_approval(it) and it.key not in approvals \
                and it.key not in awaiting:
            awaiting[it.key] = it.to_dict()

    proven = planner.goal_proven(goals, graph)
    if proven["proven"]:
        status = "proven"
        stop_reason = "goal proven"
    elif budget.exhausted(clock()):
        status = "budget_exhausted"
        stop_reason = stop_reason or budget.stop_reason
    elif awaiting:
        status = "awaiting_approval"
        stop_reason = stop_reason or "awaiting approval"
    else:
        status = "exhausted"
        stop_reason = stop_reason or "no untried in-scope actions remain"

    result = {
        "id": campaign_id or _campaign_id(),
        "objective": objective,
        "goals": goals,
        "status": status,
        "reason": stop_reason,
        "created": created or clock(),
        "updated": clock(),
        "scope": scope.to_dict(),
        "budget": budget.to_dict(),
        "proven": proven,
        "summary": graph.summary(),
        "kill_chain": graph.kill_chain(),
        "pending_approval": sorted(awaiting.values(),
                                   key=lambda i: (i["priority"], i["target"])),
        "approved": sorted(approvals),
        "refused_seeds": refused,
        "executed": executed,
        "evidence": evidence.summary() if evidence is not None else {},
        "llm": {"enabled": llm is not None, "rounds": llm_rounds},
        "next_actions": planner.next_actions(graph, scope, goals),
        "graph": graph.to_snapshot(),
        "boundary": (
            "Read-only by construction: every network action is a GET/HEAD "
            "or a read-only query; the only POST-free console work is "
            "listing. Impact enumeration requires an explicit approval. "
            "No credentials are guessed, no data is modified, and nothing "
            "is written to a target."
        ),
    }
    return result


def _execute(intent: Intent, workers: Dict[str, Callable],
             ctx: WorkerContext) -> Any:
    fn = workers.get(intent.kind)
    if fn is None:
        return Attempt(key=intent.key, kind=intent.kind, action=intent.action,
                       target=intent.target, status="skipped",
                       detail=f"no worker for kind {intent.kind!r}")
    started = ctx.budget.elapsed()
    try:
        attempt = fn(intent, ctx)
    except Exception as exc:  # worker failures never kill the campaign
        attempt = Attempt(key=intent.key, kind=intent.kind,
                          action=intent.action, target=intent.target,
                          status="failed", error=str(exc)[:500])
    attempt.seconds = max(0.0, ctx.budget.elapsed() - started)
    return attempt


def _run_wave(intents: Sequence[Intent], workers: Dict[str, Callable],
              ctx: WorkerContext, scope: Scope, graph: Graph,
              clock: Callable[[], float]) -> int:
    """Execute one round's intents, up to ``scope.max_parallel`` at once.

    Budget is spent on the calling thread before a job is dispatched and
    attempts are recorded in submission order, so concurrency cannot
    outspend the cap or reorder the graph. Per-host pacing happens in the
    paced ``fetch`` (``HostPacer``) instead of here: pacing at dispatch
    would reset at every round boundary and would measure a queued job's
    slot before the job actually issued its request.
    """
    if not intents:
        return 0
    parallel = max(1, min(8, int(scope.max_parallel or 1)))

    if parallel == 1:
        ran = 0
        for intent in intents:
            if ctx.budget.exhausted(clock()):
                break
            ctx.budget.spend(intent.cost, clock())
            graph.record_attempt(_execute(intent, workers, ctx))
            ran += 1
        return ran

    with ThreadPoolExecutor(max_workers=parallel,
                            thread_name_prefix="campaign") as pool:
        futures = []
        for intent in intents:
            if ctx.budget.exhausted(clock()):
                break
            ctx.budget.spend(intent.cost, clock())
            futures.append((intent, pool.submit(_execute, intent,
                                                workers, ctx)))
        for _intent, future in futures:
            graph.record_attempt(future.result())
        return len(futures)


def _record_blocked(graph: Graph, intent: Intent, reason: str) -> None:
    graph.record_attempt(Attempt(
        key=intent.key, kind=intent.kind, action=intent.action,
        target=intent.target, status="blocked", detail=reason,
    ))


def resume_campaign(result: Dict[str, Any], approve: Iterable[str] = (), *,
                    fetch: Optional[Callable] = None,
                    llm: Optional[Callable[[str], str]] = None,
                    evidence: Optional[EvidenceRecorder] = None,
                    workers: Optional[Dict[str, Callable]] = None,
                    clock: Callable[[], float] = time.time,
                    sleep: Callable[[float], None] = time.sleep,
                    log: Callable[[str], None] = lambda _m: None) -> Dict[str, Any]:
    """Resume a stored campaign, executing newly approved intents.

    The graph comes back from the snapshot, so completed work is never
    repeated and the budget reflects what was already spent.
    """
    graph = Graph.from_snapshot(result.get("graph"))
    scope = Scope.from_dict(result.get("scope") or {})
    prior_budget = result.get("budget") or {}
    approved = set(result.get("approved") or ()) | set(approve or ())
    # Carry the spent budget forward so an approval cannot reset the cap.
    resumed = run_campaign(
        result.get("objective", ""), scope,
        graph=graph,
        approved=approved,
        fetch=fetch,
        llm=llm,
        evidence=evidence,
        workers=workers,
        campaign_id=result.get("id"),
        created=result.get("created"),
        spent_requests=int(prior_budget.get("requests_used") or 0),
        spent_intents=int(prior_budget.get("intents_used") or 0),
        clock=clock, sleep=sleep, log=log,
    )
    if result.get("retests"):
        resumed["retests"] = list(result["retests"])
    if not resumed.get("evidence") and result.get("evidence"):
        resumed["evidence"] = dict(result["evidence"])
    return resumed


def preview(objective: str, targets: Sequence[str], *,
            allow_exploit_confirm: bool = False,
            exclude: Sequence[str] = (), limit: int = 10) -> Dict[str, Any]:
    """Dry-run plan: what the campaign would try, with zero requests sent."""
    from .scope import host_of
    goals = planner.goals_for(objective)
    roots = tuple(dict.fromkeys(host_of(t) or t for t in targets))
    scope = Scope(roots=roots, exclude=tuple(exclude), allow_active=True,
                  allow_exploit_confirm=allow_exploit_confirm)
    graph = Graph()
    refused = _seed(graph, scope, targets)
    intents = planner.next_intents(graph, scope, goals, limit=limit)
    return {
        "dry_run": True,
        "objective": objective,
        "goals": goals,
        "scope": scope.to_dict(),
        "plan": [i.to_dict() for i in intents],
        "refused_seeds": refused,
        "note": ("Dry run: no request was sent. Pass allow_active=true to "
                 "execute the plan."),
    }
