#!/usr/bin/env python3
"""End-to-end engine benchmark for ReconAnything.

Drives the REAL pipeline (runner.execute_run -> DB job queue ->
queue_worker_loop -> plugins) against the deterministic fixture site
(tests/plugin_fixtures.py), with the worker's HTTP client swapped for
a counting transport that can inject per-request latency, refuse
connections (dead host), or blackhole them (firewalled host). This is
the before/after instrument for engine speed work: same targets, same
plugins, same findings expected - only the wall clock should move.

Scenarios:
  alive     fixture site answers, latency_ms per request (default 25)
  dead      fixture host refuses every connection (ConnectError)
  blackhole fixture host accepts but never answers (client timeouts);
            use --plugins to scope it, every attempt costs a timeout

Usage (from backend/):
    python3 scripts/speed_bench.py --scenario alive --out /tmp/bench.json
    python3 scripts/speed_bench.py --scenario dead --out /tmp/bench.json
    python3 scripts/speed_bench.py --scenario blackhole \
        --plugins headers,tls,webtech,robots --out /tmp/bench.json

One scenario per process (module state is per-process by design).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import Counter

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)
sys.path.insert(0, os.path.join(BACKEND, "tests"))


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario", choices=["alive", "dead", "blackhole"],
                    default="alive")
    ap.add_argument("--target", default="fixture.test")
    ap.add_argument("--mode", default="active")
    ap.add_argument("--latency-ms", type=float, default=25.0)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--plugins", default=None,
                    help="comma-separated plugin ids (default: full set)")
    ap.add_argument("--timeout-s", type=float, default=1500.0)
    ap.add_argument("--out", default=None)
    return ap.parse_args()


ARGS = parse_args()

# --- environment must be set before importing app modules --------------
DB_PATH = f"/tmp/speed_bench_{ARGS.scenario}_{os.getpid()}.db"
for suffix in ("", "-wal", "-shm"):
    try:
        os.remove(DB_PATH + suffix)
    except OSError:
        pass
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["RECON_CONCURRENCY"] = str(ARGS.concurrency)
os.environ.pop("REDIS_URL", None)

import httpx  # noqa: E402

import plugin_fixtures as fx  # noqa: E402
from app import models, net, runner  # noqa: E402


# --- counting / fault-injecting transport -------------------------------
class BenchTransport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.mock = httpx.MockTransport(fx._handler)
        self.counts: Counter = Counter()
        self.host_counts: Counter = Counter()
        self.total = 0

    async def handle_async_request(self, request):
        url = str(request.url)
        host = request.url.host
        self.counts[url] += 1
        self.host_counts[host] += 1
        self.total += 1
        if ARGS.scenario == "dead" and host == fx.HOST:
            raise httpx.ConnectError("bench: connection refused",
                                     request=request)
        if ARGS.scenario == "blackhole" and host == fx.HOST:
            await asyncio.sleep(120)  # client timeout always fires first
        if ARGS.latency_ms:
            await asyncio.sleep(ARGS.latency_ms / 1000.0)
        return await self.mock.handle_async_request(request)


TRANSPORT = BenchTransport()


def bench_client(**kwargs):
    return httpx.AsyncClient(
        transport=TRANSPORT,
        headers=kwargs.get("headers"),
        timeout=kwargs.get("timeout", 20),
        follow_redirects=kwargs.get("follow_redirects", True),
        trust_env=False)


net.async_client = bench_client

# --- SQL instrumentation --------------------------------------------------
SQL_STATS = {"count": 0, "time_s": 0.0, "by_kind": Counter()}


def install_sql_stats():
    from sqlalchemy import event
    engine = models.engine
    if engine is None:
        return

    @event.listens_for(engine, "before_cursor_execute")
    def _before(conn, cursor, statement, parameters, context, executemany):
        context._bench_t0 = time.perf_counter()
        SQL_STATS["count"] += 1
        kind = statement.strip().split(None, 1)[0].upper() if statement else "?"
        SQL_STATS["by_kind"][kind] += 1

    @event.listens_for(engine, "after_cursor_execute")
    def _after(conn, cursor, statement, parameters, context, executemany):
        t0 = getattr(context, "_bench_t0", None)
        if t0 is not None:
            SQL_STATS["time_s"] += time.perf_counter() - t0


# --- claim instrumentation ------------------------------------------------
CLAIM_STATS = {"calls": 0, "claimed": 0, "time_s": 0.0}
_orig_claim = runner._claim_jobs


def timed_claim(session, limit):
    t0 = time.perf_counter()
    out = _orig_claim(session, limit)
    CLAIM_STATS["calls"] += 1
    CLAIM_STATS["claimed"] += len(out)
    CLAIM_STATS["time_s"] += time.perf_counter() - t0
    return out


runner._claim_jobs = timed_claim


async def amain():
    models.init_db()
    install_sql_stats()
    # Pre-warm the plugin registry + worker loop: in production the
    # worker is a long-lived process, so per-run wall time does not
    # include first-import discovery or worker startup.
    from app.plugins.registry import discover
    discover()
    runner.start_queue_worker()
    await asyncio.sleep(0.5)
    run_id = "bench" + os.urandom(4).hex()
    session = models.get_session()
    try:
        session.add(models.Run(id=run_id, mode=ARGS.mode, status="running",
                               source_type="website"))
        session.commit()
    finally:
        session.close()

    plugin_ids = (ARGS.plugins.split(",") if ARGS.plugins else None)
    t0 = time.monotonic()
    await runner.execute_run(run_id, ARGS.target, ARGS.mode,
                             plugin_ids=plugin_ids)
    deadline = t0 + ARGS.timeout_s
    status = "timeout"
    while time.monotonic() < deadline:
        await asyncio.sleep(0.25)
        s = models.get_session()
        try:
            run = s.query(models.Run).filter_by(id=run_id).first()
            status = run.status if run else "missing"
        finally:
            s.close()
        if status in ("done", "failed", "error"):
            break
    wall = time.monotonic() - t0

    # Harvest job + finding stats.
    s = models.get_session()
    try:
        jobs = s.query(models.PluginJob).filter_by(run_id=run_id).all()
        findings = s.query(models.Finding).filter_by(run_id=run_id).all()
        events = s.query(models.RunEvent).filter_by(run_id=run_id).count()
        job_rows = [{
            "plugin": j.plugin_id, "status": j.status,
            "ms": (j.result or {}).get("ms", 0),
            "rstatus": (j.result or {}).get("status", ""),
            "reason": (j.result or {}).get("reason", ""),
        } for j in jobs]
        finding_sig = sorted(
            (f.plugin_id, f.key, f.value or "") for f in findings)
        finding_pk = sorted((f.plugin_id, f.key) for f in findings)
    finally:
        s.close()

    plugin_ms = {}
    for j in job_rows:
        plugin_ms[j["plugin"]] = plugin_ms.get(j["plugin"], 0) + (j["ms"] or 0)
    top_slow = sorted(plugin_ms.items(), key=lambda kv: -kv[1])[:25]
    report = {
        "scenario": ARGS.scenario,
        "target": ARGS.target,
        "mode": ARGS.mode,
        "latency_ms": ARGS.latency_ms,
        "concurrency": ARGS.concurrency,
        "status": status,
        "wall_s": round(wall, 2),
        "jobs_total": len(job_rows),
        "jobs_by_status": dict(Counter(j["status"] for j in job_rows)),
        "jobs_by_rstatus": dict(Counter(j["rstatus"] for j in job_rows)),
        "budget_skipped": sum(1 for j in job_rows
                              if "time budget" in (j["reason"] or "")),
        "timeout_skipped": sum(1 for j in job_rows
                               if "timeout" in (j["reason"] or "")),
        "findings": len(finding_sig),
        "finding_sig": finding_sig,
        "finding_pk": finding_pk,
        "events": events,
        "requests_total": TRANSPORT.total,
        "requests_by_host": dict(TRANSPORT.host_counts.most_common(12)),
        "top_urls": TRANSPORT.counts.most_common(25),
        "unique_urls": len(TRANSPORT.counts),
        "dup_requests": TRANSPORT.total - len(TRANSPORT.counts),
        "sql": {"count": SQL_STATS["count"],
                "time_s": round(SQL_STATS["time_s"], 2),
                "by_kind": dict(SQL_STATS["by_kind"])},
        "claims": {"calls": CLAIM_STATS["calls"],
                   "claimed": CLAIM_STATS["claimed"],
                   "time_s": round(CLAIM_STATS["time_s"], 2)},
        "top_slow_plugins_ms": top_slow,
        "plugin_ms_sum": sum(plugin_ms.values()),
    }
    print(json.dumps({k: v for k, v in report.items()
                      if k not in ("finding_sig", "finding_pk")},
                     indent=1, default=str), flush=True)
    if ARGS.out:
        with open(ARGS.out, "w") as f:
            json.dump(report, f, indent=1, default=str)
        print("wrote", ARGS.out, flush=True)
    sys.stdout.flush()
    return 0 if status == "done" else 3


if __name__ == "__main__":
    try:
        code = asyncio.run(amain())
    except KeyboardInterrupt:
        code = 130
    # The queue worker task outlives the run; hard-exit so daemon
    # threads / the worker loop cannot hang the bench process.
    os._exit(code)
