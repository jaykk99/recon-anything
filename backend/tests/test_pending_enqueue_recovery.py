"""Pending-enqueue recovery: a deploy/crash mid-setup must not kill a run.

Regression coverage for the 2026-10-24 Winnipeg bank/ATM location run
that FAILED ~12s in with 0 jobs/findings. Root cause: bank/ATM location
enqueue spends seconds on network geocode/POI resolution BEFORE writing
any target or job row, so a restart in that window left a "running" run
with nothing resumable, and boot init marked it failed. The fix persists
the enqueue intent in the Run summary at creation time and replays it at
boot for runs that are still clean (0 targets, 0 jobs).

Network-free: the bankatm DOMAIN branch enqueues without geocoding, and
the in-process queue worker is disabled (WORKER_ENABLED patched off) so
no plugin ever executes against the network in these tests. Runs against
a temp SQLite DB via FastAPI TestClient, same pattern as test_runs_api.
"""
import datetime as dt
import os
import sys
import tempfile
import time

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name
os.environ["ACCESS_CODE"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import runner as runner_mod  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, PluginJob, Run, Target, get_session, init_db  # noqa: E402


def _clean():
    session = get_session()
    try:
        session.query(Finding).delete()
        session.query(PluginJob).delete()
        session.query(Target).delete()
        session.query(Run).delete()
        session.commit()
    finally:
        session.close()


def _get_run(run_id):
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if run is None:
            return None
        return {"status": run.status,
                "summary": dict(run.summary or {})}
    finally:
        session.close()


def _job_count(run_id):
    session = get_session()
    try:
        return session.query(PluginJob).filter_by(run_id=run_id).count()
    finally:
        session.close()


def _poll(fn, timeout=20.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(0.2)
    return last


@pytest.fixture(scope="module")
def client():
    # No in-process worker: queued jobs must stay queued (not execute),
    # and no second loop competes with the boot-recovery TestClient.
    prev = runner_mod.WORKER_ENABLED
    runner_mod.WORKER_ENABLED = False
    try:
        init_db()
        _clean()
        with TestClient(app) as c:
            yield c
    finally:
        runner_mod.WORKER_ENABLED = prev


_INTENT = {"targets": "example.com", "mode": "passive", "plugins": None,
           "module_overrides": {"bank": "authorized",
                                "atm": "authorized"},
           "source_type": "bankatm", "bounty": False,
           "excluded_plugin_ids": None}


def test_post_stores_intent_and_enqueue_clears_it(client):
    resp = client.post("/api/runs", json={"targets": "example.com",
                                          "mode": "passive",
                                          "source_type": "bankatm"})
    assert resp.status_code == 200, resp.text
    run_id = resp.json()["run_id"]

    def _ready():
        run = _get_run(run_id)
        if run is None:
            return False
        # Enqueue finished: jobs exist, intent cleared, run still open
        # (worker off, so nothing finalizes it).
        return (_job_count(run_id) > 0
                and "pending_enqueue" not in run["summary"]
                and run["status"] == "running")

    assert _poll(_ready), (
        f"enqueue did not complete: run={_get_run(run_id)} "
        f"jobs={_job_count(run_id)}")


def test_boot_replays_clean_pending_run_and_fails_partial(client):
    # Simulate the deploy-kill: runs created long before this boot,
    # enqueue intent intact, original task dead with the old process.
    session = get_session()
    try:
        session.add(Run(id="pend-clean-001", mode="passive",
                        status="running", source_type="bankatm",
                        created_at=dt.datetime(2020, 1, 1),
                        summary={"bounty": False,
                                 "pending_enqueue": dict(_INTENT)}))
        session.add(Run(id="pend-partial-001", mode="passive",
                        status="running", source_type="bankatm",
                        created_at=dt.datetime(2020, 1, 1),
                        summary={"bounty": False,
                                 "pending_enqueue": dict(_INTENT)}))
        # Partial enqueue: a target row already exists, so a replay
        # would duplicate rows (target ids are random uuids).
        session.add(Target(id="pend-target-1", run_id="pend-partial-001",
                           raw="example.com", type="domain",
                           normalized="example.com"))
        session.commit()
    finally:
        session.close()

    # A fresh boot: bg init must NOT fail the clean run, and the
    # recovery task must replay its enqueue. The production grace delay
    # (deploy overlap) is shortened here; the production default is 180s.
    os.environ["RECON_PENDING_RECOVERY_DELAY_S"] = "1"
    try:
        _boot_and_assert()
    finally:
        os.environ.pop("RECON_PENDING_RECOVERY_DELAY_S", None)


def _boot_and_assert():
    with TestClient(app):
        def _recovered():
            run = _get_run("pend-clean-001")
            return (run is not None and run["status"] == "running"
                    and "pending_enqueue" not in run["summary"]
                    and _job_count("pend-clean-001") > 0)

        assert _poll(_recovered), (
            f"clean pending run was not recovered: "
            f"run={_get_run('pend-clean-001')} "
            f"jobs={_job_count('pend-clean-001')}")

    # The partial run must fail loudly instead of duplicating rows.
    partial = _get_run("pend-partial-001")
    assert partial is not None and partial["status"] == "failed", partial
    assert _job_count("pend-partial-001") == 0
