"""SELECTED MEANS RUN (Jay, 2026-10-23).

When a run is created with an explicit plugin selection (the UI's
Crypto Pack preset posts exactly the cp_* ids), those plugins must
not be starved by the scan time budget: in run d67d43c2abf1, 974
jobs were budget-skipped, crypto plugins among them. These tests
drive _claim_jobs directly on a throwaway DB:

- past the hard stop, a selected job is still claimed;
- an unselected job in the same run is budget-skipped;
- a run WITHOUT a selection keeps the old behavior (all skipped);
- selected jobs claim before unselected ones regardless of tier.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models  # noqa: E402
from app import runner  # noqa: E402
from app.models import PluginJob, Run, Target as TargetRow  # noqa: E402

_TMPDB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_tmp_selected.db")


@pytest.fixture()
def db():
    engine = create_engine(f"sqlite:///{_TMPDB}")
    models.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    orig_engine, orig_factory = models.engine, models.SessionLocal
    models.engine, models.SessionLocal = engine, factory
    runner._run_clocks.clear()
    session = factory()
    yield session
    session.close()
    models.engine, models.SessionLocal = orig_engine, orig_factory
    engine.dispose()
    runner._run_clocks.clear()
    try:
        os.unlink(_TMPDB)
    except OSError:
        pass


def _mk_run(session, run_id, plugin_ids=None):
    meta = {"mode": "passive", "plugin_ids": plugin_ids,
            "source_type": "website"}
    run = Run(id=run_id, mode="passive", status="running",
              summary={"queue_meta": meta})
    session.add(run)
    t = TargetRow(id=f"t-{run_id}", run_id=run_id, raw="example.com",
                  type="domain", normalized="example.com")
    session.add(t)
    session.commit()
    return t


def _mk_job(session, run_id, target_id, plugin_id, priority=3):
    job = PluginJob(run_id=run_id, target_id=target_id,
                    plugin_id=plugin_id, phase=1, priority=priority,
                    estimate_s=60, status="queued")
    session.add(job)
    session.commit()
    return job


def _age_past_hard_stop(run_id):
    runner._run_clocks[run_id] = (
        time.monotonic() - (runner.SCAN_HARD_STOP_S + 500))


def test_selected_job_claimed_past_hard_stop(db):
    t = _mk_run(db, "run-sel", plugin_ids=["cp_btc_legacy", "cp_xmr_standard"])
    sel_job = _mk_job(db, "run-sel", t.id, "cp_btc_legacy")
    other_job = _mk_job(db, "run-sel", t.id, "some_unselected_plugin")
    _age_past_hard_stop("run-sel")
    claimed = runner._claim_jobs(db, limit=10)
    claimed_ids = [j.id for j in claimed]
    assert sel_job.id in claimed_ids
    assert other_job.id not in claimed_ids
    db.refresh(other_job)
    assert other_job.status == "skipped"
    assert "time budget" in (other_job.result or {}).get("reason", "")


def test_no_selection_keeps_budget_skip(db):
    t = _mk_run(db, "run-full", plugin_ids=None)
    job = _mk_job(db, "run-full", t.id, "cp_btc_legacy")
    _age_past_hard_stop("run-full")
    claimed = runner._claim_jobs(db, limit=10)
    assert job.id not in [j.id for j in claimed]
    db.refresh(job)
    assert job.status == "skipped"
    assert "time budget" in (job.result or {}).get("reason", "")


def test_selected_claims_first_regardless_of_tier(db):
    t = _mk_run(db, "run-order", plugin_ids=["cp_btc_legacy"])
    # unselected HIGH priority vs selected LOW priority, fresh clock:
    hi = _mk_job(db, "run-order", t.id, "port_scan", priority=1)
    sel = _mk_job(db, "run-order", t.id, "cp_btc_legacy", priority=3)
    claimed = runner._claim_jobs(db, limit=1)
    assert [j.id for j in claimed] == [sel.id]
    db.refresh(hi)
    assert hi.status == "queued"  # not skipped, just claimed later
