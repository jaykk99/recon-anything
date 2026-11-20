"""Tests for scan dispatch ordering (anti-starvation within tier).

Jay's priority policy is unchanged: HIGH tier beats MEDIUM beats LOW,
phase 1 beats phase 2. Within the same (priority, phase), claiming no
longer streams strictly fastest-first: that order left the slowest
plugins queued until the scan budget's soft stop mass-skipped them
(34 of 170 cut on the 2026-10-20 verification scan). _dispatch_order
interleaves longest-first with shortest-first inside each tier, so
long jobs start in the first claim waves and mid-length jobs fill the
tail. Rows enqueued before estimate_s existed (NULL) fall back to the
default estimate.
"""
import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ["ACCESS_CODE"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.models import PluginJob, get_session, init_db  # noqa: E402
from app.runner import (DEFAULT_PLUGIN_ESTIMATE_S, PLUGIN_TIME_ESTIMATES,  # noqa: E402
                        _dispatch_order, _queued_jobs_query)


@pytest.fixture()
def session():
    init_db()
    s = get_session()
    s.query(PluginJob).delete()
    s.commit()
    yield s
    s.close()


def _job(s, pid, priority, phase=1, estimate=None):
    j = PluginJob(run_id="r1", target_id="t1", plugin_id=pid,
                  phase=phase, priority=priority, estimate_s=estimate,
                  status="queued")
    s.add(j)
    s.commit()
    return j


def test_fastest_first_within_tier(session):
    # The base query contract is unchanged (deterministic SQL order);
    # claiming re-orders with _dispatch_order (see below).
    _job(session, "slow", priority=2, phase=1, estimate=60)
    _job(session, "fast", priority=2, phase=1, estimate=5)
    _job(session, "mid", priority=2, phase=1, estimate=20)
    order = [j.plugin_id for j in _queued_jobs_query(session).all()]
    assert order == ["fast", "mid", "slow"]


def test_dispatch_order_no_starvation(session):
    # The longest job in the tier is claimed FIRST, then the fastest:
    # slow plugins can no longer be stranded at the budget's soft stop.
    _job(session, "slow", priority=2, phase=1, estimate=60)
    _job(session, "fast", priority=2, phase=1, estimate=5)
    _job(session, "mid", priority=2, phase=1, estimate=20)
    order = [j.plugin_id for j in
             _dispatch_order(_queued_jobs_query(session).all())]
    assert order == ["slow", "fast", "mid"]


def test_dispatch_interleave_longest_first(session):
    for est in (60, 45, 30, 20, 12, 8, 5):
        _job(session, f"p{est}", priority=2, phase=1, estimate=est)
    order = [j.plugin_id for j in
             _dispatch_order(_queued_jobs_query(session).all())]
    # longest, shortest, 2nd longest, 2nd shortest, ... mid-length last
    assert order == ["p60", "p5", "p45", "p8", "p30", "p12", "p20"]


def test_dispatch_priority_and_phase_dominate(session):
    _job(session, "slow-high", priority=1, phase=1, estimate=300)
    _job(session, "fast-low", priority=3, phase=1, estimate=1)
    _job(session, "slow-p1", priority=2, phase=1, estimate=300)
    _job(session, "fast-p2", priority=2, phase=2, estimate=1)
    order = [j.plugin_id for j in
             _dispatch_order(_queued_jobs_query(session).all())]
    assert order == ["slow-high", "slow-p1", "fast-p2", "fast-low"]


def test_dispatch_null_estimate_uses_default(session):
    _job(session, "legacy", priority=2, phase=1, estimate=None)
    _job(session, "quick", priority=2, phase=1, estimate=5)
    _job(session, "slower", priority=2, phase=1,
         estimate=DEFAULT_PLUGIN_ESTIMATE_S + 50)
    order = [j.plugin_id for j in
             _dispatch_order(_queued_jobs_query(session).all())]
    # legacy counts as the default (12): desc [62, 12, 5] interleaved
    assert order == ["slower", "quick", "legacy"]


def test_priority_beats_estimate(session):
    _job(session, "slow-high", priority=1, phase=1, estimate=300)
    _job(session, "fast-low", priority=3, phase=1, estimate=1)
    order = [j.plugin_id for j in _queued_jobs_query(session).all()]
    assert order == ["slow-high", "fast-low"]


def test_phase_beats_estimate(session):
    _job(session, "slow-p1", priority=2, phase=1, estimate=300)
    _job(session, "fast-p2", priority=2, phase=2, estimate=1)
    order = [j.plugin_id for j in _queued_jobs_query(session).all()]
    assert order == ["slow-p1", "fast-p2"]


def test_null_estimate_uses_default(session):
    _job(session, "legacy", priority=2, phase=1, estimate=None)
    _job(session, "quick", priority=2, phase=1, estimate=5)
    _job(session, "slower", priority=2, phase=1,
         estimate=DEFAULT_PLUGIN_ESTIMATE_S + 50)
    order = [j.plugin_id for j in _queued_jobs_query(session).all()]
    # legacy (NULL -> default 12) sorts between quick(5) and slower(62)
    assert order == ["quick", "legacy", "slower"]


def test_tie_broken_by_id(session):
    _job(session, "b", priority=2, phase=1, estimate=10)
    _job(session, "a", priority=2, phase=1, estimate=10)
    order = [j.plugin_id for j in _queued_jobs_query(session).all()]
    ids = [j.id for j in _queued_jobs_query(session).all()]
    assert ids == sorted(ids)


def test_claim_takes_longest_in_tier_first(session):
    from app.models import Run
    from app.runner import _claim_jobs
    session.query(Run).delete()
    session.add(Run(id="r1", status="running", mode="passive"))
    session.commit()
    _job(session, "fast", priority=2, phase=1, estimate=5)
    _job(session, "slow", priority=2, phase=1, estimate=60)
    claimed = _claim_jobs(session, 1)
    assert [j.plugin_id for j in claimed] == ["slow"]
    claimed = _claim_jobs(session, 1)
    assert [j.plugin_id for j in claimed] == ["fast"]


def test_abandon_job_requeues_then_fails(session):
    from app.runner import MAX_JOB_ATTEMPTS, _abandon_job
    _job(session, "wedged", priority=2, phase=1, estimate=5)
    job = session.query(PluginJob).filter_by(plugin_id="wedged").one()
    job.status = "running"
    session.commit()
    _abandon_job(job.id)
    session.expire_all()
    job = session.query(PluginJob).filter_by(plugin_id="wedged").one()
    assert job.status == "queued" and job.attempts == 1
    # Simulate repeated wedges: at MAX_JOB_ATTEMPTS the job fails
    # (poison-pill guard) instead of looping forever.
    job.status = "running"
    job.attempts = MAX_JOB_ATTEMPTS - 1
    session.commit()
    _abandon_job(job.id)
    session.expire_all()
    job = session.query(PluginJob).filter_by(plugin_id="wedged").one()
    assert job.status == "failed" and job.attempts == MAX_JOB_ATTEMPTS


def test_non_queued_excluded(session):
    j = _job(session, "done-one", priority=1, phase=1, estimate=1)
    j.status = "done"
    session.commit()
    _job(session, "queued-one", priority=3, phase=2, estimate=999)
    order = [x.plugin_id for x in _queued_jobs_query(session).all()]
    assert order == ["queued-one"]


def test_new_plugins_have_estimates():
    new_ids = ["cookie_security", "csp_audit", "hsts", "http_methods",
               "error_pages", "exposed_debug", "phpinfo", "mixed_content",
               "http2_check", "graphql_probe", "rate_limit_audit",
               "web_manifest", "sri_audit", "html_comments", "trackers",
               "well_known_audit", "redirect_chain", "dns_infra",
               "ipv6_check", "ip_reputation", "smtp_tls", "cdn_detect",
               "typosquat", "tls_config", "caa_audit",
               "cache_control_audit"]
    missing = [pid for pid in new_ids if pid not in PLUGIN_TIME_ESTIMATES]
    assert not missing, f"plugins missing time estimates: {missing}"


# ---------------------------------------------------------------------------
# Adaptive time estimates (_calibrated_estimates)
# ---------------------------------------------------------------------------

import datetime as _dt  # noqa: E402

from app.runner import _calibrated_estimates, _enqueue_jobs  # noqa: E402


def _seed_job(s, pid, ms, status="done", age_days=0):
    created = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=age_days)
    j = PluginJob(run_id="r-cal", target_id="t1", plugin_id=pid,
                  phase=1, priority=2, estimate_s=12, status=status,
                  created_at=created,
                  result={"status": "ok", "reason": "", "findings": 1,
                          "ms": ms})
    s.add(j)
    s.commit()


def test_calibration_uses_median(session):
    for ms in (4000, 5000, 6000, 90000):  # median 5.5s -> 5
        _seed_job(session, "dns", ms)
    est = _calibrated_estimates(session)
    assert est["dns"] == 5


def test_calibration_needs_three_samples(session):
    _seed_job(session, "tls", 40000)
    _seed_job(session, "tls", 42000)
    est = _calibrated_estimates(session)
    assert "tls" not in est  # falls back to hardcoded table


def test_calibration_ignores_zero_ms(session):
    for ms in (0, 0, 0, 5000, 6000, 7000):
        _seed_job(session, "waf", ms)
    est = _calibrated_estimates(session)
    assert est["waf"] == 6  # only the real executions count


def test_calibration_clamps_outliers(session):
    for _ in range(4):
        _seed_job(session, "backup", 900000)  # 900s -> clamped to 600
    est = _calibrated_estimates(session)
    assert est["backup"] == 600


def test_calibration_ignores_old_jobs(session):
    for _ in range(4):
        _seed_job(session, "crawler", 120000, age_days=30)
    est = _calibrated_estimates(session, days=7)
    assert "crawler" not in est


def test_enqueue_uses_calibrated_estimates(session):
    from app.models import Target as TargetRow
    t = TargetRow(id="t-cal", run_id="r-cal", raw="example.com",
                  type="domain", normalized="example.com")
    session.add(t)
    session.commit()

    class P:
        id = "dns"
        phase = 1

    n = _enqueue_jobs(session, "r-cal", [P()], [t],
                      estimates={"dns": 3})
    assert n == 1
    job = session.query(PluginJob).filter_by(run_id="r-cal").first()
    assert job.estimate_s == 3


# ---------------------------------------------------------------------------
# Scan throughput and first-finding continuation regressions
# ---------------------------------------------------------------------------

def test_enqueue_only_jobs_applicable_to_each_target(session):
    from app.models import Run, Target as TargetRow
    from app.runner import _enqueue_jobs

    run_id = "r-applicable"
    session.add(Run(id=run_id, mode="passive", status="running"))
    d = TargetRow(id="t-domain", run_id=run_id,
                  raw="example.test", type="domain",
                  normalized="example.test")
    u = TargetRow(id="t-url", run_id=run_id,
                  raw="https://example.test/path", type="url",
                  normalized="https://example.test/path")
    session.add_all([d, u])
    session.commit()

    class DomainOnly:
        id = "domain_only"
        phase = 1
        accepts = ["domain"]

    class UrlOnly:
        id = "url_only"
        phase = 1
        accepts = ["url"]

    class Universal:
        id = "universal"
        phase = 1
        accepts = []

    count = _enqueue_jobs(session, run_id,
                          [DomainOnly(), UrlOnly(), Universal()], [d, u])
    assert count == 4  # not six: two impossible jobs never queued
    jobs = session.query(PluginJob).filter_by(run_id=run_id).all()
    assert {(j.target_id, j.plugin_id) for j in jobs} == {
        ("t-domain", "domain_only"), ("t-domain", "universal"),
        ("t-url", "url_only"), ("t-url", "universal"),
    }


def test_first_finding_requests_hunter_pivot_then_batches(monkeypatch):
    from app import runner

    monkeypatch.setattr(runner, "HUNTER_MIN_NEW_FINDINGS", 8)
    run_id = "r-single-finding"
    runner._hunter_marks.pop(run_id, None)
    try:
        assert not runner._hunter_pass_due(run_id, 0)
        assert runner._hunter_pass_due(run_id, 1)
        runner._hunter_marks[run_id] = 1  # first pass handled it
        assert not runner._hunter_pass_due(run_id, 2)
        assert not runner._hunter_pass_due(run_id, 8)
        assert runner._hunter_pass_due(run_id, 9)
    finally:
        runner._hunter_marks.pop(run_id, None)


def test_phase2_waits_for_first_finding_pivot(session, monkeypatch):
    from app import runner
    from app.hunters import engine
    from app.models import Finding as FindingRow, Run, Target as TargetRow

    monkeypatch.setattr(engine, "ENABLED", True)
    run_id = "r-pivot-gate"
    session.add(Run(id=run_id, mode="passive", status="running"))
    session.add(TargetRow(id="t-pivot", run_id=run_id, raw="example.test",
                          type="domain", normalized="example.test"))
    session.add(FindingRow(run_id=run_id, target_id="t-pivot",
                           plugin_id="seed", category="web", key="endpoint",
                           value="/docs", source="test"))
    session.add(PluginJob(run_id=run_id, target_id="t-pivot",
                          plugin_id="phase2_followup", phase=2,
                          priority=2, estimate_s=10, status="queued"))
    session.commit()
    runner._hunter_swept.add(run_id)
    runner._hunter_marks.pop(run_id, None)
    try:
        assert runner._claim_jobs(session, limit=10) == []
        job = session.query(PluginJob).filter_by(
            run_id=run_id, plugin_id="phase2_followup").one()
        assert job.status == "queued"
        runner._hunter_marks[run_id] = 1
        claimed = runner._claim_jobs(session, limit=10)
        assert [j.plugin_id for j in claimed] == ["phase2_followup"]
    finally:
        runner._hunter_swept.discard(run_id)
        runner._hunter_marks.pop(run_id, None)


def test_phase2_expansion_count_cached_once_per_claim_batch(session, monkeypatch):
    from app import runner
    from app.models import Run

    run_id = "r-hunter-cache"
    session.add(Run(id=run_id, mode="passive", status="running"))
    for i in range(12):
        session.add(PluginJob(run_id=run_id, target_id="t",
                              plugin_id=f"followup_{i}", phase=2,
                              priority=2, estimate_s=5, status="queued"))
    session.commit()
    calls = []

    def fake_owed(s, rid):
        calls.append(rid)
        return False

    monkeypatch.setattr(runner, "_hunter_expansion_owed", fake_owed)
    claimed = runner._claim_jobs(session, limit=12)
    assert len(claimed) == 12
    assert calls == [run_id]  # not one COUNT query per plugin
