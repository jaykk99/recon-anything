"""Tests for scan dispatch ordering (fastest-first within tier).

Jay's priority policy is unchanged: HIGH tier beats MEDIUM beats LOW,
phase 1 beats phase 2. Within the same (priority, phase) the claim
query now orders by the plugin's time estimate so quick wins stream
first. Rows enqueued before estimate_s existed (NULL) fall back to
the default estimate.
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
                        _queued_jobs_query)


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
    _job(session, "slow", priority=2, phase=1, estimate=60)
    _job(session, "fast", priority=2, phase=1, estimate=5)
    _job(session, "mid", priority=2, phase=1, estimate=20)
    order = [j.plugin_id for j in _queued_jobs_query(session).all()]
    assert order == ["fast", "mid", "slow"]


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
               "typosquat", "tls_config", "caa_audit"]
    missing = [pid for pid in new_ids if pid not in PLUGIN_TIME_ESTIMATES]
    assert not missing, f"plugins missing time estimates: {missing}"
