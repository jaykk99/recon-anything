"""Tests for the findings playground endpoint.

POST /api/runs/{run_id}/findings/{finding_id}/retest re-runs the one
plugin that produced a finding, against that finding's own target,
and reports unchanged / changed / gone / error.

Network-free: the playground's HTTP client factory is monkeypatched
to the deterministic fixture transport (tests/plugin_fixtures.py), so
the retest exercises the real Ctx + runner._run_plugin code path
against the fixture site.
"""
import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp.name}")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import playground  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Run, Target, get_session, init_db  # noqa: E402
from plugin_fixtures import fixture_client  # noqa: E402

RUN_ID = "pg-test-run"
TARGET_ID = "pg-target-1"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def fixture_http(monkeypatch):
    monkeypatch.setattr("app.net.async_client",
                        lambda **kw: fixture_client())
    monkeypatch.setattr(playground, "COOLDOWN_S", 0.0)
    playground._last_retest.clear()
    return monkeypatch


def _seed(finding_specs):
    """Fresh run + target + findings. Returns list of finding ids."""
    session = get_session()
    try:
        session.query(Finding).filter_by(run_id=RUN_ID).delete()
        session.query(Target).filter_by(id=TARGET_ID).delete()
        session.query(Run).filter_by(id=RUN_ID).delete()
        session.add(Run(id=RUN_ID, mode="passive", status="done",
                        source_type="website", summary={}))
        session.add(Target(id=TARGET_ID, run_id=RUN_ID,
                           raw="https://fixture.test/", type="url",
                           normalized="https://fixture.test/"))
        ids = []
        for spec in finding_specs:
            f = Finding(run_id=RUN_ID, target_id=TARGET_ID,
                        confidence=80, passive=True, **spec)
            session.add(f)
            session.flush()
            ids.append(f.id)
        session.commit()
        return ids
    finally:
        session.close()


def _hsts_finding(value="stale stored value", key="hsts_short_max_age"):
    return {"plugin_id": "hsts", "category": "web", "key": key,
            "value": value, "source": "HSTS analysis",
            "source_url": "https://fixture.test/"}


def test_retest_changed_verdict(client, fixture_http):
    # Same key as the fresh fixture run produces, different stored
    # value -> verdict "changed", with the fresh finding listed.
    (fid,) = _seed([_hsts_finding()])
    r = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["plugin"] == "hsts"  # dispatched to the finding's own plugin
    assert d["target"] == "https://fixture.test/"  # its own target
    assert d["status"] == "ok"
    assert d["verdict"] == "changed"
    assert d["original"]["key"] == "hsts_short_max_age"
    fresh_keys = {f["key"] for f in d["fresh_findings"]}
    assert "hsts_short_max_age" in fresh_keys
    assert d["fresh_count"] == len(d["fresh_findings"]) >= 1
    assert d["duration_ms"] >= 0


def test_retest_gone_verdict(client, fixture_http):
    # Stored key the plugin no longer produces -> "gone".
    (fid,) = _seed([_hsts_finding(key="hsts_key_that_no_longer_exists")])
    r = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest")
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "gone"


def test_retest_unknown_finding_404(client, fixture_http):
    _seed([_hsts_finding()])
    r = client.post(f"/api/runs/{RUN_ID}/findings/999999/retest")
    assert r.status_code == 404


def test_retest_unknown_run_404(client, fixture_http):
    r = client.post("/api/runs/no-such-run/findings/1/retest")
    assert r.status_code == 404


def test_retest_finding_from_other_run_404(client, fixture_http):
    # Target binding: a finding id that exists but belongs to another
    # run must not be re-testable through this run's URL.
    (fid,) = _seed([_hsts_finding()])
    session = get_session()
    try:
        session.add(Run(id="pg-other-run", mode="passive", status="done",
                        source_type="website", summary={}))
        session.commit()
    finally:
        session.close()
    r = client.post(f"/api/runs/pg-other-run/findings/{fid}/retest")
    assert r.status_code == 404


def test_retest_unknown_plugin_422(client, fixture_http):
    (fid,) = _seed([{"plugin_id": "plugin_that_no_longer_exists",
                     "category": "web", "key": "k", "value": "v",
                     "source": "s"}])
    r = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest")
    assert r.status_code == 422


def test_retest_requires_access_code(client, fixture_http, monkeypatch):
    (fid,) = _seed([_hsts_finding()])
    monkeypatch.setattr("app.config.ACCESS_CODE", "test-secret")
    try:
        r = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest")
        assert r.status_code == 401
        r = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest",
                        headers={"X-Access-Code": "test-secret"})
        assert r.status_code == 200, r.text
    finally:
        monkeypatch.undo()


def test_retest_cooldown_429(client, fixture_http, monkeypatch):
    (fid,) = _seed([_hsts_finding()])
    monkeypatch.setattr(playground, "COOLDOWN_S", 3600.0)
    playground._last_retest.clear()
    r1 = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest")
    assert r1.status_code == 200, r1.text
    r2 = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest")
    assert r2.status_code == 429
    assert r2.headers.get("Retry-After")


def test_retest_accepts_gate(client, fixture_http):
    # mobile plugin accepts store targets only; the finding's target is
    # a URL -> the retest reports the same not-applicable skip a scan
    # job would, instead of running the plugin or erroring.
    (fid,) = _seed([{"plugin_id": "mobile", "category": "mobile",
                     "key": "app", "value": "Fixture App",
                     "source": "store listing"}])
    r = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "ok"
    assert "not applicable" in d["reason"]


def test_retest_does_not_persist(client, fixture_http):
    # The playground is read-only: no new findings land in the run.
    (fid,) = _seed([_hsts_finding()])
    before = _count()
    r = client.post(f"/api/runs/{RUN_ID}/findings/{fid}/retest")
    assert r.status_code == 200
    assert _count() == before


def _count():
    session = get_session()
    try:
        return session.query(Finding).filter_by(run_id=RUN_ID).count()
    finally:
        session.close()
