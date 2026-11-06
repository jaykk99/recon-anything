"""Tests for the hosted fail-closed gate (2026-11-05 incident fix).

The live incident: the deployed service lost its GitHub OAuth env
vars (GITHUB_CLIENT_ID/SECRET) while RECON_ACCESS_CODE was also
unset, and resolve_actor treated that as the local-dev "open" state -
every gated route, GET /api/runs included, served real scan data to
anonymous callers. At the noon health sweep the same endpoint had
correctly answered 401 "sign in with GitHub required".

The rule these tests pin:
  - Hosted deploy (RENDER env present) + NO auth configured at all
    -> gated routes answer 401 {"detail": "sign in with GitHub
    required"}; the gate fails CLOSED, never open.
  - The identical unconfigured state WITHOUT the hosted marker stays
    the local-dev open mode (the existing suite and Jay's local
    instance rely on it).
  - Hosted deploy + access code configured keeps the legacy fallback
    behavior byte-for-byte ("bad access code" / owner with the code).

Network-free: temp SQLite DB via FastAPI TestClient; mode is flipped
per-test with monkeypatched env / config, same pattern as
test_signin_mode.py.
"""
import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import config  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Run, get_session, init_db  # noqa: E402

CODE = "the-legacy-access-code"
RUN_ID = "hosted-fail-closed-run"
DETAIL = "sign in with GitHub required"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def seeded():
    session = get_session()
    try:
        session.add(Run(id=RUN_ID, mode="passive", status="done",
                        source_type="website", user_id=None, summary={}))
        session.add(Finding(run_id=RUN_ID, target_id="t",
                            plugin_id="dns", category="infra",
                            key="record", value="secret-value-0",
                            source="test"))
        session.commit()
    finally:
        session.close()
    yield
    session = get_session()
    try:
        session.query(Finding).filter_by(run_id=RUN_ID).delete()
        session.query(Run).filter_by(id=RUN_ID).delete()
        session.commit()
    finally:
        session.close()


@pytest.fixture()
def hosted_unconfigured(monkeypatch):
    """The incident state, on a hosted deploy: no GitHub OAuth env,
    no access code, Render's env marker present."""
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(config, "ACCESS_CODE", "")
    monkeypatch.setenv("RENDER", "true")
    yield


@pytest.fixture()
def local_unconfigured(monkeypatch):
    """The identical unconfigured state, but a local run: no hosted
    marker, so local-dev open mode must be preserved."""
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("RENDER_EXTERNAL_URL", raising=False)
    monkeypatch.setattr(config, "ACCESS_CODE", "")
    yield


@pytest.fixture()
def hosted_fallback(monkeypatch):
    """Hosted deploy, no OAuth, access code configured: the legacy
    fallback must behave exactly as before."""
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(config, "ACCESS_CODE", CODE)
    monkeypatch.setenv("RENDER", "true")
    yield
    monkeypatch.setattr(config, "ACCESS_CODE", "")


# ------------------------------------------------- the incident state

def test_hosted_unconfigured_runs_list_is_401(client, seeded,
                                              hosted_unconfigured):
    r = client.get("/api/runs")
    assert r.status_code == 401
    assert r.json()["detail"] == DETAIL


def test_hosted_unconfigured_run_detail_is_401(client, seeded,
                                               hosted_unconfigured):
    r = client.get(f"/api/runs/{RUN_ID}")
    assert r.status_code == 401
    assert r.json()["detail"] == DETAIL
    assert "secret-value-0" not in r.text


def test_hosted_unconfigured_run_export_is_401(client, seeded,
                                               hosted_unconfigured):
    r = client.get(f"/api/runs/{RUN_ID}/export")
    assert r.status_code == 401
    assert r.json()["detail"] == DETAIL


def test_hosted_unconfigured_run_vulns_is_401(client, seeded,
                                              hosted_unconfigured):
    r = client.get(f"/api/runs/{RUN_ID}/vulns")
    assert r.status_code == 401
    assert r.json()["detail"] == DETAIL


def test_hosted_unconfigured_keys_are_401(client, hosted_unconfigured):
    r = client.get("/api/keys")
    assert r.status_code == 401
    assert r.json()["detail"] == DETAIL


def test_hosted_unconfigured_health_stays_public(client,
                                                 hosted_unconfigured):
    r = client.get("/api/health")
    assert r.status_code == 200


# ------------------------------------------------------- control cases

def test_local_unconfigured_stays_open(client, seeded,
                                       local_unconfigured):
    """Local dev with nothing configured is still the open mode the
    rest of the suite (and Jay's local instance) runs in."""
    r = client.get("/api/runs")
    assert r.status_code == 200
    assert any(run["id"] == RUN_ID for run in r.json()["runs"])


def test_hosted_fallback_wrong_code_is_401_bad_code(client,
                                                    hosted_fallback):
    r = client.get("/api/runs")
    assert r.status_code == 401
    assert r.json()["detail"] == "bad access code"


def test_hosted_fallback_right_code_is_owner(client, seeded,
                                             hosted_fallback):
    r = client.get("/api/runs", headers={"X-Access-Code": CODE})
    assert r.status_code == 200
    assert any(run["id"] == RUN_ID for run in r.json()["runs"])
