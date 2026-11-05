"""Regression for GHSA draft: broken access control on per-run endpoints.

Before the fix, a signed-in free customer could read another
customer's run through /graph, /apimap, /agent-activity, /vulns,
/diff and /fetch, probe/modify it through /subdomains/verify and
/probe/port, and manage the global API-key vault, schedules and
breach-watch list. api_run_detail and api_export already returned
404 for other customers' runs; every other per-run surface must do
the same, and global settings must be owner-only.

Network-free: temp SQLite DB via FastAPI TestClient, sign-in mode
flipped per-test. No live service, no third-party target.
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

from app import billing, config  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Run, User, get_session, init_db  # noqa: E402

CODE = "the-legacy-access-code"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def signin_mode(monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setattr(config, "ACCESS_CODE", CODE)
    yield
    monkeypatch.setattr(config, "ACCESS_CODE", "")


_counter = {"n": 7000}


def _mk_user(login):
    _counter["n"] += 1
    session = get_session()
    try:
        u = User(github_id=_counter["n"], github_login=login, plan="free")
        session.add(u)
        session.commit()
        return u.id
    finally:
        session.close()


def _cookie(uid):
    return {"Cookie": f"{billing.SESSION_COOKIE}="
                      f"{billing.make_session_token(uid)}"}


def _mk_run(run_id, user_id):
    session = get_session()
    try:
        session.add(Run(id=run_id, mode="passive", status="done",
                        source_type="website", user_id=user_id, summary={}))
        session.add(Finding(run_id=run_id, target_id="t",
                            plugin_id="dns", category="infra",
                            key="endpoint",
                            value="https://victim.example/admin",
                            source="test"))
        session.add(Finding(run_id=run_id, target_id="t",
                            plugin_id="dns", category="infra",
                            key="subdomain", value="sub.victim.example",
                            source="test"))
        session.commit()
    finally:
        session.close()


def _cleanup():
    session = get_session()
    try:
        session.query(Finding).delete()
        session.query(Run).delete()
        session.query(User).delete()
        session.commit()
    finally:
        session.close()


def test_other_customers_run_is_invisible_everywhere(client, signin_mode):
    _cleanup()
    victim = _mk_user("xca-victim")
    attacker = _mk_user("xca-attacker")
    _mk_run("xca-victim-run", victim)
    ah = _cookie(attacker)
    # Control: detail already returned 404 before the fix.
    assert client.get("/api/runs/xca-victim-run", headers=ah).status_code == 404
    # Read surfaces that returned 200 before the fix.
    for path in ("/api/runs/xca-victim-run/graph",
                 "/api/runs/xca-victim-run/apimap",
                 "/api/runs/xca-victim-run/agent-activity",
                 "/api/runs/xca-victim-run/vulns",
                 "/api/runs/xca-victim-run/fetch?url=https://victim.example/admin",
                 "/api/diff?a=xca-victim-run&b=xca-victim-run"):
        r = client.get(path, headers=ah)
        assert r.status_code == 404, (path, r.status_code, r.text[:200])
    # Write/probe surfaces that returned 200/ran before the fix.
    assert client.post("/api/runs/xca-victim-run/vulns/dry-run",
                       json={"candidate_id": "sqli"}, headers=ah).status_code == 404
    assert client.post("/api/runs/xca-victim-run/findings/1/retest",
                       headers=ah).status_code == 404
    assert client.post("/api/runs/xca-victim-run/subdomains/verify",
                       json={}, headers=ah).status_code == 404
    assert client.get("/api/runs/xca-victim-run/probe/port",
                      params={"host": "sub.victim.example", "port": 443},
                      headers=ah).status_code == 404
    # Global settings: attacker gets 403, not a read or a write.
    for path in ("/api/keys", "/api/schedules", "/api/breachwatch"):
        assert client.get(path, headers=ah).status_code == 403, path
    assert client.post("/api/keys", json={"name": "shodan", "secret": "x"},
                       headers=ah).status_code == 403
    assert client.delete("/api/keys/shodan", headers=ah).status_code == 403
    assert client.post("/api/schedules",
                       json={"target_raw": "example.com", "cron": "* * * * *"},
                       headers=ah).status_code == 403


def test_owner_and_own_run_still_work(client, signin_mode):
    _cleanup()
    owner = _mk_user("jaykk99")
    victim = _mk_user("xca-victim2")
    own = _mk_user("xca-owner2")
    _mk_run("xca-victim-run2", victim)
    _mk_run("xca-own-run2", own)
    # Owner sees the victim run on the previously-open surfaces.
    oh = _cookie(owner)
    for path in ("/api/runs/xca-victim-run2/graph",
                 "/api/runs/xca-victim-run2/apimap",
                 "/api/runs/xca-victim-run2/agent-activity",
                 "/api/runs/xca-victim-run2/vulns",
                 "/api/keys", "/api/schedules", "/api/breachwatch"):
        assert client.get(path, headers=oh).status_code == 200, path
    # A customer still sees their own run on those surfaces.
    mh = _cookie(own)
    for path in ("/api/runs/xca-own-run2/graph",
                 "/api/runs/xca-own-run2/apimap",
                 "/api/runs/xca-own-run2/vulns"):
        assert client.get(path, headers=mh).status_code == 200, path
