"""Tests for the access-code retirement (Jay's order, 2026-10-23):
"Get GitHub auth for ReconAnything and remove the access code."

The flip is configuration-driven (billing.signin_mode): when
GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET are set, the app runs in
SIGN-IN MODE - the access code is not accepted anywhere (header,
query param, /api/me identity) and a GitHub session is the only
door. When they are unset, FALLBACK MODE keeps the legacy
access-code behavior byte-for-byte, so the app is never ungated
mid-transition.

Network-free: temp SQLite DB via FastAPI TestClient; the mode is
flipped per-test with monkeypatched env / config.
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
from app.models import (Finding, FindingReveal, Order, Run, User,  # noqa: E402
                        get_session, init_db)

CODE = "the-legacy-access-code"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def signin_mode(monkeypatch):
    """Flip the app into sign-in mode: GitHub OAuth configured AND a
    legacy access code still present in config (the exact transition
    state: the code must stop working the moment the env vars land)."""
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setattr(config, "ACCESS_CODE", CODE)
    yield
    monkeypatch.setattr(config, "ACCESS_CODE", "")


@pytest.fixture()
def fallback_mode(monkeypatch):
    """Legacy fallback: no GitHub OAuth, access code configured."""
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(config, "ACCESS_CODE", CODE)
    yield
    monkeypatch.setattr(config, "ACCESS_CODE", "")


_counter = {"n": 5000}


def _mk_user(login, plan="free"):
    _counter["n"] += 1
    session = get_session()
    try:
        u = User(github_id=_counter["n"], github_login=login, plan=plan)
        session.add(u)
        session.commit()
        uid = u.id
    finally:
        session.close()
    return uid


def _cookie(uid):
    return {"Cookie": f"{billing.SESSION_COOKIE}="
                      f"{billing.make_session_token(uid)}"}


def _mk_run(run_id, user_id=None, n_findings=2):
    session = get_session()
    try:
        session.add(Run(id=run_id, mode="passive", status="done",
                        source_type="website", user_id=user_id, summary={}))
        for j in range(n_findings):
            session.add(Finding(run_id=run_id, target_id="t",
                                plugin_id="dns", category="infra",
                                key="record", value=f"secret-value-{j}",
                                source="test"))
        session.commit()
    finally:
        session.close()


def _cleanup():
    session = get_session()
    try:
        session.query(FindingReveal).delete()
        session.query(Order).delete()
        session.query(Finding).delete()
        session.query(Run).delete()
        session.query(User).delete()
        session.commit()
    finally:
        session.close()


# ------------------------------------------------------- mode detection

def test_signin_mode_detection_flips_on_env(monkeypatch):
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    assert billing.signin_mode() is False
    monkeypatch.setenv("GITHUB_CLIENT_ID", "x")
    assert billing.signin_mode() is False  # both vars required
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "y")
    assert billing.signin_mode() is True
    monkeypatch.delenv("GITHUB_CLIENT_ID")
    assert billing.signin_mode() is False


# ------------------------------------------------- sign-in mode: code

def test_signin_mode_rejects_access_code_everywhere(client, signin_mode):
    _cleanup()
    # Header form.
    r = client.get("/api/plugins", headers={"X-Access-Code": CODE})
    assert r.status_code == 401
    assert "GitHub" in r.json()["detail"]
    # Query-param form (the EventSource fallback).
    r = client.get("/api/plugins", params={"code": CODE})
    assert r.status_code == 401
    # Run list and run creation with the code: still 401.
    r = client.get("/api/runs", headers={"X-Access-Code": CODE})
    assert r.status_code == 401
    r = client.post("/api/runs",
                    json={"targets": "example.com", "mode": "passive"},
                    headers={"X-Access-Code": CODE})
    assert r.status_code == 401
    # The code no longer buys the owner identity on /api/me either.
    me = client.get("/api/me", headers={"X-Access-Code": CODE}).json()
    assert me["is_owner"] is False
    assert me["signed_in"] is False
    assert me["auth_mode"] == "github"


def test_signin_mode_anonymous_is_locked_out(client, signin_mode):
    _cleanup()
    r = client.post("/api/runs",
                    json={"targets": "example.com", "mode": "passive"})
    assert r.status_code == 401
    assert "GitHub" in r.json()["detail"]
    assert client.get("/api/plugins").status_code == 401
    assert client.get("/api/runs").status_code == 401
    # Public surfaces stay public.
    assert client.get("/pricing").status_code == 200
    assert client.get("/api/plans").status_code == 200
    me = client.get("/api/me").json()
    assert me["auth_mode"] == "github"
    assert me["signed_in"] is False


# ------------------------------------------- sign-in mode: signed-in

def test_signin_mode_user_flow_and_plan_gates(client, signin_mode):
    _cleanup()
    uid = _mk_user("signin-free")
    other = _mk_user("signin-other")
    _mk_run("signin-run-mine", user_id=uid)
    _mk_run("signin-run-theirs", user_id=other)

    h = _cookie(uid)
    assert client.get("/api/plugins", headers=h).status_code == 200
    # Run list shows only the user's own runs.
    runs = client.get("/api/runs", headers=h).json()["runs"]
    assert [r["id"] for r in runs] == ["signin-run-mine"]
    # Own run detail: free-tier reveal cap applies (1 of 2 unlocked).
    body = client.get("/api/runs/signin-run-mine", headers=h).json()
    assert body["access"]["full_findings"] is False
    assert body["access"]["locked_count"] == 1
    # Another user's run is invisible.
    r = client.get("/api/runs/signin-run-theirs", headers=h)
    assert r.status_code == 404
    # Export of the own run works and keeps the reveal lock.
    r = client.get("/api/runs/signin-run-mine/export", headers=h)
    assert r.status_code == 200
    vals = [f["value"] for f in r.json()["findings"]]
    assert billing.LOCKED_VALUE in vals
    # Plan gating on creation: crypto pack is Pro-only for free users.
    r = client.post("/api/runs",
                    json={"targets": "example.com", "mode": "passive",
                          "plugins": ["cp_wallet_exposure"]},
                    headers=h)
    assert r.status_code == 403
    # ...and the daily scan cap proves the actor resolved as this user
    # (3 runs already today -> the 4th is refused with 429, not 401).
    for i in range(2):
        _mk_run(f"signin-scan-{i}", user_id=uid, n_findings=0)
    r = client.post("/api/runs",
                    json={"targets": "example.com", "mode": "passive"},
                    headers=h)
    assert r.status_code == 429


def test_signin_mode_owner_session_full_access(client, signin_mode):
    _cleanup()
    owner = _mk_user("jaykk99")
    uid = _mk_user("signin-customer")
    _mk_run("signin-owner-view", user_id=uid)

    h = _cookie(owner)
    me = client.get("/api/me", headers=h).json()
    assert me["auth_mode"] == "github"
    assert me["is_owner"] is True
    assert me["show_payment_ui"] is False
    assert "checkout_enabled" not in me
    # Owner sees every run and opens a customer's run in full.
    runs = client.get("/api/runs", headers=h).json()["runs"]
    assert [r["id"] for r in runs] == ["signin-owner-view"]
    body = client.get("/api/runs/signin-owner-view", headers=h).json()
    assert body["access"] is None
    assert all(f["value"].startswith("secret-value-")
               for f in body["findings"])
    # Owner-only admin surface opens for the owner session.
    assert client.get("/api/admin/orders", headers=h).status_code == 200


# ------------------------------------------- fallback mode: unchanged

def test_fallback_mode_access_code_unchanged(client, fallback_mode):
    _cleanup()
    # The code works exactly as before...
    r = client.get("/api/plugins", headers={"X-Access-Code": CODE})
    assert r.status_code == 200
    # ...anonymity and wrong codes still get the legacy 401.
    r = client.get("/api/plugins")
    assert r.status_code == 401
    assert r.json()["detail"] == "bad access code"
    r = client.get("/api/plugins", headers={"X-Access-Code": "wrong"})
    assert r.status_code == 401
    # The code session is still the owner on /api/me.
    me = client.get("/api/me", headers={"X-Access-Code": CODE}).json()
    assert me["auth_mode"] == "access_code"
    assert me["is_owner"] is True
    assert me["show_payment_ui"] is False
    # A signed-in customer session also still works in fallback mode.
    uid = _mk_user("fallback-user")
    _mk_run("fallback-run", user_id=uid)
    r = client.get("/api/runs/fallback-run", headers=_cookie(uid))
    assert r.status_code == 200


def test_fallback_mode_open_when_no_code_configured(client, monkeypatch):
    _cleanup()
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(config, "ACCESS_CODE", "")
    # Local-dev open mode is part of the legacy behavior and stays.
    assert client.get("/api/plugins").status_code == 200
    me = client.get("/api/me").json()
    assert me["auth_mode"] == "access_code"


# -------------------------------- hidden nav, server side (2026-10-23)

def test_signin_mode_every_tab_api_anonymous_401(client, signin_mode):
    """The hidden-tabs rule, server side: the frontend hides the nav
    and every protected page from signed-out visitors in sign-in
    mode (middleware + server-rendered shell). That cosmetics layer
    is only honest if the APIs behind those tabs are equally closed
    - no data behind any tab may leak to an anonymous caller."""
    _cleanup()
    _mk_run("signin-hidden-run")
    for path in ("/api/keys", "/api/settings", "/api/hunters",
                 "/api/hunters/knowledge", "/api/hunters/resources",
                 "/api/runs/signin-hidden-run",
                 "/api/runs/signin-hidden-run/export",
                 "/api/orders", "/api/admin/orders",
                 "/api/auth/attestation"):
        r = client.get(path)
        assert r.status_code == 401, path
        # ...and the retired access code opens none of them either.
        r = client.get(path, headers={"X-Access-Code": CODE})
        assert r.status_code == 401, path


def test_fallback_mode_tab_apis_still_open_with_code(client, fallback_mode):
    """Fallback mode is untouched by the hidden-tabs work: the same
    tab APIs keep answering to the legacy access code."""
    _cleanup()
    h = {"X-Access-Code": CODE}
    assert client.get("/api/keys", headers=h).status_code == 200
    assert client.get("/api/settings", headers=h).status_code == 200
    assert client.get("/api/hunters", headers=h).status_code == 200
    assert client.get("/api/auth/attestation", headers=h).status_code == 200
