"""Authenticated Mode tests (app/authscan.py + main.py + runner.py).

Covers Jay's design:
- ONE-TIME per-account attestation: the warning is accepted once,
  stored server-side; authenticated runs are rejected for identities
  with no stored acceptance; after acceptance, runs need no repeated
  warning and carry the acceptance reference as their audit stamp.
- Plan gate: Authenticated Mode is Pro/Agency (+owner) only; Free and
  Starter are rejected server-side.
- Credentials: encrypted at rest, scoped to the run's seed target
  hosts only (hook test: target host gets them, every other host -
  including subdomains and hunter-style hosts - does not), wiped when
  the run finishes, and present NOWHERE in API responses, findings or
  exports.

Network-free: temp SQLite DB (same rebinding pattern as
test_modes.py), launch_run monkeypatched out, httpx MockTransport
for the header-injection proof.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

os.environ.setdefault("RECON_AUTH_SECRET", "test-auth-secret-0123456789")

from app import authscan, billing, runner  # noqa: E402
from app.plugins.base import Ctx  # noqa: E402

SECRET_COOKIE = "session=TOPSECRET-COOKIE-VALUE-9f3"

_counter = {"n": 5000}
_test_session_factory = None


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    global _test_session_factory
    tmp = tmp_path_factory.mktemp("recon_authscan")
    import app.models as models
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    eng = create_engine(f"sqlite:///{tmp}/t.db")
    models.Base.metadata.create_all(bind=eng)
    # Save the process-wide bindings and restore them at teardown:
    # later modules (e.g. test_hunters) rely on the default engine.
    orig_session_local = models.SessionLocal
    models.SessionLocal = sessionmaker(bind=eng, autoflush=False,
                                       autocommit=False)
    _test_session_factory = models.SessionLocal
    import app.main as main_mod
    orig_main_get_session = main_mod.get_session
    orig_launch_run = main_mod.launch_run
    orig_wake_worker = main_mod._wake_worker
    main_mod.get_session = models.SessionLocal

    async def _noop(*a, **k):
        return None
    main_mod.launch_run = _noop
    main_mod._wake_worker = lambda: None
    c = TestClient(main_mod.app)
    c.put("/api/settings/mode", json={"mode": "live"})
    yield c
    models.SessionLocal = orig_session_local
    main_mod.get_session = orig_main_get_session
    main_mod.launch_run = orig_launch_run
    main_mod._wake_worker = orig_wake_worker
    _test_session_factory = None


@pytest.fixture(autouse=True)
def _clean():
    # Only the API tests (which use the module client fixture) touch
    # the DB; pure unit tests run before the rebound factory exists.
    if _test_session_factory is not None:
        from app.models import (AuthAcceptance, Finding, Run, RunAuth,
                                User)
        session = _test_session_factory()
        try:
            for m in (RunAuth, AuthAcceptance, Finding, Run, User):
                session.query(m).delete()
            session.commit()
        finally:
            session.close()
    yield


def _mk_user(login, plan="free"):
    from app.models import User, get_session
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


def _accept(client, headers=None):
    r = client.post("/api/auth/attestation", json={"confirmed": True},
                    headers=headers or {})
    assert r.status_code == 200, r.text
    return r.json()


AUTH_BODY = {"type": "cookie", "cookie": SECRET_COOKIE}


# ------------------------------------------------------- config validation

def test_validate_cookie_bearer_basic_headers():
    cfg, err = authscan.validate_auth_config(
        {"type": "cookie", "cookie": "a=1"})
    assert err == "" and cfg == {"type": "cookie", "cookie": "a=1"}
    cfg, err = authscan.validate_auth_config(
        {"type": "bearer", "token": "tok"})
    assert err == "" and cfg["token"] == "tok"
    cfg, err = authscan.validate_auth_config(
        {"type": "basic", "username": "u", "password": "p"})
    assert err == "" and cfg["username"] == "u"
    cfg, err = authscan.validate_auth_config(
        {"type": "headers",
         "headers": [{"name": "X-Api-Key", "value": "k"}]})
    assert err == "" and cfg["headers"][0]["name"] == "X-Api-Key"


def test_validate_rejects_bad_configs():
    assert authscan.validate_auth_config({"type": "cookie"})[0] is None
    assert authscan.validate_auth_config({"type": "nope"})[0] is None
    assert authscan.validate_auth_config(
        {"type": "basic", "username": "u"})[0] is None
    too_many = {"type": "headers",
                "headers": [{"name": f"H{i}", "value": "v"}
                            for i in range(6)]}
    assert "at most" in authscan.validate_auth_config(too_many)[1]
    forbidden = {"type": "headers",
                 "headers": [{"name": "Host", "value": "evil"}]}
    assert authscan.validate_auth_config(forbidden)[0] is None
    dup = {"type": "headers", "headers": [{"name": "X-A", "value": "1"},
                                          {"name": "x-a", "value": "2"}]}
    assert authscan.validate_auth_config(dup)[0] is None


def test_build_headers():
    assert authscan.build_headers(
        {"type": "cookie", "cookie": "a=1"}) == {"Cookie": "a=1"}
    assert authscan.build_headers(
        {"type": "bearer", "token": "t"}) == {"Authorization": "Bearer t"}
    basic = authscan.build_headers(
        {"type": "basic", "username": "u", "password": "p"})
    assert basic["Authorization"].startswith("Basic ")
    import base64
    assert base64.b64decode(basic["Authorization"][6:]).decode() == "u:p"


# ------------------------------------------------------------- encryption

def test_secret_encrypted_at_rest_and_roundtrips():
    cfg = {"type": "cookie", "cookie": SECRET_COOKIE}
    stored = authscan.encrypt_secret(cfg)
    assert SECRET_COOKIE not in stored
    assert authscan.decrypt_secret(stored) == cfg


# ------------------------------------------------- one-time attestation

def test_one_time_acceptance_flow(client):
    r = client.get("/api/auth/attestation")
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] is False
    assert "written permission" in body["warning"]

    r = client.post("/api/auth/attestation", json={"confirmed": False})
    assert r.status_code == 400

    body = _accept(client)
    assert body["accepted"] is True
    assert body["text_version"] == authscan.ACCEPTANCE_TEXT_VERSION
    assert body["identity"] == "owner"

    r = client.get("/api/auth/attestation")
    assert r.json()["accepted"] is True

    # stored server-side with the version stamp
    from app.models import AuthAcceptance, get_session
    session = get_session()
    try:
        row = session.query(AuthAcceptance).filter_by(
            identity_key="owner").first()
        assert row is not None and row.accepted_at is not None
    finally:
        session.close()


def test_acceptance_version_bump_invalidates(client):
    _accept(client)
    from app.models import AuthAcceptance, get_session
    session = get_session()
    try:
        row = session.query(AuthAcceptance).filter_by(
            identity_key="owner").first()
        row.text_version = "v0-old"
        session.commit()
        assert authscan.get_acceptance(session, "owner") is None
    finally:
        session.close()


# ------------------------------------------------------ run creation gate

def test_auth_run_rejected_without_acceptance(client):
    # owner identity, no acceptance stored -> 403, acceptance demanded
    r = client.post("/api/runs", json={
        "targets": "example.com", "mode": "passive", "auth": AUTH_BODY})
    assert r.status_code == 403
    assert "acceptance" in r.json()["detail"].lower()


def test_auth_run_free_and_starter_rejected(client):
    for plan in ("free", "starter"):
        uid = _mk_user(f"{plan}user", plan=plan)
        _accept(client, headers=_cookie(uid))
        r = client.post("/api/runs", json={
            "targets": "example.com", "mode": "passive",
            "auth": AUTH_BODY}, headers=_cookie(uid))
        assert r.status_code == 403, (plan, r.text)
        assert "Pro" in r.json()["detail"]


def test_auth_run_pro_user_without_acceptance_rejected(client):
    uid = _mk_user("prouser", plan="pro")
    r = client.post("/api/runs", json={
        "targets": "example.com", "mode": "passive",
        "auth": AUTH_BODY}, headers=_cookie(uid))
    assert r.status_code == 403
    assert "acceptance" in r.json()["detail"].lower()


def test_auth_run_after_acceptance_stamped_and_secret_free(client):
    uid = _mk_user("prook", plan="pro")
    _accept(client, headers=_cookie(uid))
    r = client.post("/api/runs", json={
        "targets": "example.com", "mode": "passive",
        "auth": AUTH_BODY}, headers=_cookie(uid))
    assert r.status_code == 200, r.text
    run_id = r.json()["run_id"]

    # RunAuth row: encrypted secret, acceptance reference, host scope
    from app.models import RunAuth, get_session
    session = get_session()
    try:
        ra = session.query(RunAuth).filter_by(run_id=run_id).first()
        assert ra is not None
        assert ra.auth_type == "cookie"
        assert ra.secret_enc and SECRET_COOKIE not in ra.secret_enc
        assert ra.acceptance_id is not None
        assert ra.attested_by == "prook"
        assert ra.target_hosts == ["example.com"]
        assert authscan.decrypt_secret(ra.secret_enc)["cookie"] == \
            SECRET_COOKIE
    finally:
        session.close()

    # detail: badge + presence label + stamp; secret NOWHERE in it
    r = client.get(f"/api/runs/{run_id}", headers=_cookie(uid))
    assert r.status_code == 200
    assert SECRET_COOKIE not in r.text
    body = r.json()
    assert body["run"]["authenticated"] is True
    assert body["auth"]["label"] == "auth: cookie (set)"
    assert body["auth"]["attestation"]["attested_by"] == "prook"
    assert body["auth"]["attestation"]["acceptance_id"] is not None
    assert "authorized testing" in body["auth"]["disclaimer"]

    # list carries the badge too
    r = client.get("/api/runs", headers=_cookie(uid))
    row = [x for x in r.json()["runs"] if x["id"] == run_id][0]
    assert row["authenticated"] is True


def test_auth_run_bad_config_rejected(client):
    _accept(client)
    r = client.post("/api/runs", json={
        "targets": "example.com", "mode": "passive",
        "auth": {"type": "cookie"}})
    assert r.status_code == 400


def test_plain_run_has_no_auth_block(client):
    r = client.post("/api/runs", json={"targets": "example.com",
                                       "mode": "passive"})
    assert r.status_code == 200, r.text
    run_id = r.json()["run_id"]
    body = client.get(f"/api/runs/{run_id}").json()
    assert body["run"]["authenticated"] is False
    assert body["auth"] is None


# --------------------------------------------------- findings marker/leak

def test_findings_carry_marker_and_never_the_secret(client):
    _accept(client)
    r = client.post("/api/runs", json={
        "targets": "example.com", "mode": "passive", "auth": AUTH_BODY})
    run_id = r.json()["run_id"]
    from app.models import Finding, get_session
    from app.reporting import findings_dump
    session = get_session()
    try:
        session.add(Finding(run_id=run_id, target_id="t",
                            plugin_id="headers", category="web",
                            key="cookie_flags", value="ok",
                            source="test"))
        session.commit()
        rows = findings_dump(session, run_id)
    finally:
        session.close()
    assert rows and all(row["authenticated"] is True for row in rows)
    assert SECRET_COOKIE not in json.dumps(rows)


# ------------------------------------------- host-scoped header injection

class _FakeRunAuth:
    def __init__(self, cfg, hosts):
        self.secret_enc = authscan.encrypt_secret(cfg)
        self.target_hosts = hosts
        self.wiped_at = None


def _ctx_with_auth(cfg, hosts):
    ctx = Ctx(run_id="hook-test", mode="active", http=None, cache=None,
              keys={})
    ra = _FakeRunAuth(cfg, hosts)
    assert runner._attach_run_auth(ctx, ra) is True
    return ctx


def test_hook_injects_only_on_target_host():
    ctx = _ctx_with_auth({"type": "cookie", "cookie": SECRET_COOKIE},
                         ["example.com"])
    hooks = ctx.http.event_hooks["request"]
    assert hooks, "auth client must carry the request hook"

    async def _probe(url):
        req = httpx.Request("GET", url)
        for hook in hooks:
            await hook(req)
        return req

    on_target = asyncio.run(_probe("https://example.com/behind/login"))
    assert on_target.headers.get("cookie") == SECRET_COOKIE

    # other hosts: no credentials - including subdomains (hunter-style
    # expansions) and third-party APIs
    for url in ("https://sub.example.com/x",
                "https://api.thirdparty.dev/v1",
                "https://example.com.evil.test/"):
        req = asyncio.run(_probe(url))
        assert "cookie" not in req.headers, url


def test_hook_end_to_end_with_mock_transport():
    ctx = _ctx_with_auth({"type": "bearer", "token": "tok-123"},
                         ["example.com"])
    seen = {}

    def handler(request):
        seen[str(request.url)] = dict(request.headers)
        return httpx.Response(200, json={"ok": True})

    async def _go():
        async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler),
                event_hooks=ctx.http.event_hooks,
                follow_redirects=True) as c:
            await c.get("https://example.com/private")
            await c.get("https://cdn.other.net/asset")

    asyncio.run(_go())
    assert seen["https://example.com/private"]["authorization"] == \
        "Bearer tok-123"
    assert "authorization" not in seen["https://cdn.other.net/asset"]


# ------------------------------------------------------------------- wipe

def test_wipe_on_finish_erases_secret_keeps_stamp(client):
    _accept(client)
    r = client.post("/api/runs", json={
        "targets": "example.com", "mode": "passive", "auth": AUTH_BODY})
    run_id = r.json()["run_id"]
    from app.models import RunAuth, get_session
    session = get_session()
    try:
        runner._wipe_run_auth(session, run_id)
        ra = session.query(RunAuth).filter_by(run_id=run_id).first()
        assert ra is not None  # the audit stamp stays
        assert ra.secret_enc is None
        assert ra.wiped_at is not None
        assert ra.acceptance_id is not None
        assert ra.attested_by == "owner"
    finally:
        session.close()
