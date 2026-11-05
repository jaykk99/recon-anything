"""Regression for the run-page connection-lost loop (2026-10-27).

Root cause, in one line: the frontend SSE proxy forwarded ONLY the
retired ?code= value to the backend and never forwarded the GitHub
session cookie. In sign-in mode the backend ignores the code, so every
signed-in stream 401'd while the browser's EventSource auto-retried
forever and the 4s poll kept 401'ing forever too.

These tests pin the backend half of that contract: in sign-in mode a
code-only stream request is a terminal 401 (the client must stop on
it, not retry), and the same request with a session cookie passes
the gate (it reaches the stream handler, which for a missing run
answers 404, not 401). The frontend half (cookie forwarding in the
proxy, managed reconnect with backoff, stop-on-401) is in
frontend/app/live/runs/[id]/stream/route.ts and
frontend/app/run/[id]/page.tsx, verified by the frontend build.
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
from app.models import get_session, init_db, User  # noqa: E402

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


def test_stream_code_only_is_terminal_401_in_signin_mode(client, signin_mode):
    # Header form and query-param form (the old EventSource fallback).
    r = client.get("/api/runs/does-not-exist/stream",
                   headers={"X-Access-Code": CODE})
    assert r.status_code == 401
    r = client.get("/api/runs/does-not-exist/stream",
                   params={"code": CODE})
    assert r.status_code == 401
    # Anonymous, no code at all: also 401, never a silent retry loop.
    r = client.get("/api/runs/does-not-exist/stream")
    assert r.status_code == 401


def test_stream_session_cookie_passes_gate_in_signin_mode(client, signin_mode):
    session = get_session()
    try:
        u = User(github_id=987654, github_login="jaykk99", plan="free")
        session.add(u)
        session.commit()
        uid = u.id
    finally:
        session.close()
    # The gate passes, so the handler runs and reports the run missing
    # (404) instead of the auth failure (401). A real run's stream
    # would stay open here; TestClient would block on it, so the
    # missing-run case is the gate proof, not a full stream read.
    r = client.get("/api/runs/does-not-exist/stream", headers={
        "Cookie": f"{billing.SESSION_COOKIE}="
                  f"{billing.make_session_token(uid)}"})
    assert r.status_code == 404
