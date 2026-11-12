"""Tests for GET /healthz: zero-dependency liveness.

/healthz must return 200 instantly without touching the database,
the scanner queue, the plugin registry, or disk storage. It is
deliberately separate from GET /api/health, whose registry
self-report calls discover() (imports every plugin module from
disk, cached after first call).

Network-free: temp SQLite DB via FastAPI TestClient, same pattern
as test_hosted_fail_closed.py. No plugin-count pin is hardcoded
here; the /api/health cross-check compares against the live
discover() count on this branch.
"""
import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.models import init_db  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def test_healthz_returns_200_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "service": "recon-anything"}


def test_healthz_is_zero_dependency(client, monkeypatch):
    """Registry, DB and queue entry points explode if touched;
    /healthz must still answer 200."""
    import app.main as main_mod
    import app.plugins.registry as registry_mod
    import app.runner as runner_mod

    def _boom(*args, **kwargs):
        raise AssertionError("healthz touched a heavy dependency")

    monkeypatch.setattr(registry_mod, "health", _boom)
    monkeypatch.setattr(registry_mod, "discover", _boom)
    monkeypatch.setattr(main_mod, "get_session", _boom)
    monkeypatch.setattr(main_mod, "check_db", _boom)
    monkeypatch.setattr(runner_mod, "start_queue_worker", _boom)

    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_healthz_stays_public_when_hosted_unconfigured(client, monkeypatch):
    """Liveness must not be gated: even in the hosted fail-closed
    state (RENDER set, no auth configured) /healthz answers 200."""
    from app import config
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(config, "ACCESS_CODE", "")
    monkeypatch.setenv("RENDER", "true")
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "service": "recon-anything"}


def test_api_health_still_reports_live_registry_count(client):
    """/api/health is unchanged: its plugin count matches the real
    discover() count on this branch (no hardcoded pin)."""
    from app.plugins.registry import discover
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["service"] == "recon-anything"
    assert body["plugins"] == len(discover())
    assert body["plugins_healthy"] is True
