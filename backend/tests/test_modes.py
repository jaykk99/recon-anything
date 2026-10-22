"""Sandbox / LIVE mode tests.

Covers Jay's mode-setting requirements: sandbox is the default, switching
to live is an explicit audited settings change, sandbox rejects non-owned /
non-lab targets, and run records carry the mode they were created under.
The mode changes scope + data handling only - these tests assert the gate
behavior, nothing about capabilities (both modes run the same plugins).
"""
import pytest
from fastapi.testclient import TestClient

from app import modes
from app.classifier import classify_batch
from app.models import AuditLog, get_session


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("recon_modes")
    import app.models as models
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    eng = create_engine(f"sqlite:///{tmp}/t.db")
    models.Base.metadata.create_all(bind=eng)
    models.SessionLocal = sessionmaker(bind=eng, autoflush=False,
                                       autocommit=False)
    # main captured get_session at import time - point it at the test DB too.
    import app.main as main_mod
    main_mod.get_session = models.SessionLocal
    return TestClient(main_mod.app)


# -- unit: the sandbox scope rule -------------------------------------------

def test_sandbox_host_rule():
    owned = modes.DEFAULT_OWNED_ASSETS
    assert modes.sandbox_host_allowed("localhost", owned)[0]
    assert modes.sandbox_host_allowed("127.0.0.1", owned)[0]
    assert modes.sandbox_host_allowed("192.168.1.20", owned)[0]
    assert modes.sandbox_host_allowed("printer.lan", owned)[0]
    assert modes.sandbox_host_allowed("victim.test", owned)[0]
    assert modes.sandbox_host_allowed("guttergenie.pages.dev", owned)[0]
    assert modes.sandbox_host_allowed("api.guttergenie.pages.dev", owned)[0]
    assert not modes.sandbox_host_allowed("example.com", owned)[0]
    assert not modes.sandbox_host_allowed("8.8.8.8", owned)[0]
    assert not modes.sandbox_host_allowed("notguttergenie.pages.dev", owned)[0]
    assert not modes.sandbox_host_allowed(None, owned)[0]


def test_sandbox_target_check_rejects_username_and_public():
    owned = modes.DEFAULT_OWNED_ASSETS
    rejected = modes.check_sandbox_targets(
        classify_batch("example.com\nsomeuser\nhttp://127.0.0.1:8080/x"),
        owned)
    raws = {r["raw"] for r in rejected}
    assert "example.com" in raws
    assert "someuser" in raws  # username lookups are third-party, not sandbox
    assert "http://127.0.0.1:8080/x" not in raws


# -- API: default, switch, audit, enforcement --------------------------------

def test_mode_defaults_to_sandbox(client):
    r = client.get("/api/settings")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "sandbox"
    assert "guttergenie.pages.dev" in body["owned_assets"]


def test_mode_switch_persists_and_is_audited(client):
    r = client.put("/api/settings/mode", json={"mode": "live"})
    assert r.status_code == 200
    assert r.json()["audit"] == {"from": "sandbox", "to": "live"}
    assert client.get("/api/settings").json()["mode"] == "live"
    # audit trail: the switch + a settings read both visible via the API
    audit = client.get("/api/settings").json()["audit"]
    switches = [a for a in audit if a["action"] == "mode_switch"]
    assert switches and switches[0]["detail"]["to"] == "live"
    # and in the DB itself
    s = get_session()
    try:
        rows = s.query(AuditLog).filter_by(action="mode_switch").all()
        assert any((row.detail or {}).get("to") == "live" for row in rows)
    finally:
        s.close()
    # switch back for the enforcement tests below
    r = client.put("/api/settings/mode", json={"mode": "sandbox"})
    assert r.status_code == 200


def test_mode_switch_rejects_garbage(client):
    r = client.put("/api/settings/mode", json={"mode": "yolo"})
    assert r.status_code == 400


def test_sandbox_rejects_public_target(client):
    assert client.get("/api/settings").json()["mode"] == "sandbox"
    r = client.post("/api/runs", json={"targets": "example.com",
                                       "mode": "passive"})
    assert r.status_code == 400
    assert "SANDBOX" in r.json()["detail"]


def test_sandbox_allows_lab_and_owned_targets(client, monkeypatch):
    # Don't actually launch scans from tests.
    import app.main as main_mod

    async def _noop(*a, **k):
        return None
    monkeypatch.setattr(main_mod, "launch_run", _noop)
    monkeypatch.setattr(main_mod, "_wake_worker", lambda: None)
    for targets in ("http://127.0.0.1:8080/", "victim.test",
                    "guttergenie.pages.dev"):
        r = client.post("/api/runs", json={"targets": targets,
                                           "mode": "passive"})
        assert r.status_code == 200, (targets, r.text)
        rid = r.json()["run_id"]
        detail = client.get(f"/api/runs/{rid}").json()
        assert detail["run"]["env_mode"] == "sandbox"
    runs = client.get("/api/runs").json()["runs"]
    assert runs and all(r["env_mode"] == "sandbox" for r in runs)


def test_live_mode_allows_public_target_and_stamps_run(client, monkeypatch):
    import app.main as main_mod

    async def _noop(*a, **k):
        return None
    monkeypatch.setattr(main_mod, "launch_run", _noop)
    monkeypatch.setattr(main_mod, "_wake_worker", lambda: None)
    client.put("/api/settings/mode", json={"mode": "live"})
    try:
        r = client.post("/api/runs", json={"targets": "example.com",
                                           "mode": "passive"})
        assert r.status_code == 200
        rid = r.json()["run_id"]
        detail = client.get(f"/api/runs/{rid}").json()
        assert detail["run"]["env_mode"] == "live"
    finally:
        client.put("/api/settings/mode", json={"mode": "sandbox"})
