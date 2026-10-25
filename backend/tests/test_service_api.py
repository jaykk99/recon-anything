"""Tests for the service API (/api/service/*, Error Inbox black team).

Final model (Jay's call, 2026-10-25): the service key is NOT a
per-target gate. When Jay explicitly asks for a scan, ANY target is
pre-approved — there is deliberately no allowlist and no per-target
authorization table. The trigger rule (owner-initiated only) lives on
the Error Inbox side. This side enforces exactly two things: the
service-key gate, and the standing crypto.com exclusion (apex plus
all subdomains, dot-boundary matched so lookalikes pass).

Network-free: runs against a temp SQLite DB via FastAPI TestClient,
with launch_run monkeypatched so no real scan executes. The real
end-to-end path (scan triggered, findings read back) is covered by a
separate local canary, not by this suite.

Env note: DATABASE_URL must be set before app.main is imported
(the engine binds at import), mirroring test_runs_api.py. The service
key is read per call by service_auth, so tests can set/unset it freely
with monkeypatch.
"""

import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name
os.environ["ACCESS_CODE"] = ""
os.environ.pop("GITHUB_CLIENT_ID", None)
os.environ.pop("GITHUB_CLIENT_SECRET", None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Run, Target, get_session, init_db  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean():
    session = get_session()
    try:
        session.query(Finding).delete()
        session.query(Run).delete()
        session.commit()
    finally:
        session.close()


def _hdr(key="svc-key-123"):
    return {"X-Recon-Service-Key": key}


def _env(monkeypatch, key="svc-key-123"):
    if key is None:
        monkeypatch.delenv("RECON_SERVICE_KEY", raising=False)
    else:
        monkeypatch.setenv("RECON_SERVICE_KEY", key)


def _runs():
    session = get_session()
    try:
        return session.query(Run).all()
    finally:
        session.close()


def test_gate_closed_when_key_unset(client, monkeypatch):
    _env(monkeypatch, key=None)
    r = client.post("/api/service/scans",
                    json={"target": "https://error-inbox.onrender.com"},
                    headers=_hdr())
    assert r.status_code == 401


def test_gate_rejects_wrong_key_and_missing_header(client, monkeypatch):
    _env(monkeypatch)
    r = client.post("/api/service/scans",
                    json={"target": "https://error-inbox.onrender.com"},
                    headers=_hdr("wrong-key"))
    assert r.status_code == 401
    r = client.post("/api/service/scans",
                    json={"target": "https://error-inbox.onrender.com"})
    assert r.status_code == 401


def test_crypto_com_blocked_apex_and_subdomains(client, monkeypatch):
    _env(monkeypatch)
    for target in ("https://crypto.com",
                   "https://www.crypto.com",
                   "https://api.crypto.com/exchange"):
        r = client.post("/api/service/scans", json={"target": target},
                        headers=_hdr())
        assert r.status_code == 400, target
        assert "crypto.com" in r.json()["detail"]
    assert _runs() == []


def test_crypto_com_lookalikes_pass(client, monkeypatch):
    """Dot-boundary matching: evil-crypto.com and crypto.com.evil.com
    are NOT crypto.com and must not be over-blocked."""
    _env(monkeypatch)
    _fake_launch.calls.clear()
    monkeypatch.setattr(main, "launch_run", _fake_launch)
    for target in ("https://evil-crypto.com",
                   "https://crypto.com.evil.com",
                   "https://notcrypto.com"):
        r = client.post("/api/service/scans", json={"target": target},
                        headers=_hdr())
        assert r.status_code == 200, target
    assert len(_runs()) == 3


def test_any_target_preapproved_on_jays_ask(client, monkeypatch):
    """The final model: no allowlist, no authorization table. An
    arbitrary target scans fine once the service key is valid."""
    _env(monkeypatch)
    _fake_launch.calls.clear()
    monkeypatch.setattr(main, "launch_run", _fake_launch)
    r = client.post("/api/service/scans",
                    json={"target": "https://arbitrary.example.org"},
                    headers=_hdr())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target"] == "arbitrary.example.org"
    runs = _runs()
    assert len(runs) == 1
    assert (runs[0].summary or {}).get("service") is True
    assert len(_fake_launch.calls) == 1


def test_true_host_parsing(client, monkeypatch):
    """Userinfo decoys cannot smuggle a different host into the run
    record: the host recorded is urlparse's hostname, not the decoy.
    Multi-target input and empty input are not single targets."""
    _env(monkeypatch)
    _fake_launch.calls.clear()
    monkeypatch.setattr(main, "launch_run", _fake_launch)
    r = client.post(
        "/api/service/scans",
        json={"target": "https://error-inbox.onrender.com@evil.example.com/"},
        headers=_hdr())
    assert r.status_code == 200, r.text
    assert r.json()["target"] == "evil.example.com"
    for bad in ("https://error-inbox.onrender.com https://bro-agent.onrender.com",
                ""):
        r = client.post("/api/service/scans", json={"target": bad},
                        headers=_hdr())
        assert r.status_code == 400, bad
    assert len(_runs()) == 1


async def _fake_launch(run_id, targets, mode, plugins, overrides, keys,
                       source_type="website", bounty=False,
                       excluded_plugin_ids=None):
    _fake_launch.calls.append({
        "run_id": run_id, "targets": targets, "mode": mode,
        "plugins": plugins, "overrides": overrides,
        "source_type": source_type, "bounty": bounty,
    })


_fake_launch.calls = []


def test_allowed_target_creates_passive_service_run(client, monkeypatch):
    _env(monkeypatch)
    _fake_launch.calls.clear()
    monkeypatch.setattr(main, "launch_run", _fake_launch)
    r = client.post("/api/service/scans",
                    json={"target": "error-inbox.onrender.com"},
                    headers=_hdr())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "passive"
    assert body["target"] == "error-inbox.onrender.com"
    runs = _runs()
    assert len(runs) == 1
    assert runs[0].id == body["run_id"]
    assert runs[0].mode == "passive"
    assert runs[0].source_type == "website"
    assert (runs[0].summary or {}).get("service") is True
    assert len(_fake_launch.calls) == 1
    call = _fake_launch.calls[0]
    assert call["mode"] == "passive"
    assert call["source_type"] == "website"
    assert call["bounty"] is False


def test_full_scan_surface_forwarded(client, monkeypatch):
    """No narrowed subset. Active mode, bank source type, plugin
    selection, bounty flag, and module overrides all reach launch_run
    verbatim."""
    _env(monkeypatch)
    _fake_launch.calls.clear()
    monkeypatch.setattr(main, "launch_run", _fake_launch)
    r = client.post("/api/service/scans",
                    json={"target": "https://bro-agent.onrender.com",
                          "mode": "active",
                          "source_type": "bank",
                          "plugins": ["sec_test"],
                          "module_overrides": {"custom": "on"},
                          "bounty": True},
                    headers=_hdr())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "active"
    assert body["source_type"] == "bank"
    runs = _runs()
    assert len(runs) == 1
    assert runs[0].mode == "active"
    assert runs[0].source_type == "bank"
    call = _fake_launch.calls[0]
    assert call["mode"] == "active"
    assert call["source_type"] == "bank"
    assert call["plugins"] == ["sec_test"]
    assert call["bounty"] is True
    # Bank override recorded exactly as the human path records it,
    # alongside the caller's own overrides.
    assert call["overrides"]["bank"] == "authorized"
    assert call["overrides"]["custom"] == "on"


def test_invalid_mode_and_source_type_rejected(client, monkeypatch):
    _env(monkeypatch)
    for payload in ({"target": "error-inbox.onrender.com", "mode": "turbo"},
                    {"target": "error-inbox.onrender.com",
                     "source_type": "satellite"}):
        r = client.post("/api/service/scans", json=payload, headers=_hdr())
        assert r.status_code == 400
    assert _runs() == []


def _seed_run(run_id, service):
    session = get_session()
    try:
        session.add(Run(id=run_id, mode="passive", status="done",
                        source_type="website",
                        summary={"service": service} if service else {}))
        session.add(Finding(run_id=run_id, target_id="t",
                            plugin_id="sec_test", category="web",
                            key="k", value="v", source="s",
                            bounty_value="high"))
        session.commit()
    finally:
        session.close()


def test_service_read_serves_only_service_runs(client, monkeypatch):
    _env(monkeypatch)
    _seed_run("svc-run-001", service=True)
    _seed_run("human-run-001", service=False)
    r = client.get("/api/service/scans/svc-run-001", headers=_hdr())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["run"]["id"] == "svc-run-001"
    assert body["findings_count"] == 1
    assert body["severity_counts"] == {"high": 1}
    assert body["findings"][0]["plugin"] == "sec_test"
    # A human-created run is invisible to the service key.
    r = client.get("/api/service/scans/human-run-001", headers=_hdr())
    assert r.status_code == 404
    r = client.get("/api/service/scans/no-such-run", headers=_hdr())
    assert r.status_code == 404
    # And the read endpoint is gated too.
    r = client.get("/api/service/scans/svc-run-001")
    assert r.status_code == 401


def test_finalize_keeps_service_tag_on_finished_run(client, monkeypatch):
    """Canary regression: a service run finished with 1,226 findings, then
    its own service read 404d because finalize replaced the summary and
    dropped the service tag. Finalize must carry service/service_host
    forward (same precedent as bankatm) so finished runs stay readable."""
    import asyncio
    import app.runner as runner

    _env(monkeypatch)
    monkeypatch.setenv("RECON_HUNTERS_ENABLED", "0")
    if "app.hunters.engine" in sys.modules:
        monkeypatch.setattr("app.hunters.engine.ENABLED", False)
    session = get_session()
    try:
        session.add(Run(id="svc-fin-001", mode="active", status="running",
                        source_type="website",
                        summary={"service": True,
                                 "service_host": "example.com"}))
        session.add(Target(id="t1", run_id="svc-fin-001",
                           raw="https://example.com", type="website",
                           normalized="https://example.com"))
        session.commit()
    finally:
        session.close()
    assert asyncio.run(runner._finalize_run("svc-fin-001")) is True
    session = get_session()
    try:
        run = session.query(Run).filter_by(id="svc-fin-001").first()
        assert run.status == "done"
        assert run.summary.get("service") is True
        assert run.summary.get("service_host") == "example.com"
    finally:
        session.close()
    # And the finished run is still served by the service read endpoint.
    r = client.get("/api/service/scans/svc-fin-001", headers=_hdr())
    assert r.status_code == 200, r.text
    assert r.json()["run"]["status"] == "done"


def test_sweep_skips_runs_with_pending_enqueue(client, monkeypatch):
    """Canary regression: a service scan was finalized 3s after creation
    (0 findings) because the worker sweep saw zero pending jobs while
    enqueue was still in flight; the 600 jobs that landed a moment later
    were then all skipped as 'run no longer active'. The sweep must not
    finalize a run still carrying its pending_enqueue intent."""
    import asyncio
    import app.runner as runner

    _env(monkeypatch)
    monkeypatch.setenv("RECON_HUNTERS_ENABLED", "0")
    if "app.hunters.engine" in sys.modules:
        monkeypatch.setattr("app.hunters.engine.ENABLED", False)
    session = get_session()
    try:
        session.add(Run(id="svc-sweep-001", mode="active",
                        status="running", source_type="website",
                        summary={"service": True,
                                 "pending_enqueue": {
                                     "targets": "https://example.com",
                                     "mode": "active" }}))
        session.add(Run(id="svc-sweep-002", mode="passive",
                        status="running", source_type="website",
                        summary={"service": True}))
        session.commit()
    finally:
        session.close()
    # The sweep is throttled via runner._last_sweep, which a background
    # loop in the same process may have just touched; reset it so this
    # call cannot no-op on the throttle (a no-op would leave the
    # control run "running" and fail the assert below).
    runner._last_sweep = 0.0
    asyncio.run(runner._sweep_finalize(force=True))
    session = get_session()
    try:
        still = session.query(Run).filter_by(id="svc-sweep-001").first()
        assert still.status == "running"
        done = session.query(Run).filter_by(id="svc-sweep-002").first()
        assert done.status == "done"
        assert done.summary.get("service") is True
    finally:
        session.close()
