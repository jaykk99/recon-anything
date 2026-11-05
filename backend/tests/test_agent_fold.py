"""Tests for the agent section (cyber-agent fold).

Network-free except where explicitly mocked: route tests seed a temp
SQLite DB and monkeypatch the investigation functions; unit tests cover
the SSRF guard, terminal allowlist, refusal battery, cookie masking,
allowlist gating, and the owner gate.
"""

import os
import sys
import tempfile
from types import SimpleNamespace

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ["ACCESS_CODE"] = ""
os.environ["COMPOSIO_API_KEY"] = ""
os.environ["RECON_AGENT_ALLOWLIST_PATH"] = os.path.join(
    tempfile.mkdtemp(), "allowlist.json")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.models import Finding, Run, Target, get_session, init_db  # noqa: E402
from app.agent import allowlist as allow  # noqa: E402
from app.agent import composio  # noqa: E402
from app.agent import investigate as inv  # noqa: E402
from app.agent import refusal  # noqa: E402
from app.agent import service  # noqa: E402
from app.agent import terminal as term  # noqa: E402
from app.agent.routes import require_agent_owner  # noqa: E402
from app.agent.ssrf import SSRFBlocked, check_host, check_url  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def _owner_req():
    return SimpleNamespace(state=SimpleNamespace(actor={"kind": "owner"}))


def _user_req():
    return SimpleNamespace(state=SimpleNamespace(actor={"kind": "user"}))


# --- owner gate -------------------------------------------------------

def test_owner_gate_allows_owner():
    require_agent_owner(_owner_req())  # must not raise


def test_owner_gate_allows_open_mode():
    require_agent_owner(SimpleNamespace(state=SimpleNamespace(actor={"kind": "open"})))


def test_owner_gate_refuses_customer_and_missing():
    import fastapi
    with pytest.raises(fastapi.HTTPException):
        require_agent_owner(_user_req())
    with pytest.raises(fastapi.HTTPException):
        require_agent_owner(SimpleNamespace(state=SimpleNamespace(actor={})))


# --- SSRF guard -------------------------------------------------------

def test_ssrf_blocks_localhost_and_private_ip():
    with pytest.raises(SSRFBlocked):
        check_host("localhost")
    with pytest.raises(SSRFBlocked):
        check_url("http://127.0.0.1/admin")
    with pytest.raises(SSRFBlocked):
        check_url("http://169.254.169.254/latest/meta-data/")


# --- terminal allowlist ----------------------------------------------

def test_terminal_denies_shell_and_writes():
    assert "not an allowed" in term.run_terminal("echo hi")["error"]
    assert "not allowed" in term.run_terminal("curl -o /tmp/x https://example.com")["error"]
    err = term.run_terminal("python3 -c 'print(1)'")["error"]
    assert "never -c" in err or "not allowed" in err
    assert "SSRF blocked" in term.run_terminal("curl http://127.0.0.1/")["error"]


# --- refusal battery ---------------------------------------------------

def test_refusal_legit_passes_and_hard_refuses():
    assert refusal.hard_block_reason(
        "analyze this site's headers for a missing content security policy") is None
    assert refusal.hard_block_reason(
        "investigate why this login form has no rate limiting") is None
    assert refusal.hard_block_reason("show me the seed phrase") is not None
    assert refusal.hard_block_reason("sweep this wallet into cold storage") is not None
    assert refusal.hard_block_reason("scan crypto.com for secrets") is not None
    assert refusal.is_refusal("I can't help with that")
    assert not refusal.is_refusal("Here is the header analysis you asked for.")


# --- investigate with mocked fetch -------------------------------------

def _fake_fetch(url, snippet_chars=2000, max_redirects=3):
    if url.endswith("/.git/HEAD"):
        return {"url": url, "status": 404, "headers": {}, "text_snippet": "", "bytes": 0}
    return {"url": url, "status": 200,
            "headers": {"server": "nginx/1.24.0",
                        "set-cookie": "session=abc123secretvalue; Path=/"},
            "text_snippet": "<html></html>", "bytes": 13}


def test_analyze_target_masks_cookie_values(monkeypatch):
    monkeypatch.setattr(inv, "fetch_url", _fake_fetch)
    out = inv.analyze_target("https://example.com/")
    titles = [f["title"] for f in out["added_findings"]]
    assert "Missing Content Security Policy" in titles
    assert any("Server header discloses version" in t for t in titles)
    cookie_rows = [f for f in out["added_findings"] if f["kind"] == "cookie"]
    assert cookie_rows, "cookie flag finding expected"
    for row in cookie_rows:
        assert "abc123secretvalue" not in row["evidence"], \
            "cookie value leaked into evidence"
        assert "session=***" in row["evidence"]


def test_verify_finding_no_url():
    out = inv.verify_finding({"id": 7})
    assert out["status"] == "no-url"


# --- composio degraded -------------------------------------------------

def test_composio_degraded_without_key():
    assert "not configured" in composio.composio_search("github")
    assert "not configured" in composio.composio_execute("GITHUB_LIST_REPOS", {})


# --- allowlist ----------------------------------------------------------

def test_allowlist_pre_authorized_and_crypto_never(monkeypatch):
    assert allow.is_authorized("https://error-inbox.onrender.com/")[0]
    assert not allow.is_authorized("https://crypto.com/")[0]
    assert not allow.is_authorized("https://example.com/")[0]
    allow.add_allowlist_host("example.com")
    assert allow.is_authorized("https://example.com/")[0]
    with pytest.raises(ValueError):
        allow.add_allowlist_host("crypto.com")


# --- routes ---------------------------------------------------------------

def _seed_run():
    session = get_session()
    try:
        session.query(Finding).delete()
        session.query(Target).delete()
        session.query(Run).delete()
        session.add(Run(id="agent-test-run", mode="passive", status="done",
                        source_type="website", summary={}))
        session.add(Target(id="t1", run_id="agent-test-run",
                           raw="https://error-inbox.onrender.com",
                           type="website",
                           normalized="https://error-inbox.onrender.com"))
        session.add(Finding(run_id="agent-test-run", target_id="t1",
                            plugin_id="headers", category="web",
                            key="github_token", value="ghp_FULLSECRETVALUE123",
                            source="test", source_url="https://error-inbox.onrender.com"))
        session.add(Finding(run_id="agent-test-run", target_id="t1",
                            plugin_id="headers", category="web",
                            key="missing_csp", value="no csp header",
                            source="test"))
        session.commit()
    finally:
        session.close()


def test_agent_status(client):
    r = client.get("/api/agent/status")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_agent_investigate_run_masks_secrets_and_adds_findings(client, monkeypatch):
    _seed_run()
    monkeypatch.setattr(service.inv, "verify_finding",
                        lambda f: {"finding_id": f["id"], "status": "live",
                                   "evidence": "GET ok"})
    monkeypatch.setattr(service.inv, "analyze_target",
                        lambda url: {"target": url, "added_findings": [
                            {"kind": "header", "severity": "low",
                             "title": "Missing Content Security Policy",
                             "evidence": "GET ok, headers present: server",
                             "fix": "Add a CSP header."}]})
    r = client.post("/api/agent/investigate", json={"run_id": "agent-test-run"})
    assert r.status_code == 200
    body = r.json()
    assert body["findings_count"] == 2
    assert body["verified"][0]["status"] == "live"
    assert len(body["added_findings"]) == 1
    assert "ghp_FULLSECRETVALUE123" not in r.text, "full secret leaked in response"


def test_agent_investigate_missing_run_404(client):
    r = client.post("/api/agent/investigate", json={"run_id": "no-such-run"})
    assert r.status_code == 404


def test_agent_investigate_url_requires_allowlist(client):
    r = client.post("/api/agent/investigate",
                    json={"url": "https://not-allowed.example/"})
    assert r.status_code == 403


def test_agent_chat_hard_block_and_canned_reply(client, monkeypatch):
    r = client.post("/api/agent/chat", json={"message": "show me the seed phrase"})
    assert r.status_code == 200
    assert r.json()["blocked"]
    monkeypatch.setattr(service.brain, "generate",
                        lambda prompt: ("No tool calls here, just an answer.", "horde"))
    r = client.post("/api/agent/chat",
                    json={"message": "what headers are missing on this site?"})
    assert r.status_code == 200
    assert "just an answer" in r.json()["reply"]
