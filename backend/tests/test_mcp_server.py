"""Tests for the MCP server (app/mcp_server.py) mounted at /mcp.

Covers the streamable-HTTP JSON-RPC surface end to end through the
real FastAPI app: auth rejection, the initialize handshake, tools/list,
and tools/call for every read tool plus recon_start_scan (with the
runner stubbed so no scan actually executes).

Network-free: temp SQLite DB via FastAPI TestClient, same pattern as
test_runs_api.py. The service key is pinned through the env so auth is
deterministic.
"""
import json
import os
import sys
import tempfile

# Env must be set before app.main is imported (engine binds at import).
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name
os.environ["ACCESS_CODE"] = ""
os.environ["RECON_SERVICE_KEY"] = "test-service-key-123"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.mcp_server as mcp_server  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Run, get_session, init_db  # noqa: E402

KEY = {"X-Recon-Service-Key": "test-service-key-123"}
EXPECTED_TOOLS = {"recon_health", "recon_start_scan", "recon_list_runs",
                  "recon_run_status", "recon_get_findings",
                  "recon_get_graph", "recon_list_plugins"}


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def _rpc(client, payload, headers=KEY):
    return client.post("/mcp", json=payload, headers=headers)


def _call_tool(client, name, arguments=None):
    r = _rpc(client, {"jsonrpc": "2.0", "id": 99, "method": "tools/call",
                      "params": {"name": name,
                                 "arguments": arguments or {}}})
    assert r.status_code == 200, r.text
    return r.json()["result"]


def _structured(result):
    return result["structuredContent"]


# -- auth ------------------------------------------------------------------

def test_mcp_rejects_missing_key(client):
    r = _rpc(client, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
             headers={})
    assert r.status_code == 401


def test_mcp_rejects_wrong_key(client):
    r = _rpc(client, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
             headers={"X-Recon-Service-Key": "nope"})
    assert r.status_code == 401


def test_mcp_accepts_bearer_key(client):
    r = _rpc(client, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
             headers={"Authorization": "Bearer test-service-key-123"})
    assert r.status_code == 200


# -- protocol ---------------------------------------------------------------

def test_mcp_initialize_handshake(client):
    r = _rpc(client, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2025-03-26",
                                 "capabilities": {},
                                 "clientInfo": {"name": "pytest",
                                                "version": "0"}}})
    assert r.status_code == 200
    body = r.json()
    assert body["jsonrpc"] == "2.0" and body["id"] == 1
    result = body["result"]
    assert result["protocolVersion"] == "2025-03-26"
    assert result["serverInfo"]["name"] == "recon-anything"
    assert "tools" in result["capabilities"]


def test_mcp_initialize_unknown_version_gets_newest_supported(client):
    r = _rpc(client, {"jsonrpc": "2.0", "id": 2, "method": "initialize",
                      "params": {"protocolVersion": "1999-01-01"}})
    assert r.json()["result"]["protocolVersion"] == "2025-06-18"


def test_mcp_notification_gets_202_no_body(client):
    r = _rpc(client, {"jsonrpc": "2.0",
                      "method": "notifications/initialized"})
    assert r.status_code == 202
    assert r.content == b""


def test_mcp_tools_list(client):
    r = _rpc(client, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    tools = r.json()["result"]["tools"]
    assert {t["name"] for t in tools} == EXPECTED_TOOLS
    for t in tools:
        assert t["description"]
        assert t["inputSchema"]["type"] == "object"


def test_mcp_unknown_method_is_jsonrpc_error(client):
    r = _rpc(client, {"jsonrpc": "2.0", "id": 4, "method": "bogus/method"})
    assert r.json()["error"]["code"] == -32601


def test_mcp_unknown_tool_is_error_result(client):
    result = _call_tool(client, "recon_nope")
    assert result["isError"] is True


def test_mcp_get_is_405_with_key(client):
    r = client.get("/mcp", headers=KEY)
    assert r.status_code == 405


# -- tools/call ---------------------------------------------------------------

def _seed_run():
    session = get_session()
    try:
        session.query(Finding).delete()
        session.query(Run).delete()
        session.add(Run(id="mcp-test-run", mode="passive", status="done",
                        source_type="website",
                        summary={"findings": 2}))
        session.add(Finding(run_id="mcp-test-run", target_id="t1",
                            plugin_id="dns", category="dns", key="a",
                            value="1.2.3.4", source="dns",
                            confidence=0.9))
        session.add(Finding(run_id="mcp-test-run", target_id="t1",
                            plugin_id="whois", category="whois",
                            key="registrar", value="Example Registrar",
                            source="whois", confidence=0.3))
        session.commit()
    finally:
        session.close()


def test_mcp_call_health(client):
    result = _call_tool(client, "recon_health")
    assert result["isError"] is False
    data = _structured(result)
    assert data["ok"] is True and data["service"] == "recon-anything"
    # The text content block carries the same payload as JSON.
    assert json.loads(result["content"][0]["text"])["ok"] is True


def test_mcp_call_list_plugins(client):
    data = _structured(_call_tool(client, "recon_list_plugins"))
    assert data["count"] > 50
    assert all("id" in p and "label" in p for p in data["plugins"])


def test_mcp_call_list_runs_and_status(client):
    _seed_run()
    runs = _structured(_call_tool(client, "recon_list_runs",
                                   {"limit": 10}))["runs"]
    mine = [r for r in runs if r["id"] == "mcp-test-run"]
    assert mine and mine[0]["findings_count"] == 2

    status = _structured(_call_tool(client, "recon_run_status",
                                     {"run_id": "mcp-test-run"}))
    assert status["status"] == "done"
    assert status["findings_count"] == 2
    assert "progress" in status


def test_mcp_call_get_findings_with_confidence(client):
    _seed_run()
    data = _structured(_call_tool(client, "recon_get_findings",
                                   {"run_id": "mcp-test-run"}))
    assert data["findings_total"] == 2
    confs = {f["key"]: f["confidence"] for f in data["findings"]}
    assert confs == {"a": 0.9, "registrar": 0.3}
    assert data["confidence_bands"]["high (>=0.75)"] == 1
    assert data["confidence_bands"]["low (<0.4)"] == 1

    filtered = _structured(_call_tool(
        client, "recon_get_findings",
        {"run_id": "mcp-test-run", "min_confidence": 0.5}))
    assert filtered["findings_returned"] == 1


def test_mcp_call_get_graph(client):
    _seed_run()
    data = _structured(_call_tool(client, "recon_get_graph",
                                   {"run_id": "mcp-test-run"}))
    assert data["run_id"] == "mcp-test-run"
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)
    assert data["node_count"] == len(data["nodes"])


def test_mcp_call_missing_run_is_error_result(client):
    result = _call_tool(client, "recon_run_status",
                        {"run_id": "does-not-exist"})
    assert result["isError"] is True
    assert "not found" in result["content"][0]["text"]


def test_mcp_call_start_scan_quick_preset(client, monkeypatch):
    launched = {}

    async def fake_launch(run_id, targets_raw, mode, plugin_ids=None,
                          module_overrides=None, keys=None,
                          source_type="website", bounty=False,
                          excluded_plugin_ids=None):
        launched.update(run_id=run_id, targets=targets_raw, mode=mode,
                        plugin_ids=plugin_ids, source_type=source_type)
        return None

    monkeypatch.setattr(mcp_server, "launch_run", fake_launch)
    # Fresh installs boot in SANDBOX mode, which only allows Jay's own
    # assets and lab targets - localhost is a lab target.
    result = _call_tool(client, "recon_start_scan",
                        {"targets": "localhost", "preset": "quick"})
    assert result["isError"] is False, result
    data = _structured(result)
    assert data["status"] == "running" and data["mode"] == "passive"
    assert launched["run_id"] == data["run_id"]
    assert launched["mode"] == "passive"
    # Quick preset = passive plugins only, a non-empty explicit list.
    assert launched["plugin_ids"]
    described = {p["id"]: p for p in
                 _structured(_call_tool(client, "recon_list_plugins"))
                 ["plugins"]}
    assert all(described[pid]["passive"] for pid in launched["plugin_ids"])
    # And the run row really exists.
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=data["run_id"]).first()
        assert run is not None and run.summary.get("via") == "mcp"
    finally:
        session.close()


def test_mcp_call_start_scan_validates_input(client):
    result = _call_tool(client, "recon_start_scan", {"targets": "  "})
    assert result["isError"] is True
    result = _call_tool(client, "recon_start_scan",
                        {"targets": "localhost", "preset": "ludicrous"})
    assert result["isError"] is True


def test_mcp_start_scan_honors_sandbox_gate(client):
    # In SANDBOX mode an arbitrary external target must be refused over
    # MCP exactly like it is over POST /api/runs. The mode is pinned
    # explicitly: the suite shares one test DB across modules and
    # another module may have left the app in LIVE mode.
    from app import modes as app_modes
    session = get_session()
    try:
        previous = app_modes.get_mode(session)
        app_modes.set_mode(session, app_modes.SANDBOX, actor="test")
    finally:
        session.close()
    try:
        result = _call_tool(client, "recon_start_scan",
                            {"targets": "example.com"})
        assert result["isError"] is True
        assert "SANDBOX" in result["content"][0]["text"]
    finally:
        session = get_session()
        try:
            app_modes.set_mode(session, previous, actor="test")
        finally:
            session.close()


# -- standalone entrypoint ---------------------------------------------------

def test_standalone_app_serves_mcp():
    from fastapi.testclient import TestClient as TC
    standalone = mcp_server.create_standalone_app()
    with TC(standalone) as c:
        root = c.get("/")
        assert root.status_code == 200
        assert root.json()["mcp_endpoint"] == "/mcp"
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                 "method": "initialize", "params": {}},
                   headers=KEY)
        assert r.status_code == 200
        assert r.json()["result"]["serverInfo"]["name"] == "recon-anything"
