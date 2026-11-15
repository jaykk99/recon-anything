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
EXPECTED_TOOLS = {
    # v1 (PR #57)
    "recon_health", "recon_start_scan", "recon_list_runs",
    "recon_run_status", "recon_get_findings", "recon_get_graph",
    "recon_list_plugins", "recon_query_knowledge", "recon_get_delta",
    # v2: full backend surface
    "recon_classify", "recon_settings", "recon_set_mode",
    "recon_set_owned_assets", "recon_run_detail",
    "recon_agent_activity", "recon_retest_finding",
    "recon_get_apimap", "recon_export_run", "recon_fetch_run_file",
    "recon_list_vulns", "recon_test_vulns", "recon_verify_subdomains",
    "recon_probe_port", "recon_diff_runs", "recon_atm_locate",
    "recon_list_schedules", "recon_create_schedule",
    "recon_delete_schedule", "recon_breachwatch",
    "recon_breachwatch_check", "recon_agentdata", "recon_hunters",
    # v2.2: agent write / terminal / browser / crazy tools
    "agent_write_poc", "agent_write_report", "agent_cast",
    "agent_forge", "agent_anvil", "agent_slither", "agent_mythril",
    "agent_fetch", "agent_search", "agent_explorer", "agent_fuzz",
    "agent_simulate", "agent_time_travel", "agent_deploy_fork",
    "agent_multicall",
    # v2.1: agent attack/defend tools
    "agent_scan", "agent_probe", "agent_fork", "agent_trace",
    "agent_watch",
    # v2.3: investigator loop (Wave 1.1)
    "investigate", "investigation_status", "validate_candidate",
    "bounty_pack",
}


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

# -- v2: classify / settings --------------------------------------------------

def test_mcp_call_classify(client):
    data = _structured(_call_tool(client, "recon_classify",
                                  {"text": "example.com"}))
    assert data["type"] == "domain"
    batch = _structured(_call_tool(
        client, "recon_classify",
        {"text": "example.com\n1.2.3.4"}))
    assert len(batch["results"]) == 2


def test_mcp_settings_and_mode_roundtrip(client):
    from app import modes as app_modes
    data = _structured(_call_tool(client, "recon_settings"))
    assert data["mode"] in ("sandbox", "live")
    assert isinstance(data["owned_assets"], list) and data["owned_assets"]
    previous = data["mode"]
    try:
        out = _structured(_call_tool(client, "recon_set_mode",
                                     {"mode": "live"}))
        assert out["ok"] is True and out["mode"] == "live"
        assert _structured(_call_tool(
            client, "recon_settings"))["mode"] == "live"
        out = _structured(_call_tool(
            client, "recon_set_owned_assets",
            {"assets": ["Example.COM", "foo.local"]}))
        assert "example.com" in out["owned_assets"]
    finally:
        _call_tool(client, "recon_set_mode", {"mode": previous})
        session = get_session()
        try:
            app_modes.set_owned_assets(
                session, app_modes.DEFAULT_OWNED_ASSETS, actor="test")
        finally:
            session.close()


# -- v2: run detail / apimap / activity / vulns --------------------------------

def test_mcp_call_run_detail_and_apimap(client):
    _seed_run()
    detail = _structured(_call_tool(client, "recon_run_detail",
                                    {"run_id": "mcp-test-run"}))
    assert detail["status"] == "done" and detail["findings_count"] == 2
    assert len(detail["findings"]) == 2 and "progress" in detail
    amap = _structured(_call_tool(client, "recon_get_apimap",
                                  {"run_id": "mcp-test-run"}))
    assert amap["count"] == 0
    assert set(amap["groups"]) == {"pages", "api_routes", "forms",
                                   "js_endpoints", "websockets",
                                   "graphql"}


def test_mcp_call_agent_activity_and_vulns(client):
    _seed_run()
    act = _structured(_call_tool(client, "recon_agent_activity",
                                 {"run_id": "mcp-test-run"}))
    assert act["run_id"] == "mcp-test-run" and act["total_actions"] == 0
    vulns = _structured(_call_tool(client, "recon_list_vulns",
                                   {"run_id": "mcp-test-run"}))
    assert vulns["run_id"] == "mcp-test-run"
    assert isinstance(vulns["candidates"], list)


def test_mcp_test_vulns_defaults_to_dry_run(client):
    _seed_run()
    data = _structured(_call_tool(client, "recon_test_vulns",
                                  {"run_id": "mcp-test-run"}))
    assert data["dry_run"] is True
    assert isinstance(data["candidates"], list)


def test_mcp_test_vulns_rejects_non_bool_dry_run(client):
    _seed_run()
    result = _call_tool(client, "recon_test_vulns",
                        {"run_id": "mcp-test-run", "dry_run": "yes"})
    assert result["isError"] is True


def test_mcp_export_run_formats(client):
    _seed_run()
    js = _structured(_call_tool(client, "recon_export_run",
                                {"run_id": "mcp-test-run",
                                 "format": "json"}))
    assert len(js["findings"]) == 2
    csv_out = _structured(_call_tool(client, "recon_export_run",
                                     {"run_id": "mcp-test-run",
                                      "format": "csv"}))
    assert "1.2.3.4" in csv_out["content"]
    md = _structured(_call_tool(client, "recon_export_run",
                                {"run_id": "mcp-test-run",
                                 "format": "md"}))
    assert md["content"]


def test_mcp_diff_runs(client):
    _seed_run()
    session = get_session()
    try:
        session.add(Run(id="mcp-test-run-b", mode="passive",
                        status="done", source_type="website",
                        summary={}))
        session.add(Finding(run_id="mcp-test-run-b", target_id="t1",
                            plugin_id="dns", category="dns", key="a",
                            value="5.6.7.8", source="dns",
                            confidence=0.9))
        session.commit()
    finally:
        session.close()
    d = _structured(_call_tool(client, "recon_diff_runs",
                               {"run_a": "mcp-test-run",
                                "run_b": "mcp-test-run-b"}))
    assert d["counts"] == {"a": 2, "b": 1}
    assert d["new_count"] == 1 and d["removed_count"] == 2


def test_mcp_network_tools_enforce_run_guards(client):
    # SSRF guards: probe/fetch only touch data from the run itself.
    _seed_run()
    result = _call_tool(client, "recon_probe_port",
                        {"run_id": "mcp-test-run", "host": "example.com",
                         "port": 80})
    assert result["isError"] is True
    result = _call_tool(client, "recon_fetch_run_file",
                        {"run_id": "mcp-test-run",
                         "url": "https://example.com/x"})
    assert result["isError"] is True
    # Subdomain verify on a run with no subdomains is a clean no-op.
    data = _structured(_call_tool(client, "recon_verify_subdomains",
                                  {"run_id": "mcp-test-run"}))
    assert data["count"] == 0 and data["live"] == 0


# -- v2: schedules / agentdata / hunters / breachwatch --------------------------

def test_mcp_schedules_roundtrip(client):
    created = _structured(_call_tool(
        client, "recon_create_schedule",
        {"target_raw": "example.com", "cron": "0 6 * * *",
         "mode": "passive"}))
    assert created["ok"] is True
    listed = _structured(_call_tool(client, "recon_list_schedules"))
    mine = [s for s in listed["schedules"] if s["id"] == created["id"]]
    assert mine and mine[0]["target_raw"] == "example.com"
    deleted = _structured(_call_tool(
        client, "recon_delete_schedule",
        {"schedule_id": created["id"]}))
    assert deleted == {"ok": True, "deleted": 1}


def test_mcp_agentdata_and_hunters(client):
    packs = _structured(_call_tool(client, "recon_agentdata",
                                   {"view": "packs"}))
    assert isinstance(packs["packs"], list)
    hunters = _structured(_call_tool(client, "recon_hunters",
                                     {"view": "list"}))
    assert hunters["count"] > 0
    added = _structured(_call_tool(
        client, "recon_agentdata",
        {"view": "add_known", "target": "example.com",
         "asset_type": "domain", "value": "example.com"}))
    assert added["ok"] is True
    got = _structured(_call_tool(client, "recon_agentdata",
                                 {"view": "known",
                                  "target": "example.com"}))
    assert got["count"] >= 1


def test_mcp_breachwatch_list(client):
    data = _structured(_call_tool(client, "recon_breachwatch"))
    assert "configured" in data and isinstance(data["emails"], list)


def test_mcp_atm_locate_requires_authorization(client):
    _seed_run()
    result = _call_tool(client, "recon_atm_locate",
                        {"run_id": "mcp-test-run", "query": "Winnipeg",
                         "authorized": False})
    assert result["isError"] is True
    assert "authorized" in result["content"][0]["text"]


# -- v2: keyless local HTTP vs key enforcement ---------------------------------

def test_standalone_keyless_localhost_without_key(monkeypatch):
    from fastapi.testclient import TestClient as TC
    monkeypatch.delenv("RECON_SERVICE_KEY", raising=False)
    monkeypatch.delenv("RECON_MCP_NO_AUTH", raising=False)
    standalone = mcp_server.create_standalone_app(host="127.0.0.1")
    try:
        assert mcp_server.auth_required() is False
        with TC(standalone) as c:
            r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                     "method": "initialize",
                                     "params": {}})
            assert r.status_code == 200
            assert r.json()["result"]["serverInfo"]["version"] == "2.2.0"
            assert c.get("/").json()["auth"].startswith("none")
    finally:
        mcp_server._keyless_local_bind = False


def test_key_still_enforced_when_env_key_set(monkeypatch):
    from fastapi.testclient import TestClient as TC
    # The module pins RECON_SERVICE_KEY for the whole suite; a
    # non-localhost standalone bind must demand it.
    standalone = mcp_server.create_standalone_app(host="0.0.0.0")
    try:
        assert mcp_server.auth_required() is True
        with TC(standalone) as c:
            r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"},
                       headers={})
            assert r.status_code == 401
            r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"},
                       headers=KEY)
            assert r.status_code == 200
    finally:
        mcp_server._keyless_local_bind = False


# -- v2: stdio transport ---------------------------------------------------------

def test_stdio_transport_handshake(tmp_path):
    import subprocess
    db = tmp_path / "stdio.db"
    env = dict(os.environ)
    env["DATABASE_URL"] = f"sqlite:///{db}"
    env["ACCESS_CODE"] = ""
    env.pop("RECON_SERVICE_KEY", None)
    backend = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "recon_health", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "ping"},
    ]
    proc = subprocess.run(
        [sys.executable, "-m", "app.mcp_server", "--stdio"],
        input="\n".join(json.dumps(x) for x in lines) + "\n",
        capture_output=True, text=True, cwd=backend, env=env,
        timeout=180)
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
    by_id = {m.get("id"): m for m in out}
    assert by_id[1]["result"]["serverInfo"] == {
        "name": "recon-anything", "version": "2.2.0"}
    tools = by_id[2]["result"]["tools"]
    assert {t["name"] for t in tools} == EXPECTED_TOOLS
    health = by_id[3]["result"]
    assert health["isError"] is False
    assert json.loads(health["content"][0]["text"])["ok"] is True
    assert by_id[4]["result"] == {}


# -- agent attack/defend tools (v2.1) --------------------------------------

def test_mcp_agent_fork_refuses_broadcast(client):
    result = _call_tool(client, "agent_fork", {
        "chain": "bsc", "address": "0x" + "11" * 20,
        "hypothesis": {"broadcast": True,
                       "function": "mint(address,uint256)",
                       "args": []}})
    assert result["isError"] is False
    data = _structured(result)
    assert data["status"] == "refused"
    assert "broadcast" in data["detail"]
    assert data["verdict"] == "UNVERIFIED"


def test_mcp_agent_fork_rejects_bad_address(client):
    result = _call_tool(client, "agent_fork", {
        "chain": "bsc", "address": "not-an-address",
        "hypothesis": {"function": "mint(address,uint256)",
                       "args": []}})
    assert result["isError"] is True


def test_mcp_agent_scan_stubbed(client, monkeypatch):
    monkeypatch.setattr(
        mcp_server, "_agent_scan_impl",
        lambda chain, address, deep=True: {
            "chain": chain, "address": address,
            "source_status": "verified", "findings_count": 0,
            "findings": []})
    data = _structured(_call_tool(client, "agent_scan", {
        "chain": "bsc", "address": "0x" + "11" * 20}))
    assert data["source_status"] == "verified"
    assert data["findings_count"] == 0


def test_mcp_agent_watch_stubbed(client, monkeypatch):
    snap = {"chain": "bsc", "address": "0x" + "11" * 20,
            "owner": "0x" + "22" * 20, "paused": False,
            "implementation": None, "admin": None, "beacon": None,
            "code_hash": "abc", "native_wei": 0, "allowances": {},
            "unavailable": ["implementation", "admin", "beacon"]}
    monkeypatch.setattr(
        mcp_server, "_agent_watch_impl",
        lambda chain, address, spenders=None, token=None,
        prev_snapshot=None: {"chain": chain, "address": address,
                             "snapshot": snap, "changes": []})
    data = _structured(_call_tool(client, "agent_watch", {
        "chain": "bsc", "address": "0x" + "11" * 20}))
    assert data["snapshot"]["owner"] == "0x" + "22" * 20
    assert data["changes"] == []


def test_mcp_agent_probe_bad_signature(client):
    result = _call_tool(client, "agent_probe", {
        "chain": "bsc", "address": "0x" + "11" * 20,
        "signature": "not-a-signature"})
    assert result["isError"] is True
