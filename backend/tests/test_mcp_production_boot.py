"""Regression test: the production server must BOOT and serve /mcp.

PR #57 mounted the MCP router into app.main but app/modes.py (imported
by app/mcp_server.py) was never committed, so on a clean checkout the
production start command - uvicorn app.main:app, per backend/Dockerfile
- died at import time with:

    ImportError: cannot import name 'modes' from 'app'

The TestClient tests in test_mcp_server.py import the same app, but
they were only ever run in a worktree where modes.py existed as an
untracked file, so the missing module slipped through. This test runs
the REAL production command as a subprocess and speaks real HTTP to it,
so a boot-breaking import or mount error anywhere in app.main's import
graph fails here no matter what stray files a worktree happens to hold.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

import httpx
import pytest

# trust_env=False: this test only talks to 127.0.0.1, and some hosts
# carry proxy env vars (e.g. a NO_PROXY with bracketed IPv6 entries)
# that httpx's env parsing chokes on. Hermetic beats ambient.
http = httpx.Client(trust_env=False)

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_KEY = "test-service-key-123"
# Full current tool set (v2 + v2.1 agent tools). The v1-era
# 9-tool set went stale when v2 landed and this test red-lit
# on master; asserting the real set keeps the boot check
# meaningful.
EXPECTED_TOOLS = {
    "recon_health", "recon_start_scan", "recon_list_runs",
    "recon_run_status", "recon_get_findings", "recon_get_graph",
    "recon_list_plugins", "recon_query_knowledge", "recon_get_delta",
    "recon_classify", "recon_settings", "recon_set_mode",
    "recon_set_owned_assets", "recon_run_detail",
    "recon_agent_activity", "recon_retest_finding",
    "recon_get_apimap", "recon_export_run", "recon_fetch_run_file",
    "recon_list_vulns", "recon_test_vulns",
    "recon_verify_subdomains", "recon_probe_port", "recon_diff_runs",
    "recon_atm_locate", "recon_list_schedules",
    "recon_create_schedule", "recon_delete_schedule",
    "recon_breachwatch", "recon_breachwatch_check",
    "recon_agentdata", "recon_hunters",
    "agent_scan", "agent_probe", "agent_fork", "agent_trace",
    "agent_watch",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def prod_server():
    """uvicorn app.main:app, exactly as backend/Dockerfile runs it."""
    db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_file.close()
    env = dict(os.environ)
    env.update({
        "DATABASE_URL": f"sqlite:///{db_file.name}",
        "ACCESS_CODE": "",
        "RECON_SERVICE_KEY": TEST_KEY,
        "RECON_WORKER_ENABLED": "0",  # API service, per render.yaml
        "PYTHONPATH": BACKEND_DIR,
    })
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=BACKEND_DIR, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            if proc.poll() is not None:
                out = proc.stdout.read() if proc.stdout else ""
                pytest.fail(
                    "production server exited during boot "
                    f"(rc={proc.returncode}); output tail:\n"
                    + "\n".join(out.splitlines()[-25:]))
            try:
                if http.get(base + "/api/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)
        else:
            pytest.fail("production server did not answer /api/health "
                        "within 90s")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _rpc(base, payload, headers=None):
    return http.post(base + "/mcp", json=payload, headers=headers or {},
                      timeout=15)


def test_health_up(prod_server):
    r = http.get(prod_server + "/api/health", timeout=10)
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_mcp_no_key_is_401_json_not_500(prod_server):
    r = _rpc(prod_server, {"jsonrpc": "2.0", "id": 1,
                           "method": "initialize",
                           "params": {"protocolVersion": "2025-03-26"}})
    assert r.status_code == 401, r.text
    assert "service key" in r.json()["detail"]


def test_mcp_wrong_key_is_401(prod_server):
    r = _rpc(prod_server, {"jsonrpc": "2.0", "id": 1, "method": "ping"},
             headers={"X-Recon-Service-Key": "not-the-key"})
    assert r.status_code == 401, r.text


def test_mcp_initialize_with_key(prod_server):
    r = _rpc(prod_server,
             {"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-03-26",
                         "capabilities": {},
                         "clientInfo": {"name": "pytest", "version": "0"}}},
             headers={"X-Recon-Service-Key": TEST_KEY})
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    assert result["serverInfo"]["name"] == "recon-anything"
    assert result["protocolVersion"] == "2025-03-26"


def test_mcp_tools_list_has_nine_tools(prod_server):
    r = _rpc(prod_server, {"jsonrpc": "2.0", "id": 2,
                           "method": "tools/list"},
             headers={"Authorization": f"Bearer {TEST_KEY}"})
    assert r.status_code == 200, r.text
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert names == EXPECTED_TOOLS


def test_mcp_recon_health_tool(prod_server):
    r = _rpc(prod_server,
             {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "recon_health", "arguments": {}}},
             headers={"X-Recon-Service-Key": TEST_KEY})
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert structured["ok"] is True
    assert structured["service"] == "recon-anything"
    assert structured["plugins"] > 0
    # content text carries the same payload as JSON
    assert json.loads(result["content"][0]["text"])["ok"] is True
