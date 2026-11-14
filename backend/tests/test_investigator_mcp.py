"""MCP tools for the investigator loop (Wave 1.1): investigate,
investigation_status, validate_candidate, bounty_pack.

Handlers are called directly (no HTTP) with a temp investigations
store. The investigate handler runs the loop in a background thread;
the test polls the stored state until it closes.
"""
import asyncio
import os
import sys
import tempfile
import time

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ["ACCESS_CODE"] = ""
os.environ["RECON_SERVICE_KEY"] = "test-service-key-123"
os.environ["RECON_INVESTIGATIONS_DIR"] = tempfile.mkdtemp()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import app.mcp_server as mcp_server  # noqa: E402
from app.investigator.fixtures import (  # noqa: E402
    VAULT_ADDRESS, VAULT_VULN_SOURCE, WETH_ADDRESS)


def test_investigator_tools_registered():
    names = {t["name"] for t in mcp_server.TOOLS}
    assert {"investigate", "investigation_status",
            "validate_candidate", "bounty_pack"} <= names
    assert len(mcp_server.TOOLS) == 56  # 52 + 4


def _wait_closed(inv_id, timeout_s=120):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        st = mcp_server._tool_investigation_status(
            {"investigation_id": inv_id})
        if st["phase"] == "CLOSED":
            return st
        time.sleep(0.5)
    raise AssertionError(f"investigation {inv_id} never closed: "
                         f"{st['phase']}")


def test_investigate_vault_then_status_then_pack():
    started = asyncio.run(mcp_server._tool_investigate({
        "chain": "ethereum", "address": VAULT_ADDRESS,
        "source": VAULT_VULN_SOURCE, "value_usd": 250000.0}))
    inv_id = started["investigation_id"]
    assert started["status"] == "started"
    st = _wait_closed(inv_id)
    assert st["verdict"] == "UNVERIFIED"
    assert st["hypothesis"]["function"] == "withdrawAll"
    assert st["candidates"] >= 1
    assert st["report"], "high-value vault run must write a pack"
    assert os.path.isfile(st["report"]["files"]["report"])
    pack = asyncio.run(mcp_server._tool_bounty_pack(
        {"investigation_id": inv_id}))
    assert pack["verdict"] == "UNVERIFIED"
    assert os.path.isfile(pack["files"]["report"])


def test_validate_candidate_on_demand():
    out = asyncio.run(mcp_server._tool_validate_candidate({
        "candidate": {"address": VAULT_ADDRESS, "chain": "ethereum",
                      "function": "withdrawAll", "kind": "fund_drain",
                      "source": VAULT_VULN_SOURCE}}))
    assert out["verdict"] == "UNVERIFIED"
    assert "probe" in out["reason"].lower()
    assert out["candidate"]["function"] == "withdrawAll"


def test_investigate_rejects_bad_address():
    with pytest.raises(mcp_server.ToolError):
        asyncio.run(mcp_server._tool_investigate(
            {"chain": "ethereum", "address": "not-an-address"}))


def test_investigation_status_unknown_id():
    with pytest.raises(mcp_server.ToolError):
        mcp_server._tool_investigation_status(
            {"investigation_id": "inv-does-not-exist"})
