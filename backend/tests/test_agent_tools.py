"""Tests for the agent write / terminal / browser / crazy MCP tools
(app/agent_tools.py, MCP v2.2).

Offline tests run everywhere. Tests marked `live` need network (public
BSC RPC / Blockscout / GitHub) and skip cleanly when the network is
down; they never assert on live balances, only on shape + verdict.
Fork tests run against a local Anvil fork and assert the stranger
received 0 and the verdict stays UNVERIFIED.
"""
import json
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import pytest  # noqa: E402

import app.agent_tools as at  # noqa: E402

WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bC095c"
USDT = "0x55d398326f99059ff775485246999027b3197955"
STRANGER = at.STRANGER
AUDIT_BIN = os.path.expanduser("~/workspace/tools/audit/bin")
MYTHRIL_BIN = os.path.expanduser(
    "~/workspace/wt/tool-integrations/.venv-mythril/bin")


def _with_bins(monkeypatch):
    """Put foundry (+ mythril salvage venv) on PATH for the test."""
    parts = [AUDIT_BIN, MYTHRIL_BIN]
    monkeypatch.setenv(
        "PATH", os.pathsep.join(parts + [os.environ.get("PATH", "")]))


def _live_ok():
    """True when the public BSC RPC answers from this machine."""
    try:
        out, _err = at._cast(
            ["block-number", "--rpc-url", at._rpc_for_chain("bsc")],
            timeout=15)
        return bool(out and out.strip().isdigit())
    except Exception:  # noqa: BLE001 - any failure means skip live tests
        return False


live = pytest.mark.skipif(not _live_ok(), reason="no live BSC RPC")


# ---------------------------------------------------------------------------
# validation + pure helpers (offline)
# ---------------------------------------------------------------------------

def test_validate_address_rejects_bad():
    with pytest.raises(at.AgentToolError):
        at._validate_address("not-an-address")
    with pytest.raises(at.AgentToolError):
        at._validate_address("0x1234")


def test_validate_chain_rejects_unknown():
    with pytest.raises(at.AgentToolError):
        at._validate_chain("solana")


def test_validate_url_rejects_http_and_unknown_host():
    with pytest.raises(at.AgentToolError):
        at.fetch_tool("http://example.com/x")
    with pytest.raises(at.AgentToolError):
        at.fetch_tool("https://evil.example.com/x")


def test_try_decode_uint_address_bool():
    d = at._try_decode(
        "0x000000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c")
    assert d["address"] == WBNB.lower()
    d = at._try_decode(
        "0x0000000000000000000000000000000000000000000000000000000000000001")
    assert d["uint256"] == 1 and d["bool"] is True
    assert at._try_decode("") is None


def test_multicall_encode_decode_roundtrip():
    calls = [("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bC095c",
              "0x06fdde03"),
             ("0x55d398326f99059ff775485246999027b3197955",
              "0x95d89b41")]
    payload = at._encode_multicall_aggregate(calls)
    assert payload.startswith("0x252dba42")
    # fake a result: blockNumber + array of 2 (ok, bytes) tuples
    def _word(n):
        return n.to_bytes(32, "big")
    ret_a = bytes(31) + b"\x01"
    ret_b = bytes(31) + b"\x02"
    # array at byte 64: length, then 2 tuples (96 + 64*i), then bytes
    # data at 224. Each tuple's bytes offset is relative to its own
    # start: off_i = (224 + tail_before) - (96 + 64*i).
    tail = b""
    offsets = []
    for i, ret in enumerate((ret_a, ret_b)):
        offsets.append(224 + len(tail) - (96 + 64 * i))
        tail += _word(len(ret)) + ret + \
            b"\x00" * ((32 - len(ret) % 32) % 32)
    tuples = b"".join(_word(1) + _word(o) for o in offsets)
    blob = _word(123) + _word(64) + _word(2) + tuples + tail
    dec = at._decode_multicall_result("0x" + blob.hex())
    assert dec is not None and len(dec) == 2
    assert dec[0][0] is True and dec[0][1].endswith("01")
    assert dec[1][1].endswith("02")


def test_write_report_refuses_verified_real(tmp_path):
    with pytest.raises(at.AgentToolError):
        at.write_report("bsc", WBNB, verdict="VERIFIED_REAL")


def test_write_report_writes_markdown(tmp_path):
    out = at.write_report(
        "bsc", WBNB,
        scan={"status": "genuine", "findings": 3,
              "candidates": [{"function": "withdraw",
                              "plugin": "x", "severity": "high"}]},
        probe={"ok": False, "detail": "reverted"},
        verdict="FALSE_POSITIVE")
    assert os.path.isfile(out["path"])
    text = open(out["path"]).read()
    assert "FALSE_POSITIVE" in text and WBNB in text
    assert "- verdict: **FALSE_POSITIVE**" in text
    assert "verdict: **VERIFIED_REAL**" not in text
    assert out["verdict"] == "FALSE_POSITIVE"


def test_cast_refuses_private_key_flags(monkeypatch):
    _with_bins(monkeypatch)
    with pytest.raises(at.AgentToolError):
        at.cast_tool(["send", WBNB, "transfer(address,uint256)",
                      STRANGER, "1", "--private-key", "0xabc"])
    with pytest.raises(at.AgentToolError):
        at.cast_tool(["send", WBNB, "transfer(address,uint256)",
                      STRANGER, "1", "--mnemonic", "word word"])


def test_cast_refuses_mainnet_send(monkeypatch):
    _with_bins(monkeypatch)
    with pytest.raises(at.AgentToolError):
        at.cast_tool(["send", WBNB, "transfer(address,uint256)",
                      STRANGER, "1", "--rpc-url",
                      "https://bsc-rpc.publicnode.com"])


def test_cast_version_ok(monkeypatch):
    _with_bins(monkeypatch)
    out = at.cast_tool(["--version"])
    assert out["rc"] == 0
    assert "cast" in (out["stdout"] + out["stderr"]).lower()


def test_forge_refuses_outside_roots(monkeypatch):
    _with_bins(monkeypatch)
    with pytest.raises(at.AgentToolError):
        at.forge_tool("test", "/etc")
    with pytest.raises(at.AgentToolError):
        at.forge_tool("test", "/home/other/tree")


def test_forge_builds_tiny_tree(monkeypatch, tmp_path):
    _with_bins(monkeypatch)
    tree = tmp_path / "tiny"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "Tiny.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract Tiny { function one() public pure returns (uint256) "
        "{ return 1; } }\n")
    (tree / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\n")
    out = at.forge_tool("build", str(tree))
    assert out["rc"] == 0, out["stderr"]


def test_multicall_rejects_too_many_calls():
    with pytest.raises(at.AgentToolError):
        at.multicall_tool(
            "bsc", [{"address": WBNB, "function": "name()(string)"}] * 26)


def test_time_travel_rejects_too_many_blocks():
    with pytest.raises(at.AgentToolError):
        at.time_travel_tool("bsc", WBNB, "owner()(address)",
                            blocks=list(range(10)))


def test_simulate_rejects_bad_steps():
    with pytest.raises(at.AgentToolError):
        at.simulate_tool("bsc", WBNB, [])
    with pytest.raises(at.AgentToolError):
        at.simulate_tool("bsc", WBNB, [{"no_function": True}])


def test_deploy_fork_rejects_bad_source():
    with pytest.raises(at.AgentToolError):
        at.deploy_fork_tool("bsc", WBNB, "no contract here",
                            {"function": "withdraw()(bool)"})


def test_slither_unavailable_without_binary(monkeypatch):
    monkeypatch.setattr(at, "_find_binary", lambda name: None)
    out = at.slither_tool(chain="bsc", address=WBNB, timeout_s=30)
    assert out["status"] == "unavailable"


def test_slither_parses_stub_output(monkeypatch, tmp_path):
    stub = tmp_path / "slither"
    stub.write_text(
        "#!/bin/sh\n"
        "# fake slither: writes its --json file like the real one\n"
        'OUT=""; PREV=""\n'
        'for a in "$@"; do\n'
        '  if [ "$PREV" = "--json" ]; then OUT="$a"; fi\n'
        '  PREV="$a"\n'
        "done\n"
        'cat > "$OUT" <<\'JSON\'\n'
        '{"results": {"detectors": [{"check": "reentrancy-eth", '
        '"impact": "High", "description": "Reentrancy in Foo.bar", '
        '"elements": [{"name": "bar", "type": "function", '
        '"source_mapping": {"filename_short": "Foo.sol", '
        '"lines": [10, 12]}}]}]}}\n'
        "JSON\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(tmp_path) + ":/usr/bin:/bin")
    src = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
           "contract Foo { function bar() public {} }\n")
    out = at.slither_tool(source=src, timeout_s=30)
    assert out["status"] == "ok", out
    assert out["detectors"] and \
        out["detectors"][0]["check"] == "reentrancy-eth"


def test_mythril_unavailable_without_binary(monkeypatch):
    monkeypatch.setattr(at, "_find_binary", lambda name: None)
    out = at.mythril_tool(chain="bsc", address=WBNB, timeout_s=30)
    assert out["status"] == "unavailable"


# ---------------------------------------------------------------------------
# live read-only tests (skip when the RPC is unreachable)
# ---------------------------------------------------------------------------

@live
def test_cast_read_only_call(monkeypatch):
    _with_bins(monkeypatch)
    out = at.cast_tool(["call", WBNB, "name()(string)",
                        "--rpc-url", at._rpc_for_chain("bsc")])
    assert out["rc"] == 0
    assert "Wrapped BNB" in out["stdout"]


@live
def test_fetch_sourcify(monkeypatch):
    _with_bins(monkeypatch)
    out = at.fetch_tool(
        "https://repo.sourcify.dev/contracts/full_match/56/"
        "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bC095c/metadata.json")
    if out["status"] is None:
        pytest.skip(f"fetch unreachable: {out.get('detail')}")
    assert out["status"] == 200, out
    assert "WBNB" in out["text"] or "Wrapped" in out["text"]


@live
def test_explorer_token_info(monkeypatch):
    _with_bins(monkeypatch)
    out = at.explorer_tool("bsc", WBNB, "token_info")
    if out["status"] is None:
        pytest.skip(f"explorer unreachable: {out.get('detail')}")
    assert out["status"] == 200, out
    assert out["items"]


@live
def test_multicall_live(monkeypatch):
    _with_bins(monkeypatch)
    out = at.multicall_tool("bsc", [
        {"address": WBNB, "function": "name()(string)"},
        {"address": WBNB, "function": "decimals()(uint8)"},
        {"address": USDT, "function": "symbol()(string)"},
    ])
    assert len(out["calls"]) == 3
    assert all(c["ok"] for c in out["calls"]), out
    assert out["via"] in ("multicall3", "sequential")


@live
def test_time_travel_live(monkeypatch):
    _with_bins(monkeypatch)
    out = at.time_travel_tool(
        "bsc", WBNB, "name()(string)",
        blocks=[40000000, 45000000])
    assert len(out["results"]) == 2
    assert any(r["ok"] for r in out["results"]), out
    assert out["changed_across_blocks"] is False


# ---------------------------------------------------------------------------
# live fork tests (skip when the RPC is unreachable)
# ---------------------------------------------------------------------------

@live
def test_anvil_stranger_receives_nothing(monkeypatch):
    _with_bins(monkeypatch)
    out = at.anvil_tool("bsc", WBNB, {
        "function": "withdraw(uint256)", "args": [1000000000000000000],
        "tokens": [WBNB]}, timeout_s=300)
    assert out["status"] == "ok", out
    assert out["stranger_received_native_wei"] == 0, out
    assert out["verdict"] == "UNVERIFIED"


@live
def test_write_poc_stranger_receives_nothing(monkeypatch):
    _with_bins(monkeypatch)
    out = at.write_poc("bsc", WBNB, {
        "function": "withdraw(uint256)", "args": [1000000000000000000],
        "tokens": [WBNB]}, timeout_s=300)
    assert out["status"] == "passed", out
    assert out["stranger_received_native_wei"] == 0, out
    assert os.path.isfile(out["test_path"]), out
    assert out["verdict"] == "UNVERIFIED"


@live
def test_fuzz_stranger_never_gains(monkeypatch):
    _with_bins(monkeypatch)
    out = at.fuzz_tool("bsc", WBNB, token=WBNB, runs=8,
                       timeout_s=300)
    assert out["status"] in ("ok", "failed"), out
    assert out["invariant_broken"] is False, out
    assert out["verdict"] == "UNVERIFIED"


@live
def test_simulate_withdraw(monkeypatch):
    _with_bins(monkeypatch)
    out = at.simulate_tool("bsc", WBNB, [
        {"function": "withdraw(uint256)",
         "args": [1000000000000000000], "tokens": [WBNB]},
    ], timeout_s=300)
    assert out["status"] == "ok", out
    assert out["stranger_received_native_wei"] == 0, out
    assert out["verdict"] == "UNVERIFIED"
