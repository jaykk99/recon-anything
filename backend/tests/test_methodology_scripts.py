"""Unit tests for the manual-methodology scripts (fork_hypothesis,
fresh_monitor, trace_pack).

Pure functions only - no network, no foundry. The live smoke runs
(fork against a real contract, monitor against real repos, trace
pack for a real contract) are done by hand and reported with the
PR, not asserted here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts"))

import fork_hypothesis as fh  # noqa: E402
import fresh_monitor as fm  # noqa: E402
import trace_pack as tp  # noqa: E402
from business_logic_fixtures import FIXTURES  # noqa: E402

_ADDR = "0x" + "11" * 20
_ADDR2 = "0x" + "22" * 20


# ---------------------------------------------------------------------------
# fork_hypothesis
# ---------------------------------------------------------------------------

def test_parse_signature():
    assert fh.parse_signature("deposit(uint256,address)") == (
        "deposit", ["uint256", "address"])
    assert fh.parse_signature("totalSupply()") == ("totalSupply", [])
    assert fh.parse_signature(
        "onFlashLoan(address,address,uint256,uint256,bytes)") == (
        "onFlashLoan",
        ["address", "address", "uint256", "uint256", "bytes"])


def test_parse_signature_bad():
    try:
        fh.parse_signature("not a signature")
    except ValueError:
        return
    raise AssertionError("bad signature did not raise")


def test_default_arg():
    assert fh.default_arg("uint256") == "0"
    assert fh.default_arg("int128") == "0"
    assert fh.default_arg("address") == "address(0)"
    assert fh.default_arg("bool") == "false"
    assert fh.default_arg("string") == '""'
    assert fh.default_arg("uint256[]") == "new uint256[](0)"


def test_sol_literal():
    assert fh.sol_literal(1000) == "1000"
    assert fh.sol_literal(True) == "true"
    assert fh.sol_literal(_ADDR) == _ADDR
    assert fh.sol_literal("hello") == '"hello"'


def test_forbidden_refused():
    assert fh.check_forbidden(
        {"hypothesis": "broadcast this now"}) == "broadcast"
    assert fh.check_forbidden(
        {"hypothesis": "use cast send to drain"}) == "cast send"
    assert fh.check_forbidden(
        {"hypothesis": "deposit then withdraw"}) == ""


def test_build_test_contract_two_calls():
    hyp = {"chain": "bsc", "address": _ADDR,
           "function": "deposit(uint256,address)",
           "hypothesis": "test",
           "calls": [
               {"function": "deposit(uint256,address)",
                "args": [1000, _ADDR2]},
               {"function": "withdraw(uint256,address)",
                "args": [1000, _ADDR2]}]}
    src = fh.build_test_contract(
        hyp, "https://bsc-dataseed.binance.org", 12345)
    assert "vm.createFork" in src
    assert "12345" in src
    assert _ADDR in src
    assert 'deposit(uint256,address)' in src
    assert 'withdraw(uint256,address)' in src
    assert "ok0" in src and "ok1" in src
    assert "StepResult(0" in src and "StepResult(1" in src
    assert "--broadcast" not in src
    assert "broadcast" not in src.lower().replace(
        "never\n// broadcasts", "")


def test_build_test_contract_auto_single():
    hyp = {"chain": "bsc", "address": _ADDR,
           "function": "totalSupply()", "hypothesis": "auto"}
    src = fh.build_test_contract(
        hyp, "https://bsc-dataseed.binance.org", 1)
    assert 'totalSupply()' in src
    assert "ok0" in src


def test_build_test_contract_needs_function():
    try:
        fh.build_test_contract({"address": _ADDR}, "https://x", 1)
    except ValueError:
        return
    raise AssertionError("hypothesis without function did not raise")


def test_parse_forge_output():
    out = ("[PASS] test_hypothesis() (gas: 123)\n"
           "emit StepResult(step: 0, ok: true, data: 0x)\n"
           "emit StepResult(step: 1, ok: false, data: 0x)")
    parsed = fh.parse_forge_output(out)
    assert parsed["passed"] is True
    assert parsed["failed"] is False
    assert parsed["steps"] == [{"step": 0, "ok": True},
                               {"step": 1, "ok": False}]
    failed = fh.parse_forge_output(
        "[FAIL: test_hypothesis() (gas: 1)]")
    assert failed["passed"] is False
    assert failed["failed"] is True


def test_find_forge():
    # Foundry is installed in this environment; if it is not,
    # the harness must report that honestly, not fake a result.
    assert fh.find_forge().endswith("forge")


# ---------------------------------------------------------------------------
# fresh_monitor
# ---------------------------------------------------------------------------

_ATOM = b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<entry><id>tag:github.com,2026:/v1.0</id><title>v1.0</title>
<updated>2026-11-11T00:00:00Z</updated>
<link rel="alternate" href="https://github.com/o/r/releases/tag/v1.0"/>
<content>Deployed to 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c on BSC</content>
</entry>
<entry><id>tag:github.com,2026:/v1.1</id><title>v1.1</title>
<updated>2026-11-12T00:00:00Z</updated>
<link rel="alternate" href="https://github.com/o/r/releases/tag/v1.1"/>
<content>No addresses here.</content>
</entry>
</feed>"""


def test_parse_atom():
    entries = fm.parse_atom(_ATOM)
    assert len(entries) == 2
    assert entries[0]["title"] == "v1.0"
    assert entries[0]["link"].endswith("/releases/tag/v1.0")
    assert "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c" in \
        entries[0]["text"]
    assert fm.parse_atom(b"not xml") == []
    assert fm.parse_atom(b"") == []


def test_extract_addresses():
    text = ("deployed 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c "
            "and 0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c again, "
            "zero 0x0000000000000000000000000000000000000000")
    addrs = fm.extract_addresses(text)
    assert addrs == ["0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"]
    assert fm.extract_addresses("no addresses") == []


def test_extract_addresses_from_json():
    obj = {"a": {"b": "0x" + "ab" * 20},
           "c": ["0x" + "cd" * 20, "nope"],
           "d": 123}
    addrs = fm.extract_addresses_from_json(obj)
    assert len(addrs) == 2
    assert "0x" + "ab" * 20 in addrs


def test_monitor_dedupes_and_marks_watch_only(monkeypatch):
    # Feed the monitor a canned Atom feed; no network.
    def fake_fetch(url, etag="", **kwargs):
        if "releases.atom" in url:
            return 200, _ATOM, ""
        return 404, b"", ""
    monkeypatch.setattr(fm, "fetch", fake_fetch)
    state = {"seen": {}, "etags": {}}
    events, rows = fm.monitor_repo(
        {"repo": "o/r", "chains": ["bsc"]}, state, dry_run=False)
    # v1.0 has an address in the release notes -> queue row.
    # v1.1 has none -> watch-only, never faked.
    assert len(events) == 2
    by_title = {e["title"]: e for e in events}
    assert by_title["v1.0"]["queue_emitted"] is True
    assert by_title["v1.1"]["queue_emitted"] is False
    assert len(rows) == 1
    assert rows[0]["address"] == \
        "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
    assert rows[0]["queue"] == "fresh"
    # Second run: deduped, nothing new.
    events2, rows2 = fm.monitor_repo(
        {"repo": "o/r", "chains": ["bsc"]}, state, dry_run=False)
    assert events2 == [] and rows2 == []


def test_monitor_etag_304(monkeypatch):
    def fake_fetch(url, etag="", **kwargs):
        return 304, b"", etag
    monkeypatch.setattr(fm, "fetch", fake_fetch)
    state = {"seen": {}, "etags": {}}
    events, rows = fm.monitor_repo(
        {"repo": "o/r", "chains": ["bsc"]}, state, dry_run=False)
    assert events == [] and rows == []


# ---------------------------------------------------------------------------
# trace_pack
# ---------------------------------------------------------------------------

def test_trace_pack_rounding_fixture():
    src = FIXTURES["rounding_iterated_drain"]["vuln"]
    pack = tp.build_trace_pack(src, "VaultRoundingVuln", _ADDR,
                               "bsc", "0.8.20")
    assert pack["contract"]["name"] == "VaultRoundingVuln"
    assert pack["contract"]["address"] == _ADDR
    assert pack["contract"]["chain"] == "bsc"
    fns = {f["function"]: f for f in pack["value_flow"]}
    assert set(fns) == {"deposit", "withdraw"}
    assert fns["deposit"]["external_calls"] == \
        ["asset.transferFrom"]
    assert fns["withdraw"]["external_calls"] == ["asset.transfer"]
    assert fns["deposit"]["writes"] == ["balanceOf", "totalAssets",
                                        "totalSupply"]
    # No CEI violation here: writes come before the call.
    assert pack["cei_violations"] == []
    # The token is a trust assumption.
    assert any(a["external"] == "asset.transferFrom"
               for a in pack["trust_assumptions"])
    # Unused interfaces are not trust assumptions.
    assert not any(a["external"] == "IPriceFeed"
                   for a in pack["trust_assumptions"])


def test_trace_pack_cei_violation():
    src = """
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}
contract CeiVuln {
    IERC20Like public token;
    mapping(address => uint256) public balanceOf;
    function withdraw(uint256 amount, address to) external {
        token.transfer(to, amount);
        balanceOf[msg.sender] -= amount;
    }
}
"""
    pack = tp.build_trace_pack(src, "CeiVuln")
    assert len(pack["cei_violations"]) == 1
    assert pack["cei_violations"][0]["function"] == "withdraw"
    assert "balanceOf" in pack["cei_violations"][0]["detail"]


def test_trace_pack_readonly_reentrancy():
    src = """
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}
contract ReadOnlyVuln {
    IERC20Like public token;
    uint256 public totalAssets;
    function balance() public view returns (uint256) {
        return totalAssets;
    }
    function withdraw(uint256 amount, address to) external {
        token.transfer(to, amount);
        totalAssets -= amount;
    }
}
"""
    pack = tp.build_trace_pack(src, "ReadOnlyVuln")
    assert len(pack["readonly_reentrancy_shapes"]) == 1
    shape = pack["readonly_reentrancy_shapes"][0]
    assert shape["view"] == "balance"
    assert shape["writer"] == "withdraw"
    assert "totalAssets" in shape["state"]


def test_trace_pack_oracle_trust():
    src = FIXTURES["oracle_trust_assumption_break"]["vuln"]
    pack = tp.build_trace_pack(src, "OracleLendingVuln")
    assert any(a["kind"] == "price feed"
               for a in pack["trust_assumptions"])
    assert any("latestRoundData" in a["external"]
               for a in pack["trust_assumptions"])


def test_trace_pack_markdown_readable():
    src = FIXTURES["rounding_iterated_drain"]["vuln"]
    pack = tp.build_trace_pack(src, "VaultRoundingVuln", _ADDR,
                               "bsc")
    md = tp.pack_to_markdown(pack)
    assert "# Trace pack: VaultRoundingVuln" in md
    assert "## Value-flow map" in md
    assert "## External-call ordering" in md
    assert "## Trust assumptions" in md
    assert "asset.transferFrom" in md
    assert "deposit" in md and "withdraw" in md


def test_trace_pack_inheritance():
    src = """
contract Base { uint256 public x; }
contract Child is Base {
    function f() external { x = 1; }
}
"""
    pack = tp.build_trace_pack(src, "Child")
    assert pack["inheritance"]["ancestors"] == ["Base"]
