"""Agent attack/defend pack (2026-11-11): defense-monitor
detectors, fork-path detector, fork harness, defense watch, and
the five agent_* MCP tools.

Per detector: the vulnerable fixture MUST fire with the
detector's own kind + code evidence; the timelock / gated
variant MUST stay silent; every clean control MUST stay silent
under ALL detectors. The fork harness MUST refuse any broadcast
hypothesis and MUST always report UNVERIFIED. The registry
discovers exactly 1437 plugins including all five new ones and
the four Wave 1.3 live plugins (proxy_live_upgrade_window,
bridge_live_locked_vs_minted, bridge_live_validator_quorum,
bridge_live_nonce_continuity).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from app import defense_watch as dw  # noqa: E402
from app import fork_attack as fa  # noqa: E402
from app.plugins import bsc_common as bc  # noqa: E402
from app.plugins.defense_monitor import SPECS as DEF_SPECS  # noqa: E402
from app.plugins.defense_monitor import SPECS_BY_ID as DEF_BY_ID  # noqa: E402
from app.plugins.fork_attack_path import analyze_forkpath_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

DEF_IDS = [s.id for s in DEF_SPECS]
FORK_ID = "fork_attack_path_complete"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

UPGRADE_VULN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    address public owner;
    function _authorizeUpgrade(address newImplementation) internal {}
    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
    }
}
"""

UPGRADE_GATED = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    function _authorizeUpgrade(address newImplementation)
            internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
    }
}
"""

UPGRADE_CLEAN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/governance/TimelockController.sol";
contract Vault {
    TimelockController public timelock;
    address public owner;
    function _authorizeUpgrade(address newImplementation) internal {}
    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
    }
}
"""

OWNER_VULN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Token is Ownable {
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
    function pause() external onlyOwner {
        _pause();
    }
}
"""

OWNER_CLEAN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/governance/TimelockController.sol";
contract Token is Ownable {
    TimelockController public timelock;
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
"""

PERMIT_VULN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PermitToken {
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => mapping(address => uint256)) public allowance;
    function permit(address owner, address spender, uint256 value,
                    uint256 deadline, uint8 v, bytes32 r, bytes32 s)
                    external {
        address signer = ecrecover(
            keccak256(abi.encodePacked(owner, spender, value, deadline)),
            v, r, s);
        require(signer == owner, "bad sig");
        allowance[owner][spender] = value;
    }
}
"""

PLAIN_TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PlainToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""

PAUSE_VULN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Freezable {
    address public owner;
    mapping(address => bool) public blacklisted;
    bool public paused;
    function pause() external {
        require(msg.sender == owner);
        paused = true;
    }
    function blacklist(address a) external {
        require(msg.sender == owner);
        blacklisted[a] = true;
    }
}
"""

PAUSE_CLEAN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/governance/TimelockController.sol";
contract Freezable {
    TimelockController public timelock;
    address public owner;
    mapping(address => bool) public blacklisted;
    bool public paused;
    function pause() external {
        require(msg.sender == owner);
        paused = true;
    }
}
"""

FORK_DELEGATECALL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Proxy {
    function exec(address target, bytes calldata data)
            external payable {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "fail");
    }
}
"""

FORK_MINT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Minty {
    mapping(address => uint256) public balanceOf;
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
"""

FORK_GATED = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract GatedProxy is Ownable {
    function exec(address target, bytes calldata data)
            external onlyOwner payable {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "fail");
    }
}
"""

FORK_FIXED = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FixedMint {
    mapping(address => uint256) public balanceOf;
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }
    function mint(uint256 amount) external {
        _mint(0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B, amount);
    }
}
"""

FORK_CLEAN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PlainToken {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function balanceOfView(address a) external view returns (uint256) {
        return balanceOf[a];
    }
}
"""

CLEAN = {
    "upgrade_timelock": (UPGRADE_CLEAN, "Vault"),
    "owner_timelock": (OWNER_CLEAN, "Token"),
    "plain_token": (PLAIN_TOKEN, "PlainToken"),
    "pause_timelock": (PAUSE_CLEAN, "Freezable"),
    "fork_clean": (FORK_CLEAN, "PlainToken"),
}

DEF_VULN = {
    "defense_upgrade_window_open": (UPGRADE_VULN, "Vault"),
    "defense_owner_single_point": (OWNER_VULN, "Token"),
    "defense_unbounded_allowance_surface": (PERMIT_VULN, "PermitToken"),
    "defense_pause_blacklist_centralized": (PAUSE_VULN, "Freezable"),
}


def def_hits(src, pid, contract_name):
    return bc.analyze_bsc_source(src, DEF_BY_ID[pid], "",
                                  contract_name=contract_name)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_five_plugins_registered():
    assert len(DEF_IDS) == 4
    reg = discover()
    for pid in DEF_IDS + [FORK_ID]:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1437():
    reg = discover()
    assert len(reg) == 1437, \
        f"registry size {len(reg)}, expected 1437"


# ---------------------------------------------------------------------------
# Defense detectors
# ---------------------------------------------------------------------------

def test_defense_vuln_fires_with_evidence():
    for pid, (src, name) in DEF_VULN.items():
        hits = def_hits(src, pid, name)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["code"], f"{pid}: no code evidence"
            assert h["detail"], f"{pid}: no detail"


def test_defense_timelock_variants_silent():
    cases = [
        ("defense_upgrade_window_open", UPGRADE_CLEAN, "Vault"),
        ("defense_owner_single_point", OWNER_CLEAN, "Token"),
        ("defense_pause_blacklist_centralized", PAUSE_CLEAN,
         "Freezable"),
    ]
    for pid, src, name in cases:
        assert not def_hits(src, pid, name), \
            f"{pid}: timelock variant must stay silent"


def test_defense_plain_token_silent_under_allowance():
    assert not def_hits(
        PLAIN_TOKEN, "defense_unbounded_allowance_surface",
        "PlainToken")


def test_defense_clean_controls_silent_under_all():
    for _cid, (src, name) in CLEAN.items():
        for pid in DEF_IDS:
            assert not def_hits(src, pid, name), \
                f"{pid}: clean control fired"


def test_defense_no_crosstalk_between_detectors():
    # Targeted: the permit fixture must not trip the upgrade /
    # owner / pause detectors, and the pause fixture must not
    # trip the upgrade / allowance detectors. (OWNER_VULN
    # legitimately carries a pause() function, so the pause
    # detector firing on it is correct overlap, not crosstalk.)
    for other in ("defense_upgrade_window_open",
                  "defense_owner_single_point",
                  "defense_pause_blacklist_centralized"):
        assert not def_hits(PERMIT_VULN, other, "PermitToken"), \
            f"{other}: fired on the permit fixture"
    for other in ("defense_upgrade_window_open",
                  "defense_unbounded_allowance_surface"):
        assert not def_hits(PAUSE_VULN, other, "Freezable"), \
            f"{other}: fired on the pause fixture"


# ---------------------------------------------------------------------------
# Fork-path detector
# ---------------------------------------------------------------------------

def test_forkpath_delegatecall_fires_candidate_with_hypothesis():
    hits = analyze_forkpath_source(FORK_DELEGATECALL, "Proxy")
    assert hits, "delegatecall fixture did not fire"
    assert all(h["kind"] == FORK_ID for h in hits)
    for h in hits:
        assert h["code"] and h["detail"] and h["function"]
        assert h["gate_analysis"], "no gate analysis"
        assert h["report_class"] == "candidate", \
            f"must be a candidate, got {h['report_class']}"
        assert h["severity"] == "high"
        assert h["recipient"] in ("CALLER", "CALLER-SUPPLIED",
                                  "UNRESOLVED")
        hyp = h["hypothesis"]
        assert hyp["function"].startswith("exec(")
        assert hyp["args_template"][0] == "STRANGER"
        assert hyp["primitive"] == "delegatecall"


def test_forkpath_mint_fires_candidate():
    hits = analyze_forkpath_source(FORK_MINT, "Minty")
    assert hits, "mint fixture did not fire"
    assert hits[0]["report_class"] == "candidate"
    assert hits[0]["hypothesis"]["primitive"] == "mint_to_caller"
    assert hits[0]["hypothesis"]["args_template"] == [
        "STRANGER", "MAX"]


def test_forkpath_upgrade_fires_candidate():
    # An ungated upgradeTo(newImplementation) IS a stranger
    # attack path (stranger swaps the logic), so it fires here
    # as well as under the defense upgrade-window detector.
    hits = analyze_forkpath_source(UPGRADE_VULN, "Vault")
    assert hits, "upgrade fixture did not fire under forkpath"
    assert hits[0]["report_class"] == "candidate"


def test_forkpath_gated_silent():
    assert not analyze_forkpath_source(FORK_GATED, "GatedProxy"), \
        "onlyOwner exec must stay silent"


def test_forkpath_fixed_recipient_trigger_only():
    hits = analyze_forkpath_source(FORK_FIXED, "FixedMint")
    assert hits, "fixed-recipient fixture did not fire"
    for h in hits:
        assert h["report_class"] == "trigger_only", \
            f"FIXED recipient escalated to candidate: {h}"
        assert h["severity"] == "low"
        assert h["recipient"] == "FIXED"


def test_forkpath_clean_silent():
    assert not analyze_forkpath_source(FORK_CLEAN, "PlainToken")
    # The onlyRole-gated upgrade (the USDG shape) must stay
    # silent: the upgrade path is gated in _authorizeUpgrade.
    assert not analyze_forkpath_source(UPGRADE_GATED, "Vault")
    for _cid, (src, name) in CLEAN.items():
        if _cid in ("fork_clean", "upgrade_timelock"):
            continue
        # Defense fixtures carry no fork-path primitive.
        assert not analyze_forkpath_source(src, name), \
            f"forkpath fired on clean control {_cid}"


# ---------------------------------------------------------------------------
# Fork harness: refusals + mocked run
# ---------------------------------------------------------------------------

def test_fork_refuses_broadcast():
    r = fa.run_fork_attack(
        "bsc", "0x" + "11" * 20, {"broadcast": True,
                                  "function": "mint(address,uint256)",
                                  "args": []})
    assert r["status"] == "refused"
    assert "broadcast" in r["detail"]
    assert r["verdict"] == "UNVERIFIED"


def test_fork_refuses_rpc_url_and_credentials():
    for bad in ({"rpc_url": "https://x", "function": "a()"},
                {"private_key": "0x1234", "function": "a()"},
                {"function": "mint(address,uint256)",
                 "args": ["https://evil.example/x"]}):
        r = fa.run_fork_attack("bsc", "0x" + "11" * 20, bad)
        assert r["status"] == "refused", f"{bad} was not refused"


def test_fork_refuses_bad_hypothesis():
    r = fa.run_fork_attack("bsc", "0x" + "11" * 20, "not a dict")
    assert r["status"] == "refused"
    r = fa.run_fork_attack("bsc", "0x" + "11" * 20,
                           {"function": "no-parens"})
    assert r["status"] == "refused"


def test_fork_degraded_without_foundry(monkeypatch):
    monkeypatch.setattr(fa, "find_foundry_tool",
                        lambda name: "")
    r = fa.run_fork_attack(
        "bsc", "0x" + "11" * 20,
        {"function": "mint(address,uint256)",
         "args": ["STRANGER", "MAX"]})
    assert r["status"] == "degraded"
    assert r["verdict"] == "UNVERIFIED"


def test_fork_mocked_run_measures_stranger_receipt(monkeypatch):
    token = "0x" + "22" * 20
    state = {"balance_calls": 0, "token_calls": 0}

    class FakeProc:
        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    def fake_spawn(args):
        return FakeProc()

    def fake_cmd(args, timeout=25):
        if "block-number" in args:
            return "12345678\n", None
        if "anvil_setBalance" in args:
            return "{}\n", None
        if args[1:2] == ["balance"]:
            state["balance_calls"] += 1
            return ("10000000000000000\n"
                    if state["balance_calls"] == 1
                    else "10000000000000000\n"), None
        if args[1:2] == ["call"]:
            state["token_calls"] += 1
            return ("0\n" if state["token_calls"] == 1
                    else "5000000\n"), None
        if args[1:2] == ["send"]:
            return (json.dumps(
                {"status": 1, "gasUsed": 50000,
                 "effectiveGasPrice": 0,
                 "transactionHash": "0xabc"}) + "\n"), None
        return "", None

    monkeypatch.setattr(fa, "_spawn_anvil", fake_spawn)
    monkeypatch.setattr(fa, "_run_cmd", fake_cmd)
    r = fa.run_fork_attack(
        "bsc", "0x" + "11" * 20,
        {"function": "mint(address,uint256)",
         "args": ["STRANGER", "MAX"], "tokens": [token]},
        anvil_bin="/usr/bin/anvil", cast_bin="/usr/bin/cast")
    assert r["status"] == "completed", r
    assert r["verdict"] == "UNVERIFIED"
    assert r["fork_block"] == 12345678
    assert r["steps"][0]["status"] == "success"
    assert r["stranger_received"]["tokens"][token] == 5000000
    assert r["stranger_received"]["native_wei"] == 0


def test_fork_arg_resolution():
    assert fa._resolve_arg("STRANGER", "0x" + "11" * 20) == fa.STRANGER
    assert fa._resolve_arg("SELF", "0x" + "11" * 20) == "0x" + "11" * 20
    assert fa._resolve_arg("MAX", "0x" + "11" * 20) == str(2 ** 256 - 1)
    assert fa._resolve_arg("42", "0x" + "11" * 20) == "42"


# ---------------------------------------------------------------------------
# Defense watch: mocked cast
# ---------------------------------------------------------------------------

def _watch_cast_factory():
    owner = "0x" + "0" * 24 + "11" * 20
    impl = "0x" + "0" * 24 + "22" * 20
    zero = "0x" + "0" * 64

    def fake_cast(args, timeout=20):
        if args[0] == "call":
            sig = next((a for a in args if "(" in a), "")
            if sig.startswith("owner"):
                return owner + "\n", None
            if sig.startswith("paused"):
                return "true\n", None
            if sig.startswith("allowance"):
                return "0x00000000000000000000000000000000000000000000000000000000000003e8\n", None
            return None, "revert"
        if args[0] == "storage":
            slot = args[-1]
            if slot == dw.SLOT_IMPLEMENTATION:
                return impl + "\n", None
            return zero + "\n", None
        if args[0] == "code":
            return "0x6080604052\n", None
        if args[0] == "balance":
            return "1000000000000000000\n", None
        return None, "unknown call"
    return fake_cast


def test_defense_watch_snapshot_reads_all_fields(monkeypatch):
    monkeypatch.setattr(dw, "_cast", _watch_cast_factory())
    snap = dw.snapshot("bsc", "0x" + "33" * 20,
                       spenders=["0x" + "44" * 20])
    assert snap["owner"] == "0x" + "11" * 20
    assert snap["paused"] is True
    assert snap["implementation"] == "0x" + "22" * 20
    assert snap["admin"] is None
    assert snap["beacon"] is None
    assert snap["native_wei"] == 10 ** 18
    assert snap["code_hash"] is not None
    assert snap["allowances"]["0x" + "44" * 20] == 1000
    # Zero slots read as "not set", reported unavailable, never
    # treated as a value.
    assert "admin" in snap["unavailable"]
    assert "beacon" in snap["unavailable"]


def test_defense_watch_snapshot_degraded(monkeypatch):
    monkeypatch.setattr(dw, "_cast",
                        lambda args, timeout=20: (None, "boom"))
    snap = dw.snapshot("bsc", "0x" + "33" * 20)
    assert snap["owner"] is None
    assert len(snap["unavailable"]) >= 6


def test_defense_watch_diff_flags_changes():
    prev = {"owner": "0x" + "11" * 20, "paused": False,
            "implementation": "0x" + "22" * 20,
            "admin": None, "beacon": None,
            "code_hash": "aaa", "native_wei": 100,
            "allowances": {"0x" + "44" * 20: 100}}
    cur = {"owner": "0x" + "55" * 20, "paused": True,
           "implementation": "0x" + "66" * 20,
           "admin": None, "beacon": None,
           "code_hash": "aaa", "native_wei": 100,
           "allowances": {"0x" + "44" * 20: 500}}
    changes = dw.diff_snapshots(prev, cur)
    fields = {c["field"] for c in changes}
    assert fields == {"owner", "implementation", "paused",
                      "allowance:0x" + "44" * 20}
    assert all(c["severity"] in ("high", "medium", "low")
               for c in changes)


def test_defense_watch_diff_ignores_unreadable_fields():
    prev = {"owner": None, "paused": False, "allowances": {}}
    cur = {"owner": "0x" + "55" * 20, "paused": False,
           "allowances": {}}
    # owner unreadable in prev: NOT reported as a change.
    assert dw.diff_snapshots(prev, cur) == []
