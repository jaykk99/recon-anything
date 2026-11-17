"""Wave 1.3: live proxy/upgrade monitoring + implementation diffing +
live bridge invariant checks.

Per check: the vulnerable fixture MUST fire with the check's own id
and live-measured evidence; the clean control MUST stay silent; an
unreadable side MUST report degraded, never clean. Selector / slot
constants are recomputed from keccak here, so a truncated constant
(the EIP-1967 beacon slot was 62 hex chars on master) fails loudly.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from app import defense_watch as dw  # noqa: E402
from app import proxy_bridge_live as pbl  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

# ---------------------------------------------------------------------------
# Addresses / fixtures
# ---------------------------------------------------------------------------

PROXY = "0x" + "11" * 20
IMPL_A = "0x" + "22" * 20   # clean implementation
IMPL_B = "0x" + "33" * 20   # vulnerable implementation
ADMIN = "0x" + "44" * 20
VAULT = "0x" + "55" * 20
TOKEN_A = "0x" + "66" * 20
MINT_B = "0x" + "77" * 20
BRIDGE = "0x" + "88" * 20
BRIDGE_A = "0x" + "99" * 20
BRIDGE_B = "0x" + "aa" * 20

# UUPS proxy shell (implementation slot set live; the shell itself
# carries no upgrade logic).
PROXY_SHELL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract UUPSProxy {
    constructor(address impl, bytes memory data) {
        assembly {
            sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, impl)
        }
    }
    fallback() external payable {
        address impl;
        assembly {
            impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
        }
        (bool ok, ) = impl.delegatecall(msg.data);
        require(ok, "fail");
    }
}
"""

# Clean implementation: upgrade behind a timelock AND a role gate.
# (An ungated upgradeTo with only a TimelockController import still
# fires the fork-path analyzer - the import alone gates nothing -
# so the clean fixture gates _authorizeUpgrade with onlyRole too,
# the shape the repo's own UPGRADE_GATED fixture proves silent.)
IMPL_CLEAN_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/governance/TimelockController.sol";
contract VaultV1 {
    TimelockController public timelock;
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    address public owner;
    uint256 public value;
    function _authorizeUpgrade(address newImplementation)
            internal onlyRole(DEFAULT_ADMIN_ROLE) {}
    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
    }
    function setValue(uint256 v) external {
        value = v;
    }
}
"""

# Vulnerable implementation: ungated upgrade + selfdestruct, no
# timelock / multisig anywhere in source.
IMPL_VULN_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract VaultV2 {
    address public owner;
    uint256 public value;
    function _authorizeUpgrade(address newImplementation) internal {}
    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
    }
    function setValue(uint256 v) external {
        value = v;
    }
    function kill(address payable to) external {
        selfdestruct(to);
    }
}
"""

# Bytecode fixtures (PUSH4 selectors + opcodes, hand-built):
#  - old impl: upgradeTo (3659cfe6) + setValue selector
#  - new impl: same + kill selector + SELFDESTRUCT opcode (0xff)
_SEL_UPGRADE = bytes.fromhex("3659cfe6")
_SEL_SETVALUE = bytes.fromhex(pbl.selector("setValue(uint256)"))
_SEL_KILL = bytes.fromhex(pbl.selector("kill(address)"))
CODE_A = ("0x" + (b"\x63" + _SEL_UPGRADE + b"\x63" + _SEL_SETVALUE
                  + b"\x60\x00\x00").hex())
CODE_B = ("0x" + (b"\x63" + _SEL_UPGRADE + b"\x63" + _SEL_SETVALUE
                  + b"\x63" + _SEL_KILL + b"\xff\x60\x00\x00").hex())


def uint_word(n: int) -> str:
    return "0x" + format(n, "064x")


def addr_word(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:].lower()


def addr_array_word(addrs) -> str:
    # ABI address[] return: offset word, length word, then items.
    out = uint_word(0x20)[2:] + uint_word(len(addrs))[2:]
    for a in addrs:
        out += "0" * 24 + a[2:].lower()
    return "0x" + out


class FakeReader:
    """Async reader protocol over canned responses."""

    def __init__(self, storage=None, code=None, calls=None):
        self.storage = storage or {}
        self.code = code or {}
        self.calls = calls or {}

    async def aget_storage_at(self, chain, address, slot):
        return self.storage.get(
            (chain, address.lower(), slot.lower()))

    async def aget_code(self, chain, address):
        return self.code.get((chain, address.lower()))

    async def aeth_call(self, chain, to, data):
        return self.calls.get((chain, to.lower(), data[2:10]))


def fake_code_reader(code_map):
    async def _read(chain, address):
        return code_map.get(address.lower())
    return _read


def fake_source_analyzer(source_map):
    async def _analyze(chain, address):
        src = source_map.get(address.lower())
        if src is None:
            return {"source_available": False, "hits": []}
        hits = pbl.analyze_implementation_source(src, "Vault")
        return {"source_available": True, "hits": hits}
    return _analyze


# ---------------------------------------------------------------------------
# Slots / keccak
# ---------------------------------------------------------------------------

def test_proxy_slots_are_keccak_minus_one():
    cases = [
        ("eip1967.proxy.implementation", pbl.SLOT_IMPLEMENTATION),
        ("eip1967.proxy.admin", pbl.SLOT_ADMIN),
        ("eip1967.proxy.beacon", pbl.SLOT_BEACON),
        # openzeppelin-sdk lineage: keccak-1.
        ("org.zeppelinos.proxy.implementation",
         pbl.SLOT_ZEPPELINOS_IMPLEMENTATION_MINUS1),
    ]
    for preimage, slot in cases:
        assert len(slot) == 66, f"{preimage}: slot {slot} is not 32 bytes"
        assert slot == pbl.slot_from_preimage(preimage), \
            f"{preimage}: slot constant != keccak-1"
    # Original ZeppelinOS lineage (e.g. USDC's FiatTokenProxy) uses
    # the RAW keccak256, no "-1": read live 2026-11-12, the raw slot
    # holds the live implementation while the keccak-1 slot reads
    # zero. The two constants must differ by exactly 1.
    assert pbl.SLOT_ZEPPELINOS_IMPLEMENTATION == \
        "0x" + format(
            int(pbl.SLOT_ZEPPELINOS_IMPLEMENTATION_MINUS1, 16) + 1,
            "064x")
    # The defense_watch copies must match (the beacon slot was
    # truncated to 62 hex chars on master - this is the regression).
    assert dw.SLOT_IMPLEMENTATION == pbl.SLOT_IMPLEMENTATION
    assert dw.SLOT_ADMIN == pbl.SLOT_ADMIN
    assert dw.SLOT_BEACON == pbl.SLOT_BEACON
    assert dw.SLOT_ZEPPELINOS_IMPLEMENTATION == \
        pbl.SLOT_ZEPPELINOS_IMPLEMENTATION
    assert len(dw.SLOT_BEACON) == 66


def test_keccak_known_vectors():
    assert pbl.keccak_256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    assert pbl.keccak_256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    assert pbl.selector("balanceOf(address)") == "70a08231"
    assert pbl.selector("totalSupply()") == "18160ddd"
    assert pbl.selector("upgradeTo(address)") == "3659cfe6"


# ---------------------------------------------------------------------------
# Selector extraction / bytecode diff
# ---------------------------------------------------------------------------

def test_extract_selectors_skips_push_data():
    # PUSH4 0x70a08231, then a PUSH2 whose data bytes spell 0x63
    # (PUSH4 opcode) followed by fake selector bytes - the walk must
    # not mistake PUSH data for a selector.
    code = "0x" + (b"\x63\x70\xa0\x82\x31"
                    b"\x61\x63\xde\xad\xbe\xef"
                    b"\x60\x00").hex()
    assert pbl.extract_selectors(code) == {"0x70a08231"}


def test_diff_implementations_reports_added_selector_and_opcode():
    diff = pbl.diff_implementations(CODE_A, CODE_B)
    assert diff["changed"] is True
    assert diff["added_selectors"] == ["0x" + _SEL_KILL.hex()]
    assert diff["removed_selectors"] == []
    assert diff["added_dangerous_opcodes"] == ["SELFDESTRUCT"]
    assert diff["old_code_hash"] != diff["new_code_hash"]


def test_diff_implementations_identical_code_unchanged():
    diff = pbl.diff_implementations(CODE_A, CODE_A)
    assert diff["changed"] is False
    assert diff["added_selectors"] == []
    assert diff["added_dangerous_opcodes"] == []


# ---------------------------------------------------------------------------
# Live slot reads
# ---------------------------------------------------------------------------

def test_read_proxy_slots_fake_reader():
    reader = FakeReader(storage={
        ("bsc", PROXY.lower(), pbl.SLOT_IMPLEMENTATION.lower()):
            addr_word(IMPL_A),
        ("bsc", PROXY.lower(), pbl.SLOT_ADMIN.lower()):
            addr_word(ADMIN),
        ("bsc", PROXY.lower(), pbl.SLOT_BEACON.lower()):
            pbl.ZERO_WORD,
        ("bsc", PROXY.lower(),
         pbl.SLOT_ZEPPELINOS_IMPLEMENTATION.lower()):
            pbl.ZERO_WORD,
    })
    out = asyncio.run(pbl.read_proxy_slots(reader, "bsc", PROXY))
    assert out["implementation"] == IMPL_A.lower()
    assert out["admin"] == ADMIN.lower()
    assert out["beacon"] is None
    assert out["zeppelinos_implementation"] is None
    assert "beacon" in out["unavailable"]
    assert "zeppelinos_implementation" in out["unavailable"]


def test_read_proxy_slots_beacon_fallback():
    beacon = "0x" + "bb" * 20
    reader = FakeReader(storage={
        ("bsc", PROXY.lower(), pbl.SLOT_IMPLEMENTATION.lower()):
            pbl.ZERO_WORD,
        ("bsc", PROXY.lower(), pbl.SLOT_BEACON.lower()):
            addr_word(beacon),
        ("bsc", beacon.lower(), "0x0"): addr_word(IMPL_A),
    })
    out = asyncio.run(pbl.read_proxy_slots(reader, "bsc", PROXY))
    assert out["beacon"] == beacon.lower()
    assert out["implementation"] == IMPL_A.lower()
    assert out["beacon_implementation"] == IMPL_A.lower()


def test_read_proxy_slots_zeppelinos():
    reader = FakeReader(storage={
        ("bsc", PROXY.lower(), pbl.SLOT_IMPLEMENTATION.lower()):
            pbl.ZERO_WORD,
        ("bsc", PROXY.lower(),
         pbl.SLOT_ZEPPELINOS_IMPLEMENTATION.lower()):
            addr_word(IMPL_A),
        ("bsc", PROXY.lower(), pbl.SLOT_ZEPPELINOS_ADMIN.lower()):
            addr_word(ADMIN),
    })
    out = asyncio.run(pbl.read_proxy_slots(reader, "bsc", PROXY))
    assert out["zeppelinos_implementation"] == IMPL_A.lower()
    assert out["implementation"] == IMPL_A.lower()
    assert out["implementation_via"] == "zeppelinos_implementation"
    # The ZeppelinOS admin slot fills `admin` when the EIP-1967
    # admin slot is empty (USDC's layout).
    assert out["zeppelinos_admin"] == ADMIN.lower()
    assert out["admin"] == ADMIN.lower()
    assert out["admin_via"] == "zeppelinos_admin"


def test_read_proxy_slots_implementation_call_fallback():
    # Custom proxy (USDC FiatTokenProxy shape): no EIP-1967 slot
    # set, but implementation() answers.
    reader = FakeReader(storage={
        ("bsc", PROXY.lower(), pbl.SLOT_IMPLEMENTATION.lower()):
            pbl.ZERO_WORD,
        ("bsc", PROXY.lower(), pbl.SLOT_BEACON.lower()):
            pbl.ZERO_WORD,
    }, calls={
        ("bsc", PROXY.lower(),
         pbl.selector("implementation()")): addr_word(IMPL_A),
        ("bsc", PROXY.lower(), pbl.selector("admin()")):
            addr_word(ADMIN),
    })
    out = asyncio.run(pbl.read_proxy_slots(reader, "bsc", PROXY))
    assert out["implementation"] == IMPL_A.lower()
    assert out["implementation_via"] == "implementation() call"
    assert out["admin"] == ADMIN.lower()


def test_read_proxy_slots_no_proxy_all_unavailable():
    out = asyncio.run(pbl.read_proxy_slots(
        FakeReader(), "bsc", PROXY))
    assert out["implementation"] is None
    assert out["admin"] is None
    assert "implementation" in out["unavailable"]
    assert "implementation_call" in out["unavailable"]


# ---------------------------------------------------------------------------
# Re-analysis of implementation source
# ---------------------------------------------------------------------------

def test_reanalysis_fires_on_vuln_impl_silent_on_clean():
    vuln = pbl.analyze_implementation_source(IMPL_VULN_SRC, "VaultV2")
    ids = {h["kind"] for h in vuln}
    assert "defense_upgrade_window_open" in ids, ids
    assert "fork_attack_path_complete" in ids, ids
    assert all(h["report_class"] == "candidate" for h in vuln)
    clean = pbl.analyze_implementation_source(IMPL_CLEAN_SRC, "VaultV1")
    assert clean == [], f"clean impl fired: {clean}"


# ---------------------------------------------------------------------------
# Upgrade analysis (two snapshots)
# ---------------------------------------------------------------------------

def _snapshots():
    prev = {"chain": "bsc", "address": PROXY,
            "implementation": IMPL_A}
    cur = {"chain": "bsc", "address": PROXY,
           "implementation": IMPL_B}
    return prev, cur


def test_analyze_upgrade_vuln_new_impl_fires():
    prev, cur = _snapshots()
    report = asyncio.run(pbl.analyze_upgrade(
        prev, cur,
        fake_code_reader({IMPL_A.lower(): CODE_A,
                          IMPL_B.lower(): CODE_B}),
        fake_source_analyzer({IMPL_B.lower(): IMPL_VULN_SRC})))
    assert report["changed"] is True
    assert report["verdict"] == "candidate"
    assert report["selector_diff"]["added_selectors"] == \
        ["0x" + _SEL_KILL.hex()]
    ids = {f["id"] for f in report["findings"]}
    assert "defense_upgrade_window_open" in ids, ids
    assert "proxy_live_implementation_diff" in ids, ids
    assert all(f["report_class"] == "candidate"
               for f in report["findings"])
    assert "VERIFIED_REAL" not in str(report["findings"])


def test_analyze_upgrade_clean_impl_change_no_finding():
    prev, cur = _snapshots()
    report = asyncio.run(pbl.analyze_upgrade(
        prev, cur,
        fake_code_reader({IMPL_A.lower(): CODE_A,
                          IMPL_B.lower(): CODE_A}),
        fake_source_analyzer({IMPL_B.lower(): IMPL_CLEAN_SRC})))
    assert report["changed"] is True
    assert report["findings"] == []
    assert report["verdict"] == "clean"


def test_analyze_upgrade_no_change_silent():
    prev = {"chain": "bsc", "address": PROXY,
            "implementation": IMPL_A}
    report = asyncio.run(pbl.analyze_upgrade(
        prev, dict(prev), fake_code_reader({}), None))
    assert report["changed"] is False
    assert report["findings"] == []
    assert report["verdict"] == "clean"


def test_analyze_upgrade_unverified_source_degraded():
    prev, cur = _snapshots()
    # Same bytecode both sides (no opcode finding) + no verified
    # source: the change is recorded but nothing is cleared.
    report = asyncio.run(pbl.analyze_upgrade(
        prev, cur,
        fake_code_reader({IMPL_A.lower(): CODE_A,
                          IMPL_B.lower(): CODE_A}),
        fake_source_analyzer({})))
    assert report["changed"] is True
    assert report["findings"] == []
    assert report["verdict"] == "degraded"
    assert report["reanalysis"]["source_available"] is False


def test_analyze_upgrade_missing_bytecode_degraded():
    prev, cur = _snapshots()
    report = asyncio.run(pbl.analyze_upgrade(
        prev, cur, fake_code_reader({}), None))
    assert report["changed"] is True
    assert report["verdict"] == "degraded"


def test_defense_watch_analyze_upgrade_via_cast(monkeypatch):
    # The defense_watch wrapper reads implementation bytecode with
    # cast; mock _cast to return the fixture code per address.
    def fake_cast(args, timeout=20):
        addr = args[-1].lower()
        if addr == IMPL_A.lower():
            return CODE_A + "\n", None
        if addr == IMPL_B.lower():
            return CODE_B + "\n", None
        return None, "no code"
    monkeypatch.setattr(dw, "_cast", fake_cast)
    prev, cur = _snapshots()
    report = asyncio.run(dw.analyze_upgrade(prev, cur))
    assert report["changed"] is True
    assert report["selector_diff"]["added_selectors"] == \
        ["0x" + _SEL_KILL.hex()]
    # No source analyzer wired in the cast path: opcode finding
    # fires, verdict is candidate, nothing is claimed clean.
    assert report["verdict"] == "candidate"
    assert {f["id"] for f in report["findings"]} == \
        {"proxy_live_implementation_diff"}


def test_defense_watch_snapshot_reads_zeppelinos(monkeypatch):
    def fake_cast(args, timeout=20):
        if args[0] == "call":
            sig = next((a for a in args if "(" in a), "")
            if sig.startswith("owner"):
                return "0x" + "0" * 24 + "11" * 20 + "\n", None
            return None, "revert"
        if args[0] == "storage":
            slot = args[-1]
            if slot == dw.SLOT_IMPLEMENTATION:
                return addr_word(IMPL_A) + "\n", None
            if slot == dw.SLOT_ZEPPELINOS_IMPLEMENTATION:
                return addr_word(IMPL_B) + "\n", None
            return pbl.ZERO_WORD + "\n", None
        if args[0] == "code":
            return "0x6080604052\n", None
        if args[0] == "balance":
            return "0\n", None
        return None, "unknown call"
    monkeypatch.setattr(dw, "_cast", fake_cast)
    snap = dw.snapshot("bsc", PROXY)
    assert snap["implementation"] == IMPL_A.lower()
    assert snap["zeppelinos_implementation"] == IMPL_B.lower()
    assert "zeppelinos_implementation" not in snap["unavailable"]


# ---------------------------------------------------------------------------
# Bridge: locked vs minted
# ---------------------------------------------------------------------------

def _lockmint_reader(locked, minted):
    return FakeReader(calls={
        ("ethereum", TOKEN_A.lower(), pbl.SEL_BALANCE_OF):
            uint_word(locked),
        ("bsc", MINT_B.lower(), pbl.SEL_TOTAL_SUPPLY):
            uint_word(minted),
    })


def _lockmint_cfg():
    return pbl.BridgeLockMintConfig("ethereum", VAULT, TOKEN_A,
                                    "bsc", MINT_B, label="test-bridge")


def test_locked_vs_minted_broken_fires_with_both_numbers():
    res = asyncio.run(pbl.check_locked_vs_minted(
        _lockmint_reader(1000, 1500), _lockmint_cfg()))
    assert res["broken"] is True
    assert res["verdict"] == "candidate"
    assert res["locked"] == 1000
    assert res["minted"] == 1500
    assert res["shortfall"] == 500
    assert "1000" in res["detail"] and "1500" in res["detail"]


def test_locked_vs_minted_balanced_silent():
    res = asyncio.run(pbl.check_locked_vs_minted(
        _lockmint_reader(1000, 1000), _lockmint_cfg()))
    assert res["broken"] is False
    assert res["verdict"] == "clean"


def test_locked_vs_minted_overcollateralized_silent():
    res = asyncio.run(pbl.check_locked_vs_minted(
        _lockmint_reader(1500, 1000), _lockmint_cfg()))
    assert res["broken"] is False
    assert res["verdict"] == "clean"


def test_locked_vs_minted_unreadable_degraded():
    res = asyncio.run(pbl.check_locked_vs_minted(
        FakeReader(), _lockmint_cfg()))
    assert res["broken"] is False
    assert res["verdict"] == "degraded"
    assert res["locked"] is None and res["minted"] is None


# ---------------------------------------------------------------------------
# Bridge: quorum vs live validator set
# ---------------------------------------------------------------------------

def _quorum_reader(quorum, validators, via_array=False):
    calls = {
        ("ethereum", BRIDGE.lower(),
         pbl.selector("quorum()")): uint_word(quorum),
    }
    if via_array:
        calls[("ethereum", BRIDGE.lower(),
               pbl.selector("getValidators()"))] = addr_array_word(
            ["0x" + "%02x" % i * 20 for i in range(1, validators + 1)])
    else:
        calls[("ethereum", BRIDGE.lower(),
               pbl.selector("validatorCount()"))] = uint_word(validators)
    cfg = pbl.BridgeQuorumConfig(
        "ethereum", BRIDGE,
        count_sigs=("getValidators()",) if via_array
        else ("validatorCount()",))
    return FakeReader(calls=calls), cfg


def test_quorum_unreachable_fires():
    reader, cfg = _quorum_reader(3, 2)
    res = asyncio.run(pbl.check_validator_quorum(reader, cfg))
    assert res["broken"] is True
    assert res["verdict"] == "candidate"
    assert res["quorum"] == 3 and res["validator_count"] == 2


def test_quorum_single_signer_fires():
    reader, cfg = _quorum_reader(1, 5)
    res = asyncio.run(pbl.check_validator_quorum(reader, cfg))
    assert res["broken"] is True
    assert res["quorum"] == 1 and res["validator_count"] == 5


def test_quorum_healthy_silent():
    reader, cfg = _quorum_reader(2, 5)
    res = asyncio.run(pbl.check_validator_quorum(reader, cfg))
    assert res["broken"] is False
    assert res["verdict"] == "clean"


def test_quorum_empty_set_fires():
    reader, cfg = _quorum_reader(2, 0)
    res = asyncio.run(pbl.check_validator_quorum(reader, cfg))
    assert res["broken"] is True


def test_quorum_array_count_read():
    reader, cfg = _quorum_reader(2, 4, via_array=True)
    res = asyncio.run(pbl.check_validator_quorum(reader, cfg))
    assert res["validator_count"] == 4
    assert res["count_sig"] == "getValidators()"
    assert res["broken"] is False


def test_quorum_unreadable_degraded():
    res = asyncio.run(pbl.check_validator_quorum(
        FakeReader(),
        pbl.BridgeQuorumConfig("ethereum", BRIDGE)))
    assert res["broken"] is False
    assert res["verdict"] == "degraded"


# ---------------------------------------------------------------------------
# Bridge: nonce continuity
# ---------------------------------------------------------------------------

def _nonce_reader(src_n, dst_n):
    return FakeReader(calls={
        ("ethereum", BRIDGE_A.lower(), pbl.selector("nonce()")):
            uint_word(src_n),
        ("bsc", BRIDGE_B.lower(), pbl.selector("nonce()")):
            uint_word(dst_n),
    })


def _nonce_cfg():
    return pbl.BridgeNonceConfig("ethereum", BRIDGE_A, "bsc", BRIDGE_B,
                                 label="test-nonce")


def test_nonce_dest_ahead_fires():
    res = asyncio.run(pbl.check_nonce_continuity(
        _nonce_reader(100, 105), _nonce_cfg()))
    assert res["broken"] is True
    assert res["verdict"] == "candidate"
    assert res["source_nonce"] == 100
    assert res["dest_nonce"] == 105


def test_nonce_lag_silent():
    res = asyncio.run(pbl.check_nonce_continuity(
        _nonce_reader(100, 90), _nonce_cfg()))
    assert res["broken"] is False
    assert res["verdict"] == "clean"


def test_nonce_unreadable_degraded():
    res = asyncio.run(pbl.check_nonce_continuity(
        FakeReader(), _nonce_cfg()))
    assert res["broken"] is False
    assert res["verdict"] == "degraded"


# ---------------------------------------------------------------------------
# Target specs + registry
# ---------------------------------------------------------------------------

def test_parse_bridge_target():
    cfg = pbl.parse_bridge_target(
        f"bridge-lock:ethereum:{VAULT}:{TOKEN_A}:bsc:{MINT_B}")
    assert isinstance(cfg, pbl.BridgeLockMintConfig)
    assert cfg.vault_a == VAULT and cfg.mint_token_b == MINT_B
    cfg = pbl.parse_bridge_target(f"bridge-quorum:ethereum:{BRIDGE}")
    assert isinstance(cfg, pbl.BridgeQuorumConfig)
    cfg = pbl.parse_bridge_target(
        f"bridge-nonce:ethereum:{BRIDGE_A}:bsc:{BRIDGE_B}")
    assert isinstance(cfg, pbl.BridgeNonceConfig)
    assert pbl.parse_bridge_target("0x" + "11" * 20) is None
    assert pbl.parse_bridge_target(
        "bridge-lock:ethereum:not-an-address:0x00:bsc:0x00") is None
    assert pbl.parse_bridge_target(
        "bridge-lock:nosuchchain:0x" + "11" * 20 + ":0x" + "22" * 20
        + ":bsc:0x" + "33" * 20) is None


def test_parse_guardian_set_real_layout():
    # Real getGuardianSet(7) return, read live 2026-11-13 from the
    # Wormhole core contract: struct {address[] keys; uint32
    # expiry} - word0 = 0x20 (offset to struct), word1 = 0x40
    # (offset to keys), word2 = expiry 0 (current set), word3 = 19
    # keys. A naive word2 read reports 0 guardians (false broken).
    raw = (
        "0x0000000000000000000000000000000000000000000000000000000000000020"
        "0000000000000000000000000000000000000000000000000000000000000040"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000013"
        "0000000000000000000000005893b5a76c3f739645648885bdccc06cd70a3cd3"
        "000000000000000000000000ff6cb952589bde862c25ef4392132fb9d4a42157"
        "000000000000000000000000114de8460193bdf3a2fcf81f86a09765f4762fd1"
        "000000000000000000000000107a0086b32d7a0977926a205131d8731d39cbeb"
        "0000000000000000000000008c82b2fd82faed2711d59af0f2499d16e726f6b2"
        "00000000000000000000000042579bffbcf4276e290ab8e4c162bd4052b97970"
        "000000000000000000000000938f104aeb5581293216ce97d771e0cb721221b1"
        "000000000000000000000000f3ea0ad4ffb5a178ae4ebc21861651b25bdcbb91"
        "0000000000000000000000009d16870160e703324d057c3361c34c5befba2c34"
        "000000000000000000000000000ac0076727b35fbea2dac28fee5ccb0fea768e"
        "000000000000000000000000af45ced136b9d9e24903464ae889f5c8a723fc14"
        "000000000000000000000000f93124b7c738843cbb89e864c862c38cddcccf95"
        "000000000000000000000000d2cc37a4dc036a8d232b48f62cdd4731412f4890"
        "000000000000000000000000da798f6896a3331f64b48c12d1d57fd9cbe70811"
        "000000000000000000000000ae565927bb8db25cd8bf3e7bb663d70023e4ea78"
        "0000000000000000000000003f851ad586a47cef8d04748f33ab0d71395f06b4"
        "000000000000000000000000178e21ad2e77ae06711549cfbb1f9c7a9d8096e8"
        "0000000000000000000000007899ceab1dc961dae9defdb7a4f521269a5448fc"
        "00000000000000000000000061d9800f9fcb4160fb0c6cf3a0902592bac2b434")
    parsed = pbl.parse_guardian_set(raw)
    assert parsed == {"guardian_count": 19, "expiry": 0}, parsed
    assert pbl.parse_guardian_set("0x") is None
    assert pbl.parse_guardian_set(None) is None
    # Flat (non-struct) layout must not parse as a guardian set.
    flat = ("0x" + "0" * 64 * 2 + format(19, "064x")
            + "0" * 64)
    assert pbl.parse_guardian_set(flat) is None


def test_live_plugins_registered():
    reg = discover()
    for pid in ("proxy_live_upgrade_window",
                "bridge_live_locked_vs_minted",
                "bridge_live_validator_quorum",
                "bridge_live_nonce_continuity"):
        assert pid in reg, f"{pid} missing from registry"
