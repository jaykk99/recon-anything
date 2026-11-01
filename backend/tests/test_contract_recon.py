"""Smart Contract Recon (contract_recon) tests.

Layers:
1. Chain config + target parsing (config-driven chains).
2. Verified-source analysis against fixture contracts: a feature-rich
   vault, an Ethernaut-"Fallback"-style vulnerable contract (fixtures
   written for this suite, modeled on the public Ethernaut pattern),
   and a safe vault that must NOT trigger the takeover detectors.
   Secrets are asserted IN FULL (Jay's 2026-10-29 order: no masking).
3. Bytecode analysis: crafted runtime bytecode with known selectors,
   sensitive opcodes, an EIP-1167 minimal proxy, and a CBOR metadata
   tail (ipfs + solc).
4. Plugin runs with the chain layer stubbed (no network): source
   path, bytecode-only path, total RPC failure (fail closed), and
   the web-scan bus path.
"""
import asyncio
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import contract_recon  # noqa: E402
from app.plugins.base import PluginStatus, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x" + "ab" * 20
FAKE_PRIVATE_KEY = ("0x4c0883a69102937d6231471b5dbb6204fe5129617082792"
                    "ae468d01a3f362318")

VULN_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DemoVault {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    address public owner;
    address public treasury = 0x1234567890AbcdEF1234567890aBcdef12345678;
    string public apiEndpoint = "https://api.example-vault.io/v1";
    string private backupKey = "BACKUPKEY";
    mapping(address => uint256) public balances;
    mapping(address => bool) public blacklisted;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) public onlyOwner {
        balances[to] += amount;
    }

    function withdrawAll() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function blacklist(address user, bool flag) public onlyOwner {
        blacklisted[user] = flag;
    }

    function execute(address target, bytes calldata data) public onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    function kill() public onlyOwner {
        selfdestruct(payable(owner));
    }

    function isOwner() public view returns (bool) {
        return tx.origin == owner;
    }

    function payout(address to, uint256 amount) public {
        to.call{value: amount}("");
    }
}
""".replace("BACKUPKEY", FAKE_PRIVATE_KEY)

# Ethernaut "Fallback"-style fixture, written for this suite from the
# public pattern: contribute() tracks per-sender deposits, receive()
# hands ownership to any sender, withdraw() drains everything.
FALLBACK_SOURCE = r"""
pragma solidity ^0.8.0;

contract Fallback {
    mapping(address => uint256) public contributions;
    address public owner;

    constructor() {
        owner = msg.sender;
        contributions[msg.sender] = 1000 * (1 ether);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function contribute() public payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }

    function getContribution() public view returns (uint256) {
        return contributions[msg.sender];
    }

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 0);
        owner = msg.sender;
    }
}
"""

SAFE_SOURCE = r"""
pragma solidity ^0.8.20;

contract SafeVault {
    mapping(address => uint256) public deposits;
    address private immutable owner;

    event Received(address from, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function setEmergencyContact(address contact) public onlyOwner {
        emergencyContact = contact;
    }

    address public emergencyContact;

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }
}
"""


def _kinds(findings):
    return {f["kind"] for f in findings}


def _by_kind(findings, kind):
    return [f for f in findings if f["kind"] == kind]


# ---------------------------------------------------------------------------
# 1. Chain config + target parsing
# ---------------------------------------------------------------------------

def test_chain_config():
    assert cc.CHAINS["ethereum"].chain_id == 1
    assert cc.CHAINS["bsc"].chain_id == 56
    for chain in cc.CHAINS.values():
        assert chain.rpc_urls, chain.id
        assert "{addr}" in chain.explorer_address
        assert chain.blockscout_api, chain.id


def test_parse_target_address():
    assert cc.parse_target_address(ADDR) == (None, ADDR)
    assert cc.parse_target_address("bsc:" + ADDR) == ("bsc", ADDR)
    assert cc.parse_target_address("eth:" + ADDR) == ("ethereum", ADDR)
    assert cc.parse_target_address("bnb:" + ADDR) == ("bsc", ADDR)
    assert cc.parse_target_address("example.com") == (None, None)
    assert cc.parse_target_address("0x123") == (None, None)


def test_registry():
    reg = discover()
    assert "contract_recon" in reg
    p = reg["contract_recon"]()
    assert p.group == "web3"
    assert p.requires_keys == []  # keyless-first, like the other web3 plugins
    assert "crypto_wallet" in p.accepts


# ---------------------------------------------------------------------------
# 2. Source analysis
# ---------------------------------------------------------------------------

def test_source_analysis_vuln():
    findings = cc.analyze_contract_source(
        VULN_SOURCE, {"contract_name": "DemoVault",
                      "compiler": "v0.8.20"})
    kinds = _kinds(findings)
    for want in ("identity", "proxy", "privileged_function",
                 "delegatecall", "selfdestruct", "tx_origin",
                 "unchecked_call", "hardcoded_address",
                 "embedded_endpoint", "secret_string",
                 "full_balance_withdraw"):
        assert want in kinds, f"missed {want}: {sorted(kinds)}"

    ident = _by_kind(findings, "identity")[0]
    assert ident["contract_name"] == "DemoVault"
    assert "contract DemoVault" in ident["code"]

    priv = _by_kind(findings, "privileged_function")
    cats = {f["priv_category"] for f in priv}
    for want in ("mint", "withdraw_sweep", "pause", "blacklist"):
        assert want in cats, f"missed privileged {want}: {cats}"
    mint = [f for f in priv if f["priv_category"] == "mint"][0]
    assert "function mint" in mint["code"]  # the code is SHOWN
    assert mint["gated"] is True

    # Proxy carries the ERC1967 evidence.
    proxy = _by_kind(findings, "proxy")[0]
    assert "ERC1967" in proxy["title"]

    # Secret shown IN FULL, never masked (Jay's 2026-10-29 order).
    sec = _by_kind(findings, "secret_string")[0]
    assert sec["secret_value"] == FAKE_PRIVATE_KEY
    assert FAKE_PRIVATE_KEY in sec["title"]
    assert "..." not in sec["title"].split(":")[-1]
    # The ERC1967 slot constant must NOT be flagged as a secret.
    assert not any("360894a13ba1a3210667c828492db98dca3e2076cc3735a920"
                   "a3ca505d382bbc" in f["title"]
                   for f in _by_kind(findings, "secret_string"))

    # No takeover path here: no fallback/deposit route to ownership.
    assert "ownership_takeover_path" not in kinds
    assert "ownership_takeover_fallback" not in kinds
    assert "deposit_to_own" not in kinds


def test_source_analysis_fallback_pattern():
    findings = cc.analyze_contract_source(FALLBACK_SOURCE, {})
    kinds = _kinds(findings)
    assert "ownership_takeover_fallback" in kinds, sorted(kinds)
    assert "deposit_to_own" in kinds, sorted(kinds)
    assert "full_balance_withdraw" in kinds, sorted(kinds)
    assert "ownership_takeover_path" in kinds, sorted(kinds)

    path = _by_kind(findings, "ownership_takeover_path")[0]
    assert path["severity"] == "high"
    # All three code pieces are shown together in the one finding.
    for piece in ("function contribute", "receive()",
                  "function withdraw"):
        assert piece in path["code"], f"path finding missing {piece}"

    d1 = _by_kind(findings, "ownership_takeover_fallback")[0]
    assert "owner = msg.sender" in d1["code"]

    d2 = _by_kind(findings, "deposit_to_own")[0]
    assert d2["mapping"] == "contributions"


def test_source_analysis_safe():
    findings = cc.analyze_contract_source(SAFE_SOURCE, {})
    kinds = _kinds(findings)
    for bad in ("ownership_takeover_fallback", "deposit_to_own",
                "full_balance_withdraw", "ownership_takeover_path",
                "fallback_state_write", "delegatecall",
                "selfdestruct", "tx_origin", "secret_string",
                "unchecked_call"):
        assert bad not in kinds, f"safe contract triggered {bad}"


def test_fallback_state_write_quirk():
    src = r"""
    pragma solidity ^0.8.0;
    contract TipJar {
        uint256 public totalTips;
        fallback() external payable {
            totalTips += msg.value;
        }
    }
    """
    findings = cc.analyze_contract_source(src, {})
    assert "fallback_state_write" in _kinds(findings)
    fw = _by_kind(findings, "fallback_state_write")[0]
    assert "totalTips += msg.value" in fw["code"]


# ---------------------------------------------------------------------------
# 3. Bytecode analysis
# ---------------------------------------------------------------------------

def _craft_bytecode() -> str:
    ipfs_hash = bytes.fromhex("1220" + "ab" * 32)
    cbor = (bytes([0xA2]) + b"\x64ipfs" + bytes([0x58, 0x22]) +
            ipfs_hash + b"\x64solc" + bytes([0x43, 0, 8, 20]))
    body = bytes.fromhex(
        "63a9059cbb"      # PUSH4 transfer(address,uint256)
        "63" "8da5cb5b"   # PUSH4 owner()
        "63" "deadbeef"   # PUSH4 unknown selector
        "f4"              # DELEGATECALL
        "f1"              # CALL
        "ff"              # SELFDESTRUCT
    )
    code = body + cbor + len(cbor).to_bytes(2, "big")
    return "0x" + code.hex()


def test_bytecode_analysis():
    hex_code = _craft_bytecode()
    bc = cc.analyze_bytecode(hex_code)
    raw = bytes.fromhex(hex_code[2:])
    assert bc["size"] == len(raw)
    assert bc["sha256"] == hashlib.sha256(raw).hexdigest()

    sels = {s["selector"]: s["signature"] for s in bc["selectors"]}
    assert sels["0xa9059cbb"] == "transfer(address,uint256)"
    assert sels["0x8da5cb5b"] == "owner()"
    assert sels["0xdeadbeef"] is None  # unknown, honestly labeled

    assert bc["opcodes"].get("DELEGATECALL") == 1
    assert bc["opcodes"].get("SELFDESTRUCT") == 1
    assert bc["opcodes"].get("CALL") == 1

    assert bc["metadata"]["ipfs"] == "1220" + "ab" * 32
    assert bc["metadata"]["solc"] == "0.8.20"
    assert bc["minimal_proxy_impl"] is None


def test_bytecode_minimal_proxy():
    impl = "cd" * 20
    code = ("0x363d3d373d3d3d363d73" + impl +
            "5af43d82803e903d91602b57fd5bf3")
    bc = cc.analyze_bytecode(code)
    assert bc["minimal_proxy_impl"] == "0x" + impl


def test_bytecode_empty_and_garbage():
    assert cc.analyze_bytecode("0x")["size"] == 0
    assert cc.analyze_bytecode("not hex")["size"] == 0


# ---------------------------------------------------------------------------
# 4. Plugin runs (chain layer stubbed, no network)
# ---------------------------------------------------------------------------

class FakeCtx:
    def __init__(self, shared=None):
        self.keys = {}
        self.mode = "passive"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = "test"
        self.module_overrides = {}
        self.shared = shared or {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


def _patch(monkeypatch, code_by_chain, source):
    async def fake_get_code(ctx, chain, address):
        return code_by_chain.get(chain.id)
    async def fake_source(ctx, chain, address, key=None):
        return source
    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)


def test_plugin_source_path(monkeypatch):
    src_meta = {"source": VULN_SOURCE, "contract_name": "DemoVault",
                "compiler": "v0.8.20+commit", "proxy": False,
                "implementation": "", "origin": "Blockscout"}
    _patch(monkeypatch, {"ethereum": _craft_bytecode()}, src_meta)
    p = contract_recon.ContractReconPlugin()
    target = Target(raw=ADDR, type="crypto_wallet", normalized=ADDR)
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.status == PluginStatus.OK
    keys = {f.key for f in res.findings}
    assert "contract_code_identity" in keys
    assert "contract_privileged_function" in keys
    assert "contract_secret_string" in keys
    assert "contract_bytecode" in keys
    secret = [f for f in res.findings
              if f.key == "contract_secret_string"][0]
    assert FAKE_PRIVATE_KEY in secret.value  # full, unmasked
    assert secret.evidence["secret_value"] == FAKE_PRIVATE_KEY
    ident = [f for f in res.findings
             if f.key == "contract_code_identity"][0]
    assert "DemoVault" in ident.value
    assert ident.evidence["chain"] == "ethereum"


def test_plugin_chain_prefix(monkeypatch):
    src_meta = {"source": FALLBACK_SOURCE, "contract_name": "Fallback",
                "compiler": "v0.8.0", "proxy": False,
                "implementation": "", "origin": "Sourcify"}
    _patch(monkeypatch, {"bsc": _craft_bytecode()}, src_meta)
    p = contract_recon.ContractReconPlugin()
    target = Target(raw="bsc:" + ADDR, type="username",
                    normalized="bsc:" + ADDR)
    res = asyncio.run(p.run(target, FakeCtx()))
    keys = {f.key for f in res.findings}
    assert "contract_ownership_takeover_path" in keys
    path = [f for f in res.findings
            if f.key == "contract_ownership_takeover_path"][0]
    assert path.evidence["chain"] == "bsc"
    assert path.evidence["severity"] == "high"


def test_plugin_bytecode_only_path(monkeypatch):
    _patch(monkeypatch, {"ethereum": _craft_bytecode()}, None)
    p = contract_recon.ContractReconPlugin()
    target = Target(raw=ADDR, type="crypto_wallet", normalized=ADDR)
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.status == PluginStatus.OK
    keys = {f.key for f in res.findings}
    assert "contract_source_unavailable" in keys
    bc_f = [f for f in res.findings if f.key == "contract_bytecode"][0]
    assert "SOURCE UNAVAILABLE" in bc_f.value
    assert "transfer(address,uint256)" in bc_f.value
    assert bc_f.evidence["source_available"] is False


def test_plugin_rpc_failure_fails_closed(monkeypatch):
    async def boom(ctx, chain, address):
        raise RuntimeError("network down")

    async def no_source(ctx, chain, address, key=None):
        return None
    monkeypatch.setattr(cc, "rpc_get_code", boom)
    monkeypatch.setattr(cc, "fetch_verified_source", no_source)
    p = contract_recon.ContractReconPlugin()
    target = Target(raw=ADDR, type="crypto_wallet", normalized=ADDR)
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.status == PluginStatus.OK  # honest finding, no crash
    # rpc_get_code raising inside _recon_address propagates to run()'s
    # guard, which emits the failure finding.
    assert any(f.key == "contract_recon_failed" for f in res.findings)


def test_plugin_no_code_anywhere(monkeypatch):
    _patch(monkeypatch, {c: "0x" for c in cc.CHAINS}, None)
    p = contract_recon.ContractReconPlugin()
    target = Target(raw=ADDR, type="crypto_wallet", normalized=ADDR)
    res = asyncio.run(p.run(target, FakeCtx()))
    assert any(f.key == "contract_no_code" for f in res.findings)


def test_plugin_bus_addresses(monkeypatch):
    src_meta = {"source": FALLBACK_SOURCE, "contract_name": "Fallback",
                "compiler": "v0.8.0", "proxy": False,
                "implementation": "", "origin": "Blockscout"}
    _patch(monkeypatch, {"ethereum": _craft_bytecode()}, src_meta)
    p = contract_recon.ContractReconPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    ctx = FakeCtx(shared={"contract_addresses": [ADDR]})
    res = asyncio.run(p.run(target, ctx))
    assert any(f.key == "contract_ownership_takeover_path"
               for f in res.findings)


def test_plugin_skips_cleanly_without_addresses():
    p = contract_recon.ContractReconPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.status == PluginStatus.OK
    assert res.findings == []
