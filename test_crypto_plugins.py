"""Test the 4 crypto security plugins. No network needed except when keys set."""
import asyncio
import sys

sys.path.insert(0, "backend")

from app.plugins import shodan_enum, chain_osint, contract_audit, defi_risk  # noqa: E402
from app.plugins.base import Target, Ctx, PluginStatus  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.plugins.contract_audit import audit_source  # noqa: E402
from app.plugins.defi_risk import scan_defi_risks  # noqa: E402


class FakeCtx:
    """Minimal ctx for plugin.run(): skip paths never touch http/limiter."""
    def __init__(self, keys=None, shared=None):
        self.keys = keys or {}
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


VULN_SRC = """
pragma solidity ^0.4.24;
contract Vault {
    mapping(address => uint) public balances;
    address public owner;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint amt) public {
        require(balances[msg.sender] >= amt);
        msg.sender.call.value(amt)("");
        balances[msg.sender] -= amt;
    }
    function drain() public { owner.transfer(address(this).balance); }
    function auth(address u) public { if (tx.origin == owner) { balances[u] = 100; } }
    function riskySend(address to) public { to.send(1 ether); }
}
"""

CLEAN_SRC = """
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Vault is ReentrancyGuard {
    mapping(address => uint) private balances;
    address private immutable owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner { require(msg.sender == owner, "no"); _; }
    function withdraw(uint amt) public nonReentrant {
        require(balances[msg.sender] >= amt, "bal");
        balances[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "xfer fail");
    }
    function setOwner(address o) public onlyOwner { owner = o; }
}
"""

DEFI_SRC = """
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
contract Pool is ERC1967Proxy {
    address public owner;
    uint public fee;
    mapping(address => uint) public balances;
    modifier onlyOwner { require(msg.sender == owner); _; }
    function setFee(uint f) public onlyOwner { fee = f; }
    function pause() public onlyOwner { paused = true; }
    function _takeFee(address from, uint amt) internal { balances[from] -= amt * fee / 100; }
    function mint(address to, uint amt) public onlyOwner { balances[to] += amt; }
    function _afterTokenTransfer(address from, address to, uint amt) internal {
        if (fee > 0) { _takeFee(from, amt); }
    }
    function fallback() external payable { address(impl).delegatecall(msg.data); }
}
"""


def test_registry():
    reg = discover()
    for pid in ("shodan_enum", "chain_osint", "contract_audit", "defi_risk"):
        assert pid in reg, f"plugin {pid} not registered"
        p = reg[pid]()
        assert p.group == "web3", f"{pid} group={p.group}"
        # Deliberate design (Jay's standing order): web3 plugins are
        # keyless-first. They work without keys and a key only enhances
        # them, so requires_keys must stay EMPTY.
        assert p.requires_keys == [], \
            f"{pid} must stay keyless-first, got requires_keys={p.requires_keys}"
    print("PASS registry: all 4 plugins registered, group=web3, keyless-first")


def test_audit_source():
    issues = audit_source(VULN_SRC)
    checks = {i["check"] for i in issues}
    assert "reentrancy" in checks, f"missed reentrancy: {checks}"
    assert "tx_origin" in checks, f"missed tx.origin: {checks}"
    assert "unchecked_call" in checks, f"missed unchecked call: {checks}"
    assert "overflow" in checks, f"missed pre-0.8 overflow: {checks}"
    mac = [i for i in issues if i["check"] == "missing_access_control"]
    assert any(i["function"] == "auth" for i in mac), f"missed unguarded auth: {checks}"
    print(f"PASS audit_source(vuln): found {sorted(checks)}")
    clean_issues = audit_source(CLEAN_SRC)
    bad = [i for i in clean_issues if i["severity"] in ("high",)]
    assert not bad, f"clean contract flagged: {clean_issues}"
    print(f"PASS audit_source(clean): {len(clean_issues)} low/med notes, no highs")


def test_defi_scan():
    risks = scan_defi_risks(DEFI_SRC)
    checks = {r["check"] for r in risks}
    for want in ("proxy", "owner_only", "pause", "fee_on_transfer", "mint"):
        assert want in checks, f"missed {want}: {checks}"
    print(f"PASS scan_defi_risks: found {sorted(checks)}")
    clean_risks = scan_defi_risks(CLEAN_SRC)
    clean_checks = {r["check"] for r in clean_risks}
    # onlyOwner on setOwner is a legit true positive; single_key_admin also
    # fires on purpose here: onlyOwner exists but no timelock/multisig/Safe
    # pattern is present, which is a real centralization finding. Nothing
    # structural beyond these two may appear.
    assert clean_checks <= {"owner_only", "single_key_admin"}, \
        f"clean contract over-flagged: {clean_checks}"
    assert not any(r["severity"] == "high" for r in clean_risks)
    print(f"PASS scan_defi_risks(clean): only {sorted(clean_checks)}, no highs")


async def test_skips():
    target = Target(raw="example.com", type="domain", normalized="example.com")
    for mod in (shodan_enum, chain_osint, contract_audit, defi_risk):
        p = next(v() for k, v in discover().items() if k == mod.__name__.split(".")[-1])
        res = await p.run(target, FakeCtx())
        assert res.status == PluginStatus.OK, f"{p.id} status={res.status}"
        assert res.findings == [], f"{p.id} produced findings without keys"
        low = res.reason.lower()
        assert "not configured" in low or "no " in low, f"{p.id} skip note unclear: {res.reason}"
        print(f"PASS {p.id}: skipped gracefully: {res.reason[:90]}")


async def test_skip_env_mentions():
    p = shodan_enum.ShodanEnumPlugin()
    res = await p.run(Target(raw="1.2.3.4", type="ip", normalized="1.2.3.4"), FakeCtx())
    assert "SHODAN_API_KEY" in res.reason
    p2 = chain_osint.ChainOsintPlugin()
    res2 = await p2.run(Target(raw="example.com", type="domain", normalized="example.com"),
                        FakeCtx(shared={"contract_addresses": ["0x" + "ab" * 20]}))
    assert "ETHERSCAN_API_KEY" in res2.reason
    print("PASS skip notes name the exact env vars")


if __name__ == "__main__":
    test_registry()
    test_audit_source()
    test_defi_scan()
    asyncio.run(test_skips())
    asyncio.run(test_skip_env_mentions())
    print("\nALL TESTS PASSED")
