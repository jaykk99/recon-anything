"""Tier-9 Forked Mainnet Simulation & Dynamic Execution Analysis.

HARD RULE under test: every Tier-9 finding is SIM-DERIVED and
UNVERIFIED - never VERIFIED_REAL, never proof. A dedicated test
asserts the markers on EVERY finding from EVERY shipped plugin.

Shipped (8): anvil_fork_probe, hardhat_fork_config, chisel_repl_eval,
ganache_timewarp_probe, halmos_symbolic, certora_rules,
scribble_annotations, forge_inspect.

DUPLICATE-OF (2, behavior-checked against the existing lane, no new
plugin):
- Echidna -> contract_fuzz: fuzz_engine() resolves the real Echidna
  binary and the lane builds an Echidna harness with stranger-profit
  properties (tests/test_contract_fuzz.py canaries A-F).
- Suri -> contract_fuzz + contract_simulation's Mythril symbolic
  lane: Suri's lineage is Solidity/Vyper fuzz+symbolic property
  testing, which is exactly those two lanes' combined surface.

Per shipped plugin: fires on VULN fixture, silent on CLEAN, no crash
on malformed. Sources are injected via ctx.shared["tier9_sources"]
(the plugins' documented upstream/test injection point) so no
network is touched; anvil_fork_probe's sequence transport is stubbed
(the real planning + flag discipline + marking run).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import anvil_fork_probe as afp  # noqa: E402
from app.plugins import certora_rules as cert  # noqa: E402
from app.plugins import chisel_repl_eval as chisel  # noqa: E402
from app.plugins import contract_fuzz as cf  # noqa: E402
from app.plugins import contract_sim as cs  # noqa: E402
from app.plugins import forge_inspect as fi  # noqa: E402
from app.plugins import ganache_timewarp_probe as gan  # noqa: E402
from app.plugins import halmos_symbolic as hal  # noqa: E402
from app.plugins import hardhat_fork_config as hh  # noqa: E402
from app.plugins import scribble_annotations as scr  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x" + "ab" * 20
NEW_IDS = ["anvil_fork_probe", "hardhat_fork_config", "chisel_repl_eval",
           "ganache_timewarp_probe", "halmos_symbolic", "certora_rules",
           "scribble_annotations", "forge_inspect"]


class FakeCtx:
    def __init__(self, source=None, shared=None):
        self.keys = {}
        self.mode = "active"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = "tier9-test"
        self.module_overrides = {}
        self.shared = dict(shared or {})
        if source is not None:
            self.shared["tier9_sources"] = [
                {"address": ADDR, "chain": "ethereum",
                 "chain_id": "ethereum", "source": source,
                 "origin": "fixture"}]

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


def _run(plugin, source):
    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet")
    return asyncio.run(plugin.run(target, FakeCtx(source)))


def _keys(res):
    return [f.key for f in res.findings]


def _assert_unverified(res):
    for f in res.findings:
        assert f.evidence["verdict"] == "UNVERIFIED", f
        assert f.evidence["verification_status"] == "UNVERIFIED"
        assert f.evidence["sim_derived"] is True
        assert f.evidence["proof_type"] == "simulation_only_not_proof"
        assert f.evidence["not_verified_real"] is True
        assert "VERIFIED_REAL" not in f.value


# ------------------------------------------------------------------
# 1. anvil_fork_probe
# ------------------------------------------------------------------
ANVIL_VULN = r"""
contract SimVault {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""
ANVIL_CLEAN = r"""
contract SimVaultGated {
    address public owner;
    mapping(address => uint256) public balances;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawAll() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""


def _stub_seq(monkeypatch, status):
    async def fake(ctx, chain, addr, seq):
        return {"status": status, "engine": "stub-fork",
                "detail": "stubbed"}
    monkeypatch.setattr(afp, "execute_sequence", fake)


def test_anvil_fires_on_vuln(monkeypatch):
    _stub_seq(monkeypatch, "success")
    # planning is stateful: a sequence exists for the sweep function
    seqs = afp.plan_sequences(ANVIL_VULN)
    assert seqs and seqs[0]["target"]["name"] == "withdrawAll"
    res = _run(afp.AnvilForkProbePlugin(), ANVIL_VULN)
    assert "fork_probe_candidate" in _keys(res)
    _assert_unverified(res)


def test_anvil_silent_on_clean(monkeypatch):
    _stub_seq(monkeypatch, "revert")  # gated on a real fork: reverts
    res = _run(afp.AnvilForkProbePlugin(), ANVIL_CLEAN)
    assert res.findings == []


def test_anvil_malformed_no_crash(monkeypatch):
    _stub_seq(monkeypatch, "success")
    res = _run(afp.AnvilForkProbePlugin(), "not solidity {{{ ;;")
    assert res.findings == []


# ------------------------------------------------------------------
# 2. hardhat_fork_config
# ------------------------------------------------------------------
HH_VULN = r"""
// hardhat.config.js
module.exports = {
  networks: { hardhat: {
    forking: { url: "https://eth-mainnet.g.alchemy.com/v2/AbCdEfGhIjKlMnOpQrStUvWx12345678" },
    accounts: ["0xabababababababababababababababababababababababababababababababab"]
  } }
};
"""
HH_CLEAN = r"""
// hardhat.config.js
module.exports = {
  networks: { hardhat: {
    forking: { url: "https://ethereum-rpc.publicnode.com", blockNumber: 19000000 }
  } }
};
"""


def test_hardhat_fires_on_vuln():
    res = _run(hh.HardhatForkConfigPlugin(), HH_VULN)
    assert "hardhat_fork_rpc_key_leak" in _keys(res)
    assert "hardhat_fork_unpinned_block" in _keys(res)
    _assert_unverified(res)


def test_hardhat_silent_on_clean():
    res = _run(hh.HardhatForkConfigPlugin(), HH_CLEAN)
    assert res.findings == []


def test_hardhat_malformed_no_crash():
    res = _run(hh.HardhatForkConfigPlugin(), "{{{ forking:")
    assert res.findings == []


# ------------------------------------------------------------------
# 3. chisel_repl_eval
# ------------------------------------------------------------------
CHISEL_VULN = r"""
contract Fees {
    uint256 public constant FEE_BPS = 10000;
    uint256 public constant MAX_SUPPLY = type(uint256).max;
    uint256 public constant THRESHOLD = 1;
}
"""
CHISEL_CLEAN = r"""
contract Fees {
    uint256 public constant FEE_BPS = 250;
    uint256 public constant MAX_SUPPLY = 1000000 * (10 ** 18);
    uint256 public constant THRESHOLD = 3;
}
"""


def test_chisel_evaluates_constants():
    env = chisel.evaluate_constants(CHISEL_VULN)
    assert env["FEE_BPS"] == 10000
    assert env["MAX_SUPPLY"] == (1 << 256) - 1
    assert env["THRESHOLD"] == 1
    assert chisel.evaluate_constants(CHISEL_CLEAN)["MAX_SUPPLY"] == \
        1000000 * 10 ** 18


def test_chisel_fires_on_vuln():
    res = _run(chisel.ChiselReplEvalPlugin(), CHISEL_VULN)
    assert "chisel_eval_dangerous_fee" in _keys(res)
    assert "chisel_eval_unlimited_cap" in _keys(res)
    assert "chisel_eval_weak_threshold" in _keys(res)
    _assert_unverified(res)


def test_chisel_silent_on_clean_and_malformed():
    assert _run(chisel.ChiselReplEvalPlugin(), CHISEL_CLEAN).findings == []
    assert _run(chisel.ChiselReplEvalPlugin(), "uint256 constant ;;").findings == []


# ------------------------------------------------------------------
# 4. ganache_timewarp_probe
# ------------------------------------------------------------------
GAN_VULN = r"""
contract TimeVault {
    uint256 public unlockTime;
    function setUnlock(uint256 t) public { unlockTime = t; }
    function withdraw() public {
        require(block.timestamp >= unlockTime);
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""
GAN_CLEAN = r"""
contract TimeVault {
    address public owner;
    uint256 public unlockTime;
    constructor() { owner = msg.sender; unlockTime = 1893456000; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setUnlock(uint256 t) public onlyOwner { unlockTime = t; }
    function withdraw() public {
        require(block.timestamp >= unlockTime);
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""


def test_ganache_fires_on_vuln():
    res = _run(gan.GanacheTimewarpProbePlugin(), GAN_VULN)
    assert "ganache_timewarp_anchor_settable" in _keys(res)
    _assert_unverified(res)


def test_ganache_silent_on_clean_and_malformed():
    assert _run(gan.GanacheTimewarpProbePlugin(), GAN_CLEAN).findings == []
    assert _run(gan.GanacheTimewarpProbePlugin(), "require(block.timestamp >=").findings == []


# ------------------------------------------------------------------
# 5. halmos_symbolic
# ------------------------------------------------------------------
HAL_VULN = r"""
contract H {
    uint256 public totalSupply;
    uint256 public cap;
    function mint(uint256 a) public { totalSupply += a; }
    function check_supplyBound() public view {
        assert(totalSupply <= cap);
    }
}
"""
HAL_CLEAN = r"""
contract H {
    uint256 public totalSupply;
    uint256 public cap;
    function mint(uint256 a) public {
        require(totalSupply + a <= cap);
        totalSupply += a;
    }
    function check_supplyBound() public view {
        assert(totalSupply <= cap);
    }
}
"""


def test_halmos_fires_on_vuln():
    res = _run(hal.HalmosSymbolicPlugin(), HAL_VULN)
    assert "halmos_invariant_contradicted" in _keys(res)
    _assert_unverified(res)


def test_halmos_silent_on_clean_and_malformed():
    assert _run(hal.HalmosSymbolicPlugin(), HAL_CLEAN).findings == []
    assert _run(hal.HalmosSymbolicPlugin(), "assert( {{{").findings == []


# ------------------------------------------------------------------
# 7. certora_rules
# ------------------------------------------------------------------
CERT_VULN = r"""
contract C {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    function mint(address to, uint256 a) public { balances[to] += a; }
    function transfer(address to, uint256 a) public {
        balances[msg.sender] -= a;
        balances[to] += a / 2;
    }
}
"""
CERT_CLEAN = r"""
contract C {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    function mint(address to, uint256 a) public {
        balances[to] += a;
        totalSupply += a;
    }
    function transfer(address to, uint256 a) public {
        balances[msg.sender] -= a;
        balances[to] += a;
    }
}
"""


def test_certora_fires_on_vuln():
    res = _run(cert.CertoraRulesPlugin(), CERT_VULN)
    assert "certora_rule_sum_of_balances" in _keys(res)
    assert "certora_rule_conservation" in _keys(res)
    _assert_unverified(res)


def test_certora_silent_on_clean_and_malformed():
    assert _run(cert.CertoraRulesPlugin(), CERT_CLEAN).findings == []
    assert _run(cert.CertoraRulesPlugin(), "mapping( => {{{").findings == []


# ------------------------------------------------------------------
# 8. scribble_annotations
# ------------------------------------------------------------------
SCR_VULN = r"""
contract S {
    address public owner;
    /// #if_succeeds {:msg "only owner may call"} msg.sender == owner;
    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""
SCR_CLEAN = r"""
contract S {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    /// #if_succeeds {:msg "only owner may call"} msg.sender == owner;
    function withdrawAll() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""


def test_scribble_parses_annotations():
    anns = scr.parse_annotations(SCR_VULN)
    assert anns and anns[0]["kind"] == "if_succeeds"
    assert anns[0]["function"] == "withdrawAll"


def test_scribble_fires_on_vuln():
    res = _run(scr.ScribbleAnnotationsPlugin(), SCR_VULN)
    assert "scribble_annotation_unenforced" in _keys(res)
    _assert_unverified(res)


def test_scribble_silent_on_clean_and_malformed():
    assert _run(scr.ScribbleAnnotationsPlugin(), SCR_CLEAN).findings == []
    assert _run(scr.ScribbleAnnotationsPlugin(), "/// #if_succeeds").findings == []


# ------------------------------------------------------------------
# 9. forge_inspect
# ------------------------------------------------------------------
FI_VULN = r"""
contract Up {
    address public owner;
    function upgradeTo(address impl) external { owner = impl; }
    function setOwner(address o) external { owner = o; }
    function kill() external { selfdestruct(payable(msg.sender)); }
}
"""
FI_CLEAN = r"""
contract Up {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function upgradeTo(address impl) external onlyOwner { }
    function setOwner(address o) external onlyOwner { owner = o; }
}
"""


def test_forge_inspect_catalog_helpers():
    methods = fi.method_identifiers(FI_VULN)
    assert methods["upgradeTo(address)"] == "0x3659cfe6"
    # canonicalization: bare `uint` in source is uint256 in the ABI
    weth_like = ("contract W { function withdraw(uint a) external {} "
                 "function approve(address s, uint a) external {} }")
    wm = fi.method_identifiers(weth_like)
    assert wm["withdraw(uint256)"] == "0x2e1a7d4d"
    assert wm["approve(address,uint256)"] == "0x095ea7b3"
    layout = fi.storage_layout(FI_VULN)
    assert layout and layout[0]["name"] == "owner" and layout[0]["slot"] == 0


def test_forge_inspect_fires_on_vuln():
    res = _run(fi.ForgeInspectPlugin(), FI_VULN)
    assert "forge_inspect_unguarded_upgrade_selector" in _keys(res)
    assert "forge_inspect_owner_slot_ungated_write" in _keys(res)
    _assert_unverified(res)


def test_forge_inspect_silent_on_clean_and_malformed():
    assert _run(fi.ForgeInspectPlugin(), FI_CLEAN).findings == []
    assert _run(fi.ForgeInspectPlugin(), "function ( {{{").findings == []


# ------------------------------------------------------------------
# Duplicates: behavior-check the EXISTING lanes, no new plugins
# ------------------------------------------------------------------
def test_echidna_is_duplicate_of_contract_fuzz():
    assert "echidna_fuzz" not in discover()
    assert "contract_fuzz" in discover()
    engine = cf.fuzz_engine()
    assert engine is not None and "echidna" in engine  # real binary here


def test_suri_is_duplicate_of_fuzz_and_symbolic_lanes():
    ids = discover()
    assert not any("suri" in i for i in ids)
    assert "contract_fuzz" in ids            # fuzz/property lane
    assert "contract_simulation" in ids      # symbolic (Mythril) lane
    assert hasattr(cs, "run_symbolic") and hasattr(cs, "find_mythril")


# ------------------------------------------------------------------
# Registry + the UNVERIFIED marker across every shipped plugin
# ------------------------------------------------------------------
def test_registry_tier9():
    ids = discover()
    for pid in NEW_IDS:
        assert pid in ids, pid
    assert len(ids) == 967  # 927 master + 8 tier9 (2 duplicates ship none) + 10 Tier-10 Mempool/MEV plugins (PR #130)


def test_every_tier9_finding_is_unverified_sim_derived(monkeypatch):
    _stub_seq(monkeypatch, "success")
    runs = [
        _run(afp.AnvilForkProbePlugin(), ANVIL_VULN),
        _run(hh.HardhatForkConfigPlugin(), HH_VULN),
        _run(chisel.ChiselReplEvalPlugin(), CHISEL_VULN),
        _run(gan.GanacheTimewarpProbePlugin(), GAN_VULN),
        _run(hal.HalmosSymbolicPlugin(), HAL_VULN),
        _run(cert.CertoraRulesPlugin(), CERT_VULN),
        _run(scr.ScribbleAnnotationsPlugin(), SCR_VULN),
        _run(fi.ForgeInspectPlugin(), FI_VULN),
    ]
    total = sum(len(r.findings) for r in runs)
    assert total >= 12, total
    for r in runs:
        assert r.findings, r.plugin_id
        _assert_unverified(r)


def test_malformed_shared_sources_no_crash():
    ctx = FakeCtx(shared={"tier9_sources": [
        {"nope": 1}, "junk", {"source": 42},
        {"source": "contract X { }", "address": ADDR}]})
    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet")
    for plugin in (hh.HardhatForkConfigPlugin(), cert.CertoraRulesPlugin(),
                   fi.ForgeInspectPlugin()):
        res = asyncio.run(plugin.run(target, ctx))
        assert res.findings == []
