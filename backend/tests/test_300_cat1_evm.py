"""300-expansion Category 1: EVM & Ethereum plugins (22 plugins).

Per plugin: fires on a VULN fixture, silent on a CLEAN fixture, no
crash on malformed input. Pure analysis functions are driven
directly; plugin run() is driven with a stub ctx whose discovery
bus carries the fixture (source / bytecode / structured records),
mirroring how phase-1 lanes feed phase-2 plugins in real scans.
The three simulation plugins (reentrancy-path-finder,
flashloan-simulator, ether-forcing-tester) must stamp every
finding UNVERIFIED.
"""
import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

IDS = ["vyper_bug_hunter", "immutable_arg_extractor",
       "evm_decompiler_bridge", "storage_slot_mapper",
       "contract_state_tracer", "abi_reconstructor",
       "reentrancy_path_finder", "gas_opt_analyzer",
       "solc_version_matcher", "flashloan_simulator",
       "oracle_drift_calc", "create2_address_predictor",
       "erc20_compliance_verify", "erc721_metadata_guard",
       "frontrunning_guard_eval", "access_control_scraper",
       "bytecode_diff_viewer", "constant_inliner_check",
       "yul_optimizer_audit", "ether_forcing_tester",
       "fallback_behavior_analyzer", "foundry_test_generator"]

ADDR = "0x1111111111111111111111111111111111111111"


def _handler(request):
    return httpx.Response(404, content="", request=request)


def _ctx(shared=None):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_handler), follow_redirects=True,
        trust_env=False)
    ctx = Ctx(run_id="cat1-test", mode="active", http=client,
              cache=Cache(), keys={}, limiter=RateLimiter(),
              evidence_dir="/tmp", source_type="website")
    ctx.shared.update(shared or {})
    return ctx


def run_plugin(pid, shared=None, raw=ADDR):
    from app.plugins.registry import discover
    cls = discover()[pid]
    ctx = _ctx(shared)

    async def _go():
        try:
            return await asyncio.wait_for(
                cls().run(Target(raw=raw, type="crypto_wallet",
                                 normalized=raw), ctx), timeout=30)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def keys_of(res):
    return {f.key for f in res.findings}


def test_registry_size_and_ids():
    from app.plugins.registry import discover
    reg = discover()
    assert len(reg) == 967  # 945 master + 22 Cat-1 (300-expansion) plugins
    for pid in IDS:
        assert pid in reg, pid


@pytest.mark.parametrize("pid", IDS)
def test_no_crash_on_malformed(pid):
    bad = Target(raw="", type="email", normalized="not a url @@")
    from app.plugins.registry import discover
    cls = discover()[pid]
    ctx = _ctx()

    async def _go():
        try:
            return await asyncio.wait_for(cls().run(bad, ctx),
                                          timeout=30)
        finally:
            await ctx.http.aclose()
    res = asyncio.run(_go())
    assert res is not None and isinstance(res.findings, list)


# ---------------------------------------------------------------------------
# 20. vyper-bug-hunter (SHIP)
# ---------------------------------------------------------------------------

VYPER_VULN = """
# @version 0.3.7
vault: public(address)

@external
@nonreentrant("lock")
def withdraw(to: address, amount: uint256):
    raw_call(to, b"", value=amount)
"""
VYPER_CLEAN = """
# @version 0.4.0
count: public(uint256)

@external
def ping():
    self.count += 1
"""


def test_vyper_fires():
    from app.plugins.vyper_bug_hunter import analyze_vyper_source
    ks = {h["key"] for h in analyze_vyper_source(VYPER_VULN)}
    assert "vyper_reentrancy_lock_compiler_bug" in ks
    assert "vyper_raw_call_user_target" in ks
    res = run_plugin("vyper_bug_hunter",
                     {"contract_source": [VYPER_VULN]})
    assert "vyper_reentrancy_lock_compiler_bug" in keys_of(res)


def test_vyper_silent():
    from app.plugins.vyper_bug_hunter import analyze_vyper_source
    assert analyze_vyper_source(VYPER_CLEAN) == []
    res = run_plugin("vyper_bug_hunter",
                     {"contract_source": [VYPER_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 29. immutable-arg-extractor (SHIP)
# ---------------------------------------------------------------------------

def _word_addr(a):
    return "0" * 24 + a[2:]


def _word_int(n):
    return "%064x" % n


RUNTIME = "0x" + _word_addr("0x2222222222222222222222222222222222222222") \
    + _word_int(500)
REFS = [{"name": "owner", "type": "address", "offset": 0, "length": 32},
        {"name": "feeBps", "type": "uint256", "offset": 32, "length": 32}]


def test_immutable_fires():
    from app.plugins.immutable_arg_extractor import extract_immutables
    hits = extract_immutables(RUNTIME, REFS)
    vals = {h["evidence"]["variable"]: h["evidence"]["decoded_value"]
            for h in hits}
    assert vals["owner"] == "0x2222222222222222222222222222222222222222"
    assert vals["feeBps"] == "500"
    args = extract_immutables(
        "", [], arg_hex="0x" + _word_addr(ADDR) + _word_int(42),
        constructor_types=["address", "uint256"])
    assert {h["evidence"]["decoded_value"] for h in args} >= {"42"}
    res = run_plugin("immutable_arg_extractor",
                     {"contract_bytecode": [RUNTIME],
                      "immutable_refs": REFS})
    assert "immutable_value_extracted" in keys_of(res)


def test_immutable_silent():
    from app.plugins.immutable_arg_extractor import extract_immutables
    assert extract_immutables("0x60006000f3", []) == []
    res = run_plugin("immutable_arg_extractor",
                     {"contract_bytecode": ["0x60006000f3"]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 1. evm-decompiler-bridge
# ---------------------------------------------------------------------------

BC_DANGER = "0x63a9059cbb6000f46000ff"  # PUSH4, PUSH1 0, DELEGATECALL, PUSH1 0, SELFDESTRUCT
BC_CLEAN = "0x60006000f3"


def test_decompiler_fires():
    from app.plugins.evm_decompiler_bridge import (
        analyze_decompiled, decompile_pseudocode)
    dec = decompile_pseudocode(BC_DANGER)
    assert dec["functions"][0]["name"] == "transfer"
    ks = {h["key"] for h in analyze_decompiled(BC_DANGER)}
    assert "decompiled_delegatecall_flow" in ks
    assert "decompiled_selfdestruct_flow" in ks
    res = run_plugin("evm_decompiler_bridge",
                     {"contract_bytecode": [BC_DANGER]})
    assert "decompiled_delegatecall_flow" in keys_of(res)


def test_decompiler_silent():
    from app.plugins.evm_decompiler_bridge import analyze_decompiled
    assert analyze_decompiled(BC_CLEAN) == []
    assert analyze_decompiled("0xzz") == []
    res = run_plugin("evm_decompiler_bridge",
                     {"contract_bytecode": [BC_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 2. storage-slot-mapper
# ---------------------------------------------------------------------------

STORAGE_VULN = """
contract Vault {
    address public owner;
    bool public paused;
    address public implementation;
    uint256 public totalAssets;
}
"""
STORAGE_CLEAN = """
contract Counter {
    uint256 public count;
    string public name;
    function inc() public { count += 1; }
}
"""


def test_storage_mapper_fires():
    from app.plugins.storage_slot_mapper import (
        analyze_layout, map_storage_layout)
    layout = map_storage_layout(STORAGE_VULN)
    by_name = {e["name"]: e for e in layout}
    assert by_name["owner"]["slot"] == 0
    assert by_name["paused"]["slot"] == 0  # packed with owner
    assert by_name["implementation"]["slot"] == 1
    ks = {h["key"] for h in analyze_layout(STORAGE_VULN)}
    assert "storage_slot_privileged_var" in ks
    res = run_plugin("storage_slot_mapper",
                     {"contract_source": [STORAGE_VULN]})
    assert "storage_slot_privileged_var" in keys_of(res)


def test_storage_mapper_silent():
    from app.plugins.storage_slot_mapper import analyze_layout
    assert analyze_layout(STORAGE_CLEAN) == []
    res = run_plugin("storage_slot_mapper",
                     {"contract_source": [STORAGE_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 3. contract-state-tracer
# ---------------------------------------------------------------------------

SLOT0 = "0x" + "0" * 64
SAMPLES_VULN = [
    {"block": 100, "slot": SLOT0, "label": "owner",
     "value": "0x" + "0" * 24 + "11" * 20},
    {"block": 200, "slot": SLOT0, "label": "owner",
     "value": "0x" + "0" * 24 + "22" * 20},
]
SAMPLES_CLEAN = [
    {"block": 100, "slot": SLOT0, "label": "owner",
     "value": "0x" + "0" * 24 + "11" * 20},
    {"block": 200, "slot": SLOT0, "label": "owner",
     "value": "0x" + "0" * 24 + "11" * 20},
]


def test_state_tracer_fires():
    from app.plugins.contract_state_tracer import trace_slot_changes
    hits = trace_slot_changes(SAMPLES_VULN)
    assert hits and hits[0]["severity"] == "high"
    res = run_plugin("contract_state_tracer",
                     {"storage_samples": SAMPLES_VULN})
    assert "contract_state_slot_changed" in keys_of(res)


def test_state_tracer_silent():
    from app.plugins.contract_state_tracer import trace_slot_changes
    assert trace_slot_changes(SAMPLES_CLEAN) == []
    assert trace_slot_changes([]) == []
    res = run_plugin("contract_state_tracer",
                     {"storage_samples": SAMPLES_CLEAN})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 4. abi-reconstructor
# ---------------------------------------------------------------------------

def test_abi_fires():
    from app.plugins.abi_reconstructor import (
        analyze_abi, reconstruct_abi)
    abi = reconstruct_abi("0x63deadbeef6000f3")
    assert abi[0]["resolved"] is False
    assert abi[0]["name"] == "unknown_deadbeef"
    ks = {h["key"] for h in analyze_abi("0x63deadbeef6000f3")}
    assert "abi_unresolved_selector" in ks
    res = run_plugin("abi_reconstructor",
                     {"contract_bytecode": ["0x63deadbeef6000f3"]})
    assert "abi_unresolved_selector" in keys_of(res)


def test_abi_silent():
    from app.plugins.abi_reconstructor import analyze_abi
    assert analyze_abi("0x63a9059cbb6000f3") == []  # transfer resolves
    res = run_plugin("abi_reconstructor",
                     {"contract_bytecode": ["0x63a9059cbb6000f3"]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 6. reentrancy-path-finder (UNVERIFIED stamped)
# ---------------------------------------------------------------------------

REENT_VULN = """
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
    function deposit() public payable { balances[msg.sender] += msg.value; }
}
"""
REENT_CLEAN = """
contract SafeVault {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
"""


def test_reentrancy_path_fires_and_stamped():
    from app.plugins.reentrancy_path_finder import find_reentrancy_paths
    hits = find_reentrancy_paths(REENT_VULN)
    assert hits and "withdraw" in hits[0]["evidence"]["path"]
    res = run_plugin("reentrancy_path_finder",
                     {"contract_source": [REENT_VULN]})
    assert "reentrancy_path" in keys_of(res)
    for f in res.findings:
        assert f.value.startswith("UNVERIFIED (sim): ")
        assert f.evidence["sim_derived"] is True
        assert f.evidence["not_verified_real"] is True


def test_reentrancy_path_silent():
    from app.plugins.reentrancy_path_finder import find_reentrancy_paths
    assert find_reentrancy_paths(REENT_CLEAN) == []
    res = run_plugin("reentrancy_path_finder",
                     {"contract_source": [REENT_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 8. gas-opt-analyzer
# ---------------------------------------------------------------------------

GAS_VULN = """
contract G {
    uint256[] public items;
    uint256 public total;
    function sumAll() public view returns (uint256 s) {
        for (uint256 i = 0; i < items.length; i++) {
            total = total + items[i];
            s = s + total + total + total + total;
        }
        return s;
    }
}
"""
GAS_CLEAN = """
contract G2 {
    uint256[] public items;
    function sumAll() public view returns (uint256 s) {
        uint256 len = items.length;
        uint256 acc = 0;
        for (uint256 i = 0; i < len; i++) { acc += items[i]; }
        return acc;
    }
}
"""


def test_gas_fires():
    from app.plugins.gas_opt_analyzer import analyze_gas_source
    ks = {h["key"] for h in analyze_gas_source(GAS_VULN)}
    assert "gas_loop_storage_length" in ks
    assert "gas_storage_write_in_loop" in ks
    res = run_plugin("gas_opt_analyzer", {"contract_source": [GAS_VULN]})
    assert "gas_loop_storage_length" in keys_of(res)


def test_gas_silent():
    from app.plugins.gas_opt_analyzer import analyze_gas_source
    assert analyze_gas_source(GAS_CLEAN) == []
    res = run_plugin("gas_opt_analyzer",
                     {"contract_source": [GAS_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 9. solc-version-matcher
# ---------------------------------------------------------------------------

def test_solc_fires():
    from app.plugins.solc_version_matcher import match_solc_version
    hits = match_solc_version("0.5.7")
    assert hits and hits[0]["evidence"]["bug"] == \
        "abi_encoder_v2_optimizer_bugs"
    res = run_plugin("solc_version_matcher",
                     {"contract_source": [
                         "pragma solidity 0.5.7;\ncontract X {}"]})
    assert "solc_known_compiler_bug" in keys_of(res)


def test_solc_silent():
    from app.plugins.solc_version_matcher import match_solc_version
    assert match_solc_version("0.8.26") == []
    assert match_solc_version("") == []
    res = run_plugin("solc_version_matcher",
                     {"contract_source": [
                         "pragma solidity 0.8.26;\ncontract X {}"]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 11. flashloan-simulator (UNVERIFIED stamped)
# ---------------------------------------------------------------------------

FLASH_VULN = """
contract Victim {
    function price() public view returns (uint256) {
        (uint256 r0, uint256 r1, ) = pair.getReserves();
        return r0 / r1;
    }
    function flashLoan(uint256 amt) public { }
}
"""
FLASH_CLEAN = """
contract Safe {
    function price() public view returns (uint256) {
        return oracle.observe(1800);
    }
    function swap(uint256 a, uint256 amountOutMin, uint256 deadline)
        public { }
}
"""


def test_flashloan_fires_and_stamped():
    from app.plugins.flashloan_simulator import analyze_flashloan
    ks = {h["key"] for h in analyze_flashloan(FLASH_VULN)}
    assert "flashloan_spot_price_victim" in ks
    scen = analyze_flashloan("", {"spot_price": 120,
                                  "reference_price": 100,
                                  "victim_exposure": 10000})
    assert scen[0]["evidence"]["estimated_extraction"] == 2000.0
    res = run_plugin("flashloan_simulator",
                     {"contract_source": [FLASH_VULN]})
    assert "flashloan_spot_price_victim" in keys_of(res)
    for f in res.findings:
        assert f.value.startswith("UNVERIFIED (sim): ")
        assert f.evidence["unverified"] is True


def test_flashloan_silent():
    from app.plugins.flashloan_simulator import analyze_flashloan
    assert analyze_flashloan(FLASH_CLEAN) == []
    res = run_plugin("flashloan_simulator",
                     {"contract_source": [FLASH_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 12. oracle-drift-calc
# ---------------------------------------------------------------------------

DRIFT_VULN = [{"asset": "ETH/USD", "spot": 103.0, "oracle": 100.0},
              {"asset": "ETH/USD", "spot": 103.5, "oracle": 100.0},
              {"asset": "ETH/USD", "spot": 102.8, "oracle": 100.0}]
DRIFT_CLEAN = [{"asset": "ETH/USD", "spot": 100.05, "oracle": 100.0},
               {"asset": "ETH/USD", "spot": 99.97, "oracle": 100.0}]


def test_oracle_drift_fires():
    from app.plugins.oracle_drift_calc import calc_oracle_drift
    hits = calc_oracle_drift(DRIFT_VULN)
    assert hits and hits[0]["evidence"]["peak_bps"] >= 300
    res = run_plugin("oracle_drift_calc", {"oracle_samples": DRIFT_VULN})
    assert "oracle_spot_drift" in keys_of(res)


def test_oracle_drift_silent():
    from app.plugins.oracle_drift_calc import calc_oracle_drift
    assert calc_oracle_drift(DRIFT_CLEAN) == []
    assert calc_oracle_drift([{"asset": "X", "spot": 103.0,
                               "oracle": 100.0}]) == []  # 1 tick only
    res = run_plugin("oracle_drift_calc",
                     {"oracle_samples": DRIFT_CLEAN})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 14. create2-address-predictor
# ---------------------------------------------------------------------------

def test_create2_known_vector_and_collision():
    from app.plugins.create2_address_predictor import (
        analyze_create2, predict_create2_address)
    # EIP-1014 worked example
    addr = predict_create2_address(
        "0x0000000000000000000000000000000000000000", 0, "0x00")
    assert addr == "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"
    out = analyze_create2({
        "deployer": "0x0000000000000000000000000000000000000000",
        "salt": 0, "init_code": "0x00",
        "code_at_address": "0x60006000f3"})
    assert out["hits"][0]["key"] == "create2_predicted_collision"
    res = run_plugin("create2_address_predictor", {"create2": [{
        "deployer": "0x0000000000000000000000000000000000000000",
        "salt": 0, "init_code": "0x00", "balance": 10 ** 15}]})
    assert "create2_predicted_prefunded" in keys_of(res)


def test_create2_clean_prediction_silent():
    from app.plugins.create2_address_predictor import analyze_create2
    out = analyze_create2({
        "deployer": "0x0000000000000000000000000000000000000000",
        "salt": 0, "init_code": "0x00", "code_at_address": "0x",
        "balance": 0})
    assert out["hits"] == [] and out["address"].startswith("0x")
    res = run_plugin("create2_address_predictor", {"create2": [{
        "deployer": "0x0000000000000000000000000000000000000000",
        "salt": 0, "init_code": "0x00"}]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 17. erc20-compliance-verify
# ---------------------------------------------------------------------------

ERC20_VULN = """
contract BadToken {
    function totalSupply() public view returns (uint256) { return 1000; }
    function balanceOf(address who) public view returns (uint256) { return 0; }
    function transfer(address to, uint256 value) public { }
    function approve(address spender, uint256 value) public returns (bool) { return true; }
    function transferFrom(address from, address to, uint256 value) public returns (bool) { return true; }
    event Transfer(address from, address to, uint256 value);
}
"""
ERC20_CLEAN = """
contract GoodToken {
    function totalSupply() public view returns (uint256) { return 1000; }
    function balanceOf(address account) public view returns (uint256) { return 0; }
    function transfer(address to, uint256 amount) public returns (bool) { return true; }
    function allowance(address owner, address spender) public view returns (uint256) { return 0; }
    function approve(address spender, uint256 amount) public returns (bool) { return true; }
    function transferFrom(address from, address to, uint256 amount) public returns (bool) { return true; }
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
"""


def test_erc20_fires():
    from app.plugins.erc20_compliance_verify import verify_erc20
    ks = {(h["key"], h["evidence"].get("function") or
           h["evidence"].get("event")) for h in verify_erc20(ERC20_VULN)}
    assert ("erc20_missing_function", "allowance") in ks
    assert ("erc20_missing_event", "Transfer") in ks
    res = run_plugin("erc20_compliance_verify",
                     {"contract_source": [ERC20_VULN]})
    assert "erc20_missing_function" in keys_of(res)


def test_erc20_silent():
    from app.plugins.erc20_compliance_verify import verify_erc20
    assert verify_erc20(ERC20_CLEAN) == []
    res = run_plugin("erc20_compliance_verify",
                     {"contract_source": [ERC20_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 18. erc721-metadata-guard
# ---------------------------------------------------------------------------

NFT_VULN = """
contract NFT {
    string private base;
    function setBaseURI(string memory u) public { base = u; }
    function mint(string memory uri) public { _setTokenURI(1, uri); }
    function _setTokenURI(uint256 id, string memory uri) internal { }
}
"""
NFT_CLEAN = """
contract NFT2 {
    string private base;
    bool public uriFrozen;
    function setBaseURI(string memory u) public onlyOwner {
        require(!uriFrozen);
        base = u;
    }
    function freezeBaseURI() public onlyOwner { uriFrozen = true; }
}
"""


def test_erc721_fires():
    from app.plugins.erc721_metadata_guard import analyze_erc721_metadata
    ks = {h["key"] for h in analyze_erc721_metadata(NFT_VULN)}
    assert "erc721_ungated_uri_setter" in ks
    assert "erc721_mint_caller_uri" in ks
    res = run_plugin("erc721_metadata_guard",
                     {"contract_source": [NFT_VULN]})
    assert "erc721_ungated_uri_setter" in keys_of(res)


def test_erc721_silent():
    from app.plugins.erc721_metadata_guard import analyze_erc721_metadata
    assert analyze_erc721_metadata(NFT_CLEAN) == []
    res = run_plugin("erc721_metadata_guard",
                     {"contract_source": [NFT_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 19. frontrunning-guard-eval
# ---------------------------------------------------------------------------

FRONT_VULN = """
contract Swap {
    function swapTokens(uint256 amountIn) public returns (uint256) {
        return amountIn;
    }
}
"""
FRONT_CLEAN = """
contract Swap2 {
    function swapExact(uint256 amountIn, uint256 amountOutMin,
                       uint256 deadline) public returns (uint256) {
        require(deadline >= block.timestamp);
        require(amountOutMin > 0);
        return amountOutMin;
    }
    function increaseAllowance(address s, uint256 v) public
        returns (bool) { return true; }
}
"""


def test_frontrunning_fires():
    from app.plugins.frontrunning_guard_eval import evaluate_frontrunning
    ks = {h["key"] for h in evaluate_frontrunning(FRONT_VULN)}
    assert "frontrunning_unguarded_swap" in ks
    res = run_plugin("frontrunning_guard_eval",
                     {"contract_source": [FRONT_VULN]})
    assert "frontrunning_unguarded_swap" in keys_of(res)


def test_frontrunning_silent():
    from app.plugins.frontrunning_guard_eval import evaluate_frontrunning
    assert evaluate_frontrunning(FRONT_CLEAN) == []
    res = run_plugin("frontrunning_guard_eval",
                     {"contract_source": [FRONT_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 21. access-control-scraper
# ---------------------------------------------------------------------------

A1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
A2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
OWN = "0xcccccccccccccccccccccccccccccccccccccccc"
ROLE_VULN = [{"contract": "0xdddddddddddddddddddddddddddddddddddddddd",
              "owner": OWN,
              "roles": {"DEFAULT_ADMIN_ROLE": [A1, A2],
                        "MINTER_ROLE": [A1]}}]
ROLE_CLEAN = [{"contract": "0xdddddddddddddddddddddddddddddddddddddddd",
               "owner": A1, "roles": {"DEFAULT_ADMIN_ROLE": [A1]}}]


def test_access_scraper_fires():
    from app.plugins.access_control_scraper import (
        aggregate_roles, analyze_role_records)
    ks = {h["key"] for h in analyze_role_records(ROLE_VULN)}
    assert "access_admin_role_spread" in ks
    assert "access_owner_admin_divergence" in ks
    # event replay: grant then revoke leaves no holder
    tbl = aggregate_roles([{"contract": "c", "events": [
        {"type": "RoleGranted", "role": "R", "account": A1},
        {"type": "RoleRevoked", "role": "R", "account": A1}]}])
    assert tbl["c"]["roles"]["R"] == []
    res = run_plugin("access_control_scraper", {"role_data": ROLE_VULN})
    assert "access_admin_role_spread" in keys_of(res)


def test_access_scraper_silent():
    from app.plugins.access_control_scraper import analyze_role_records
    assert analyze_role_records(ROLE_CLEAN) == []
    res = run_plugin("access_control_scraper",
                     {"role_data": ROLE_CLEAN})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 22. bytecode-diff-viewer
# ---------------------------------------------------------------------------

OLD_BC = "0x60006000f3"
NEW_BC = "0x63deadbeef6000f4ff"


def test_bytecode_diff_fires():
    from app.plugins.bytecode_diff_viewer import analyze_diff, diff_bytecode
    d = diff_bytecode(OLD_BC, NEW_BC)
    assert "0xdeadbeef" in d["added_selectors"]
    ks = {h["key"] for h in analyze_diff(OLD_BC, NEW_BC)}
    assert "bytecode_diff_dangerous_opcode_added" in ks
    res = run_plugin("bytecode_diff_viewer",
                     {"bytecode_pair": [{"old": OLD_BC, "new": NEW_BC}]})
    assert "bytecode_diff_dangerous_opcode_added" in keys_of(res)


def test_bytecode_diff_silent():
    from app.plugins.bytecode_diff_viewer import analyze_diff
    assert analyze_diff(OLD_BC, OLD_BC) == []
    res = run_plugin("bytecode_diff_viewer",
                     {"bytecode_pair": [{"old": OLD_BC, "new": OLD_BC}]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 23. constant-inliner-check
# ---------------------------------------------------------------------------

SECRET32 = ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c"
            "15b0f00a08")
BC_SECRET = "0x7f" + SECRET32 + "6000f3"
BC_ADDR = "0x73" + "11" * 20 + "6000f3"


def test_constant_inliner_fires():
    from app.plugins.constant_inliner_check import analyze_constants
    hits = analyze_constants(BC_SECRET)
    assert hits and hits[0]["key"] == "constant_inlined_secret_shaped"
    # the full constant must never appear in a finding value (masked)
    assert SECRET32 not in hits[0]["value"]
    res = run_plugin("constant_inliner_check",
                     {"contract_bytecode": [BC_SECRET]})
    assert "constant_inlined_secret_shaped" in keys_of(res)


def test_constant_inliner_silent():
    from app.plugins.constant_inliner_check import analyze_constants
    assert analyze_constants(BC_ADDR) == []
    assert analyze_constants(BC_SECRET, source="x = 0x" + SECRET32) == []
    res = run_plugin("constant_inliner_check",
                     {"contract_bytecode": [BC_ADDR]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 24. yul-optimizer-audit
# ---------------------------------------------------------------------------

YUL_VULN = """
contract Y {
    function store() public {
        assembly {
            let v := calldataload(0)
            sstore(0, v)
            returndatacopy(0, 0, returndatasize())
        }
    }
}
"""
YUL_CLEAN = """
contract Y2 {
    function store() public {
        assembly {
            let v := calldataload(0)
            if gt(v, 1000) { revert(0, 0) }
            sstore(0, v)
        }
    }
}
"""


def test_yul_fires():
    from app.plugins.yul_optimizer_audit import audit_yul
    ks = {h["key"] for h in audit_yul(YUL_VULN)}
    assert "yul_calldata_taint_write" in ks
    assert "yul_unbounded_returndatacopy" in ks
    res = run_plugin("yul_optimizer_audit",
                     {"contract_source": [YUL_VULN]})
    assert "yul_calldata_taint_write" in keys_of(res)


def test_yul_silent():
    from app.plugins.yul_optimizer_audit import audit_yul
    assert audit_yul(YUL_CLEAN) == []
    res = run_plugin("yul_optimizer_audit",
                     {"contract_source": [YUL_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 27. ether-forcing-tester (UNVERIFIED stamped)
# ---------------------------------------------------------------------------

FORCE_VULN = """
contract Pot {
    uint256 public target;
    function claim() public {
        require(address(this).balance == target);
    }
}
"""
FORCE_CLEAN = """
contract Pot2 {
    uint256 public totalDeposited;
    function claim() public { require(totalDeposited >= 100); }
}
"""


def test_ether_forcing_fires_and_stamped():
    from app.plugins.ether_forcing_tester import analyze_ether_forcing
    ks = {h["key"] for h in analyze_ether_forcing(FORCE_VULN)}
    assert "ether_forcing_breaks_equality" in ks
    res = run_plugin("ether_forcing_tester",
                     {"contract_source": [FORCE_VULN]})
    assert "ether_forcing_breaks_equality" in keys_of(res)
    for f in res.findings:
        assert f.value.startswith("UNVERIFIED (sim): ")
        assert f.evidence["sim_derived"] is True


def test_ether_forcing_silent():
    from app.plugins.ether_forcing_tester import analyze_ether_forcing
    assert analyze_ether_forcing(FORCE_CLEAN) == []
    res = run_plugin("ether_forcing_tester",
                     {"contract_source": [FORCE_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 28. fallback-behavior-analyzer
# ---------------------------------------------------------------------------

FB_VULN = """
contract F {
    address public impl;
    uint256 public visits;
    fallback() external payable {
        visits += 1;
        (bool ok, ) = impl.delegatecall(msg.data);
    }
}
"""
FB_CLEAN = """
contract F2 {
    event Got(address from, uint256 value);
    receive() external payable { emit Got(msg.sender, msg.value); }
    fallback() external { revert("nope"); }
}
"""


def test_fallback_fires():
    from app.plugins.fallback_behavior_analyzer import analyze_fallback
    ks = {h["key"] for h in analyze_fallback(FB_VULN)}
    assert "fallback_delegatecall_catchall" in ks
    assert "fallback_state_write_map" in ks
    probe = analyze_fallback("", [{"selector": "0xdeadbeef",
                                   "reverted": False,
                                   "returned_bytes": 32}])
    assert probe[0]["key"] == "fallback_probe_catchall_success"
    res = run_plugin("fallback_behavior_analyzer",
                     {"contract_source": [FB_VULN]})
    assert "fallback_delegatecall_catchall" in keys_of(res)


def test_fallback_silent():
    from app.plugins.fallback_behavior_analyzer import analyze_fallback
    assert analyze_fallback(FB_CLEAN) == []
    res = run_plugin("fallback_behavior_analyzer",
                     {"contract_source": [FB_CLEAN]})
    assert res.findings == []


# ---------------------------------------------------------------------------
# 30. foundry-test-generator
# ---------------------------------------------------------------------------

TRACE_VULN = {"block": 18000000, "anomaly": "balance delta +5 ETH",
              "calls": [{"from": ADDR,
                         "to": "0x2222222222222222222222222222222222222222",
                         "value": 0, "data": "0xa9059cbb"}]}
TRACE_CLEAN = {"block": 18000000,
               "calls": [{"from": ADDR,
                          "to": "0x2222222222222222222222222222222222222222",
                          "value": 0, "data": "0xa9059cbb"}]}


def test_foundry_fires():
    from app.plugins.foundry_test_generator import (
        analyze_trace, generate_foundry_test)
    code = generate_foundry_test(TRACE_VULN)
    assert "vm.createSelectFork" in code and "18000000" in code
    assert "test_replayAnomalousTrace" in code
    hits = analyze_trace(TRACE_VULN)
    assert hits and "forge test" in hits[0]["value"]
    assert "AnomalousTraceTest" in hits[0]["evidence"]["generated_test"]
    res = run_plugin("foundry_test_generator", {"trace": [TRACE_VULN]})
    assert "foundry_test_generated" in keys_of(res)


def test_foundry_silent():
    from app.plugins.foundry_test_generator import analyze_trace
    assert analyze_trace(TRACE_CLEAN) == []
    res = run_plugin("foundry_test_generator", {"trace": [TRACE_CLEAN]})
    assert res.findings == []
