"""Contract Simulation lane (contract_simulation) tests.

Layers:
1. Pure helpers: selectors, ABI encoding, boundary matrix,
   probe-function extraction and the gate cross-check
   (flag_reason) - success alone never flags; payment-context
   purchases never flag.
2. Plugin runs with the chain layer AND the eth_call transport
   stubbed (no network, no live chain):
   - an unguarded withdraw fixture whose probe succeeds from an
     unrelated caller MUST flag as a simulation_candidate;
   - an onlyOwner fixture whose probes revert MUST NOT flag;
   - a legitimately public payable purchase path whose probe
     succeeds MUST NOT flag (FP discipline);
   - bulk contexts (shared marker / several discovered contracts)
     are refused with one note finding and zero probes;
   - the per-contract time budget cuts probing off and reports
     partial coverage instead of hanging.
3. Architecture: the lanes execute ONLY in an explicitly marked
   heavy-lane context (FakeCtx below is heavy by default via the
   module override). A fast/default context gets an immediate
   info-note refusal with zero chain reads and zero probes, and
   the budget comes from RECON_HEAVY_TIMEOUT (default 120s, hard
   cap 300s) - never the 20s RECON_TIMEOUT request path. The
   Mythril adapter reports a missing external binary honestly.
4. Registry discovery picks the plugin up.
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import contract_sim  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x" + "cd" * 20

UNGUARDED_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

GATED_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimVaultGated {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawAll() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

# Public purchase path: payable, payout derived from msg.value -
# legitimately callable by anyone. MUST NOT flag even when the
# simulated call succeeds.
PURCHASE_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SimSale {
    IERC20 public token;
    uint256 public rate = 100;

    function mint(uint256 weiAmount) public payable {
        uint256 tokens = msg.value * rate;
        require(token.transfer(msg.sender, tokens));
    }
}
"""


# ---------------------------------------------------------------------------
# 1. Pure helpers
# ---------------------------------------------------------------------------

def test_selectors_match_known_values():
    assert contract_sim.function_selector(
        "transfer(address,uint256)") == "0xa9059cbb"
    assert contract_sim.function_selector("withdrawAll()") == \
        "0x853828b6"
    assert contract_sim.function_selector("totalSupply()") == \
        "0x18160ddd"


def test_encode_call_args():
    enc = contract_sim.encode_call_args(
        ["address", "uint256"], [ADDR, 1])
    assert enc == "0" * 24 + ADDR[2:] + "%064x" % 1
    dyn = contract_sim.encode_call_args(["string"], ["fuzz"])
    assert dyn is not None and dyn.startswith("%064x" % 32)
    # Arrays are encodable since the complex-args encoder fix:
    # offset + length + element.
    assert contract_sim.encode_call_args(["uint256[]"], [[1]]) == \
        "%064x" % 32 + "%064x" % 1 + "%064x" % 1


def test_boundary_cases_cover_extremes():
    cases = contract_sim.boundary_cases(["uint256"], ADDR)
    vals = [c[0][0] for c in cases]
    assert 0 in vals and 1 in vals and (1 << 256) - 1 in vals
    addr_cases = contract_sim.boundary_cases(["address"], ADDR)
    seen = [c[0][0] for c in addr_cases]
    assert contract_sim.FUZZ_CALLER in seen and ADDR in seen
    assert len(contract_sim.boundary_cases(
        ["uint256", "address", "bool", "bytes32"], ADDR)) <= \
        contract_sim.MAX_CASES_PER_FUNCTION


def test_extract_and_flag_reason():
    fns = {f["name"]: f for f in
           contract_sim.extract_probe_functions(UNGUARDED_SOURCE)}
    assert "withdrawAll" in fns and "deposit" in fns
    w = fns["withdrawAll"]
    assert w["sensitive"] == "withdraw_sweep"
    assert w["gated"] is False and w["moves_value"] is True
    verdict = contract_sim.flag_reason(w, gated_siblings=0,
                                       state_changing_siblings=2)
    assert verdict is not None and verdict["severity"] == "high"

    gated = {f["name"]: f for f in
             contract_sim.extract_probe_functions(GATED_SOURCE)}
    assert gated["withdrawAll"]["gated"] is True

    sale = {f["name"]: f for f in
            contract_sim.extract_probe_functions(PURCHASE_SOURCE)}
    assert sale["mint"]["payment_context"] is True
    assert contract_sim.flag_reason(
        sale["mint"], gated_siblings=0,
        state_changing_siblings=1) is None


def test_standard_ops_and_own_balance_never_flag():
    # Regression (live REQ smoke, 2026-11-02): a standard ERC20
    # transfer inside a heavily-gated multi-contract source was
    # flagged by the gate-convention branch. Standard token ops
    # and own-balance withdrawals are public BY DESIGN.
    src = r"""
    contract GateyToken {
        address public owner;
        mapping(address => uint256) public balances;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function transfer(address to, uint256 amt) external {
            balances[msg.sender] -= amt;
            balances[to] += amt;
        }
        function withdraw() external {
            uint256 a = balances[msg.sender];
            balances[msg.sender] = 0;
            payable(msg.sender).transfer(a);
        }
        function mint(address to, uint256 a) external onlyOwner {
            balances[to] += a;
        }
        function pause() external onlyOwner { owner = address(0); }
        function setFee(uint256 f) external onlyOwner { owner = address(0); }
    }
    """
    fns = {f["name"]: f for f in
           contract_sim.extract_probe_functions(src)}
    assert contract_sim.flag_reason(
        fns["transfer"], gated_siblings=3,
        state_changing_siblings=5) is None
    assert contract_sim.flag_reason(
        fns["withdraw"], gated_siblings=3,
        state_changing_siblings=5) is None


# ---------------------------------------------------------------------------
# 2. Plugin runs (transport stubbed, no network)
# ---------------------------------------------------------------------------

class FakeCtx:
    """Heavy-lane context by default (module override marker).

    Tests that want the fast/default lane clear the override -
    see test_fast_context_refused_immediately.
    """

    def __init__(self, shared=None, run_id="test"):
        self.keys = {}
        self.mode = "active"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = run_id
        self.module_overrides = {"contract_simulation": "heavy"}
        self.shared = shared or {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


def _src_meta(source):
    return {"source": source, "contract_name": "Fixture",
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def _patch_chain(monkeypatch, source):
    async def fake_get_code(ctx, chain, address):
        return "0x60006000"

    async def fake_source(ctx, chain, address, key=None):
        return _src_meta(source) if source else None

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)


def _run_plugin(ctx, raw=None, budget=None):
    plugin = contract_sim.ContractSimPlugin()
    if budget is not None:
        plugin.budget_s = budget
    target = Target(raw=raw or f"ethereum:{ADDR}", type="crypto_wallet")
    return asyncio.run(plugin.run(target, ctx))


def test_unguarded_withdraw_success_flags_candidate(monkeypatch):
    _patch_chain(monkeypatch, UNGUARDED_SOURCE)
    withdraw_sel = contract_sim.function_selector("withdrawAll()")
    calls = []

    async def fake_eth_call(ctx, chain, to_addr, data_hex, sender,
                            value="0x0"):
        calls.append((data_hex, sender, value))
        if data_hex.startswith(withdraw_sel):
            return {"status": "success", "result": "0x",
                    "via": "stub"}
        return {"status": "revert", "detail": "execution reverted",
                "via": "stub"}

    monkeypatch.setattr(contract_sim, "eth_call", fake_eth_call)
    res = _run_plugin(FakeCtx())
    cands = [f for f in res.findings if f.key == "simulation_candidate"]
    assert len(cands) == 1
    f = cands[0]
    assert f.evidence["function"] == "withdrawAll"
    assert f.evidence["simulation_candidate"] is True
    assert f.evidence["review_status"].startswith("pending human review")
    assert f.evidence["gated_in_source"] is False
    assert f.evidence["caller"] == contract_sim.FUZZ_CALLER
    assert "address(this).balance" in f.evidence["code"]
    # probes really went out, all from the fuzz caller, value 0
    assert calls and all(c[1] == contract_sim.FUZZ_CALLER
                         and c[2] == "0x0" for c in calls)


def test_onlyowner_revert_never_flags(monkeypatch):
    _patch_chain(monkeypatch, GATED_SOURCE)

    async def fake_eth_call(ctx, chain, to_addr, data_hex, sender,
                            value="0x0"):
        return {"status": "revert", "detail": "execution reverted",
                "via": "stub"}

    monkeypatch.setattr(contract_sim, "eth_call", fake_eth_call)
    res = _run_plugin(FakeCtx())
    assert [f for f in res.findings
            if f.key == "simulation_candidate"] == []
    assert "0 simulation candidate" in res.reason


def test_public_purchase_success_never_flags(monkeypatch):
    _patch_chain(monkeypatch, PURCHASE_SOURCE)

    async def fake_eth_call(ctx, chain, to_addr, data_hex, sender,
                            value="0x0"):
        return {"status": "success", "result": "0x", "via": "stub"}

    monkeypatch.setattr(contract_sim, "eth_call", fake_eth_call)
    res = _run_plugin(FakeCtx())
    assert [f for f in res.findings
            if f.key == "simulation_candidate"] == []


def test_bulk_context_refused_without_probing(monkeypatch):
    _patch_chain(monkeypatch, UNGUARDED_SOURCE)
    probed = []

    async def fake_eth_call(ctx, chain, to_addr, data_hex, sender,
                            value="0x0"):
        probed.append(data_hex)
        return {"status": "success", "result": "0x", "via": "stub"}

    monkeypatch.setattr(contract_sim, "eth_call", fake_eth_call)

    res = _run_plugin(FakeCtx(shared={"bulk_sweep": True}))
    notes = [f for f in res.findings
             if f.key == "contract_simulation_note"]
    assert len(notes) == 1 and "bulk" in notes[0].value
    assert probed == []

    # several discovered contracts, no explicit target: also bulk
    many = {"contract_addresses": ["0x" + "11" * 20,
                                   "0x" + "22" * 20,
                                   "0x" + "33" * 20]}
    res2 = _run_plugin(FakeCtx(shared=many),
                       raw="https://example.com")
    notes2 = [f for f in res2.findings
              if f.key == "contract_simulation_note"]
    assert len(notes2) == 1 and "per-contract" in notes2[0].value
    assert probed == []


def test_budget_exhaustion_reports_partial(monkeypatch):
    _patch_chain(monkeypatch, UNGUARDED_SOURCE)

    async def slow_eth_call(ctx, chain, to_addr, data_hex, sender,
                            value="0x0"):
        await asyncio.sleep(30)
        return {"status": "success", "result": "0x", "via": "stub"}

    monkeypatch.setattr(contract_sim, "eth_call", slow_eth_call)
    t0 = time.monotonic()
    res = _run_plugin(FakeCtx(), budget=0.3)
    elapsed = time.monotonic() - t0
    assert elapsed < 10  # cut off, did not hang on the 30s probe
    notes = [f for f in res.findings
             if f.key == "contract_simulation_note"]
    assert any("budget" in n.value for n in notes)
    assert [f for f in res.findings
            if f.key == "simulation_candidate"] == []


def test_no_verified_source_notes_and_skips(monkeypatch):
    _patch_chain(monkeypatch, None)

    async def fake_eth_call(ctx, chain, to_addr, data_hex, sender,
                            value="0x0"):
        raise AssertionError("must not probe without source")

    monkeypatch.setattr(contract_sim, "eth_call", fake_eth_call)
    res = _run_plugin(FakeCtx())
    notes = [f for f in res.findings
             if f.key == "contract_simulation_note"]
    assert any("no verified source" in n.value for n in notes)


# ---------------------------------------------------------------------------
# 3. Architecture: heavy lane only, RECON_HEAVY_TIMEOUT budget,
#    external Mythril adapter
# ---------------------------------------------------------------------------

def test_fast_context_refused_immediately(monkeypatch):
    async def forbidden_code(ctx, chain, address):
        raise AssertionError("chain read from a fast context")

    async def forbidden_call(ctx, chain, to_addr, data_hex, sender,
                             value="0x0"):
        raise AssertionError("probe from a fast context")

    monkeypatch.setattr(cc, "rpc_get_code", forbidden_code)
    monkeypatch.setattr(contract_sim, "eth_call", forbidden_call)
    ctx = FakeCtx()
    ctx.module_overrides = {}  # no heavy marker: default/fast lane
    res = _run_plugin(ctx)
    notes = [f for f in res.findings
             if f.key == "contract_simulation_note"]
    assert len(notes) == 1
    assert notes[0].value.startswith("INFO:")
    assert "heavy-lane" in notes[0].value
    assert "RECON_HEAVY_TIMEOUT" in notes[0].value
    assert [f for f in res.findings
            if f.key == "simulation_candidate"] == []
    # the plugin really declares the heavy lane to the runner
    assert contract_sim.ContractSimPlugin.heavy_lane is True
    assert contract_sim.heavy_lane_context(ctx) is False
    heavy_ctx = FakeCtx()
    assert contract_sim.heavy_lane_context(heavy_ctx) is True
    shared_ctx = FakeCtx(shared={"execution_lane": "heavy"})
    shared_ctx.module_overrides = {}
    assert contract_sim.heavy_lane_context(shared_ctx) is True
    # the runner agrees: it grants the heavy budget only here
    from app.runner import _heavy_lane_context, _heavy_timeout_s
    plugin = contract_sim.ContractSimPlugin()
    assert _heavy_lane_context(plugin, ctx) is False
    assert _heavy_lane_context(plugin, FakeCtx()) is True
    monkeypatch.setenv("RECON_HEAVY_TIMEOUT", "9999")
    assert _heavy_timeout_s() == 300


def test_heavy_timeout_config_default_and_cap(monkeypatch):
    plugin = contract_sim.ContractSimPlugin()
    monkeypatch.delenv("RECON_HEAVY_TIMEOUT", raising=False)
    assert plugin._budget() == 120
    monkeypatch.setenv("RECON_HEAVY_TIMEOUT", "42")
    assert plugin._budget() == 42
    monkeypatch.setenv("RECON_HEAVY_TIMEOUT", "9999")
    assert plugin._budget() == 300  # hard cap stands
    monkeypatch.setenv("RECON_HEAVY_TIMEOUT", "not-a-number")
    assert plugin._budget() == 120


import pytest  # noqa: E402

_MYTHRIL = contract_sim.find_mythril()


@pytest.mark.skipif(_MYTHRIL is None,
                    reason="external mythril side venv not installed")
def test_symbolic_fixture_run_flags_swc105():
    # Real engine, real fixture: the unguarded-withdraw contract
    # must surface Mythril's SWC-105. Takes ~30-60s when it runs;
    # skipped wherever the external side venv does not exist.
    issues, error = asyncio.run(
        contract_sim.run_symbolic(UNGUARDED_SOURCE, 120))
    assert error is None
    assert any(str(i.get("swc-id")) == "105" for i in issues), \
        f"expected SWC-105 in {[i.get('swc-id') for i in issues]}"


@pytest.mark.skipif(_MYTHRIL is None,
                    reason="external mythril side venv not installed")
def test_plugin_symbolic_lane_maps_mythril_findings(monkeypatch):
    _patch_chain(monkeypatch, UNGUARDED_SOURCE)

    async def fake_eth_call(ctx, chain, to_addr, data_hex, sender,
                            value="0x0"):
        return {"status": "revert", "detail": "execution reverted",
                "via": "stub"}

    monkeypatch.setattr(contract_sim, "eth_call", fake_eth_call)
    monkeypatch.setenv("RECON_SIM_SYMBOLIC", "1")
    res = _run_plugin(FakeCtx())
    myth = [f for f in res.findings
            if f.key == "simulation_candidate"
            and f.source == "mythril"]
    assert myth, [f.value[:120] for f in res.findings]
    assert myth[0].evidence["engine"] == "mythril"
    assert myth[0].evidence["swc_id"] == "105"
    assert myth[0].evidence["simulation_candidate"] is True


def test_mythril_adapter_missing_binary_is_honest(monkeypatch):
    orig = contract_sim.find_mythril
    monkeypatch.setattr(contract_sim, "find_mythril", lambda: None)
    issues, error = asyncio.run(
        contract_sim.run_symbolic("contract C {}", 30))
    assert issues == []
    assert error is not None and "not bundled" in error
    # an explicit but missing RECON_MYTHRIL_BIN is authoritative:
    # the adapter reports absence instead of hunting elsewhere
    monkeypatch.setattr(contract_sim, "find_mythril", orig)
    monkeypatch.setenv("RECON_MYTHRIL_BIN", "/nonexistent/myth")
    assert contract_sim.find_mythril() is None


# ---------------------------------------------------------------------------
# 4. Registry
# ---------------------------------------------------------------------------

def test_plugin_registered():
    reg = discover()
    assert "contract_simulation" in reg
    assert len(reg) == 809  # master 655 + 100 BSC/BNB detectors (bsc100) + 1 ast_visual_audit plugin + 5 deep-audit detectors + 6 deep-audit batch-2 detectors + 6 recipient-first detectors + 1 auto-validator + 4 deep-analysis plugins (deep_layers) + 5 deep3 detectors + 3 deep-audit batch-4 detectors (deep_audit4) + 9 deep-audit batch-6 detectors (deep_audit6) + 14 deep-audit batch-8 detectors (deep_audit8)
