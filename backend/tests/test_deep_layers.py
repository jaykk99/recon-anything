"""Phase 2C/2D deep analysis layers: tests.

Layers:
1. quant_math hand-computed vectors (vault/shares incl. the
   inflation attack profitable on a no-virtual-shares vault and
   unprofitable behind a decimals offset, fee-on-transfer, AMM,
   supply/claim math) + provenance stamping.
2. Call graph: gated target -> UNGATED callee drain fires;
   gated callee stays silent; caller-supplied route fires;
   missing callee source degrades the edge, never fakes it.
3. Storage: ungated withdraw + live paused=false / owner=0 fires;
   paused=true control stays silent; layout derivation; the
   storage->gate synergy helper upgrades/downgrades; token
   params land in the shared record (synergy -> math).
4. Bytecode deep: hand-assembled bytecode with DELEGATECALL +
   withdraw selector fires; sweep(address) classifies
   CALLER-SUPPLIED; benign bytecode silent; plugin skips when
   source exists.
5. Confirmation queue (heavy lane, tools stubbed at the module
   boundary): slither match -> tool-confirmed pattern; slither
   clean -> false-positive; tool unavailable -> unconfirmed with
   reason; non-heavy context -> lane stays off.
6. Step paths + corroboration: complete path + probe =
   VERIFIED_REAL_CANDIDATE; an UNPROVEN step caps at UNVERIFIED;
   lane disagreement marks probe_settles.
7. Plugin runs with ALL network stubbed at the contract_chain /
   module boundary, following test_contract_logic's FakeCtx style.
8. Registry discovery: 774 + 4 = 778.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import deep_layers as dl  # noqa: E402
from app.plugins import quant_math as qm  # noqa: E402
from app.plugins import step_paths as sp  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.cryptopack_util import keccak256  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

TARGET_ADDR = "0x" + "aa" * 20
CALLEE_ADDR = "0x" + "bb" * 20
OWNER_ADDR = "0x" + "cc" * 20


# ---------------------------------------------------------------------------
# 1. quant_math vectors (hand-computed)
# ---------------------------------------------------------------------------

def test_quant_vault_vectors():
    assert qm.shares_out(1000, 0, 0, 0) == 1000            # empty vault 1:1
    assert qm.shares_out(1000, 2000, 1000, 0) == 500       # 1000*1001//2001
    assert qm.shares_out(100, 0, 0, 3) == 100_000          # offset 3
    assert qm.assets_out(500, 2000, 1000, 0) == 999        # 500*2001//1001
    assert qm.assets_out(0, 2000, 1000, 0) == 0


def test_quant_inflation_attack_vectors():
    # Vulnerable vault (no virtual shares): deposit 1, donate
    # 10_000, victim deposits 5_000 -> victim gets 0 shares,
    # attacker redeems the whole 15_001 for a 5_000 profit.
    vuln = qm.inflation_attack(1, 10_000, 5_000, virtual=False)
    assert vuln["attacker_shares"] == 1
    assert vuln["victim_shares"] == 0
    assert vuln["attacker_redeem"] == 15_001
    assert vuln["attacker_profit"] == 5_000
    assert vuln["profitable"] is True
    # Defended vault (virtual shares, offset 6): same numbers lose
    # the attacker exactly the victim's fair share.
    defended = qm.inflation_attack(1, 10_000, 5_000,
                                   decimals_offset=6, virtual=True)
    assert defended["victim_shares"] == 999_800
    assert defended["attacker_profit"] == -5_000
    assert defended["profitable"] is False


def test_quant_fee_amm_supply_vectors():
    assert qm.expected_received(10_000, fee_bps=250) == {
        "received": 9_750, "fee_amount": 250, "shortfall": 250,
        "fee_bps": 250}
    assert qm.expected_received(1_000, fee_fraction=0.10)["received"] == 900
    # AMM: price with differing decimals; 0.3% amount_out; impact.
    assert qm.amm_spot_price(1000 * 10**6, 2000 * 10**18, 6, 18) == 2.0
    assert qm.amm_amount_out(1000, 10_000, 10_000, fee_bps=30) == 906
    assert qm.amm_price_impact_bps(1000, 10_000, 10_000, 30) == 939
    mv = qm.amm_max_movable(10_000, 10_000, fee_bps=30)
    assert mv["max_out_ceiling"] == 10_000
    assert mv["out_for_half_reserve"] == 5_000
    assert mv["in_required_for_half_reserve"] == 10_030
    # Supply / claim math.
    assert qm.remaining_mintable(1000, 400) == 600
    assert qm.remaining_mintable(None, 400) is None
    assert qm.remaining_mintable(0, 400) is None
    assert qm.claimable(100, 30) == 30
    assert qm.claimable(100) == 100
    st = qm.stamped({"x": 1}, {"slot": "0x0"}, "2026-11-04T00:00:00Z")
    assert st["inputs"] == {"slot": "0x0"} and st["figures"] == {"x": 1}


# ---------------------------------------------------------------------------
# 2. Call graph fixtures
# ---------------------------------------------------------------------------

TARGET_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVault {
    function drain(address to, uint256 amt) external;
    function sweepTo(address dst) external;
}

contract GateKeeper {
    IVault public vault = IVault(0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb);
    address public owner;

    function adminWithdraw(address to, uint256 amt) public onlyOwner {
        vault.drain(to, amt);
    }

    function route(address dst) public {
        vault.sweepTo(dst);
    }
}
"""

CALLEE_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    function drain(address to, uint256 amt) public {
        payable(to).transfer(amt);
    }

    function sweepTo(address dst) public {
        payable(dst).transfer(address(this).balance);
    }
}
"""

CALLEE_GATED_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;

    function drain(address to, uint256 amt) public onlyOwner {
        payable(to).transfer(amt);
    }

    function sweepTo(address dst) public onlyOwner {
        payable(dst).transfer(address(this).balance);
    }
}
"""


def _meta(source, name):
    return {"source": source, "contract_name": name,
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def test_call_graph_gate_bypass_fires():
    hits, edges = dl.analyze_call_graph(
        TARGET_SOURCE, {CALLEE_ADDR: _meta(CALLEE_SOURCE, "Vault")},
        contract_name="GateKeeper")
    kinds = {h["kind"] for h in hits}
    assert "call_graph_gate_bypass" in kinds
    bypass = [h for h in hits if h["kind"] == "call_graph_gate_bypass"][0]
    assert bypass["function"] == "adminWithdraw"
    assert bypass["callee_function"] == "drain"
    assert bypass["code"] and bypass["callee_code"]
    assert all(e["status"] == "ran" for e in edges)


def test_call_graph_caller_supplied_route_fires():
    hits, _edges = dl.analyze_call_graph(
        TARGET_SOURCE, {CALLEE_ADDR: _meta(CALLEE_SOURCE, "Vault")},
        contract_name="GateKeeper")
    routes = [h for h in hits
              if h["kind"] == "call_graph_caller_supplied_route"]
    assert routes and routes[0]["recipient"] == "CALLER-SUPPLIED"


def test_call_graph_gated_callee_silent():
    hits, _edges = dl.analyze_call_graph(
        TARGET_SOURCE,
        {CALLEE_ADDR: _meta(CALLEE_GATED_SOURCE, "Vault")},
        contract_name="GateKeeper")
    assert hits == []


def test_call_graph_missing_callee_degrades():
    hits, edges = dl.analyze_call_graph(
        TARGET_SOURCE, {CALLEE_ADDR: None}, contract_name="GateKeeper")
    assert hits == []
    assert edges and all(e["status"] == "degraded" for e in edges)


# ---------------------------------------------------------------------------
# 3. Storage fixtures + synergy
# ---------------------------------------------------------------------------

STORAGE_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StorageVault {
    address public owner;
    bool public paused;
    uint256 public totalSupply;

    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""


def _word_addr(addr):
    return "0x" + "00" * 12 + addr.removeprefix("0x").lower()


def _word_int(n):
    return "0x" + format(n, "064x")


def test_storage_layout_derivation():
    layout = dl.state_layout(STORAGE_SOURCE, "StorageVault")
    by_name = {v["name"]: v["slot"] for v in layout}
    assert by_name["owner"] == 0
    assert by_name["paused"] == 1
    assert by_name["totalSupply"] == 2
    assert dl.decode_word(_word_addr(OWNER_ADDR), "address") == OWNER_ADDR.lower()
    assert dl.decode_word(_word_int(0), "bool") is False
    assert dl.decode_word(_word_int(1), "bool") is True


def test_storage_gate_synergy_helper():
    cand = {"severity": "high", "gated": False,
            "report_class": "candidate"}
    assert dl.apply_storage_gate(None, cand)["adjustment"] == "none"
    assert dl.apply_storage_gate({}, cand)["adjustment"] == "none"
    paused_rec = {"storage": {"paused": True}}
    adj = dl.apply_storage_gate(paused_rec, cand)
    assert adj["adjustment"] == "downgraded_paused"
    assert adj["severity"] == "low" and adj["report_class"] == "trigger_only"
    open_rec = {"storage": {"paused": False}}
    adj = dl.apply_storage_gate(open_rec, cand)
    assert adj["adjustment"] == "upgraded_live_open"
    assert adj["severity"] == "high"


def test_token_params_extraction():
    src = "contract T { uint256 public feeBps = 250; }"
    params = dl.extract_token_params(
        src, {"decimals": 6, "totalSupply": 1_000_000})
    assert params["decimals"] == {"value": 6, "origin": "eth_call"}
    assert params["totalSupply"]["value"] == 1_000_000
    assert params["fee_source_constant"] == {"value": 250,
                                             "origin": "source"}


# ---------------------------------------------------------------------------
# 4. Bytecode deep fixtures (hand-assembled)
# ---------------------------------------------------------------------------

def _sel(sig):
    return keccak256(sig.encode())[:4].hex()


# PUSH4 withdraw() ; CALL ; DELEGATECALL ; SELFDESTRUCT
BYTECODE_VULN = "0x63" + _sel("withdraw()") + "f1f4ff"
# PUSH4 sweep(address) ; CALL
BYTECODE_SWEEP = "0x63" + _sel("sweep(address)") + "f1"
BYTECODE_CLEAN = "0x6001600201"  # PUSH1 1, PUSH1 2, ADD


def test_bytecode_deep_fires():
    hits = dl.analyze_bytecode_deep(BYTECODE_VULN)
    kinds = {h["kind"] for h in hits}
    assert "bytecode_delegatecall" in kinds
    assert "bytecode_selfdestruct" in kinds
    assert "bytecode_selector_withdraw" in kinds
    for h in hits:
        assert h["recipient"] == "UNRESOLVED"
        assert "missing piece" in h["detail"] or "UNRESOLVED" in h["detail"]


def test_bytecode_sweep_recipient_caller_supplied():
    hits = dl.analyze_bytecode_deep(BYTECODE_SWEEP)
    sel = [h for h in hits if h["kind"] == "bytecode_selector_sweep"]
    assert sel and sel[0]["recipient"] == "CALLER-SUPPLIED"


def test_bytecode_clean_silent():
    assert dl.analyze_bytecode_deep(BYTECODE_CLEAN) == []
    assert dl.analyze_bytecode_deep("0x") == []


# ---------------------------------------------------------------------------
# 5. Confirmation classification (pure)
# ---------------------------------------------------------------------------

_CAND = {"check": "access_control_flaw", "severity": "high",
         "gated": False, "report_class": "candidate",
         "function": "withdraw", "recipient": "CALLER"}


def test_confirmation_classification():
    hit = {"detector": "unprotected-upgrade",
           "message": "unprotected upgrade / access control"}
    v = dl.classify_confirmation(_CAND, {"ran": True, "hits": [hit]})
    assert v["verdict"] == "tool_confirmed_pattern"
    v = dl.classify_confirmation(_CAND, {"ran": True, "hits": []})
    assert v["verdict"] == "false_positive" and v["severity"] == "low"
    v = dl.classify_confirmation(
        _CAND, {"ran": False, "hits": [], "reason": "no binary"})
    assert v["verdict"] == "unconfirmed" and "no binary" in v["reason"]
    v = dl.classify_confirmation(
        _CAND, {"ran": True, "hits": [hit]},
        record={"storage": {"paused": True}})
    assert v["verdict"] == "trigger_only"


# ---------------------------------------------------------------------------
# 6. Step paths + corroboration
# ---------------------------------------------------------------------------

def _full_candidate():
    return {"function": "withdraw",
            "code": "function withdraw() public { "
                    "payable(msg.sender).transfer(1); }",
            "gated": False, "recipient": "CALLER",
            "check": "access_control_flaw",
            "amount_figures": {"received": 9750, "fee_bps": 250}}


def test_step_path_complete_with_probe():
    rec = {"storage": {"paused": False, "owner": OWNER_ADDR},
           "call_edges": [], "math": {}}
    out = sp.build_step_path(_full_candidate(), rec)
    assert all(s["status"] == "evidenced" for s in out["steps"])
    assert out["verdict"] == "PATH_COMPLETE"
    cand = dict(_full_candidate(), probe={"status": "success"})
    out = sp.build_step_path(cand, rec)
    assert out["verdict"] == "VERIFIED_REAL_CANDIDATE"


def test_step_path_unproven_caps_verdict():
    cand = _full_candidate()
    cand["recipient"] = "UNRESOLVED"
    out = sp.build_step_path(cand, {"storage": {}, "call_edges": []})
    assert out["verdict"] == "UNVERIFIED"
    assert any(s["status"] == "UNPROVEN" for s in out["steps"])
    corr = sp.corroborate("claim", "flags", "silent")
    assert corr["agree"] is False and corr["probe_settles"] is True
    corr = sp.corroborate("claim", "flags", "flags")
    assert corr["agree"] is True


# ---------------------------------------------------------------------------
# 7. Plugin runs (all network stubbed)
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


def _target(addr=TARGET_ADDR):
    return Target(raw=f"ethereum:{addr}", type="crypto_wallet",
                  normalized=f"ethereum:{addr}")


def _patch_chain(monkeypatch, code="0x60006000", source_by_addr=None,
                 storage_by_slot=None):
    async def fake_code(ctx, chain, address):
        return code

    async def fake_source(ctx, chain, address, key=None):
        return (source_by_addr or {}).get(address.lower())

    async def fake_storage(ctx, chain, address, slot):
        return (storage_by_slot or {}).get(slot, _word_int(0))

    monkeypatch.setattr(cc, "rpc_get_code", fake_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "rpc_get_storage_at", fake_storage)


def test_plugin_call_graph_run(monkeypatch):
    _patch_chain(monkeypatch, source_by_addr={
        TARGET_ADDR.lower(): _meta(TARGET_SOURCE, "GateKeeper"),
        CALLEE_ADDR.lower(): _meta(CALLEE_SOURCE, "Vault")})
    ctx = FakeCtx()
    res = asyncio.run(
        dl.CrossContractCallGraphPlugin().run(_target(), ctx))
    hits = [f for f in res.findings if f.key == "call_graph_gate_bypass"]
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["recipient"] in ("CALLER", "CALLER-SUPPLIED", "UNRESOLVED")
    assert ev["steps"] and ev["path_verdict"]
    assert ev["corroboration"][0]["claim"] == "call_graph_gate_bypass"
    cov = [f for f in res.findings if f.key == "deep_layer_coverage"]
    assert cov and cov[0].evidence["depth"]["callees"] == 1
    rec = dl.peek_record(ctx, "ethereum", TARGET_ADDR)
    assert [a.lower() for a in rec["callees"]] == [CALLEE_ADDR.lower()]
    assert ctx.shared.get("deep_candidates")


def test_plugin_storage_run_fires_and_synergy(monkeypatch):
    slots = {dl.slot_hex(0): _word_addr("0x" + "00" * 20),
             dl.slot_hex(1): _word_int(0)}  # owner = 0, paused = false
    _patch_chain(monkeypatch,
                 source_by_addr={TARGET_ADDR.lower():
                                 _meta(STORAGE_SOURCE, "StorageVault")},
                 storage_by_slot=slots)

    async def fake_eth(ctx, chain, addr, sig):
        return {"decimals()": 18, "totalSupply()": 1000,
                "totalAssets()": 2000}.get(sig)

    monkeypatch.setattr(dl, "eth_call_read", fake_eth)
    ctx = FakeCtx()
    res = asyncio.run(
        dl.StorageStateAnalysisPlugin().run(_target(), ctx))
    keys = {f.key for f in res.findings}
    assert "storage_ungated_drain_live" in keys
    assert "storage_owner_zero_ungated" in keys
    hit = [f for f in res.findings
           if f.key == "storage_ungated_drain_live"][0]
    assert hit.evidence["storage"]["slots"]["paused"]["raw"] == _word_int(0)
    assert hit.evidence["observed_at"]
    rec = dl.peek_record(ctx, "ethereum", TARGET_ADDR)
    assert rec["token_params"]["decimals"]["value"] == 18
    assert rec["math"]["inflation_check"]["figures"]["attacker_profit"] \
        is not None
    # synergy chain: a later detector-side read upgrades the flag
    adj = dl.apply_storage_gate(rec, {"severity": "high", "gated": False})
    assert adj["adjustment"] == "upgraded_live_open"


def test_plugin_storage_paused_control_silent(monkeypatch):
    slots = {dl.slot_hex(0): _word_addr(OWNER_ADDR),
             dl.slot_hex(1): _word_int(1)}  # paused = true
    _patch_chain(monkeypatch,
                 source_by_addr={TARGET_ADDR.lower():
                                 _meta(STORAGE_SOURCE, "StorageVault")},
                 storage_by_slot=slots)

    async def fake_eth(ctx, chain, addr, sig):
        return None

    monkeypatch.setattr(dl, "eth_call_read", fake_eth)
    ctx = FakeCtx()
    res = asyncio.run(
        dl.StorageStateAnalysisPlugin().run(_target(), ctx))
    keys = {f.key for f in res.findings}
    assert "storage_ungated_drain_live" not in keys
    assert "storage_owner_zero_ungated" not in keys
    cov = [f for f in res.findings if f.key == "deep_layer_coverage"]
    assert cov and cov[0].evidence["depth"]["storage"] == "ran"


def test_plugin_bytecode_run(monkeypatch):
    _patch_chain(monkeypatch, code=BYTECODE_VULN, source_by_addr={})
    ctx = FakeCtx()
    res = asyncio.run(
        dl.BytecodeDeepAnalysisPlugin().run(_target(), ctx))
    keys = {f.key for f in res.findings}
    assert "bytecode_delegatecall" in keys
    cov = [f for f in res.findings if f.key == "deep_layer_coverage"]
    assert cov[0].evidence["depth"]["bytecode_deep"] == "ran"
    # source available -> skip, no bytecode findings
    _patch_chain(monkeypatch, code=BYTECODE_VULN, source_by_addr={
        TARGET_ADDR.lower(): _meta(STORAGE_SOURCE, "StorageVault")})
    res = asyncio.run(
        dl.BytecodeDeepAnalysisPlugin().run(_target(), FakeCtx()))
    assert not [f for f in res.findings
                if f.key.startswith("bytecode_")]
    cov = [f for f in res.findings if f.key == "deep_layer_coverage"]
    assert cov[0].evidence["depth"]["bytecode_deep"] == \
        "source_available_skip"


def test_plugin_confirmation_queue(monkeypatch):
    async def fake_slither(source):
        return {"ran": True, "hits": [
            {"detector": "unprotected-upgrade",
             "message": "access control missing"}], "reason": ""}

    monkeypatch.setattr(dl, "run_slither_confirmation", fake_slither)
    cand = dict(_CAND, address=TARGET_ADDR, chain="ethereum",
                source=STORAGE_SOURCE, code="function withdraw() {}")
    ctx = FakeCtx(shared={"allow_heavy": True,
                          "deep_candidates": [cand]})
    res = asyncio.run(
        dl.CandidateConfirmationQueuePlugin().run(_target(), ctx))
    hits = [f for f in res.findings if f.key == "candidate_confirmation"]
    assert len(hits) == 1
    assert hits[0].evidence["confirmation"] == "tool_confirmed_pattern"
    assert hits[0].evidence["fuzz"]["ran"] is False  # honest seam
    assert hits[0].evidence["steps"]


def test_plugin_confirmation_queue_off_fast_lane():
    cand = dict(_CAND, address=TARGET_ADDR, chain="ethereum",
                source=STORAGE_SOURCE)
    ctx = FakeCtx(shared={"deep_candidates": [cand]})
    res = asyncio.run(
        dl.CandidateConfirmationQueuePlugin().run(_target(), ctx))
    assert res.findings == []
    assert "stayed off" in res.reason


def test_fuzz_seam_honest_default():
    out = asyncio.run(dl.run_fuzz_confirmation(_CAND))
    assert out["ran"] is False and "not auto-run" in out["reason"]


# ---------------------------------------------------------------------------
# 8. Registry
# ---------------------------------------------------------------------------

def test_registry_discovers_deep_plugins():
    reg = discover()
    for pid in ("cross_contract_call_graph", "storage_state_analysis",
                "bytecode_deep_analysis", "candidate_confirmation_queue"):
        assert pid in reg
    assert len(reg) == 794  # 778 master + 4 deep-analysis plugins (deep_layers) + 5 deep3 detectors + 3 deep-audit batch-4 detectors (deep_audit4) + 8 deep-audit batch-9 detectors (deep_audit9)
