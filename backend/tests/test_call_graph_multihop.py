"""Wave 1.2: multi-hop cross-contract call graph (deep_layers).

Covers analyze_call_graph_multihop (pure) and the
CallGraphMultihopPlugin run (all network stubbed, FakeCtx style
from test_deep_layers):

1. 2-contract composer: gated A.execute -> ungated B.relay, whose
   transfer is the sink. Must fire gate-bypass, caller-supplied
   route AND value-sink findings, with the full 2-hop path in the
   evidence.
2. Correctly-gated 2-contract pair: B.relay is onlyOwner-gated.
   Must stay silent.
3. 3-hop chain: gated A.execute -> ungated B.relay -> ungated
   C.drain (the sink). Must fire with the full 3-hop path.
4. Live storage gate at a middle hop: paused=true downgrades the
   path to trigger-only; paused=false keeps it a candidate.
5. Missing middle-hop source degrades the edge, never fakes it.
6. A call cycle (B calls back into A) terminates, never loops.
7. Plugin run: BFS fetch, per-hop storage reads, coverage depth,
   deep_candidates published.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import deep_layers as dl  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

COMPOSER_ADDR = "0x" + "aa" * 20
RELAY_ADDR = "0x" + "bb" * 20
DRAIN_ADDR = "0x" + "cc" * 20
RELAY2_ADDR = "0x" + "dd" * 20
BOUNCE_ADDR = "0x" + "ee" * 20
OWNER_ADDR = "0x" + "ff" * 20


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

COMPOSER_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRelay {
    function relay(address to, uint256 amt) external;
}

contract Composer {
    IRelay public relay = IRelay(0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb);
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function execute(address to, uint256 amt) public onlyOwner {
        relay.relay(to, amt);
    }
}
"""

COMPOSER3_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRelay {
    function relay(address to, uint256 amt) external;
}

contract Composer {
    IRelay public relay = IRelay(0xDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDd);
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function execute(address to, uint256 amt) public onlyOwner {
        relay.relay(to, amt);
    }
}
"""

RELAY_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Relay {
    function relay(address to, uint256 amt) public {
        payable(to).transfer(amt);
    }
}
"""

RELAY_GATED_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Relay {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function relay(address to, uint256 amt) public onlyOwner {
        payable(to).transfer(amt);
    }
}
"""

RELAY2_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDrain {
    function drain(address to, uint256 amt) external;
}

contract Relay2 {
    IDrain public drainer = IDrain(0xCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCc);
    address public owner;

    function relay(address to, uint256 amt) public {
        drainer.drain(to, amt);
    }
}
"""

DRAIN_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Drain {
    function drain(address to, uint256 amt) public {
        payable(to).transfer(amt);
    }
}
"""

BOUNCE_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IComposer {
    function execute(address to, uint256 amt) external;
}

contract Bounce {
    IComposer public composer = IComposer(0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa);

    function bounce(address to, uint256 amt) public {
        composer.execute(to, amt);
    }
}
"""


def _meta(source, name):
    return {"source": source, "contract_name": name,
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def _kinds(hits):
    return {h["kind"] for h in hits}


# ---------------------------------------------------------------------------
# 1. Two-contract composer fires, full path in evidence
# ---------------------------------------------------------------------------

def test_multihop_two_contract_composer_fires():
    hits, paths, edges = dl.analyze_call_graph_multihop(
        COMPOSER_ADDR, COMPOSER_SOURCE,
        {RELAY_ADDR.lower(): _meta(RELAY_SOURCE, "Relay")},
        contract_name="Composer")
    kinds = _kinds(hits)
    assert "call_graph_gate_bypass_multihop" in kinds
    assert "call_graph_caller_supplied_route_multihop" in kinds
    assert "call_graph_value_sink_multihop" in kinds
    assert len(paths) == 1
    path = paths[0]
    assert len(path) == 2
    assert [h["function"] for h in path] == ["execute", "relay"]
    assert path[0]["gated"] is True
    assert path[1]["gated"] is False
    assert path[1]["recipient"] == "CALLER-SUPPLIED"
    assert path[0]["address"] == COMPOSER_ADDR
    assert path[1]["address"].lower() == RELAY_ADDR.lower()
    bypass = [h for h in hits
              if h["kind"] == "call_graph_gate_bypass_multihop"][0]
    assert bypass["severity"] == "high"
    assert bypass["report_class"] == "candidate"
    assert bypass["hops"] == 2
    assert bypass["recipient"] == "CALLER-SUPPLIED"
    assert "execute" in bypass["detail"] and "relay" in bypass["detail"]
    assert all(e["status"] == "ran" for e in edges)


# ---------------------------------------------------------------------------
# 2. Correctly-gated pair stays silent
# ---------------------------------------------------------------------------

def test_multihop_gated_pair_silent():
    hits, paths, _edges = dl.analyze_call_graph_multihop(
        COMPOSER_ADDR, COMPOSER_SOURCE,
        {RELAY_ADDR.lower(): _meta(RELAY_GATED_SOURCE, "Relay")},
        contract_name="Composer")
    assert hits == []
    # the value path exists but every hop after the entry is gated,
    # so no finding is emitted for it
    assert len(paths) == 1
    assert paths[0][1]["gated"] is True


# ---------------------------------------------------------------------------
# 3. Three-hop chain fires with the full path
# ---------------------------------------------------------------------------

def test_multihop_three_hop_chain_fires():
    hits, paths, edges = dl.analyze_call_graph_multihop(
        COMPOSER_ADDR, COMPOSER3_SOURCE,
        {RELAY2_ADDR.lower(): _meta(RELAY2_SOURCE, "Relay2"),
         DRAIN_ADDR.lower(): _meta(DRAIN_SOURCE, "Drain")},
        contract_name="Composer")
    kinds = _kinds(hits)
    assert "call_graph_gate_bypass_multihop" in kinds
    assert "call_graph_caller_supplied_route_multihop" in kinds
    assert "call_graph_value_sink_multihop" in kinds
    assert len(paths) == 1
    path = paths[0]
    assert len(path) == 3
    assert [h["function"] for h in path] == ["execute", "relay", "drain"]
    assert [h["gated"] for h in path] == [True, False, False]
    assert path[2]["recipient"] == "CALLER-SUPPLIED"
    bypass = [h for h in hits
              if h["kind"] == "call_graph_gate_bypass_multihop"][0]
    assert bypass["hops"] == 3
    assert bypass["callee"].lower() == DRAIN_ADDR.lower()
    assert bypass["callee_function"] == "drain"
    assert all(e["status"] == "ran" for e in edges)


# ---------------------------------------------------------------------------
# 4. Live storage gate at a middle hop
# ---------------------------------------------------------------------------

def test_multihop_paused_middle_hop_downgrades():
    storage = {RELAY_ADDR.lower(): {"paused": True,
                                    "owner": OWNER_ADDR}}
    hits, _paths, _edges = dl.analyze_call_graph_multihop(
        COMPOSER_ADDR, COMPOSER_SOURCE,
        {RELAY_ADDR.lower(): _meta(RELAY_SOURCE, "Relay")},
        contract_name="Composer", storage_by_addr=storage)
    assert hits, "paused path is reported, downgraded - not dropped"
    bypass = [h for h in hits
              if h["kind"] == "call_graph_gate_bypass_multihop"][0]
    assert bypass["severity"] == "low"
    assert bypass["report_class"] == "trigger_only"
    assert "paused=true" in bypass["detail"]
    assert "Relay.relay" in bypass["detail"]


def test_multihop_live_open_middle_hop_keeps_candidate():
    storage = {RELAY_ADDR.lower(): {"paused": False,
                                    "owner": OWNER_ADDR}}
    hits, _paths, _edges = dl.analyze_call_graph_multihop(
        COMPOSER_ADDR, COMPOSER_SOURCE,
        {RELAY_ADDR.lower(): _meta(RELAY_SOURCE, "Relay")},
        contract_name="Composer", storage_by_addr=storage)
    bypass = [h for h in hits
              if h["kind"] == "call_graph_gate_bypass_multihop"][0]
    assert bypass["severity"] == "high"
    assert bypass["report_class"] == "candidate"


def test_multihop_missing_live_state_says_so():
    hits, _paths, _edges = dl.analyze_call_graph_multihop(
        COMPOSER_ADDR, COMPOSER_SOURCE,
        {RELAY_ADDR.lower(): _meta(RELAY_SOURCE, "Relay")},
        contract_name="Composer", storage_by_addr={})
    bypass = [h for h in hits
              if h["kind"] == "call_graph_gate_bypass_multihop"][0]
    assert bypass["severity"] == "high"
    assert "unavailable" in bypass["detail"]


# ---------------------------------------------------------------------------
# 5. Missing middle-hop source degrades, never fakes
# ---------------------------------------------------------------------------

def test_multihop_missing_callee_degrades():
    hits, paths, edges = dl.analyze_call_graph_multihop(
        COMPOSER_ADDR, COMPOSER_SOURCE,
        {RELAY_ADDR.lower(): None},
        contract_name="Composer")
    assert hits == []
    assert paths == []
    assert edges and all(e["status"] == "degraded" for e in edges)


# ---------------------------------------------------------------------------
# 6. Call cycle terminates
# ---------------------------------------------------------------------------

def test_multihop_cycle_terminates():
    hits, paths, _edges = dl.analyze_call_graph_multihop(
        COMPOSER_ADDR, COMPOSER_SOURCE,
        {BOUNCE_ADDR.lower(): _meta(BOUNCE_SOURCE, "Bounce")},
        contract_name="Composer")
    # Bounce calls back into the Composer entry; the walk must stop
    # at the visited set instead of looping, and no sink is reached.
    assert hits == []
    assert paths == []


# ---------------------------------------------------------------------------
# 7. Plugin run (all network stubbed)
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


def _target(addr=COMPOSER_ADDR):
    return Target(raw=f"ethereum:{addr}", type="crypto_wallet",
                  normalized=f"ethereum:{addr}")


def _word_addr(addr):
    return "0x" + "00" * 12 + addr.removeprefix("0x").lower()


def _word_int(n):
    return "0x" + format(n, "064x")


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


def test_plugin_multihop_run(monkeypatch):
    _patch_chain(monkeypatch, source_by_addr={
        COMPOSER_ADDR.lower(): _meta(COMPOSER3_SOURCE, "Composer"),
        RELAY2_ADDR.lower(): _meta(RELAY2_SOURCE, "Relay2"),
        DRAIN_ADDR.lower(): _meta(DRAIN_SOURCE, "Drain")},
        storage_by_slot={dl.slot_hex(0): _word_addr(OWNER_ADDR)})
    ctx = FakeCtx()
    res = asyncio.run(
        dl.CallGraphMultihopPlugin().run(_target(), ctx))
    keys = {f.key for f in res.findings}
    assert "call_graph_gate_bypass_multihop" in keys
    assert "call_graph_caller_supplied_route_multihop" in keys
    assert "call_graph_value_sink_multihop" in keys
    hit = [f for f in res.findings
           if f.key == "call_graph_gate_bypass_multihop"][0]
    ev = hit.evidence
    assert ev["hops"] == 3
    assert [h["function"] for h in ev["path"]] == [
        "execute", "relay", "drain"]
    assert ev["recipient"] == "CALLER-SUPPLIED"
    assert ev["report_class"] == "candidate"
    assert ev["hop_storage"], "per-hop live storage in evidence"
    assert ev["steps"] and ev["path_verdict"]
    assert ev["corroboration"][0]["claim"] == \
        "call_graph_gate_bypass_multihop"
    cov = [f for f in res.findings if f.key == "deep_layer_coverage"]
    assert cov and cov[0].evidence["depth"]["call_graph_multihop"] == "ran"
    assert cov[0].evidence["depth"]["nodes"] == 3
    rec = dl.peek_record(ctx, "ethereum", COMPOSER_ADDR)
    assert rec["depth"]["multihop_max_depth"] == 3
    assert rec["depth"]["multihop_paths"] == 1
    assert rec["depth"]["multihop_degraded_edges"] == 0
    cands = ctx.shared.get("deep_candidates") or []
    assert {c["check"] for c in cands} >= {
        "call_graph_gate_bypass_multihop",
        "call_graph_caller_supplied_route_multihop",
        "call_graph_value_sink_multihop"}


def test_plugin_multihop_no_source_degrades(monkeypatch):
    _patch_chain(monkeypatch, source_by_addr={})
    ctx = FakeCtx()
    res = asyncio.run(
        dl.CallGraphMultihopPlugin().run(_target(), ctx))
    assert not [f for f in res.findings
                if f.key.startswith("call_graph_")
                and f.key != "deep_layer_coverage"]
    cov = [f for f in res.findings if f.key == "deep_layer_coverage"]
    assert cov and cov[0].evidence["depth"]["call_graph_multihop"] == \
        "degraded_no_source"


def test_registry_discovers_multihop_plugin():
    reg = discover()
    assert "call_graph_multihop" in reg
    assert len(reg) == 1434
