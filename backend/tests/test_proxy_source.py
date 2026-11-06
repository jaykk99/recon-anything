"""Chain-layer proxy resolution (scripts/proxy_source.py).

Unit tests with the cast/fetch layers monkeypatched - no live
chain reads in the suite (the live read-only smoke is run
manually against a well-known proxy, see the lane report).

Covered: EIP-1967 storage word -> address extraction, beacon
two-step (implementation() call, then slot-0 fallback), EIP-1167
fixture bytecode, function-in-implementation happy path,
function-nowhere -> None, depth-2 (impl of impl), and the fast
path: function already in the target's deployed scope returns
the target source with NO chain reads at all.
"""
import importlib.util
import pathlib


def _load():
    path = pathlib.Path(__file__).resolve().parent.parent / \
        "scripts" / "proxy_source.py"
    spec = importlib.util.spec_from_file_location(
        "proxy_source", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PROXY = "0x1000000000000000000000000000000000000001"
IMPL = "0x2000000000000000000000000000000000000002"
IMPL2 = "0x3000000000000000000000000000000000000003"
BEACON = "0x4000000000000000000000000000000000000004"


def _word(addr):
    return "0x" + "00" * 12 + addr[2:].lower()


ZERO_WORD = "0x" + "00" * 32

PROXY_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract FiatProxy {
    function admin() external view returns (address) {
        return address(0);
    }
}
"""

IMPL_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract FiatToken {
    function sweep(address to, uint256 amt) external {
    }
    function transfer(address to, uint256 amt) external
        returns (bool) {
        return true;
    }
}
"""

IMPL2_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DeepToken {
    function sweep(address to, uint256 amt) external {
    }
}
"""


def _src(source, name, origin="Sourcify"):
    return {"source": source, "contract_name": name,
            "origin": origin}


# ---------------------------------------------------------------------------
# storage_at / _cast layer
# ---------------------------------------------------------------------------

def test_storage_at_returns_word_and_passes_slot(monkeypatch):
    mod = _load()
    seen = []

    def fake_cast(args, timeout=25):
        seen.append(args)
        return _word(IMPL) + "\n", None

    monkeypatch.setattr(mod.av, "_cast", fake_cast)
    word = mod.storage_at("ethereum", PROXY,
                          mod.cc.EIP1967_IMPLEMENTATION_SLOT)
    assert word == _word(IMPL)
    assert seen and seen[0][0] == "storage"
    assert mod.cc.EIP1967_IMPLEMENTATION_SLOT in seen[0]
    assert PROXY in seen[0]


def test_storage_at_unknown_chain_is_none():
    mod = _load()
    assert mod.storage_at("nope-chain", PROXY, "0x0") is None


# ---------------------------------------------------------------------------
# resolve_implementation_sync
# ---------------------------------------------------------------------------

def test_eip1967_word_to_address(monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "code_at", lambda c, a: "0x6000")
    slots = {mod.cc.EIP1967_IMPLEMENTATION_SLOT: _word(IMPL)}
    monkeypatch.setattr(
        mod, "storage_at",
        lambda c, a, s: slots.get(s, ZERO_WORD))
    res = mod.resolve_implementation_sync("ethereum", PROXY)
    assert res == {"implementation": IMPL, "via": "eip1967",
                   "beacon": ""}


def test_eip1167_fixture_bytecode(monkeypatch):
    mod = _load()
    code = ("0x363d3d373d3d3d363d73" + IMPL[2:] +
            "5af43d82803e903d91602b57fd5bf3")
    monkeypatch.setattr(mod, "code_at", lambda c, a: code)

    def no_storage(c, a, s):
        raise AssertionError("storage read on the EIP-1167 path")

    monkeypatch.setattr(mod, "storage_at", no_storage)
    res = mod.resolve_implementation_sync("ethereum", PROXY)
    assert res == {"implementation": IMPL, "via": "eip1167",
                   "beacon": ""}


def test_beacon_two_step_via_call(monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "code_at", lambda c, a: "0x6000")
    slots = {(PROXY, mod.cc.EIP1967_IMPLEMENTATION_SLOT): ZERO_WORD,
             (PROXY, mod.cc.EIP1967_BEACON_SLOT): _word(BEACON)}
    monkeypatch.setattr(
        mod, "storage_at",
        lambda c, a, s: slots.get((a, s), ZERO_WORD))
    calls = []

    def fake_call(c, a, sig):
        calls.append((a, sig))
        return IMPL

    monkeypatch.setattr(mod, "call_address", fake_call)
    res = mod.resolve_implementation_sync("ethereum", PROXY)
    assert res == {"implementation": IMPL, "via": "beacon",
                   "beacon": BEACON}
    assert calls == [(BEACON, "implementation()(address)")]


def test_beacon_slot0_fallback(monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "code_at", lambda c, a: "0x6000")
    slots = {(PROXY, mod.cc.EIP1967_IMPLEMENTATION_SLOT): ZERO_WORD,
             (PROXY, mod.cc.EIP1967_BEACON_SLOT): _word(BEACON),
             (BEACON, "0x0"): _word(IMPL)}
    monkeypatch.setattr(
        mod, "storage_at",
        lambda c, a, s: slots.get((a, s), ZERO_WORD))
    monkeypatch.setattr(mod, "call_address", lambda c, a, s: "")
    res = mod.resolve_implementation_sync("ethereum", PROXY)
    assert res == {"implementation": IMPL, "via": "beacon",
                   "beacon": BEACON}


def test_no_proxy_anywhere(monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "code_at", lambda c, a: "0x6000")
    monkeypatch.setattr(mod, "storage_at",
                        lambda c, a, s: ZERO_WORD)
    res = mod.resolve_implementation_sync("ethereum", PROXY)
    assert res == {"implementation": "", "via": "", "beacon": ""}


# ---------------------------------------------------------------------------
# fetch_source_for fallback order
# ---------------------------------------------------------------------------

def test_fetch_source_for_falls_back_to_v2(monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod.av, "fetch_sourcify",
                        lambda c, a: None)
    monkeypatch.setattr(mod, "fetch_sourcify_v2",
                        lambda c, a: _src(IMPL_SOURCE, "FiatToken",
                                          "Sourcify v2"))
    out = mod.fetch_source_for("ethereum", IMPL)
    assert out["origin"] == "Sourcify v2"


def test_fetch_source_for_prefers_v1(monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod.av, "fetch_sourcify",
                        lambda c, a: _src(IMPL_SOURCE, "FiatToken"))
    monkeypatch.setattr(
        mod, "fetch_sourcify_v2",
        lambda c, a: (_ for _ in ()).throw(
            AssertionError("v2 consulted after a v1 hit")))
    assert mod.fetch_source_for("ethereum", IMPL)["origin"] == \
        "Sourcify"


# ---------------------------------------------------------------------------
# resolve_candidate_source
# ---------------------------------------------------------------------------

def _patch_fetch(mod, monkeypatch, mapping):
    monkeypatch.setattr(
        mod, "fetch_source_for",
        lambda c, a: mapping.get(a.lower()))


def test_function_in_impl_happy_path(monkeypatch):
    mod = _load()
    _patch_fetch(mod, monkeypatch, {
        PROXY: _src(PROXY_SOURCE, "FiatProxy"),
        IMPL: _src(IMPL_SOURCE, "FiatToken", "Sourcify v2"),
    })
    monkeypatch.setattr(
        mod, "resolve_implementation_sync",
        lambda c, a: {"implementation": IMPL, "via": "eip1967",
                      "beacon": ""})
    out = mod.resolve_candidate_source("ethereum", PROXY, "sweep")
    assert out is not None
    assert out["source"] == IMPL_SOURCE
    assert out["contract_name"] == "FiatToken"
    assert out["implementation"] == IMPL
    assert out["via"] == "eip1967"
    assert out["origin"] == \
        f"Sourcify v2 via eip1967 implementation {IMPL}"


def test_function_nowhere_returns_none(monkeypatch):
    mod = _load()
    _patch_fetch(mod, monkeypatch, {
        PROXY: _src(PROXY_SOURCE, "FiatProxy"),
        IMPL: _src(IMPL_SOURCE, "FiatToken"),
    })
    monkeypatch.setattr(
        mod, "resolve_implementation_sync",
        lambda c, a: {"implementation": IMPL, "via": "eip1967",
                      "beacon": ""}
        if a == PROXY else
        {"implementation": "", "via": "", "beacon": ""})
    assert mod.resolve_candidate_source(
        "ethereum", PROXY, "nonexistentFn") is None


def test_depth_two_impl_of_impl(monkeypatch):
    mod = _load()
    _patch_fetch(mod, monkeypatch, {
        PROXY: _src(PROXY_SOURCE, "FiatProxy"),
        IMPL: _src(PROXY_SOURCE, "FiatProxy"),
        IMPL2: _src(IMPL2_SOURCE, "DeepToken"),
    })
    chain_map = {PROXY: IMPL, IMPL: IMPL2}
    monkeypatch.setattr(
        mod, "resolve_implementation_sync",
        lambda c, a: {"implementation": chain_map.get(a, ""),
                      "via": "eip1967", "beacon": ""})
    out = mod.resolve_candidate_source("ethereum", PROXY, "sweep")
    assert out is not None
    assert out["implementation"] == IMPL2
    assert out["source"] == IMPL2_SOURCE


def test_target_scope_already_fine_no_chain_reads(monkeypatch):
    mod = _load()
    target = _src(IMPL_SOURCE, "FiatToken")
    _patch_fetch(mod, monkeypatch, {PROXY: target})

    def boom(*a, **k):
        raise AssertionError(
            "chain read on the target-scope fast path")

    monkeypatch.setattr(mod, "resolve_implementation_sync", boom)
    monkeypatch.setattr(mod, "storage_at", boom)
    monkeypatch.setattr(mod, "code_at", boom)
    monkeypatch.setattr(mod, "call_address", boom)
    out = mod.resolve_candidate_source("ethereum", PROXY,
                                       "transfer")
    assert out is not None
    assert out["source"] == IMPL_SOURCE
    assert out["implementation"] == "" and out["via"] == ""
    assert out["origin"] == "Sourcify"


def test_empty_function_returns_none():
    mod = _load()
    assert mod.resolve_candidate_source("ethereum", PROXY, "") \
        is None
