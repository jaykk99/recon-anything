"""Probe encoder for complex ABI arguments (arrays / bytes /
tuples), the auto-validator probe construction, and the
auto_validate runner's cast-argument defaults.

Known-vector expectations were generated with
`cast calldata` / `cast abi-encode` (foundry 1.4.4) during
development and are hardcoded here - the tests never call cast.
"""
import asyncio
import importlib.util
import os
import pathlib
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins import auto_validator as av  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import contract_sim as sim  # noqa: E402

ADDR = "0x" + "ab" * 20

SAM_CALLDATA = (
    "0xa5643bf2"
    "0000000000000000000000000000000000000000000000000000000000000060"
    "0000000000000000000000000000000000000000000000000000000000000001"
    "00000000000000000000000000000000000000000000000000000000000000a0"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "6461766500000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003")

TUPLE_CALLDATA = (
    "0xc5cba275"
    "0000000000000000000000000000000000000000000000000000000000000005"
    "0000000000000000000000000000000000000000000000000000000000000001")

FIXED_ARRAY_CALLDATA = (
    "0xd14d385d"
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003")

BYTES_CALLDATA = (
    "0xb2e4ec10"
    "0000000000000000000000000000000000000000000000000000000000000020"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "1234000000000000000000000000000000000000000000000000000000000000")

NESTED_CALLDATA = (
    "0xe498d66f"
    "0000000000000000000000000000000000000000000000000000000000000020"
    "0000000000000000000000000000000000000000000000000000000000000007"
    "0000000000000000000000000000000000000000000000000000000000000040"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000008"
    "0000000000000000000000000000000000000000000000000000000000000009")

ARRAY_OF_TUPLES_CALLDATA = (
    "0xbfe011d3"
    "0000000000000000000000000000000000000000000000000000000000000020"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000000")


def _calldata(name, types, values):
    return sim.function_selector(
        sim.canonical_signature(name, types)) + \
        sim.encode_call_args(types, values)


# ---------------------------------------------------------------------------
# Known vectors
# ---------------------------------------------------------------------------

def test_sam_spec_example():
    # Solidity ABI spec example: sam(bytes,bool,uint256[])
    # with (b"dave", True, [1, 2, 3]).
    assert _calldata("sam", ["bytes", "bool", "uint256[]"],
                     [b"dave", True, [1, 2, 3]]) == SAM_CALLDATA


def test_tuple_argument():
    assert _calldata("f", ["(uint256,bool)"],
                     [(5, True)]) == TUPLE_CALLDATA


def test_fixed_array():
    assert _calldata("g", ["uint256[3]"],
                     [[1, 2, 3]]) == FIXED_ARRAY_CALLDATA


def test_nested_tuple_with_dynamic_array():
    assert _calldata("n", ["(uint256,uint256[])"],
                     [(7, [8, 9])]) == NESTED_CALLDATA


def test_array_of_tuples():
    assert _calldata("m", ["(uint256,bool)[]"],
                     [[(1, True), (2, False)]]) == \
        ARRAY_OF_TUPLES_CALLDATA


def test_bytes_regression():
    # Dynamic bytes already worked before this fix; the encoding
    # must stay byte-identical.
    assert _calldata("h", ["bytes"],
                     [bytes.fromhex("1234")]) == BYTES_CALLDATA


def test_static_regression_byte_identical():
    addr = "0x" + "cd" * 20
    enc = sim.encode_call_args(["address", "uint256"], [addr, 1])
    assert enc == "0" * 24 + addr[2:] + "%064x" % 1
    dyn = sim.encode_call_args(["string"], ["fuzz"])
    assert dyn is not None and dyn.startswith("%064x" % 32)


# ---------------------------------------------------------------------------
# _param_types
# ---------------------------------------------------------------------------

def test_param_types_morpho_style_tuple():
    # Morpho deallocateInternal shape: a tuple parameter that the
    # old parser rejected outright.
    assert sim._param_types(
        "deallocateInternal((address,address,uint256),uint256)") == \
        ["(address,address,uint256)", "uint256"]
    # Same shape as it appears in verified source, with parameter
    # names and a visibility tail.
    assert sim._param_types(
        "function deallocateInternal("
        "(address token, address adapter, uint256 assets) params, "
        "uint amount) external") == \
        ["(address,address,uint256)", "uint256"]


def test_param_types_arrays_and_aliases():
    assert sim._param_types(
        "function f(uint[] memory a, address payable b, "
        "uint256[3] c) external") == \
        ["uint256[]", "address", "uint256[3]"]


def test_param_types_named_struct_still_none():
    assert sim._param_types(
        "function f(DataTypes.Args memory args) external") is None
    assert sim._param_types(
        "function f(MarketParams params) external") is None
    assert sim._param_types(
        "function f(MarketParams[] params) external") is None


# ---------------------------------------------------------------------------
# boundary_cases over complex types
# ---------------------------------------------------------------------------

def test_boundary_cases_complex_types_encode():
    for types in (["uint256[]"], ["(uint256,bool)"],
                  ["uint256[3]"], ["(uint256,uint256[])"]):
        cases = sim.boundary_cases(types, ADDR)
        assert cases, types
        for values, _label in cases:
            assert sim.encode_call_args(types, values) is not None, \
                (types, values)
    defaults = sim.boundary_cases(["uint256[]"], ADDR)[0][0]
    assert defaults == [[]]
    tuple_default = sim.boundary_cases(["(uint256,bool)"], ADDR)[0][0]
    assert tuple_default == [(0, False)]


# ---------------------------------------------------------------------------
# scripts/auto_validate.py default_args
# ---------------------------------------------------------------------------

def _load_runner():
    path = pathlib.Path(__file__).resolve().parent.parent / \
        "scripts" / "auto_validate.py"
    spec = importlib.util.spec_from_file_location(
        "auto_validate_runner", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_default_args_array_and_tuple():
    runner = _load_runner()
    args = runner.default_args(
        "f(uint256[] amounts, (address,uint256) dest)", ADDR)
    assert args is not None
    assert args[0] == "[]"
    assert args[1] == f"({av.STRANGER},0)"
    fixed = runner.default_args("f(uint256[3] a)", ADDR)
    assert fixed == ["[0,0,0]"]
    named = runner.default_args("f(DataTypes.Args args)", ADDR)
    assert named is None


def test_default_args_bytes():
    runner = _load_runner()
    assert runner.default_args("f(bytes data)", ADDR) == ["0x"]
    assert runner.default_args("f(bytes32 h)", ADDR) == \
        ["0x" + "00" * 32]


# ---------------------------------------------------------------------------
# auto_validator probe construction (boundary_cases tuples, not dicts)
# ---------------------------------------------------------------------------

def test_gather_and_validate_probes_array_function(monkeypatch):
    src = ("contract C {\n"
           "    function bar(uint256[] memory xs) external {\n"
           "        uint256 y = xs.length;\n"
           "    }\n"
           "}\n")

    async def fake_src(ctx, chain, address, key):
        return {"source": src, "contract_name": "C",
                "origin": "test"}

    captured = []

    async def fake_call(ctx, chain, address, data, sender):
        captured.append((data, sender))
        return {"status": "success", "result": "0x", "via": "stub"}

    async def fake_bal(ctx, chain, address):
        return {"native_wei": 10 ** 18, "observed_at": "t",
                "source": "stub"}

    monkeypatch.setattr(cc, "fetch_verified_source", fake_src)
    monkeypatch.setattr(sim, "eth_call", fake_call)
    monkeypatch.setattr(av, "_native_balance", fake_bal)

    class Ctx:
        http = None
        limiter = None

    out = asyncio.run(av.gather_and_validate(
        Ctx(), None, {"chain": "ethereum", "address": ADDR,
                      "function": "bar", "kind": "test"}))
    assert captured, "no stranger probe was built"
    expected = sim.function_selector("bar(uint256[])") + \
        sim.encode_call_args(["uint256[]"], [[]])
    assert captured[0][0] == expected
    assert captured[0][1] == av.STRANGER
    assert out["address"] == ADDR
