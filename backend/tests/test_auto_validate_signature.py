"""signature_of() canonicalization (scripts/auto_validate.py).

Regression tests for the fixup re-probe diagnosis (2026-11-04):
signature_of used to return the raw source head with custom
modifiers and returns clauses still attached, e.g.
`mint(uint256 amt) mintlive pass(msg.sender) returns (uint256 _out)`,
which cast cannot parse -- every probe on such a function failed
locally with "could not parse function signature" and the rows
were misread as transport failures. Round 2 of the re-probe
canonicalized at runner level and closed 23/23 rows; this moves
that canonicalization into the runner itself.
"""
import importlib.util
import pathlib
import re


def _load_runner():
    path = pathlib.Path(__file__).resolve().parent.parent / \
        "scripts" / "auto_validate.py"
    spec = importlib.util.spec_from_file_location(
        "auto_validate_runner", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amt) external returns (bool);
}

contract Vault {
    bool public live;
    modifier mintLive() { require(live); _; }
    modifier pass(address who) { require(who != address(0)); _; }
    modifier onlyOwner() { _; }

    function mint(uint256 amt) external mintLive pass(msg.sender)
        returns (uint256 _out) {
        return amt;
    }

    function sweep(IERC20 token) external {
    }

    function withdraw(uint256 amount, address to) public onlyOwner {
    }

    function plain(uint256 x) public view returns (uint256) {
        return x;
    }

    function batch(uint256[] calldata amounts, (address,uint256) dest)
        external {
    }

    function poke() external {
    }
}
"""

CAST_SHAPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\([^ ]*\)$")


def _sig(runner, name):
    sig, fn = runner.signature_of(SOURCE, name, "Vault")
    assert fn is not None, f"{name} not found by signature_of"
    return sig


def test_custom_modifiers_and_returns_stripped():
    runner = _load_runner()
    assert _sig(runner, "mint") == "mint(uint256)"


def test_interface_param_maps_to_address():
    runner = _load_runner()
    assert _sig(runner, "sweep") == "sweep(address)"


def test_named_modifier_without_args_stripped():
    runner = _load_runner()
    assert _sig(runner, "withdraw") == "withdraw(uint256,address)"


def test_view_and_returns_stripped():
    runner = _load_runner()
    assert _sig(runner, "plain") == "plain(uint256)"


def test_array_and_tuple_params_canonicalized():
    runner = _load_runner()
    assert _sig(runner, "batch") == \
        "batch(uint256[],(address,uint256))"


def test_no_params():
    runner = _load_runner()
    assert _sig(runner, "poke") == "poke()"


def test_all_signatures_cast_shaped_and_args_buildable():
    runner = _load_runner()
    addr = "0x0000000000000000000000000000000000000001"
    for name in ("mint", "sweep", "withdraw", "plain", "batch",
                 "poke"):
        sig = _sig(runner, name)
        assert CAST_SHAPE.match(sig), sig
        assert runner.default_args(sig, addr) is not None, sig
    assert runner.default_args("mint(uint256)", addr) == ["0"]
    sweep_args = runner.default_args("sweep(address)", addr)
    assert sweep_args is not None and len(sweep_args) == 1
    assert sweep_args[0].startswith("0x") and len(sweep_args[0]) == 42


def test_missing_function_returns_none():
    runner = _load_runner()
    sig, fn = runner.signature_of(SOURCE, "nonexistent", "Vault")
    assert sig is None and fn is None
