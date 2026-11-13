"""Bytecode structural plugins (Track 3: bytecode-only coverage).

bytecode_dispatcher_recovery + bytecode_proxy_delegatecall_audit:
per plugin - fires on a VULN bytecode fixture, silent on a CLEAN
bytecode fixture, no crash on malformed input. Pure analysis
functions are driven directly; plugin run() is driven with a stub
ctx whose discovery bus carries the bytecode, mirroring how the
_cat300_common lanes feed phase-2 plugins in real scans. Fixtures
are hand-assembled runtime bytecode (hex), not source: these
plugins exist precisely for contracts with no verified source.
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
from app.plugins.cryptopack_util import keccak256  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

IDS = ["bytecode_dispatcher_recovery",
       "bytecode_proxy_delegatecall_audit"]

ADDR = "0x1111111111111111111111111111111111111111"

EIP1967_IMPL_SLOT = (
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")


def _sel(sig: str) -> str:
    return keccak256(sig.encode())[:4].hex()


def _dispatcher(*selector_hex: str) -> str:
    """Minimal dispatcher: per entry, PUSH4 <sel> EQ PUSH1 0 JUMPI."""
    out = []
    for sel in selector_hex:
        out.append("63" + sel + "14" + "6000" + "57")
    return "0x" + "".join(out) + "00"


# --- Fixtures ------------------------------------------------------

# Clean: ordinary ERC20 surface only, no delegatecall, no proxy
# slots, no privileged or unknown dispatcher entries.
CLEAN = _dispatcher(
    _sel("transfer(address,uint256)"),
    _sel("approve(address,uint256)"),
    _sel("balanceOf(address)"),
    _sel("totalSupply()"))

# Vulnerable (dispatcher): privileged entry points plus one
# selector no offline table can name.
VULN_DISPATCH = _dispatcher(
    _sel("withdraw()"),
    _sel("mint(address,uint256)"),
    _sel("upgradeTo(address)"),
    "deadbeef")

# A PUSH4 constant in a function body (no EQ after it) is NOT a
# dispatcher entry point, even when it spells a privileged selector.
BODY_CONSTANT_ONLY = (
    "0x" + "63" + _sel("withdraw()") + "600052" + "00")

# Vulnerable (proxy/delegatecall): EIP-1967 implementation slot
# read (PUSH32 slot, SLOAD) feeding a raw DELEGATECALL, with no
# address masking anywhere in the code.
VULN_PROXY = (
    _dispatcher(_sel("transfer(address,uint256)"))[:-2]
    + "7f" + EIP1967_IMPL_SLOT + "54" + "5a" + "f4" + "00")

# Clean (proxy/delegatecall): DELEGATECALL whose target is masked
# with the canonical PUSH20 0xff..ff / AND sequence, no proxy slots.
MASKED_DELEGATECALL = (
    _dispatcher(_sel("transfer(address,uint256)"))[:-2]
    + "73" + "ff" * 20 + "16" + "5a" + "f4" + "00")

# EIP-1167 minimal proxy for 0x1111...1111.
MINIMAL_PROXY = (
    "0x363d3d373d3d3d363d73"
    "1111111111111111111111111111111111111111"
    "5af43d82803e903d91602b57fd5bf3")


# --- Harness (mirrors test_300_cat1_evm) ----------------------------

def _handler(request):
    return httpx.Response(404, content="", request=request)


def _ctx(shared=None):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_handler), follow_redirects=True,
        trust_env=False)
    ctx = Ctx(run_id="bytecode-structural-test", mode="active",
              http=client, cache=Cache(), keys={},
              limiter=RateLimiter(), evidence_dir="/tmp",
              source_type="website")
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


# --- Registry --------------------------------------------------------

def test_registry_size_and_ids():
    from app.plugins.registry import discover
    reg = discover()
    assert len(reg) == 1414, (
        f"registry size {len(reg)}, expected 1414 "
        f"(1339 master + 2 bytecode structural plugins)")
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


# --- Dispatcher recovery (pure) --------------------------------------

def test_selector_table_resolves_common_signatures():
    from app.plugins.bytecode_structural import SELECTOR_TABLE
    for sig in ("transfer(address,uint256)",
                "transferFrom(address,address,uint256)",
                "approve(address,uint256)", "withdraw()",
                "mint(address,uint256)", "balanceOf(address)"):
        assert SELECTOR_TABLE[_sel(sig)] == sig


def test_recover_dispatcher_selectors_push4_eq_only():
    from app.plugins.bytecode_structural import (
        recover_dispatcher_selectors)
    entries = recover_dispatcher_selectors(VULN_DISPATCH)
    sels = [e["selector"] for e in entries]
    assert "0x" + _sel("withdraw()") in sels
    assert "0x" + _sel("mint(address,uint256)") in sels
    assert "0xdeadbeef" in sels
    by_sel = {e["selector"]: e["signature"] for e in entries}
    assert by_sel["0x" + _sel("withdraw()")] == "withdraw()"
    assert by_sel["0xdeadbeef"] is None
    # A body PUSH4 with no EQ comparison is not an entry point.
    assert recover_dispatcher_selectors(BODY_CONSTANT_ONLY) == []


def test_dispatcher_vuln_fires():
    from app.plugins.bytecode_structural import analyze_dispatcher
    hits = analyze_dispatcher(VULN_DISPATCH)
    keys = {h["key"] for h in hits}
    assert "bytecode_privileged_dispatcher_entry" in keys
    assert "bytecode_unknown_dispatcher_entry" in keys
    priv = [h for h in hits
            if h["key"] == "bytecode_privileged_dispatcher_entry"]
    funcs = {h["evidence"]["function"] for h in priv}
    assert funcs == {"withdraw", "mint", "upgradeTo"}
    # Detection only: nothing here may claim verified-real status.
    for h in hits:
        assert h["severity"] in ("low", "medium")


def test_dispatcher_clean_silent():
    from app.plugins.bytecode_structural import analyze_dispatcher
    assert analyze_dispatcher(CLEAN) == []
    assert analyze_dispatcher(BODY_CONSTANT_ONLY) == []
    assert analyze_dispatcher("") == []
    assert analyze_dispatcher("0x") == []
    assert analyze_dispatcher("not hex at all") == []


def test_dispatcher_plugin_run_vuln_and_clean():
    res = run_plugin("bytecode_dispatcher_recovery",
                     shared={"bytecode": [VULN_DISPATCH]})
    assert "bytecode_privileged_dispatcher_entry" in keys_of(res)
    assert "bytecode_unknown_dispatcher_entry" in keys_of(res)
    res = run_plugin("bytecode_dispatcher_recovery",
                     shared={"bytecode": [CLEAN]})
    assert res.findings == []


# --- Proxy / delegatecall audit (pure) --------------------------------

def test_proxy_vuln_fires():
    from app.plugins.bytecode_structural import (
        analyze_proxy_delegatecall)
    hits = analyze_proxy_delegatecall(VULN_PROXY)
    keys = {h["key"] for h in hits}
    assert "bytecode_eip1967_proxy_slot" in keys
    assert "bytecode_unmasked_delegatecall" in keys
    slot = [h for h in hits
            if h["key"] == "bytecode_eip1967_proxy_slot"][0]
    assert slot["evidence"]["slot_kind"] == "implementation"


def test_proxy_minimal_proxy_fires_without_unmasked():
    from app.plugins.bytecode_structural import (
        analyze_proxy_delegatecall)
    hits = analyze_proxy_delegatecall(MINIMAL_PROXY)
    keys = {h["key"] for h in hits}
    assert keys == {"bytecode_minimal_proxy"}
    assert hits[0]["evidence"]["implementation"] == ADDR


def test_proxy_clean_silent():
    from app.plugins.bytecode_structural import (
        analyze_proxy_delegatecall)
    assert analyze_proxy_delegatecall(CLEAN) == []
    # Masked delegatecall target: not the unmasked shape.
    assert analyze_proxy_delegatecall(MASKED_DELEGATECALL) == []
    assert analyze_proxy_delegatecall("") == []
    assert analyze_proxy_delegatecall("0xzz") == []


def test_proxy_plugin_run_vuln_and_clean():
    res = run_plugin("bytecode_proxy_delegatecall_audit",
                     shared={"bytecode": [VULN_PROXY]})
    assert "bytecode_eip1967_proxy_slot" in keys_of(res)
    assert "bytecode_unmasked_delegatecall" in keys_of(res)
    res = run_plugin("bytecode_proxy_delegatecall_audit",
                     shared={"bytecode": [CLEAN]})
    assert res.findings == []
    res = run_plugin("bytecode_proxy_delegatecall_audit",
                     shared={"bytecode": [MINIMAL_PROXY]})
    assert keys_of(res) == {"bytecode_minimal_proxy"}
