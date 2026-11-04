"""Shared chain-data layer: sharing, DEGRADED status, TTL retry.

Proves the hitting-path contract of app/plugins/chain_data.py:
- two different wired plugins on the same target+ctx trigger ONE
  underlying fetch sequence (stub counters on contract_chain);
- when every RPC route fails, a BSC detector reports DEGRADED
  (never a clean-looking skip);
- a degraded record is retried after the TTL instead of being
  inherited forever.
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bsc100_fixtures as fx  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import chain_data  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x1111111111111111111111111111111111111111"
PID = "bep20_fake_transfer_events"


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


def _meta(source):
    if source is None:
        return None
    return {"source": source, "contract_name": "Fixture",
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def _target():
    return Target(raw=f"bsc:{ADDR}", type="crypto_wallet",
                  normalized=f"bsc:{ADDR}")


def _patch_ok(monkeypatch, counts):
    async def fake_get_code(ctx, chain, address):
        counts["code"] += 1
        return "0x60006000"

    async def fake_source(ctx, chain, address, key=None):
        counts["source"] += 1
        return _meta(fx.VULN[PID])

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)


def test_fetch_shared_across_plugins(monkeypatch):
    counts = {"code": 0, "source": 0}
    _patch_ok(monkeypatch, counts)
    ctx = FakeCtx()
    # Two different wired families, same ctx (one run): a BSC
    # detector and contract_logic.
    res1 = asyncio.run(discover()[PID]().run(_target(), ctx))
    res2 = asyncio.run(discover()["contract_logic"]().run(
        _target(), ctx))
    assert any(f.key == PID for f in res1.findings)
    # ONE underlying fetch sequence served both plugins.
    assert counts == {"code": 1, "source": 1}, counts


def test_degraded_is_reported_not_masked(monkeypatch):
    async def fake_get_code(ctx, chain, address):
        return None

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    res = asyncio.run(discover()[PID]().run(_target(), FakeCtx()))
    assert res.reason.startswith("DEGRADED:"), res.reason
    assert [f for f in res.findings if f.key == PID] == []


def test_degraded_record_retries_after_ttl(monkeypatch):
    state = {"fail": True, "calls": 0}

    async def fake_get_code(ctx, chain, address):
        state["calls"] += 1
        return None if state["fail"] else "0x60006000"

    async def fake_source(ctx, chain, address, key=None):
        return _meta(fx.VULN[PID])

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    ctx = FakeCtx()
    chain = cc.CHAINS["bsc"]

    async def go():
        rec1 = await chain_data.get_chain_data(ctx, chain, ADDR)
        assert rec1.status == chain_data.STATUS_DEGRADED
        # Within the TTL the failure is shared, not refetched.
        rec2 = await chain_data.get_chain_data(ctx, chain, ADDR)
        assert rec2.status == chain_data.STATUS_DEGRADED
        assert state["calls"] == 1
        # Age the record past the TTL, routes recover, retry hits.
        rec1.fetched_at = time.monotonic() - (
            chain_data.DEGRADED_TTL_S + 1)
        state["fail"] = False
        rec3 = await chain_data.get_chain_data(ctx, chain, ADDR)
        assert rec3.status == chain_data.STATUS_OK
        assert state["calls"] == 2

    asyncio.run(go())


def test_functions_extracted_once_and_shared(monkeypatch):
    counts = {"code": 0, "source": 0}
    _patch_ok(monkeypatch, counts)
    ctx = FakeCtx()
    chain = cc.CHAINS["bsc"]

    async def go():
        rec = await chain_data.get_chain_data(ctx, chain, ADDR)
        f1 = rec.functions()
        f2 = rec.functions()
        assert f1 is f2 and len(f1) > 0

    asyncio.run(go())


# ---------------------------------------------------------------------------
# Phase 2B: batched RPC reads, shared proxy resolution, and the
# deep-audit / recipient scaffolding wired onto the shared layer.
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def test_rpc_batch_single_post_ordered_results(monkeypatch):
    calls = {"n": 0}

    async def fake_fetch(http, limiter, method, url, **kw):
        calls["n"] += 1
        payload = kw["json"]
        assert isinstance(payload, list) and len(payload) == 3
        return _FakeResp([
            {"jsonrpc": "2.0", "id": 3, "result": "0xabc"},
            {"jsonrpc": "2.0", "id": 1, "result": "0x6000"},
            {"jsonrpc": "2.0", "id": 2, "result": "0x10"},
        ])

    monkeypatch.setattr(cc, "fetch", fake_fetch)
    ctx = FakeCtx()
    ctx.http = object()
    out = asyncio.run(cc.rpc_batch(ctx, cc.CHAINS["bsc"], [
        ("eth_getCode", [ADDR, "latest"]),
        ("eth_getBalance", [ADDR, "latest"]),
        ("eth_getStorageAt", [ADDR, "0x0", "latest"])]))
    # One POST, results re-ordered into request order.
    assert calls["n"] == 1
    assert out == ["0x6000", "0x10", "0xabc"]


def test_rpc_batch_failure_returns_none_for_fallback(monkeypatch):
    async def fake_fetch(http, limiter, method, url, **kw):
        return _FakeResp({"jsonrpc": "2.0", "id": 1,
                          "result": "0x"}, status_code=500)

    monkeypatch.setattr(cc, "fetch", fake_fetch)
    ctx = FakeCtx()
    ctx.http = object()
    out = asyncio.run(cc.rpc_batch(ctx, cc.CHAINS["bsc"], [
        ("eth_getCode", [ADDR, "latest"])]))
    assert out is None  # caller falls back to per-call reads


def test_fetch_once_uses_batch_for_code_and_balance(monkeypatch):
    counts = {"code": 0, "source": 0}

    async def fake_batch(ctx, chain, calls):
        assert [c[0] for c in calls] == ["eth_getCode",
                                         "eth_getBalance"]
        return ["0x60006000", "0x10"]

    async def fake_get_code(ctx, chain, address):
        counts["code"] += 1
        return "0xdead"

    async def fake_source(ctx, chain, address, key=None):
        counts["source"] += 1
        return _meta("contract Fixture {}")

    monkeypatch.setattr(cc, "rpc_batch", fake_batch)
    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    ctx = FakeCtx()
    ctx.http = object()

    async def go():
        rec = await chain_data.get_chain_data(
            ctx, cc.CHAINS["bsc"], ADDR)
        assert rec.code_hex == "0x60006000"  # batch won, not fallback
        assert rec.balance_wei == 16
        assert rec.status == chain_data.STATUS_OK

    asyncio.run(go())
    assert counts == {"code": 0, "source": 1}
    assert chain_data.stats(ctx)["batched_reads"] == 1


def test_implementation_resolution_shared(monkeypatch):
    counts = {"resolve": 0}

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        counts["resolve"] += 1
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)
    ctx = FakeCtx()
    chain = cc.CHAINS["bsc"]

    async def go():
        r1 = await chain_data.get_implementation(
            ctx, chain, ADDR, "0x6000", {"implementation": ""})
        r2 = await chain_data.get_implementation(
            ctx, chain, ADDR, "0x6000", {"implementation": ""})
        assert r1 is r2

    asyncio.run(go())
    assert counts["resolve"] == 1
    st = chain_data.stats(ctx)
    assert st["impl_resolutions"] == 1 and st["impl_cache_hits"] == 1


def test_deep_and_recipient_plugins_share_one_fetch(monkeypatch):
    counts = {"code": 0, "source": 0, "resolve": 0}

    async def fake_get_code(ctx, chain, address):
        counts["code"] += 1
        return "0x60006000"

    async def fake_source(ctx, chain, address, key=None):
        counts["source"] += 1
        return _meta(fx.VULN[PID])

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        counts["resolve"] += 1
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)
    ctx = FakeCtx()
    reg = discover()
    for pid in ("vault_share_inflation", "hook_cei_reentrancy",
                "recipient_mint_to_caller"):
        asyncio.run(reg[pid]().run(_target(), ctx))
    # Three scaffolding families, ONE fetch sequence + ONE proxy
    # resolution (recipient plugins never resolve) for the contract.
    assert counts == {"code": 1, "source": 1, "resolve": 1}, counts
    assert chain_data.stats(ctx)["fetch_sequences"] == 1


def test_deep_plugin_degraded_not_masked(monkeypatch):
    async def fake_get_code(ctx, chain, address):
        return None

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    reg = discover()
    res = asyncio.run(reg["vault_share_inflation"]().run(
        _target(), FakeCtx()))
    assert res.reason.startswith("DEGRADED:"), res.reason
    res2 = asyncio.run(reg["recipient_mint_to_caller"]().run(
        _target(), FakeCtx()))
    assert any(f.key == "recipient_mint_to_caller_failed"
               for f in res2.findings), [f.key for f in res2.findings]
