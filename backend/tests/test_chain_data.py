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
