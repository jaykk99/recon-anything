"""Per-run RPC dedupe: the ~29 plugins that read the same bytecode/storage
for one contract must share a single live call, not re-fetch each.

This is pure dedupe - it must return identical values to the uncached call
and must never cache a failure (so a transient outage can't poison a run).
Lives in CI so the caching can't silently regress back to per-plugin
re-fetching, which was a large part of the ~124s/contract.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app.plugins.contract_chain as cc  # noqa: E402


class _Chain:
    id = "ethereum"
    rpc_urls = ["https://rpc1", "https://rpc2"]


class _Ctx:
    def __init__(self):
        self.shared = {}
        self.http = None
        self.limiter = None


ADDR = "0xABCdef0000000000000000000000000000000001"


def test_concurrent_identical_getcode_is_one_call(monkeypatch):
    calls = {"n": 0}

    async def fake_post(ctx, rpc, payload):
        calls["n"] += 1
        await asyncio.sleep(0.01)
        return {"result": "0x6080604052"}

    monkeypatch.setattr(cc, "_rpc_post", fake_post)

    async def run():
        ctx, ch = _Ctx(), _Chain()
        res = await asyncio.gather(
            *[cc.rpc_get_code(ctx, ch, ADDR) for _ in range(29)])
        assert all(r == "0x6080604052" for r in res)
        assert calls["n"] == 1, f"expected 1 POST, got {calls['n']}"
        # repeat hits cache
        before = calls["n"]
        await cc.rpc_get_code(ctx, ch, ADDR)
        assert calls["n"] == before

    asyncio.run(run())


def test_failure_is_not_cached(monkeypatch):
    calls = {"n": 0}

    async def failing_post(ctx, rpc, payload):
        calls["n"] += 1
        return None  # every endpoint "down"

    monkeypatch.setattr(cc, "_rpc_post", failing_post)

    async def run():
        ctx, ch = _Ctx(), _Chain()
        r1 = await cc.rpc_get_code(ctx, ch, ADDR)
        assert r1 is None
        n_after_first = calls["n"]
        # a later call must retry (None not cached), not return a poisoned hit
        r2 = await cc.rpc_get_code(ctx, ch, ADDR)
        assert r2 is None
        assert calls["n"] > n_after_first

    asyncio.run(run())
