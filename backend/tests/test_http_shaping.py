"""Request shaping: jitter, per-host concurrency cap, proxy rotation.

These are the three knobs that stop a 64-plugin fan-out from looking like a
botnet to a Cloudflare/Akamai edge:

  * a per-request jitter ceiling (default off; graceful WAF mode always jits),
  * a per-HOST in-flight cap (default 16) on top of the global cap,
  * a proxy rotation pool with a failure cooldown.

Tests are deterministic: no real network, no real sleeps beyond microseconds.
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import net  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402


def test_shape_reports_policy():
    limiter = RateLimiter(default_rps=50, host_concurrency=4, jitter_s=0.02,
                          global_concurrency=32)
    shape = limiter.shape()
    assert shape["host_concurrency"] == 4
    assert shape["jitter_ms"] == 20
    assert shape["global_concurrency"] == 32


def test_jitter_is_bounded_and_optional():
    off = RateLimiter(host_concurrency=4, jitter_s=0.0)
    asyncio.run(off.wait("example.com"))
    assert off._next.get("example.com", 0) == 0  # no jitter scheduled

    on = RateLimiter(default_rps=1000, host_concurrency=4, jitter_s=0.05)
    asyncio.run(on.wait("example.com"))
    gap = on._next.get("example.com", 0) - time.monotonic()
    assert -0.01 <= gap <= 0.06, gap


def test_per_host_concurrency_cap():
    limiter = RateLimiter(host_concurrency=2)
    active = {"now": 0, "max": 0}

    async def worker():
        async with limiter.host_slot("target.test"):
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
            await asyncio.sleep(0.01)
            active["now"] -= 1

    async def run():
        await asyncio.gather(*[worker() for _ in range(8)])

    asyncio.run(run())
    assert active["max"] == 2, active["max"]


def test_host_cap_is_per_host_not_global():
    limiter = RateLimiter(host_concurrency=2)
    seen = {"a": 0, "max_a": 0}

    async def worker(host):
        async with limiter.host_slot(host):
            if host == "a.test":
                seen["a"] += 1
                seen["max_a"] = max(seen["max_a"], seen["a"])
            await asyncio.sleep(0.01)
            if host == "a.test":
                seen["a"] -= 1

    async def run():
        await asyncio.gather(*[worker("a.test") for _ in range(4)],
                             *[worker("b.test") for _ in range(4)])

    asyncio.run(run())
    # b.test's load must not consume a.test's slots
    assert seen["max_a"] == 2


def test_host_cap_zero_disables():
    limiter = RateLimiter(host_concurrency=0)

    async def run():
        async with limiter.host_slot("h"):
            pass
    asyncio.run(run())


def test_proxy_pool_rotation_and_cooldown(monkeypatch=None):
    env = {"RECON_PROXY_URLS": "http://p1:8080,http://p2:8080"}
    old = {k: os.environ.get(k) for k in env}
    net._PROXY_STATE["index"] = 0
    net._PROXY_STATE["down"].clear()
    os.environ.update(env)
    try:
        first = net.select_proxy()
        second = net.select_proxy()
        assert {first, second} == {"http://p1:8080", "http://p2:8080"}
        assert net.proxy_state()["pool"] == 2
        # a failed proxy is skipped while cooling down
        net.note_proxy_failure(first)
        picks = {net.select_proxy() for _ in range(4)}
        assert picks == {second}, picks
        assert first in net.proxy_state()["cooling"]
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        net._PROXY_STATE["index"] = 0
        net._PROXY_STATE["down"].clear()


def test_no_pool_falls_back_to_env_proxy():
    old_pool = os.environ.pop("RECON_PROXY_URLS", None)
    old_proxy = os.environ.get("HTTPS_PROXY")
    os.environ["HTTPS_PROXY"] = "http://env-proxy:3128"
    try:
        assert net.proxy_pool() == []
        assert net.select_proxy() == "http://env-proxy:3128"
    finally:
        if old_pool is not None:
            os.environ["RECON_PROXY_URLS"] = old_pool
        if old_proxy is None:
            os.environ.pop("HTTPS_PROXY", None)
        else:
            os.environ["HTTPS_PROXY"] = old_proxy


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} request shaping tests passed")


if __name__ == "__main__":
    _run_all()
