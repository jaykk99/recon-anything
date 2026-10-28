"""Speed-pass (2026-10-23) engine regressions.

Covers the behavior contracts the speed work must not break:

1. Circuit breaker (ratelimit.fetch): dead hosts fast-fail after a few
   consecutive CONNECT failures, any real response resets the count,
   read timeouts never count, and retries stop once the breaker opens.
2. probe() singleflight (plugins/base): concurrent probes of one URL
   share a single in-flight request and the same result object.
3. Limiter stand-ins without breaker methods keep working (duck-typing).
"""
import asyncio

import httpx
import pytest

from app import ratelimit
from app.ratelimit import RateLimiter, fetch


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_breaker_opens_after_threshold_and_fast_fails():
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ConnectError("refused", request=request)

    async def main():
        limiter = RateLimiter(default_rps=1000.0)
        async with _client(handler) as client:
            for _ in range(ratelimit.BREAKER_THRESHOLD):
                with pytest.raises(httpx.ConnectError):
                    await fetch(client, limiter, "GET",
                                "https://dead.test/", max_retries=0)
            assert limiter.breaker_open("dead.test")
            n_calls = len(calls)
            # Breaker open: raise WITHOUT touching the transport.
            with pytest.raises(httpx.ConnectError):
                await fetch(client, limiter, "GET", "https://dead.test/",
                            max_retries=0)
            assert len(calls) == n_calls

    asyncio.run(main())


def test_breaker_resets_on_any_response():
    state = {"fail": True}

    def handler(request):
        if state["fail"]:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(500, text="err")

    async def main():
        limiter = RateLimiter(default_rps=1000.0)
        async with _client(handler) as client:
            for _ in range(ratelimit.BREAKER_THRESHOLD - 1):
                with pytest.raises(httpx.ConnectError):
                    await fetch(client, limiter, "GET",
                                "https://flaky.test/", max_retries=0)
            state["fail"] = False
            resp = await fetch(client, limiter, "GET",
                               "https://flaky.test/", max_retries=0)
            assert resp.status_code == 500  # a 500 still proves life
            assert not limiter.breaker_open("flaky.test")
            # Counter reset: another threshold-1 failures must not open.
            state["fail"] = True
            for _ in range(ratelimit.BREAKER_THRESHOLD - 1):
                with pytest.raises(httpx.ConnectError):
                    await fetch(client, limiter, "GET",
                                "https://flaky.test/", max_retries=0)
            assert not limiter.breaker_open("flaky.test")

    asyncio.run(main())


def test_read_timeouts_never_trip_breaker():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    async def main():
        limiter = RateLimiter(default_rps=1000.0)
        async with _client(handler) as client:
            for _ in range(ratelimit.BREAKER_THRESHOLD + 3):
                with pytest.raises(httpx.ReadTimeout):
                    await fetch(client, limiter, "GET",
                                "https://slow.test/", max_retries=0)
            assert not limiter.breaker_open("slow.test")

    asyncio.run(main())


def test_retry_stops_when_breaker_opens(monkeypatch):
    monkeypatch.setattr(ratelimit, "BREAKER_THRESHOLD", 1)
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ConnectError("refused", request=request)

    async def main():
        limiter = RateLimiter(default_rps=1000.0)
        async with _client(handler) as client:
            with pytest.raises(httpx.ConnectError):
                await fetch(client, limiter, "GET", "https://dead.test/",
                            max_retries=3)

    asyncio.run(main())
    # One real attempt only: the retry loop saw the open breaker.
    assert len(calls) == 1


def test_half_open_probe_after_window(monkeypatch):
    monkeypatch.setattr(ratelimit, "BREAKER_THRESHOLD", 1)
    monkeypatch.setattr(ratelimit, "BREAKER_OPEN_S", 0.05)
    state = {"fail": True}

    def handler(request):
        if state["fail"]:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, text="ok")

    async def main():
        limiter = RateLimiter(default_rps=1000.0)
        async with _client(handler) as client:
            with pytest.raises(httpx.ConnectError):
                await fetch(client, limiter, "GET", "https://back.test/",
                            max_retries=0)
            assert limiter.breaker_open("back.test")
            await asyncio.sleep(0.08)
            state["fail"] = False
            resp = await fetch(client, limiter, "GET",
                               "https://back.test/", max_retries=0)
            assert resp.status_code == 200
            assert not limiter.breaker_open("back.test")

    asyncio.run(main())


class _StubLimiter:
    """Pre-breaker limiter stand-in: wait/note_* only, no breaker."""

    def __init__(self):
        self.waits = 0

    async def wait(self, host):
        self.waits += 1

    def note_result(self, host, verdict):
        pass

    def note_429(self, host, retry_after=None):
        pass


def test_fetch_works_with_stub_limiter_without_breaker():
    def handler(request):
        return httpx.Response(200, text="ok")

    async def main():
        async with _client(handler) as client:
            resp = await fetch(client, _StubLimiter(), "GET",
                               "https://any.test/", max_retries=0)
            assert resp.status_code == 200

    asyncio.run(main())


def test_probe_singleflight_shares_one_request():
    from app.cache import Cache
    from app.plugins.base import Ctx

    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, text="body")

    async def main():
        limiter = RateLimiter(default_rps=1000.0)
        async with _client(handler) as client:
            ctx = Ctx(run_id="speed-pass", mode="active", http=client,
                      cache=Cache(), keys={}, limiter=limiter,
                      evidence_dir="/tmp", source_type="website")
            url = "https://one.test/static/app.js"
            results = await asyncio.gather(
                *[ctx.probe(url) for _ in range(8)])
            assert len(calls) == 1
            assert all(r["status"] == 200 for r in results)
            assert all(r is results[0] for r in results)
            # And the result is cached for later callers.
            again = await ctx.probe(url)
            assert again is results[0]
            assert len(calls) == 1

    asyncio.run(main())
