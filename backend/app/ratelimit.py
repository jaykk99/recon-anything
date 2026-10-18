"""Global + per-host rate limiter with exponential backoff.

Honors 429 Retry-After. Configurable requests-per-second per host.
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Dict

import httpx


class RateLimiter:
    def __init__(self, default_rps: float = 10.0) -> None:
        self.default_rps = default_rps
        self._rps: Dict[str, float] = {}
        self._next: Dict[str, float] = {}
        self._locks: Dict[str, asyncio.Lock] = {}

    def set_rps(self, host: str, rps: float) -> None:
        self._rps[host] = rps

    def _lock(self, host: str) -> asyncio.Lock:
        if host not in self._locks:
            self._locks[host] = asyncio.Lock()
        return self._locks[host]

    async def wait(self, host: str) -> None:
        rps = self._rps.get(host, self.default_rps)
        async with self._lock(host):
            now = time.monotonic()
            nxt = self._next.get(host, 0)
            if now < nxt:
                await asyncio.sleep(nxt - now)
            self._next[host] = time.monotonic() + 1.0 / max(rps, 0.1)

    def note_429(self, host: str, retry_after: float | None) -> None:
        wait = retry_after if retry_after else 5.0
        self._next[host] = time.monotonic() + min(wait, 120)


async def fetch(client: httpx.AsyncClient, limiter: RateLimiter, method: str,
                url: str, *, max_retries: int = 2, **kwargs) -> httpx.Response:
    """HTTP with rate limiting, retries, backoff+jitter, 429 handling.

    Retries transient failures (429/5xx, timeouts) so findings are not lost
    to a single bad response. Bounded: at most max_retries extra attempts.
    """
    from urllib.parse import urlparse
    host = urlparse(url).netloc
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        await limiter.wait(host)
        try:
            resp = await client.request(method, url, **kwargs)
            if resp.status_code == 429:
                ra = resp.headers.get("retry-after")
                try:
                    limiter.note_429(host, float(ra) if ra else None)
                except (ValueError, TypeError):
                    limiter.note_429(host, None)
                if attempt < max_retries:
                    await asyncio.sleep(random.uniform(1, 3) * (attempt + 1))
                    continue
                return resp
            if resp.status_code >= 500 and attempt < max_retries:
                await asyncio.sleep(random.uniform(0.5, 1.5) * (2 ** attempt))
                continue
            return resp
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            last_exc = e
            if attempt < max_retries:
                await asyncio.sleep(random.uniform(0.5, 1.5) * (2 ** attempt))
                continue
            raise
    assert last_exc is not None
    raise last_exc