"""Cache layer with per-source TTLs.

Every external call goes through here. Uses Redis when REDIS_URL is set
and the redis package is installed, otherwise an in-process TTL dict.
TTL table (seconds) follows the spec: DNS 5m, WHOIS/RDAP 24h, CT 1h,
Shodan/VT 24h, Wayback 6h, default 10m.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Optional

from .config import REDIS_URL

TTL_TABLE = {
    "dns": 300,
    "rdap": 86400,
    "whois": 86400,
    "ct": 3600,
    "shodan": 86400,
    "virustotal": 86400,
    "wayback": 21600,
    "http": 600,
    "github": 3600,
    "hibp": 86400,
    "playstore": 86400,
    "appstore": 86400,
    "default": 600,
}


def _key(source: str, target: str) -> str:
    h = hashlib.sha256(f"{source}:{target}".encode()).hexdigest()[:32]
    return f"recon:{source}:{h}"


class _MemoryCache:
    def __init__(self) -> None:
        self._d = {}

    def get(self, key: str) -> Optional[Any]:
        row = self._d.get(key)
        if not row:
            return None
        exp, val = row
        if exp < time.time():
            self._d.pop(key, None)
            return None
        return val

    def set(self, key: str, val: Any, ttl: int) -> None:
        self._d[key] = (time.time() + ttl, val)


class Cache:
    def __init__(self) -> None:
        self._redis = None
        self._mem = _MemoryCache()
        if REDIS_URL:
            try:
                import redis as redis_lib
                self._redis = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
                self._redis.ping()
            except Exception:
                self._redis = None

    def ttl_for(self, source: str) -> int:
        return TTL_TABLE.get(source, TTL_TABLE["default"])

    def get(self, source: str, target: str) -> Optional[Any]:
        k = _key(source, target)
        if self._redis is not None:
            try:
                raw = self._redis.get(k)
                return json.loads(raw) if raw else None
            except Exception:
                pass
        return self._mem.get(k)

    def set(self, source: str, target: str, val: Any, ttl: Optional[int] = None) -> None:
        k = _key(source, target)
        ttl = ttl if ttl is not None else self.ttl_for(source)
        if self._redis is not None:
            try:
                self._redis.setex(k, ttl, json.dumps(val, default=str))
                return
            except Exception:
                pass
        self._mem.set(k, val, ttl)

    async def cached(self, source: str, target: str, fn, ttl: Optional[int] = None):
        """Return cached value or run async fn() and cache the result."""
        hit = self.get(source, target)
        if hit is not None:
            return hit, True
        val = await fn()
        try:
            self.set(source, target, val, ttl)
        except Exception:
            pass
        return val, False
