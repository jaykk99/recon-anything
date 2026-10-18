"""Favicon hasher plugin (passive, read-only).

Fetches /favicon.ico, computes the MurmurHash3 of the base64-encoded
content (Shodan's http.favicon.hash algorithm), and links the Shodan
search so Jay can find related assets running the same stack.

Pure-Python MurmurHash3 (x86_32) - no extra dependency. Local hashing
only; no Shodan API key needed.
"""
from __future__ import annotations

import base64
import time
from typing import List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 - matches Shodan's favicon hash when fed
    base64(icon_bytes) with newlines every 76 chars (standard b64encode)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed
    nblocks = len(data) // 4
    for i in range(nblocks):
        k = int.from_bytes(data[i * 4:(i + 1) * 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k = 0
    for i, b in enumerate(tail):
        k |= b << (8 * i)
    if tail:
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    # signed 32-bit like mmh3
    return h - 0x100000000 if h & 0x80000000 else h


class FaviconHashPlugin(Plugin):
    id = "favicon_hash"
    label = "Favicon Hasher"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "MurmurHash3 favicon hash (Shodan-compatible) for asset pivoting."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []

        icon: Optional[bytes] = None
        icon_url = ""
        for path in ("/favicon.ico", "/favicon.png"):
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base + path,
                                timeout=10)
                if r.status_code == 200 and len(r.content) > 100:
                    icon = r.content
                    icon_url = base + path
                    break
            except Exception:
                continue
        if not icon:
            res = self._ok([], "no favicon found")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Shodan hashes base64(icon) with standard 76-char line wrapping.
        b64 = base64.encodebytes(icon)
        h = _mmh3_x86_32(b64)
        shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash:{h}"
        findings.append(self._f(
            "web", "favicon_hash",
            f"Favicon MurmurHash3: {h} ({len(icon)} bytes from {icon_url}). "
            f"Pivot on Shodan for sibling assets running the same stack.",
            source="favicon hash", source_url=shodan_url,
            confidence=95, passive=True,
            evidence={"severity": "low",
                      "remediation": "A unique favicon is fine; just know attackers pivot on it too.",
                      "favicon_hash": h,
                      "shodan_query": f"http.favicon.hash:{h}"}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"favicon hash {h}")
        res.duration_ms = dur
        return res
