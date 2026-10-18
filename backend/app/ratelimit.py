"""Global + per-host rate limiter with exponential backoff.

Honors 429 Retry-After. Configurable requests-per-second per host.
For authorized testing only: evasion helpers here exist to complete an
authorized scan without being blocked, not to attack.

Proxy support: HTTP clients are built through app.net, which honors
HTTP_PROXY and HTTPS_PROXY environment variables automatically.
No extra code is needed for env-based proxying.
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Dict, Literal, Optional

import httpx


class RateLimiter:
    def __init__(self, default_rps: float = 10.0) -> None:
        self.default_rps = default_rps
        self._rps: Dict[str, float] = {}
        self._next: Dict[str, float] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        # WAF/challenge visibility: how many times each host served a
        # protection page. Lets the runner warn Jay instead of silently
        # burning requests on challenge pages.
        self._protection_hits: Dict[str, int] = {}

    def note_protection(self, host: str) -> int:
        self._protection_hits[host] = self._protection_hits.get(host, 0) + 1
        return self._protection_hits[host]

    def protection_hits(self, host: str) -> int:
        return self._protection_hits.get(host, 0)

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
                url: str, *, max_retries: int = 2, rotate_ua: bool = False,
                **kwargs) -> httpx.Response:
    """HTTP with rate limiting, retries, backoff+jitter, 429 handling.

    Retries transient failures (429/5xx, timeouts) so findings are not lost
    to a single bad response. Bounded: at most max_retries extra attempts.

    rotate_ua: when True, send a random real browser UA plus realistic
    headers (Accept, Sec-Fetch-*, etc.) so the request looks like normal
    browser traffic. Default False so existing callers are unchanged.
    """
    from urllib.parse import urlparse

    from .evasion import browser_headers
    from .evasion import rotate_ua as pick_ua

    host = urlparse(url).netloc
    if rotate_ua:
        ua = pick_ua()
        merged = dict(browser_headers(ua))
        extra = kwargs.get("headers") or {}
        merged.update(extra)  # caller-supplied headers still win
        kwargs["headers"] = merged
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        await limiter.wait(host)
        try:
            resp = await client.request(method, url, **kwargs)
            # Cheap WAF/challenge accounting: only inspect bodies on
            # statuses that can carry a challenge page.
            if resp.status_code in (403, 429, 503):
                try:
                    if detect_protection(resp):
                        limiter.note_protection(host)
                except Exception:
                    pass
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


_PROTECTION_BODY_MARKERS = (
    "cf-challenge",
    "jschl",
    "checking your browser",
    "just a moment",
    "challenge-platform",
    "captcha",
    "recaptcha",
    "cf-turnstile",
    "incapsula",
    "sucuri",
    "cloudflare",
    "akamai",
    "access denied",
    "request blocked",
    "waf",
    "web application firewall",
)

_PROTECTION_HEADERS = (
    "cf-mitigated",
    "cf-ray",
    "x-sucuri-id",
    "x-iinfo",
    "x-akamai-",
)


def detect_protection(resp: httpx.Response) -> Optional[
    Literal["waf", "rate-limit", "js-challenge"]
]:
    """Classify a response as blocked by protection, or None.

    "rate-limit": 429, or 503 with rate-limit wording.
    "js-challenge": body looks like a JS challenge or captcha page.
    "waf": 403 with WAF/CDN markers, or known protection headers.
    Detection only, never attempts to bypass.
    """
    status = resp.status_code
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    if status == 429:
        return "rate-limit"
    if status == 503 and "retry" in " ".join(headers_lower).lower():
        return "rate-limit"

    body = ""
    try:
        body = resp.text.lower()
    except Exception:
        body = ""

    from .evasion import detect_js_challenge

    if detect_js_challenge(body):
        return "js-challenge"

    if any(h in headers_lower for h in _PROTECTION_HEADERS):
        return "waf"
    if status == 403 and any(m in body for m in _PROTECTION_BODY_MARKERS):
        return "waf"

    return None