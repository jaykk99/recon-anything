"""Global + per-host rate limiter with WAF-aware graceful backoff.

Honors 429/503 Retry-After (seconds or HTTP-date). Configurable
requests-per-second per host. When a host shows WAF/challenge/rate-limit
behavior, the limiter enters graceful mode for that host:

- per-host rate drops to the WAF floor (default 1 RPS, RECON_WAF_RPS)
- inter-request timing gets jitter so requests don't look robotic
- aggressive plugins are told to stand down (see runner.py)

Lightweight checks keep flowing - findings still win. Non-WAF hosts see
zero behavior change: same pacing, no jitter, no suppression.

For authorized testing only: these helpers exist to complete an authorized
scan without being blocked, not to attack.

Proxy support: HTTP clients are built through app.net, which honors
HTTP_PROXY and HTTPS_PROXY environment variables automatically.
No extra code is needed for env-based proxying.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import os
import random
import time
from typing import Dict, Literal, Optional

import httpx

from .waf import BLOCK_KINDS, WafVerdict, classify_response

# Per-host request floor once WAF/challenge behavior is seen. 1 RPS keeps
# lightweight checks alive without hammering a host that is fighting back.
WAF_RPS_FLOOR = float(os.environ.get("RECON_WAF_RPS", "1.0"))
# Generic (unfingerprinted) 403s also count, but it takes a few of them to
# trigger graceful mode - a single 403 is often just a path ACL, not a WAF.
WAF_BLOCK_THRESHOLD = 3


def parse_retry_after(value: object) -> Optional[float]:
    """Retry-After as seconds. Accepts delay-seconds or an HTTP-date."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return float(s)
    except (ValueError, TypeError):
        pass
    try:
        from email.utils import parsedate_to_datetime
        when = parsedate_to_datetime(s)
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        delta = (when - dt.datetime.now(dt.timezone.utc)).total_seconds()
        return max(delta, 0.0)
    except Exception:
        return None


class RateLimiter:
    def __init__(self, default_rps: float = 10.0) -> None:
        self.default_rps = default_rps
        self._rps: Dict[str, float] = {}
        self._next: Dict[str, float] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        # Per-host WAF state: vendor, counters, graceful-mode flag.
        self._waf: Dict[str, Dict] = {}

    # -- per-host WAF state -------------------------------------------
    def _waf_state(self, host: str) -> Dict:
        return self._waf.setdefault(host, {
            "vendor": None, "blocked": 0, "succeeded": 0,
            "not_found": 0, "server_error": 0,
            "active": False, "first_seen": None,
        })

    def note_result(self, host: str, verdict: WafVerdict) -> None:
        """Fold one classified response into the host's WAF state.

        Clean responses count as successes; 404/5xx are neutral (neither
        success nor block); WAF/rate-limit/challenge/blocked responses
        count as blocks and can flip the host into graceful mode.
        """
        st = self._waf_state(host)
        kind = verdict.kind
        if kind == "clean":
            st["succeeded"] += 1
            return
        if kind == "not-found":
            st["not_found"] += 1
            return
        if kind == "server-error":
            st["server_error"] += 1
            return
        if kind not in BLOCK_KINDS:
            return
        st["blocked"] += 1
        if verdict.vendor and not st["vendor"]:
            st["vendor"] = verdict.vendor
        # Activate graceful mode: vendor-attributed block is decisive;
        # generic blocks need a few hits to rule out per-path ACLs.
        if not st["active"] and (verdict.vendor or
                                 st["blocked"] >= WAF_BLOCK_THRESHOLD):
            st["active"] = True
            st["first_seen"] = time.time()
            cur = self._rps.get(host, self.default_rps)
            self._rps[host] = min(cur, WAF_RPS_FLOOR)

    def waf_active(self, host: str) -> bool:
        return self._waf.get(host, {}).get("active", False)

    def waf_vendor(self, host: str) -> Optional[str]:
        return self._waf.get(host, {}).get("vendor")

    def waf_stats(self, host: str) -> Dict:
        st = self._waf.get(host, {})
        return {
            "host": host,
            "vendor": st.get("vendor"),
            "active": st.get("active", False),
            "blocked": st.get("blocked", 0),
            "succeeded": st.get("succeeded", 0),
            "not_found": st.get("not_found", 0),
            "server_error": st.get("server_error", 0),
            "first_seen": st.get("first_seen"),
        }

    def waf_hosts(self) -> list:
        return [h for h, st in self._waf.items() if st.get("active")]

    # -- legacy protection accounting (kept for compatibility) ---------
    def note_protection(self, host: str) -> int:
        st = self._waf_state(host)
        st["blocked"] += 1
        return st["blocked"]

    def protection_hits(self, host: str) -> int:
        return self._waf.get(host, {}).get("blocked", 0)

    # -- pacing --------------------------------------------------------
    def set_rps(self, host: str, rps: float) -> None:
        self._rps[host] = rps

    def _lock(self, host: str) -> asyncio.Lock:
        if host not in self._locks:
            self._locks[host] = asyncio.Lock()
        return self._locks[host]

    async def wait(self, host: str) -> None:
        rps = self._rps.get(host, self.default_rps)
        protected = self._waf.get(host, {}).get("active", False)
        async with self._lock(host):
            now = time.monotonic()
            nxt = self._next.get(host, 0)
            if now < nxt:
                await asyncio.sleep(nxt - now)
                now = time.monotonic()
            gap = 1.0 / max(rps, 0.1)
            if protected:
                # Jitter the spacing on protected hosts so the request
                # pattern doesn't look robotic. Non-WAF hosts keep the
                # exact same deterministic pacing as before.
                gap *= random.uniform(0.8, 1.4)
            self._next[host] = now + gap

    def note_429(self, host: str, retry_after: object = None) -> None:
        """Honor Retry-After (delay-seconds or HTTP-date), cap 120s."""
        wait = parse_retry_after(retry_after)
        if wait is None:
            wait = 5.0
        self._next[host] = time.monotonic() + min(max(wait, 0.0), 120.0)


async def fetch(client: httpx.AsyncClient, limiter: RateLimiter, method: str,
                url: str, *, max_retries: int = 2, rotate_ua: bool = False,
                **kwargs) -> httpx.Response:
    """HTTP with rate limiting, WAF accounting, retries, backoff+jitter.

    Every response is classified (WAF vendor, rate-limit, challenge,
    blocked, not-found, server-error, clean) and folded into the host's
    WAF state, which drives graceful backoff. Retries transient failures
    (429/5xx, timeouts) so findings are not lost to a single bad response.
    Bounded: at most max_retries extra attempts.

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
            # Classify every response: vendor attribution + block kinds
            # feed graceful backoff; clean/404/5xx are accounted too.
            verdict: Optional[WafVerdict] = None
            try:
                verdict = classify_response(resp)
                limiter.note_result(host, verdict)
            except Exception:
                pass
            if resp.status_code == 429 or (
                    resp.status_code == 503 and verdict is not None
                    and verdict.kind == "rate-limit"):
                # Respect Retry-After on 429 and rate-limit 503s.
                limiter.note_429(host, resp.headers.get("retry-after"))
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


def detect_protection(resp: httpx.Response) -> Optional[
    Literal["waf", "rate-limit", "js-challenge"]
]:
    """Legacy classifier kept for compatibility.

    "rate-limit": 429, or 503 with rate-limit wording.
    "js-challenge": body looks like a JS challenge or captcha page.
    "waf": vendor-identified WAF block or generic block wording.
    Detection only, never attempts to bypass.
    """
    verdict = classify_response(resp)
    if verdict.kind == "rate-limit":
        return "rate-limit"
    if verdict.kind == "js-challenge":
        return "js-challenge"
    if verdict.kind in ("waf", "blocked"):
        return "waf"
    return None
