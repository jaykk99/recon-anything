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
import contextlib
import datetime as dt
import os
import random
import time
from collections import deque
from typing import Dict, Literal, Optional

import httpx

from .waf import BLOCK_KINDS, WafVerdict, classify_response

# Per-host request floor once WAF/challenge behavior is seen. 1 RPS keeps
# lightweight checks alive without hammering a host that is fighting back.
WAF_RPS_FLOOR = float(os.environ.get("RECON_WAF_RPS", "1.0"))
# Per-host circuit breaker (speed pass 2026-10-23): after this many
# CONSECUTIVE connect failures (refused / DNS / connect timeout - i.e.
# the host never accepted a connection), fetches to the host fail fast
# with ConnectError for BREAKER_OPEN_S seconds instead of each plugin
# paying full connect timeouts + retry backoff + limiter pacing for its
# own doomed requests. Profiling: a dead-host run issued ~6,400 requests
# to the dead host and spent ~128s of its 179s wall just pacing them
# through the limiter. Any real HTTP response (even a 500) proves the
# host is alive and resets the counter; read/write timeouts after a
# successful connect do NOT count (the host accepted the connection).
# Half-open after the window: one probe request is allowed through;
# its success closes the breaker, its connect failure re-opens it.
BREAKER_THRESHOLD = int(os.environ.get("RECON_BREAKER_THRESHOLD", "5"))
BREAKER_OPEN_S = float(os.environ.get("RECON_BREAKER_OPEN_S", "20"))
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
    def __init__(self, default_rps: float = 10.0, *,
                 spike_window: int = 20, spike_min_samples: int = 8,
                 spike_ratio: float = 0.4, backoff_base_s: float = 10.0,
                 backoff_max_s: float = 120.0,
                 global_concurrency: Optional[int] = None) -> None:
        self.default_rps = default_rps
        self._rps: Dict[str, float] = {}
        self._next: Dict[str, float] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        # Per-host WAF state: vendor, counters, graceful-mode flag.
        self._waf: Dict[str, Dict] = {}
        # Per-host circuit-breaker state (see BREAKER_* above):
        # consecutive connect failures, open-until timestamp, and a
        # half-open single-probe flag.
        self._breaker: Dict[str, Dict] = {}
        # Token buckets per host (infra upgrade): refill at the host
        # RPS, capacity = one second of burst. Steady-state rate is
        # identical to the old fixed-interval pacing; short bursts
        # no longer pay full spacing for every request.
        self._buckets: Dict[str, Dict] = {}
        # 429/503 spike backoff per host (infra upgrade): a sliding
        # window of recent response classes; when throttled responses
        # (429/503) reach spike_ratio of the window, the host backs
        # off exponentially (base * 2^level, capped) until the
        # window lifts; a clean streak resets the level.
        self._throttle: Dict[str, Dict] = {}
        self._spike_window = max(4, spike_window)
        self._spike_min_samples = max(1, spike_min_samples)
        self._spike_ratio = spike_ratio
        self._backoff_base_s = backoff_base_s
        self._backoff_max_s = backoff_max_s
        # Global in-flight request cap shared by ALL consumers of
        # this limiter (fetch_many's old semaphore was per-call, so
        # parallel callers each got their own full allowance).
        # RECON_GLOBAL_CONCURRENCY, default 256; <= 0 disables.
        if global_concurrency is None:
            try:
                global_concurrency = int(
                    os.environ.get("RECON_GLOBAL_CONCURRENCY", "256"))
            except ValueError:
                global_concurrency = 256
        self._global_concurrency = global_concurrency
        self._global_sem: Optional[asyncio.Semaphore] = None
        self._global_sem_loop = None

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

    # -- per-host circuit breaker --------------------------------------
    def _breaker_state(self, host: str) -> Dict:
        return self._breaker.setdefault(host, {
            "fails": 0, "open_until": 0.0, "probe": False, "probe_at": 0.0,
        })

    def breaker_allows(self, host: str) -> bool:
        """False while the host's breaker is open. After the open window
        elapses, exactly one half-open probe is allowed through. A probe
        whose caller was cancelled mid-flight never reports back, so a
        probe older than the staleness bound is treated as abandoned
        and a fresh one is granted - the breaker can never wedge shut."""
        st = self._breaker.get(host)
        if not st or st["open_until"] <= 0:
            return True
        now = time.monotonic()
        if now < st["open_until"]:
            return False
        if st["probe"] and now - st["probe_at"] < BREAKER_OPEN_S + 30.0:
            return False
        st["probe"] = True
        st["probe_at"] = now
        return True

    def breaker_success(self, host: str) -> None:
        """The host produced an HTTP response: it is alive, close up."""
        st = self._breaker.get(host)
        if st:
            st["fails"] = 0
            st["open_until"] = 0.0
            st["probe"] = False

    def breaker_failure(self, host: str) -> None:
        """One connect-level failure (refused / DNS / connect timeout)."""
        st = self._breaker_state(host)
        st["fails"] += 1
        st["probe"] = False
        if st["fails"] >= BREAKER_THRESHOLD:
            st["open_until"] = time.monotonic() + BREAKER_OPEN_S

    def breaker_neutral(self, host: str) -> None:
        """Attempt ended without a connect verdict (e.g. a read timeout:
        the host DID accept the connection). Only releases a dangling
        half-open probe flag; the failure count is left alone."""
        st = self._breaker.get(host)
        if st:
            st["probe"] = False

    def breaker_open(self, host: str) -> bool:
        st = self._breaker.get(host)
        return bool(st and st["open_until"] > time.monotonic())

    # -- pacing --------------------------------------------------------
    def set_rps(self, host: str, rps: float) -> None:
        self._rps[host] = rps

    def _lock(self, host: str) -> asyncio.Lock:
        if host not in self._locks:
            self._locks[host] = asyncio.Lock()
        return self._locks[host]

    async def wait(self, host: str) -> None:
        protected = self._waf.get(host, {}).get("active", False)
        async with self._lock(host):
            now = time.monotonic()
            nxt = self._next.get(host, 0)
            if now < nxt:
                # Retry-After floor (note_429): honored before any
                # bucket math, exactly as the old pacing honored it.
                await asyncio.sleep(nxt - now)
                now = time.monotonic()
            # 429/503 spike backoff: hold until the window lifts.
            th = self._throttle.get(host)
            if th and now < th["until"]:
                await asyncio.sleep(th["until"] - now)
                now = time.monotonic()
            if protected:
                # WAF graceful mode keeps the exact old behavior:
                # jittered fixed-interval spacing at the floor rate.
                gap = 1.0 / max(self._rps.get(host, self.default_rps), 0.1)
                gap *= random.uniform(0.8, 1.4)
                self._next[host] = now + gap
                return
            # Token bucket: refill at the host RPS, capacity = one
            # second of burst (min 1). Same steady-state rate as the
            # old fixed-interval pacing, without charging full
            # spacing for the first requests of a burst.
            rps = max(self._rps.get(host, self.default_rps), 0.1)
            b = self._buckets.get(host)
            if b is None:
                b = self._buckets[host] = {"tokens": max(1.0, rps),
                                           "updated": now}
            cap = max(1.0, rps)
            b["tokens"] = min(cap, b["tokens"] + (now - b["updated"]) * rps)
            b["updated"] = now
            if b["tokens"] >= 1.0:
                b["tokens"] -= 1.0
                return
            deficit = (1.0 - b["tokens"]) / rps
            await asyncio.sleep(deficit)
            b["tokens"] = 0.0
            b["updated"] = now + deficit

    def note_429(self, host: str, retry_after: object = None) -> None:
        """Honor Retry-After (delay-seconds or HTTP-date), cap 120s."""
        wait = parse_retry_after(retry_after)
        if wait is None:
            wait = 5.0
        self._next[host] = time.monotonic() + min(max(wait, 0.0), 120.0)

    # -- 429/503 spike backoff -----------------------------------------
    def _throttle_state(self, host: str) -> Dict:
        return self._throttle.setdefault(host, {
            "window": deque(maxlen=self._spike_window),
            "level": 0, "until": 0.0, "clean": 0,
        })

    def note_status(self, host: str, status_code: int) -> None:
        """Fold one response status into the host's spike window.

        Per-response Retry-After (note_429) handles a single 429;
        this handles the BURST case: when 429/503 responses reach
        spike_ratio of the recent window (with enough samples), the
        host's backoff level rises and wait() holds requests until
        the backoff lifts. Ten consecutive clean responses reset
        the level."""
        st = self._throttle_state(host)
        if status_code not in (429, 503):
            st["window"].append(False)
            st["clean"] += 1
            if st["clean"] >= 10 and st["level"] > 0:
                st["level"] = 0
                st["until"] = 0.0
                st["clean"] = 0
            return
        st["window"].append(True)
        st["clean"] = 0
        win = st["window"]
        if len(win) < self._spike_min_samples:
            return
        if sum(win) / len(win) < self._spike_ratio:
            return
        now = time.monotonic()
        if now < st["until"]:
            return  # already backing off; don't stack levels mid-window
        st["level"] = min(st["level"] + 1, 5)
        st["until"] = now + min(
            self._backoff_max_s,
            self._backoff_base_s * (2 ** (st["level"] - 1)))
        win.clear()

    def throttle_state(self, host: str) -> Dict:
        st = self._throttle.get(host)
        if not st:
            return {"host": host, "level": 0, "backoff_active": False,
                    "backoff_until": 0.0, "window": 0}
        return {"host": host, "level": st["level"],
                "backoff_active": st["until"] > time.monotonic(),
                "backoff_until": st["until"], "window": len(st["window"])}

    # -- global in-flight cap -------------------------------------------
    def _global_semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._global_sem is None or self._global_sem_loop is not loop:
            self._global_sem = asyncio.Semaphore(self._global_concurrency)
            self._global_sem_loop = loop
        return self._global_sem

    @contextlib.asynccontextmanager
    async def global_slot(self):
        """One slot of the shared global in-flight request cap.
        Every fetch() through this limiter takes a slot, so the cap
        holds across all concurrent consumers, not per call site."""
        if self._global_concurrency <= 0:
            yield
            return
        sem = self._global_semaphore()
        await sem.acquire()
        try:
            yield
        finally:
            sem.release()


async def fetch(client: httpx.AsyncClient, limiter: RateLimiter, method: str,
                url: str, *, max_retries: int = 1, rotate_ua: bool = False,
                **kwargs) -> httpx.Response:
    """HTTP with rate limiting, WAF accounting, retries, backoff+jitter.

    Every response is classified (WAF vendor, rate-limit, challenge,
    blocked, not-found, server-error, clean) and folded into the host's
    WAF state, which drives graceful backoff. Retries transient failures
    (429/5xx, timeouts) so findings are not lost to a single bad response.
    Bounded: at most max_retries extra attempts.

    Default max_retries=1 (one retry): the old default of 2 tripled the
    worst-case cost of every dead/slow host (3 x timeout + backoff sleeps)
    and stalled scans. No plugin requests 2 explicitly; bulk sweeps already
    pass 1 or 0.

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
    # Circuit breaker hooks (duck-typed: limiter stand-ins without them
    # keep the exact pre-breaker behavior).
    _b_allows = getattr(limiter, "breaker_allows", None)
    _b_open = getattr(limiter, "breaker_open", None)
    _b_success = getattr(limiter, "breaker_success", None)
    _b_failure = getattr(limiter, "breaker_failure", None)
    _b_neutral = getattr(limiter, "breaker_neutral", None)
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        if _b_allows is not None and not _b_allows(host):
            # Host is in its fast-fail window: raise the same exception
            # a dead host produces, without spending a limiter slot, a
            # connect timeout, or retry backoff on it. Plugins degrade
            # exactly as they do for an unreachable host.
            raise httpx.ConnectError(
                f"circuit open for unreachable host: {host}",
                request=httpx.Request(method, url))
        await limiter.wait(host)
        try:
            # Shared global in-flight cap (duck-typed like the
            # breaker hooks: limiter stand-ins without it keep the
            # exact pre-existing behavior).
            _slot = getattr(limiter, "global_slot", None)
            if _slot is not None:
                async with _slot():
                    resp = await client.request(method, url, **kwargs)
            else:
                resp = await client.request(method, url, **kwargs)
            if _b_success is not None:
                _b_success(host)
            # Classify every response: vendor attribution + block kinds
            # feed graceful backoff; clean/404/5xx are accounted too.
            verdict: Optional[WafVerdict] = None
            try:
                verdict = classify_response(resp)
                limiter.note_result(host, verdict)
            except Exception:
                pass
            # 429/503 spike accounting: bursts raise the host's
            # adaptive backoff level (see RateLimiter.note_status).
            _ns = getattr(limiter, "note_status", None)
            if _ns is not None:
                try:
                    _ns(host, resp.status_code)
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
            if isinstance(e, httpx.ConnectError):
                # Includes ConnectTimeout (a ConnectError subclass):
                # the host never accepted a connection.
                if _b_failure is not None:
                    _b_failure(host)
            elif _b_neutral is not None:
                # Read/write timeout: connection was accepted, so this
                # is not evidence the host is down.
                _b_neutral(host)
            if attempt < max_retries:
                if _b_open is not None and _b_open(host):
                    raise  # breaker just opened: stop paying retries
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


async def fetch_many(client: httpx.AsyncClient, limiter: RateLimiter,
                     requests: list, *, concurrency: int = 6,
                     max_retries: int = 1, deadline: float | None = None,
                     **shared_kwargs) -> list:
    """Fetch many URLs concurrently, results in input order.

    requests: list of (method, url) tuples or (method, url, kwargs-dict).
    Returns a list aligned with the input: httpx.Response on success,
    None on failure (never raises). The shared rate limiter paces
    per-host requests and applies WAF backoff, so concurrent fetches
    stay polite. Use for independent enumeration probes (sitemaps,
    well-known paths, doc endpoints) - not for injection payloads,
    which stay sequential to avoid tripping WAFs.

    deadline: optional wall-clock cap (seconds) for the whole sweep.
    Requests still in flight when it expires come back as None, so
    callers keep partial results instead of losing the entire chunk
    (battle-test 2026-10-18: gobuster discarded full 300-probe chunks
    on slow networks and reported "probed 0 paths").
    """
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(req):
        if len(req) == 3:
            method, url, kw = req
            kw = {**shared_kwargs, **kw}
        else:
            method, url = req
            kw = shared_kwargs
        async with sem:
            try:
                # Battle-test fix 2026-10-18: passing max_retries both
                # explicitly AND inside per-request kwargs raised
                # "TypeError: multiple values for keyword argument",
                # which this except swallowed -> EVERY probe silently
                # returned None (gobuster/feroxbuster/wget/firecrawl
                # were enumerating nothing). Per-request value wins.
                kw = dict(kw)
                kw.setdefault("max_retries", max_retries)
                return await fetch(client, limiter, method, url, **kw)
            except Exception:
                return None

    tasks = [asyncio.ensure_future(_one(r)) for r in requests]
    if not tasks:
        return []
    if deadline is None:
        return list(await asyncio.gather(*tasks))
    done, pending = await asyncio.wait(tasks, timeout=max(0.1, deadline))
    for t in pending:
        t.cancel()
    out = []
    for t in tasks:
        if t in done:
            try:
                out.append(t.result())
            except Exception:
                out.append(None)
        else:
            out.append(None)  # timed out: partial results survive
    await asyncio.sleep(0)  # let cancellations release semaphore slots
    return out
