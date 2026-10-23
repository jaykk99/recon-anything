"""Regression tests for the 2026-10-23 false-negative fixes.

The falseneg harness (false-neg-tests/run_falseneg.py) exposed real misses
that were NOT logic bugs but scheduling bugs: sqli, traversal and
param_discovery each timed out before reaching the vulnerable endpoints
(sqli burned 60s on all-methods-per-URL; traversal re-fetched the baseline
per payload and probed alphabetically; param_discovery sent one request
per param per seed, sequentially).

These tests pin the fixed behavior with a MockTransport fixture that
simulates the vulnerable endpoints: UNION error, SLEEP delay,
boolean content diff, /etc/passwd leak, and a raw-echo page.
"""
import asyncio
import time
from urllib.parse import parse_qs, urlparse

import httpx

# NOTE: app.* imports are intentionally function-level, not module-level.
# app.cache pulls in app.config, which snapshots DATABASE_URL at first
# import. A module-level import here would poison test_hunters.py (which
# sets its own DATABASE_URL at import time): the engine would bind to
# the default ./recon.db instead of the test's throwaway DB and 16
# hunter tests would fail on duplicate keys. Keep app imports lazy.

HOST = "falseneg.test"
BASE = f"http://{HOST}"

FILLER = "lorem ipsum dolor sit amet. " * 200

HOME = """<html><body>
<a href="/union.php?cat=1">u</a>
<a href="/blind.php?id=1">b</a>
<a href="/bool.php?id=1">o</a>
<a href="/product.php?pic=logo.png">p</a>
<a href="/legacy.php?x=1">l</a>
</body></html>"""


async def _handler(request: httpx.Request) -> httpx.Response:
    # NOTE: async on purpose. The /blind.php delay MUST be
    # `await asyncio.sleep(...)`, never time.sleep(): a blocking sleep
    # stalls the client's event loop and inflates the measured latency
    # of every concurrent request, producing false time-blind positives
    # on unrelated params (the real vulnapp sleeps in its own thread).
    url = str(request.url)
    p = urlparse(url)
    q = parse_qs(p.query)
    if p.path in ("/", ""):
        return httpx.Response(200, content=HOME, request=request)
    if p.path == "/union.php":
        cat = q.get("cat", [""])[0]
        if "union" in cat.lower():
            return httpx.Response(
                200,
                content="<html><body>DB Error: The used SELECT statements "
                        "have a different number of columns</body></html>",
                request=request)
        return httpx.Response(200, content=f"<html><body>{FILLER}</body></html>",
                               request=request)
    if p.path == "/blind.php":
        i = q.get("id", [""])[0]
        if "sleep(" in i.lower():
            await asyncio.sleep(5)  # simulated DB delay, loop stays free
        return httpx.Response(200, content=f"<html><body>{FILLER}</body></html>",
                               request=request)
    if p.path == "/bool.php":
        i = q.get("id", [""])[0]
        if "'1'='2" in i:
            return httpx.Response(200, content="<html><body>no results</body></html>",
                                   request=request)
        return httpx.Response(200, content=f"<html><body>{FILLER}</body></html>",
                               request=request)
    if p.path == "/product.php":
        pic = q.get("pic", [""])[0]
        if ".." in pic or "etc/passwd" in pic:
            return httpx.Response(
                200,
                content="<html><body><pre>root:x:0:0:root:/root:/bin/bash\n"
                        "</pre></body></html>",
                request=request)
        return httpx.Response(200, content="<html><body>showing pic</body></html>",
                               request=request)
    if p.path == "/legacy.php":
        rows = "".join(f"<li>{k} = {v[0]}</li>" for k, v in q.items())
        return httpx.Response(200,
                               content=f"<html><body><ul>{rows}</ul></body></html>",
                               request=request)
    return httpx.Response(404, content="not found", request=request)


def make_ctx(mode="active"):
    from app.cache import Cache
    from app.plugins.base import Ctx
    from app.ratelimit import RateLimiter
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="falseneg-reg", mode=mode, http=client, cache=Cache(),
               keys={}, limiter=RateLimiter(default_rps=200.0), shared={})


def target():
    from app.plugins.base import Target
    return Target(raw=BASE + "/", type="url", normalized=BASE + "/")


def _keys(findings):
    return {f.key for f in findings}


def test_sqli_finds_union_before_budget():
    from app.plugins import sqli
    """Round 1 (error) + round 2 (UNION) must sweep every URL: the UNION
    endpoint used to be missed because the plugin burned its budget on
    all-methods-per-URL for the first few URLs only."""
    ctx = make_ctx()
    try:
        res = asyncio.run(asyncio.wait_for(
            sqli.SqliPlugin().run(target(), ctx), timeout=90))
    finally:
        asyncio.run(ctx.http.aclose())
    keys = _keys(res.findings)
    assert "sqli_union_based" in keys, f"UNION missed: {keys}"


def test_sqli_finds_time_blind():
    from app.plugins import sqli
    ctx = make_ctx()
    try:
        res = asyncio.run(asyncio.wait_for(
            sqli.SqliPlugin().run(target(), ctx), timeout=120))
    finally:
        asyncio.run(ctx.http.aclose())
    keys = _keys(res.findings)
    assert "sqli_time_blind" in keys, f"time-blind missed: {keys}"


def test_sqli_finds_boolean_blind():
    from app.plugins import sqli
    ctx = make_ctx()
    try:
        res = asyncio.run(asyncio.wait_for(
            sqli.SqliPlugin().run(target(), ctx), timeout=120))
    finally:
        asyncio.run(ctx.http.aclose())
    keys = _keys(res.findings)
    assert "sqli_boolean_blind" in keys, f"boolean-blind missed: {keys}"


def test_traversal_confirms_passwd_leak():
    from app.plugins import traversal
    """Traversal must confirm /etc/passwd via ?pic= even though the URL
    sorts late alphabetically: file-ish params are now probed first and
    the baseline is fetched once per URL, not once per payload."""
    ctx = make_ctx()
    try:
        res = asyncio.run(asyncio.wait_for(
            traversal.TraversalPlugin().run(target(), ctx), timeout=60))
    finally:
        asyncio.run(ctx.http.aclose())
    keys = _keys(res.findings)
    assert "dir_traversal_confirmed" in keys, f"traversal missed: {keys}"


def test_traversal_baseline_fetched_once_per_url():
    from app.plugins import traversal
    """Baseline FP guard must not cost a fetch per payload: probe counts
    stay small even with several URLs x payloads."""
    calls = []

    async def counting_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return await _handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(counting_handler),
                               follow_redirects=True, trust_env=False)
    from app.cache import Cache
    from app.plugins.base import Ctx
    from app.ratelimit import RateLimiter
    ctx = Ctx(run_id="falseneg-reg2", mode="active", http=client,
              cache=Cache(), keys={}, limiter=RateLimiter(default_rps=200.0),
              shared={})
    try:
        res = asyncio.run(asyncio.wait_for(
            traversal.TraversalPlugin().run(target(), ctx), timeout=60))
    finally:
        asyncio.run(ctx.http.aclose())
    assert "dir_traversal_confirmed" in _keys(res.findings)
    # 5 fixture URLs -> at most ~2 baseline+homepage fetches each plus the
    # probes; the old code re-fetched the baseline inside the payload loop
    # (3 payloads x params x URLs). Sanity bound, not exact.
    assert len(calls) < 120, f"too many fetches: {len(calls)}"


def test_param_discovery_finds_reflecting_param():
    from app.plugins import param_discovery
    """/legacy.php echoes every param raw: batch probing must surface
    param_reflected without timing out on the per-param loop."""
    ctx = make_ctx()
    try:
        res = asyncio.run(asyncio.wait_for(
            param_discovery.ParamDiscoveryPlugin().run(target(), ctx),
            timeout=120))
    finally:
        asyncio.run(ctx.http.aclose())
    keys = _keys(res.findings)
    assert "param_reflected" in keys, f"reflection missed: {keys}"



def test_time_control_measured_before_payload():
    """The benign control for time-based detection must be fetched BEFORE
    the SLEEP payload, not after. A 5s server sleep lets the shared
    limiter queue build up behind it, so a post-payload control sees a
    worse queue and true positives get rejected (V03/V09 missed under
    full-scan contention)."""
    import app.plugins.sqli as sqli_mod
    calls = []

    orig = sqli_mod.fetch
    async def spy_fetch(http, limiter, method, url, **kw):
        calls.append(url)
        return await orig(http, limiter, method, url, **kw)

    sqli_mod.fetch = spy_fetch
    try:
        ctx = make_ctx()
        try:
            res = asyncio.run(asyncio.wait_for(
                sqli_mod.SqliPlugin().run(target(), ctx), timeout=120))
        finally:
            asyncio.run(ctx.http.aclose())
    finally:
        sqli_mod.fetch = orig
    # sqli_time_blind must still be found via the pre-payload control
    assert "sqli_time_blind" in _keys(res.findings), (
        f"time_blind missed with pre-payload control: {_keys(res.findings)}")
    # The first SLEEP payload URL must appear AFTER a benign control
    # fetch for the same endpoint in the call order.
    blind_calls = [u for u in calls if "/blind.php" in u]
    sleep_idx = next(i for i, u in enumerate(blind_calls)
                     if "SLEEP" in u.upper())
    assert sleep_idx > 0, "no benign control before the SLEEP payload"
    assert "SLEEP" not in blind_calls[sleep_idx - 1].upper(), (
        "control must be the benign URL")
