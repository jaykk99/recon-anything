"""Regression tests for the zeroday_error_miner no-endpoints fallback.

The Nov 5 10-URL scan crashed this plugin on EVERY target with
``TypeError: web_base() missing 2 required positional arguments``:
when ctx carried no discovered endpoints, run() fell back to

    base = web_base(target.normalized)

but net.web_base is ``async def web_base(ctx, target, domain)`` -
wrong arity and never awaited. The canary tests in
test_zeroday_hunters.py always publish an endpoint into ctx, so the
fallback path was never exercised. These tests publish NOTHING and
drive the plugin through the fallback for url and domain targets,
against the same buggy/clean canary apps (httpx MockTransport, no
live network): the buggy app must still yield its leak findings via
the fallback, the clean app must stay silent, and an unreachable
target must return normally instead of raising.
"""

import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.zeroday_error_miner import (  # noqa: E402
    ZerodayErrorMinerPlugin)
from app.ratelimit import RateLimiter  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


LEAK_BODY = (
    'Traceback (most recent call last):\n'
    '  File "/srv/app/handlers/item.py", line 42, in get_item\n'
    '    row = db.query("SELECT * FROM items WHERE id = " + raw)\n'
    'psycopg2.errors.UndefinedTable: relation "secret_items" '
    'does not exist')


def _item_ok():
    return httpx.Response(200, json={"id": 1, "name": "widget",
                                     "price": 10})


def _buggy_handler(request: httpx.Request) -> httpx.Response:
    # Same planted bug as the canary app in test_zeroday_hunters.py:
    # a non-numeric ID reaches an error path that leaks internals.
    url = request.url
    if url.path != "/api/item":
        return httpx.Response(404, json={"error": "not found"})
    if request.method == "POST":
        return httpx.Response(400, json={"error": "bad body"})
    raw = url.params.get("id", "")
    if raw and not raw.lstrip("-").isdigit():
        return httpx.Response(500, text=LEAK_BODY)
    if raw in ("", "0", "-1") or (raw.isdigit() and int(raw) > 10 ** 6):
        return httpx.Response(404, json={"error": "not found"})
    return _item_ok()


def _clean_handler(request: httpx.Request) -> httpx.Response:
    url = request.url
    if url.path != "/api/item":
        return httpx.Response(404, json={"error": "not found"})
    if request.method == "POST":
        return httpx.Response(400, json={"error": "bad body"})
    raw = url.params.get("id", "")
    if not raw.isdigit() or int(raw) <= 0:
        return httpx.Response(400, json={"error": "invalid id"})
    if int(raw) > 10 ** 6:
        return httpx.Response(404, json={"error": "not found"})
    return _item_ok()


def _ctx_no_endpoints(handler):
    # Deliberately publishes no "endpoints": forces the web_base
    # fallback inside ZerodayErrorMinerPlugin.run().
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return Ctx(run_id="fallback-regression", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp")


def test_no_endpoints_url_target_finds_leak():
    # url target: web_base returns the URL exactly as given, so the
    # target URL itself (the canary endpoint) is the probe target.
    target = Target(raw="https://canary.test/api/item?id=1",
                    type="url",
                    normalized="https://canary.test/api/item?id=1")
    res = _run(ZerodayErrorMinerPlugin().run(
        target, _ctx_no_endpoints(_buggy_handler)))
    kinds = {(f.evidence or {}).get("disclosure_kind")
             for f in res.findings}
    assert "internal_file_path" in kinds
    assert "sql_fragment" in kinds


def test_no_endpoints_clean_control_is_silent():
    target = Target(raw="https://canary.test/api/item?id=1",
                    type="url",
                    normalized="https://canary.test/api/item?id=1")
    res = _run(ZerodayErrorMinerPlugin().run(
        target, _ctx_no_endpoints(_clean_handler)))
    assert res.findings == []


def test_no_endpoints_domain_target_completes():
    # domain target: web_base probes https with HEAD through ctx.http
    # and caches the resolved scheme; the plugin must complete and
    # stay silent on a clean root.
    def root_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    target = Target(raw="canary.test", type="domain",
                    normalized="canary.test")
    ctx = _ctx_no_endpoints(root_handler)
    res = _run(ZerodayErrorMinerPlugin().run(target, ctx))
    assert res.findings == []
    assert ctx.shared.get("_webscheme:canary.test") == \
        "https://canary.test"


def test_no_endpoints_unreachable_target_no_crash():
    # Every request fails at transport level (malformed/unreachable
    # input robustness): the plugin returns normally, zero findings.
    def dead_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    target = Target(raw="canary.test", type="domain",
                    normalized="canary.test")
    res = _run(ZerodayErrorMinerPlugin().run(
        target, _ctx_no_endpoints(dead_handler)))
    assert res.findings == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
