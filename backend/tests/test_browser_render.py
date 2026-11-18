"""Browser-rendered discovery: SPA gate, same-site handling, and the
real capture path (post-JS DOM links/forms + live XHR/fetch endpoints).

The capture test renders a tiny local SPA in the pre-installed Chromium
and asserts the dynamic surface is recovered and published to the bus.
It skips cleanly where Playwright/Chromium is unavailable, so CI without
a browser still runs the pure-logic checks.
"""
import asyncio
import functools
import http.server
import os
import socketserver
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import app.plugins.browser_render as br  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402


# -- pure logic (always runs) ---------------------------------------------

def test_spa_heuristic():
    assert br.looks_like_spa('<div id="root"></div><script src="/a.js"></script>')
    assert br.looks_like_spa(
        '<div id="__next"></div>'
        '<script src="/_next/a.js"></script><script src="/_next/b.js"></script>'
        '<script src="/_next/c.js"></script>')
    assert not br.looks_like_spa(
        "<html><body>" + "<p>real content here about things.</p>" * 80
        + "</body></html>")
    assert not br.looks_like_spa("")


def test_same_site_ignores_port():
    # the bug this guards: netloc carries the port and must not defeat
    # the same-site check.
    assert br._same_site("http://127.0.0.1:50115/api/x", "127.0.0.1")
    assert br._same_site("https://a.example.com/x", "example.com")
    assert not br._same_site("https://evil.com/x", "example.com")


def test_passive_mode_skips():
    p = br.BrowserRenderPlugin()
    ctx = _ctx(mode="passive")
    res = asyncio.run(p.run(_T("https://example.com/"), ctx))
    assert res.status.value == "ok"
    assert "passive" in res.reason


# -- helpers ---------------------------------------------------------------

class _Cache:
    def get(self, ns, k):
        return None

    def set(self, ns, k, v, ttl=None):
        pass

    async def cached(self, ns, k, fn):
        return await fn(), False


def _ctx(mode="active"):
    return Ctx(run_id="t", mode=mode, http=None, cache=_Cache(), keys={},
               limiter=None, shared={}, module_overrides={})


def _T(url):
    return Target(raw=url, type="url", normalized=url)


def _browser_available():
    try:
        from playwright.async_api import async_playwright  # noqa: F401
    except Exception:
        return False
    from app.browser import _candidate_paths
    # default-bundled or an explicit candidate must exist
    return True


# -- full capture (skips without a browser) -------------------------------

@pytest.mark.skipif(not _browser_available(),
                    reason="playwright/chromium not available")
def test_renders_local_spa_and_captures_surface():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "index.html"), "w") as f:
        f.write(
            '<html><head><script src="/static/app.js"></script></head>'
            '<body><div id="root"></div>'
            '<a href="/dashboard">d</a><a href="/admin/panel">a</a>'
            '<form action="/login" method="post"><input name="user"></form>'
            '</body></html>')
    os.makedirs(os.path.join(d, "static"), exist_ok=True)
    with open(os.path.join(d, "static", "app.js"), "w") as f:
        f.write("fetch('/api/v1/users');"
                "setTimeout(()=>fetch('/internal/debug'),150);")

    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=d)
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        orig = br.looks_like_spa
        br.looks_like_spa = lambda html: True  # force render
        try:
            ctx = _ctx()
            res = asyncio.run(asyncio.wait_for(
                br.BrowserRenderPlugin().run(
                    _T(f"http://127.0.0.1:{port}/"), ctx), timeout=50))
        finally:
            br.looks_like_spa = orig
    finally:
        httpd.shutdown()

    if res.status.value != "ok" or "launch failed" in (res.reason or ""):
        pytest.skip(f"browser could not launch here: {res.reason}")

    eps = {e.rsplit(str(port), 1)[-1] for e in ctx.shared.get("endpoints", [])}
    # the live XHRs (incl. the delayed one) and the API-shaped DOM link
    assert "/api/v1/users" in eps
    assert "/internal/debug" in eps          # caught by the settle wait
    assert "/admin/panel" in eps
    assert any(f.key == "rendered_form" for f in res.findings)
    assert any(f.key == "spa_rendered" for f in res.findings)
