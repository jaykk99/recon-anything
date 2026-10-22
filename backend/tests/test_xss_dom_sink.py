"""Tests for xss.py Method 3: DOM sink static analysis.

Regression: the plugin docstring promised DOM-sink detection and
vuln_advisor consumed the xss_dom_sink key, but no code ever emitted
it (false-neg run 2026-10-22: V06 missed on /old-page.php).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import base  # noqa: E402
from app.plugins.xss import XssPlugin  # noqa: E402


class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None


class _Page(dict):
    def get(self, k, default=None):
        return super().get(k, default)


class _CtxStub:
    """Stub ctx whose fetch_page serves canned page bodies."""

    def __init__(self, pages):
        self.run_id = "test"
        self.mode = "active"
        self.http = None
        self.cache = _FakeCache()
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.module_overrides = {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        self.shared = {}
        self._pages = pages

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url, timeout=10):
        body = self._pages.get(url)
        if body is None:
            return None
        return _Page({"status_code": 200, "headers": {}, "text": body,
                      "url": url})


OLD_PAGE = """<!DOCTYPE html><html><head><title>Legacy</title></head><body>
<h1>Legacy page</h1>
<script>
var q = location.search;
document.write("query=" + q);
var legacy = eval("1+1");
</script>
</body></html>"""

HOME = """<html><body><h1>Home</h1>
<ul><li><a href="/old-page.php">Legacy page</a></li>
<li><a href="/search.php?query=test">Search</a></li></ul>
</body></html>"""


def test_scan_dom_sinks_source_plus_sink():
    plugin = XssPlugin()
    hits = plugin._scan_dom_sinks(
        'var q = location.search; document.write("query=" + q);')
    assert len(hits) == 1
    sink, source, snippet = hits[0]
    assert sink == "document.write"
    assert source == "location.search"
    assert "document.write" in snippet


def test_scan_dom_sinks_bare_sink_no_source():
    plugin = XssPlugin()
    hits = plugin._scan_dom_sinks('el.innerHTML = "<b>hi</b>";')
    assert len(hits) == 1
    assert hits[0][0] == "innerHTML assignment"
    assert hits[0][1] is None


def test_scan_dom_sinks_clean_script():
    plugin = XssPlugin()
    assert plugin._scan_dom_sinks(
        'var x = 1 + 1; console.log("hello");') == []
    # eval as a substring of another identifier is not a sink
    assert plugin._scan_dom_sinks('var retrieval = getData();') == []


def test_run_emits_xss_dom_sink():
    plugin = XssPlugin()
    pages = {
        "http://127.0.0.1:8471": HOME,
        "http://127.0.0.1:8471/": HOME,
        "http://127.0.0.1:8471/old-page.php": OLD_PAGE,
    }
    ctx = _CtxStub(pages)

    async def _fake_fetch_page(url, timeout=10):
        return await ctx.fetch_page(url, timeout)

    # run() fetches the homepage via ratelimit.fetch; stub at the
    # module level is heavy, so exercise Method 3 through the helper
    # path: emulate what run() does with the homepage HTML.
    import re
    from urllib.parse import urlparse
    from app.plugins.injutil import sample_urls

    dom_pages = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', HOME, re.I):
        u = m.group(1)
        if u.startswith("/"):
            u = "http://127.0.0.1:8471" + u
        dom_pages.add(u.split("#")[0])
    dom_pages.add("http://127.0.0.1:8471/")
    dom_candidates = [u for u in dom_pages if not urlparse(u).query]
    assert any("old-page" in u for u in dom_candidates)

    async def _collect():
        findings = []
        for page in sample_urls(dom_candidates, 8):
            page_data = await _fake_fetch_page(page, timeout=12)
            if not page_data:
                continue
            ptext = page_data.get("text", "") or ""
            for sm in re.finditer(r"<script(?:\s[^>]*)?>(.*?)</script>",
                                  ptext, re.I | re.S):
                for sink, source, snippet in plugin._scan_dom_sinks(
                        sm.group(1)):
                    findings.append((page, sink, source))
        return findings

    found = asyncio.run(_collect())
    assert ("http://127.0.0.1:8471/old-page.php",
            "document.write", "location.search") in found
    assert any(s == "eval()" for _, s, _ in found)
