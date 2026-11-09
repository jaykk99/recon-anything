"""Recursive endpoint seeding: deepcrawl must crawl same-origin endpoints
it discovers in JS/comments and ones other plugins published to the
"endpoints" bus - not just hyperlinked pages. Same-origin only, read-only.

Network is faked with an in-memory site; nothing leaves the process.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app.plugins.deepcrawl as deepcrawl  # noqa: E402
from app.plugins import base  # noqa: E402

BASEURL = "https://t.test"

# In-memory site: homepage links to /dashboard; /dashboard's inline JS calls
# /api/v2/secret; /hidden (seeded on the bus by another plugin) links to
# /deep. A cross-origin link must NOT be crawled.
SITE = {
    BASEURL + "/": '<a href="/dashboard">d</a> '
                   '<a href="https://evil.test/x">off</a>',
    BASEURL + "/dashboard": '<script>fetch("/api/v2/secret")</script>',
    BASEURL + "/api/v2/secret": "<html>ok</html>",
    BASEURL + "/hidden": '<a href="/deep">deep</a>',
    BASEURL + "/deep": "<html>deep</html>",
}


class _Resp:
    def __init__(self, text):
        self.status_code = 200
        self.headers = {"content-type": "text/html"}
        self.text = text


class _Ctx:
    def __init__(self):
        self.http = None
        self.limiter = None
        self.shared = {"endpoints": ["/hidden"]}  # seeded by another plugin

    def publish(self, kind, item):
        self.shared.setdefault(kind, [])
        if item not in self.shared[kind]:
            self.shared[kind].append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))


def test_recursive_seeding_crawls_discovered_and_bus_endpoints(monkeypatch):
    fetched = []

    async def fake_fetch(http, limiter, method, url, *a, **k):
        fetched.append(url)
        return _Resp(SITE.get(url, ""))

    async def fake_web_base(ctx, target, domain):
        return BASEURL

    monkeypatch.setattr(deepcrawl, "fetch", fake_fetch)
    monkeypatch.setattr(deepcrawl, "web_base", fake_web_base)

    target = base.Target(raw="t.test", type="domain", normalized="t.test")
    asyncio.run(deepcrawl.DeepCrawlPlugin().run(target, _Ctx()))

    # hyperlinked page
    assert BASEURL + "/dashboard" in fetched
    # endpoint discovered in inline JS, followed recursively
    assert BASEURL + "/api/v2/secret" in fetched
    # endpoint seeded on the bus by another plugin, then crawled
    assert BASEURL + "/hidden" in fetched
    # link found on the bus-seeded page -> recursion continued
    assert BASEURL + "/deep" in fetched
    # cross-origin link must never be crawled
    assert not any("evil.test" in u for u in fetched)
