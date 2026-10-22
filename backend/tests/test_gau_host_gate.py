"""Archive-URL gating for the gau (Get All URLs) plugin.

Regression test for the 2026-10-22 false-negative run: the Wayback CDX
endpoint answers IP-literal queries (e.g. ``127.0.0.1/*``) with captures
of *payload strings* where the host is just a placeholder - XSS/SQLi
probe artifacts from archived exploit kits (``http://127.0.0.1/" + url
+ "index.php?act=idx``). gau emitted 80 of them as ``archived_url``
findings against a localhost test app.

Every archive row is now gated before it can become a finding or a
published discovery-bus asset:
  1. host must be the target domain (or a subdomain) - drops
     off-target captures from unfiltered archive APIs;
  2. not a captured payload string (see _archive_row_is_junk).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import base  # noqa: E402
from app.plugins.gau import GauPlugin, _archive_row_is_junk  # noqa: E402
from app.plugins.injutil import same_domain  # noqa: E402


class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None


class _CtxStub:
    def __init__(self):
        self.run_id = "test"
        self.mode = "passive"
        self.http = None
        self.cache = _FakeCache()
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.module_overrides = {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        self.shared = {}

    def publish(self, kind, item):
        bucket = self.shared.setdefault(kind, [])
        if item not in bucket:
            bucket.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))


def test_same_domain_exact_subdomain_and_port():
    assert same_domain("https://example.com/a?x=1", "example.com")
    assert same_domain("https://sub.example.com/a?x=1", "example.com")
    assert same_domain("https://example.com:8080/a?x=1", "example.com")


def test_same_domain_rejects_off_target():
    assert not same_domain("https://evil.com/?next=example.com",
                             "example.com")
    assert not same_domain("https://notexample.com/", "example.com")
    assert not same_domain("not a url at all", "example.com")
    assert not same_domain("", "example.com")


def test_archive_row_is_junk_payload_strings():
    # real rows observed from the CDX API for an IP-literal query
    assert _archive_row_is_junk(
        "http://127.0.0.1/%EF%BF%BDhttp://static.streampad.com/x.js?api=foo")
    assert _archive_row_is_junk(
        "http://127.0.0.1/'%20+%20url%20+%20'index.php?act=idx")
    assert _archive_row_is_junk("http://127.0.0.1/%22%20+%20_legend%5Bi%5D")
    assert _archive_row_is_junk("http://127.0.0.1:80/%22$login_page/")


def test_archive_row_is_junk_keeps_real_urls():
    assert not _archive_row_is_junk("https://example.com/admin/?debug=1")
    assert not _archive_row_is_junk("https://example.com/backup.zip")
    assert not _archive_row_is_junk(
        "https://example.com/search?q=hello%20world")


def test_run_drops_junk_and_off_target_archive_urls():
    plugin = GauPlugin()
    junk_payload = ("http://127.0.0.1/%EF%BF%BDhttp://static.streampad.com/"
                    "x.js?api=foo")
    off_target = "https://evil.com/?next=example.com"
    good = "https://example.com/admin/?debug=1"

    async def _fake_otx(ctx, domain):
        return {good, junk_payload, off_target}

    async def _fake_wayback(ctx, domain):
        return {junk_payload}

    async def _fake_cc(ctx, domain):
        return set()

    plugin._otx = _fake_otx
    plugin._wayback = _fake_wayback
    plugin._commoncrawl = _fake_cc

    ctx = _CtxStub()
    target = base.Target(raw="https://example.com", type="url",
                         normalized="https://example.com")
    res = asyncio.run(plugin.run(target, ctx))
    assert res.status == base.PluginStatus.OK
    values = [f.value for f in res.findings]
    assert good in values
    assert all(junk_payload not in v for v in values)
    assert all(off_target not in v for v in values)
    # junk must not reach the discovery bus either
    published = ctx.consume("urls")
    assert good in published
    assert junk_payload not in published
    assert off_target not in published
    assert "dropped 2 off-target/junk" in res.reason
