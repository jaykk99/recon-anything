"""Exchange-web plugin run() end-to-end (fetch stubbed).

Proves the generated exch_* plugin classes work through the real
Plugin.run path: a vulnerable JS bundle produces a finding under
the plugin's own id with masked evidence, a weak header set fires
the header detector, and a clean site produces no findings.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.plugins.base import Target, _as_page  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

BASE = "https://exchange.example"
BUNDLE = BASE + "/app.js"

VULN_BUNDLE = ('const cfg={apiKey:"AKEX9f2kLmN8pQr4sT6v",'
               'apiSecret:"Zx8Qw2Er5Ty7Ui9Op0As3Df6Gh1Jk4Lz"};')
CLEAN_BUNDLE = "const cfg={apiKey:process.env.EXCHANGE_API_KEY};"


class FakeCtx:
    def __init__(self, pages):
        self.keys = {}
        self.mode = "passive"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = "test"
        self.module_overrides = {}
        self.shared = {}
        self._pages = pages

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)

    async def fetch_page(self, url, timeout=10):
        page = self._pages.get(url.rstrip("/"))
        if page is None:
            page = self._pages.get(url)
        return _as_page(page) if page is not None else None


def _ctx(bundle_text, headers=None):
    html = f'<html><head><script src="/app.js"></script></head></html>'
    pages = {
        BASE: {"status_code": 200, "headers": headers or {},
               "text": html, "url": BASE + "/"},
        BUNDLE: {"status_code": 200, "headers": {},
                 "text": bundle_text, "url": BUNDLE},
    }
    return FakeCtx(pages)


def _target():
    return Target(raw=BASE, type="url", normalized=BASE)


def test_run_flags_secret_pair_in_bundle():
    pid = "exch_api_key_secret_pair_js"
    plugin = discover()[pid]()
    res = asyncio.run(plugin.run(_target(), _ctx(VULN_BUNDLE)))
    hits = [f for f in res.findings if f.key == pid]
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["fingerprint_sha256"]
    blob = hits[0].value + str(ev)
    assert "Zx8Qw2Er5Ty7Ui9Op0As3Df6Gh1Jk4Lz" not in blob
    assert "AKEX9f2kLmN8pQr4sT6v" not in blob


def test_run_clean_bundle_silent():
    pid = "exch_api_key_secret_pair_js"
    plugin = discover()[pid]()
    res = asyncio.run(plugin.run(_target(), _ctx(CLEAN_BUNDLE)))
    assert [f for f in res.findings if f.key == pid] == []


def test_run_header_detector_fires_on_missing_csp():
    pid = "exch_csp_missing_login"
    plugin = discover()[pid]()
    headers = {"content-type": "text/html",
               "strict-transport-security": "max-age=63072000",
               "x-frame-options": "DENY"}
    res = asyncio.run(plugin.run(_target(), _ctx("", headers)))
    hits = [f for f in res.findings if f.key == pid]
    assert len(hits) == 1


def test_run_header_detector_silent_with_csp():
    pid = "exch_csp_missing_login"
    plugin = discover()[pid]()
    headers = {"content-security-policy": "default-src 'self'",
               "strict-transport-security": "max-age=63072000",
               "x-frame-options": "DENY"}
    res = asyncio.run(plugin.run(_target(), _ctx("", headers)))
    assert [f for f in res.findings if f.key == pid] == []
