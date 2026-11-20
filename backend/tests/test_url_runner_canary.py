"""Network-free URL canaries for the plugin runner.

A URL scan must keep collecting findings after its first hit and must
retain checkpointed evidence when a slow plugin reaches its time cap.
No outside system is contacted: httpx.MockTransport provides both URLs.
"""
import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import runner  # noqa: E402
from app.plugins.base import Ctx, Finding, Plugin, Target  # noqa: E402


class UrlCanary(Plugin):
    id = "url_canary"
    label = "URL canary"
    accepts = ["url"]
    timeout_s = 2

    def __init__(self, paths=("/",)):
        self.paths = paths

    async def run(self, target, ctx):
        found = []
        for path in self.paths:
            resp = await ctx.http.get(target.normalized.rstrip("/") + path)
            if resp.status_code == 200:
                found.append(Finding(
                    plugin_id=self.id, category="web",
                    key="canary_response", value=path,
                    source="mock-url", source_url=str(resp.url)))
                self._checkpoint(found)
        return self._ok(found)


class SlowAfterFinding(Plugin):
    id = "url_slow_checkpoint"
    label = "Slow URL canary"
    accepts = ["url"]
    timeout_s = 0.02

    async def run(self, target, ctx):
        first = Finding(
            plugin_id=self.id, category="web",
            key="checkpointed", value="first", source="mock-url",
            source_url=target.normalized)
        self._checkpoint([first])
        await asyncio.sleep(0.2)  # must hit the cap, without real IO
        return self._ok([first])


@pytest.mark.parametrize("url", [
    "https://canary.example.test", "http://canary.example.test",
])
def test_multiple_url_findings_continue_after_first(url, monkeypatch):
    events = []

    async def capture(_run_id, name, payload):
        events.append((name, payload))

    monkeypatch.setattr(runner, "_emit", capture)
    requests = []

    def handler(request):
        requests.append(str(request.url))
        return httpx.Response(
            200 if request.url.path in ("/", "/one", "/two") else 404,
            text="canary response")

    async def scan():
        async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler),
                trust_env=False) as http:
            ctx = Ctx(run_id="canary-url", mode="passive",
                      http=http, cache=None, keys={})
            target = Target(raw=url, type="url", normalized=url)
            first = await runner._run_plugin(UrlCanary(("/",)), target, ctx)
            more = await runner._run_plugin(
                UrlCanary(("/one", "/two")), target, ctx)
            return first, more

    first, more = asyncio.run(scan())
    assert len(first.findings) == 1
    assert len(more.findings) == 2
    assert len(requests) == 3
    assert all(u.startswith(url + "/") for u in requests)
    done = [payload for name, payload in events if name == "plugin_done"]
    assert [d["findings"] for d in done] == [1, 2]


def test_timeout_keeps_first_url_finding_and_other_checks_continue(monkeypatch):
    events = []

    async def capture(_run_id, name, payload):
        events.append((name, payload))

    monkeypatch.setattr(runner, "_emit", capture)

    async def scan():
        async with httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda req: httpx.Response(200, text="ok")),
                trust_env=False) as http:
            ctx = Ctx(run_id="canary-timeout", mode="passive",
                      http=http, cache=None, keys={})
            target = Target(raw="https://canary.example.test",
                            type="url")
            partial = await runner._run_plugin(SlowAfterFinding(), target, ctx)
            next_result = await runner._run_plugin(
                UrlCanary(("/two",)), target, ctx)
            return partial, next_result

    partial, next_result = asyncio.run(scan())
    assert len(partial.findings) == 1
    assert "partial results" in partial.reason
    assert len(next_result.findings) == 1
    assert [payload["partial_findings"] for name, payload in events
            if name == "plugin_timeout"] == [1]


def test_loopback_http_url_continues_after_first_finding(monkeypatch):
    """Real local TCP/HTTP, not a mocked transport or an external scan."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"local canary"
            self.send_response(200 if self.path in ("/", "/one", "/two") else 404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    async def capture(*_args):
        pass

    monkeypatch.setattr(runner, "_emit", capture)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"

    async def scan():
        async with httpx.AsyncClient(timeout=3, trust_env=False) as http:
            ctx = Ctx(run_id="canary-loopback", mode="passive",
                      http=http, cache=None, keys={})
            target = Target(raw=url, type="url", normalized=url)
            first = await runner._run_plugin(UrlCanary(("/",)), target, ctx)
            second = await runner._run_plugin(
                UrlCanary(("/one", "/two")), target, ctx)
            return first, second

    try:
        first, second = asyncio.run(scan())
        assert [len(first.findings), len(second.findings)] == [1, 2]
        assert {f.source_url for f in first.findings + second.findings} == {
            url + "/", url + "/one", url + "/two"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
