"""Tests for the 2026-10-26 command-tools plugins + service API uncapping.

Network-free: _exec is stubbed, so no real command runs. The live
canary (real commands, real pipeline) is the proof these tests support,
not a replacement for it.
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import app.plugins.cmdtools as cmd  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402


class _CtxStub:
    run_id = "test"
    mode = "passive"
    http = None
    cache = None
    keys = {}
    limiter = None
    emit = None
    module_overrides = {}
    evidence_dir = "/tmp"
    source_type = "website"
    shared = {}

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))


def _run(plugin, target, ttype="domain"):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        plugin.run(Target(raw=target, type=ttype, normalized=target),
                   _CtxStub()))


def test_host_validation_rejects_shell_metachars(monkeypatch):
    calls = []

    async def fake_exec(argv, timeout_s):
        calls.append(argv)
        return 0, "", ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    p = cmd.CmdDnsPlugin()
    res = _run(p, "example.com; rm -rf /")
    assert res.status.value == "ok" and res.findings == []
    assert calls == [], "crafted target must never reach a command line"


def test_cmd_dns_parses_dig_output(monkeypatch):
    async def fake_exec(argv, timeout_s):
        if argv[0] == "dig" and argv[-1] in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"):
            return 0, {"A": "93.184.216.34\n", "MX": "10 mail.example.com.\n"}.get(argv[-1], ""), ""
        if argv[0] == "dig" and argv[1] == "-v":
            return 0, "DiG 9.18\n", ""
        if argv[0] == "dig" and "-x" in argv:
            return 0, "example.com.\n", ""
        return 0, "", ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdDnsPlugin(), "example.com")
    keys = {(f.key, f.value) for f in res.findings}
    assert ("a", "93.184.216.34") in keys
    assert ("mx", "10 mail.example.com.") in keys
    assert ("ptr", "example.com.") in keys


def test_cmd_dns_skips_when_no_tool(monkeypatch):
    async def fake_exec(argv, timeout_s):
        return None

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdDnsPlugin(), "example.com")
    assert res.findings == [] and "no DNS command tool" in res.reason


def test_cmd_tls_parses_cert(monkeypatch):
    pem = ("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
    sclient = (f"New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n{pem}\n")

    async def fake_exec(argv, timeout_s):
        if argv[0] == "openssl" and "-tls1" in argv:
            return 0, "alert handshake failure", ""
        if argv[0] == "openssl" and "-tls1_1" in argv:
            return 0, "alert handshake failure", ""
        return 0, sclient, ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    # Stub the x509 child process: patch create_subprocess_exec is heavy;
    # instead verify the handshake-level findings parse from s_client.
    res = _run(cmd.CmdTlsPlugin(), "example.com")
    keys = {f.key for f in res.findings}
    assert "tls_protocol" in keys and "tls_cipher" in keys
    assert not any(f.key == "weak_tls_version" for f in res.findings)


def test_cmd_http_parses_redirect_chain(monkeypatch):
    out = ("HTTP/1.1 200 Connection established\r\n\r\n"
           "HTTP/2 301\r\nServer: cloudflare\r\n\r\n"
           "HTTP/2 200\r\nServer: cloudflare\r\n\r\n"
           "CURL_META 200 0.42 https://example.com/")

    async def fake_exec(argv, timeout_s):
        return 0, out, ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdHttpPlugin(), "https://example.com", "url")
    hops = [f for f in res.findings if f.key == "http_hop"]
    assert len(hops) == 2, "proxy CONNECT line must not count as a hop"
    assert any(f.key == "server_banner" for f in res.findings)
    assert any(f.key == "http_final" for f in res.findings)


def test_cmd_http_000_is_a_skip_not_a_finding(monkeypatch):
    out = "HTTP/1.1 200 Connection established\r\n\r\nCURL_META 000 15.00 https://example.com/"

    async def fake_exec(argv, timeout_s):
        return 0, out, ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdHttpPlugin(), "https://example.com", "url")
    assert res.findings == [] and "could not complete" in res.reason


def test_cmd_ports_reports_open_and_banner(monkeypatch):
    async def fake_exec(argv, timeout_s):
        if argv[0] == "nc":
            return 0, "SSH-2.0-OpenSSH_9.0\r\n", ""
        return None

    monkeypatch.setattr(cmd, "_exec", fake_exec)

    async def fake_conn(host, port):
        class W:
            def close(self):
                pass

        class R:
            async def read(self, n):
                return b"SSH-2.0-OpenSSH_9.0\r\n"

        return R(), W()

    async def fake_wait_for(coro, timeout):
        return await coro

    monkeypatch.setattr(asyncio, "open_connection", fake_conn)
    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)
    monkeypatch.setattr(cmd.socket, "getaddrinfo",
                        lambda *a: [("AF_INET", None, None, None, ("93.184.216.34", 0))])
    res = _run(cmd.CmdPortsPlugin(), "example.com")
    assert any(f.key == "open_port" and ":22 " in f.value for f in res.findings)
    assert any(f.key == "service_banner" and "OpenSSH" in f.value for f in res.findings)


def test_cmd_smtp_quits_without_mailing(monkeypatch):
    async def fake_exec(argv, timeout_s):
        if argv[0] == "dig":
            return 0, "10 mail.example.com.\n", ""
        return 0, "", ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)

    written = []

    async def fake_conn(host, port):
        class W:
            def write(self, data):
                written.append(data)

            async def drain(self):
                pass

            def close(self):
                pass

        class R:
            async def read(self, n):
                return b"220 mail.example.com ESMTP\r\n"

        return R(), W()

    async def fake_wait_for(coro, timeout):
        return await coro

    monkeypatch.setattr(asyncio, "open_connection", fake_conn)
    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)
    res = _run(cmd.CmdSmtpPlugin(), "example.com")
    assert any(f.key == "smtp_banner" for f in res.findings)
    assert written == [b"QUIT\r\n"], "only QUIT may ever be sent, never mail"


# ---------------------------------------------------------------------------
# Service API uncapping: 250 findings must all come back (was rows[:200]).
# ---------------------------------------------------------------------------

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ["RECON_SERVICE_KEY"] = "canary-test-key"
os.environ["ACCESS_CODE"] = ""

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Finding, Run, get_session, init_db  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    s = get_session()
    try:
        s.query(Finding).delete()
        s.query(Run).delete()
        s.add(Run(id="svc-cap-run", mode="passive", status="done",
                  source_type="website", summary={"service": True}))
        for i in range(250):
            s.add(Finding(run_id="svc-cap-run", target_id="t",
                          plugin_id="p", category="web", key="k",
                          value=f"finding-{i}", source="test"))
        s.commit()
    finally:
        s.close()
    with TestClient(app) as c:
        yield c


def test_service_api_returns_full_finding_set(client):
    r = client.get("/api/service/scans/svc-cap-run",
                   headers={"X-Recon-Service-Key": "canary-test-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["findings_count"] == 250
    assert body["findings_returned"] == 250
    assert len(body["findings"]) == 250


def test_service_api_pages_through_full_set(client):
    r = client.get("/api/service/scans/svc-cap-run?limit=100&offset=200",
                   headers={"X-Recon-Service-Key": "canary-test-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["findings_count"] == 250
    assert len(body["findings"]) == 50
    assert body["findings"][0]["value"] == "finding-200"
