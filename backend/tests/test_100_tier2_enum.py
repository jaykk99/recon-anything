"""Tier-2 (100-plugin expansion) enumeration plugins: fixture tests.

Per plugin: fires on VULN, silent on CLEAN, no crash on malformed
input. TCP plugins are tested through their injectable seams
(module-level resolve_ips / tcp_* / tls_probe names) plus a real
localhost-listener integration test on 127.0.0.1 with an ephemeral
port - localhost only, never an external address. HTTP plugins run
against the MockTransport fixture site (tests/plugin_fixtures.py).
"""
import asyncio
import os
import socket
import sys

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.plugins.base import Target  # noqa: E402
from app.plugins import (dirsearch as dirsearch_mod,  # noqa: E402
                         feroxbuster as ferox_mod,
                         gobuster as gobuster_mod,
                         httpx_probe as httpx_mod,
                         masscan as masscan_mod,
                         naabu as naabu_mod,
                         nmap_nse as nmap_mod,
                         rustscan as rustscan_mod,
                         tlsx as tlsx_mod,
                         zmap as zmap_mod)
from plugin_fixtures import make_fixture_ctx, url_target, domain_target  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _weird_target():
    return Target(raw="@@@", type="weird", normalized="@@")


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _listener(banner: bytes = b""):
    async def handle(reader, writer):
        try:
            if banner:
                writer.write(banner)
                await writer.drain()
            await asyncio.sleep(0.3)
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def _patch(mod, **kw):
    old = {}
    for k, v in kw.items():
        old[k] = getattr(mod, k)
        setattr(mod, k, v)
    return old


def _restore(mod, old):
    for k, v in old.items():
        setattr(mod, k, v)


async def _fake_resolve(host, cap=4):
    return ["127.0.0.1"]


def _fast_limiter():
    from app.ratelimit import RateLimiter
    return RateLimiter(default_rps=10000.0)


def _active_ctx():
    ctx = make_fixture_ctx(mode="active", seed=False)
    ctx.limiter = _fast_limiter()
    return ctx


def _clean_ctx(mode="active"):
    """Fixture ctx whose transport is a dead host (connect error)."""
    ctx = make_fixture_ctx(mode=mode, seed=False)

    def handler(request):
        raise httpx.ConnectError("no service", request=request)

    ctx.http = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                 follow_redirects=True, trust_env=False)
    ctx.limiter = _fast_limiter()
    return ctx


def _notfound_ctx(mode="active"):
    """Fixture ctx whose transport 404s everything (soft site)."""
    ctx = make_fixture_ctx(mode=mode, seed=False)

    def handler(request):
        return httpx.Response(404, content="<html>404 Not Found</html>",
                              headers={"Content-Type": "text/html"},
                              request=request)

    ctx.http = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                 follow_redirects=True, trust_env=False)
    ctx.limiter = _fast_limiter()
    return ctx


# ---------------------------------------------------------------- naabu
def test_naabu_fires_on_open_localhost_port():
    async def main():
        server, port = await _listener()
        old = _patch(naabu_mod, resolve_ips=_fake_resolve,
                     TOP_PORTS=[port, _closed_port()])
        try:
            plugin = naabu_mod.NaabuPlugin()
            res = await plugin.run(domain_target(),
                                   make_fixture_ctx(mode="active",
                                                    seed=False))
        finally:
            _restore(naabu_mod, old)
            server.close()
        return res
    res = _run(main())
    hits = [f for f in res.findings if f.key == "naabu_open_port"]
    assert len(hits) == 1 and "127.0.0.1" in hits[0].value


def test_naabu_silent_when_all_closed():
    async def main():
        old = _patch(naabu_mod, resolve_ips=_fake_resolve,
                     TOP_PORTS=[_closed_port(), _closed_port()])
        try:
            return await naabu_mod.NaabuPlugin().run(
                domain_target(), make_fixture_ctx(mode="active", seed=False))
        finally:
            _restore(naabu_mod, old)
    assert _run(main()).findings == []


def test_naabu_malformed_target_no_crash():
    res = _run(naabu_mod.NaabuPlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# --------------------------------------------------------------- masscan
def test_masscan_fires_on_open_localhost_port():
    async def main():
        server, port = await _listener(b"SSH-2.0-TestSrv\r\n")
        old = _patch(masscan_mod, resolve_ips=_fake_resolve,
                     WIDE_PORTS=[port, _closed_port()])
        try:
            res = await masscan_mod.MasscanPlugin().run(
                domain_target(), make_fixture_ctx(mode="active", seed=False))
        finally:
            _restore(masscan_mod, old)
            server.close()
        return res
    res = _run(main())
    hits = [f for f in res.findings if f.key == "masscan_open_port"]
    assert len(hits) == 1


def test_masscan_silent_when_all_closed():
    async def main():
        old = _patch(masscan_mod, resolve_ips=_fake_resolve,
                     WIDE_PORTS=[_closed_port()])
        try:
            return await masscan_mod.MasscanPlugin().run(
                domain_target(), make_fixture_ctx(mode="active", seed=False))
        finally:
            _restore(masscan_mod, old)
    assert _run(main()).findings == []


def test_masscan_malformed_target_no_crash():
    res = _run(masscan_mod.MasscanPlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# -------------------------------------------------------------- nmap_nse
def test_nmap_nse_banner_classification():
    info = nmap_mod.parse_banner_service(22, "SSH-2.0-OpenSSH_8.9p1\r\n")
    assert info["service"] == "ssh" and "OpenSSH" in info["product"]
    info = nmap_mod.parse_banner_service(80, "HTTP/1.1 200 OK\r\n\r\n")
    assert info["service"] == "http"
    info = nmap_mod.parse_banner_service(65000, "\x00\xff garbage")
    assert info["service"] == "unknown"  # no crash on binary garbage


def test_nmap_nse_fires_on_ssh_banner_listener():
    async def main():
        server, port = await _listener(b"SSH-2.0-OpenSSH_8.9\r\n")
        old = _patch(nmap_mod, resolve_ips=_fake_resolve,
                     PROBE_PORTS=[port])
        try:
            res = await nmap_mod.NmapNsePlugin().run(
                domain_target(), make_fixture_ctx(mode="active", seed=False))
        finally:
            _restore(nmap_mod, old)
            server.close()
        return res
    res = _run(main())
    hits = [f for f in res.findings if f.key == "nmap_service_version"]
    assert len(hits) == 1 and "ssh" in hits[0].value


def test_nmap_nse_silent_when_closed_and_malformed():
    async def main():
        old = _patch(nmap_mod, resolve_ips=_fake_resolve,
                     PROBE_PORTS=[_closed_port()])
        try:
            res = await nmap_mod.NmapNsePlugin().run(
                domain_target(), make_fixture_ctx(mode="active", seed=False))
        finally:
            _restore(nmap_mod, old)
        return res
    assert _run(main()).findings == []
    res = _run(nmap_mod.NmapNsePlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# ------------------------------------------------------------ httpx_probe
def test_httpx_probe_fires_on_fixture_site():
    res = _run(httpx_mod.HttpxProbePlugin().run(
        url_target(), make_fixture_ctx(mode="active", seed=False)))
    hits = [f for f in res.findings if f.key == "httpx_http_service"]
    assert hits and "Fixture Corp" in hits[0].value
    assert any("Apache" in str(f.evidence.get("tech")) or
               f.evidence.get("server") for f in hits)


def test_httpx_probe_silent_on_dead_host():
    res = _run(httpx_mod.HttpxProbePlugin().run(
        url_target(), _clean_ctx()))
    assert res.findings == []


def test_httpx_probe_malformed_target_no_crash():
    res = _run(httpx_mod.HttpxProbePlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# ------------------------------------------------------------------ tlsx
VALID_CERT = {"subject": "CN=fixture.test", "issuer": "CN=Fixture CA",
              "san": ["fixture.test", "www.fixture.test"],
              "not_before": "Jan  1 00:00:00 2026 GMT",
              "not_after": "Jan  1 00:00:00 2099 GMT",
              "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
              "self_signed": False}
EXPIRED_CERT = dict(VALID_CERT, not_after="Jan  1 00:00:00 2020 GMT",
                    self_signed=True, protocol="TLSv1")


def test_tlsx_classify_cert_pure():
    import datetime as dt
    now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
    assert tlsx_mod.classify_cert(VALID_CERT, now=now) == []
    issues = tlsx_mod.classify_cert(EXPIRED_CERT, now=now)
    assert "expired" in issues and "self_signed" in issues
    assert "weak_protocol" in issues
    assert tlsx_mod.classify_cert({}) == []
    assert tlsx_mod.classify_cert("not a dict") == []
    assert tlsx_mod.classify_cert({"not_after": "garbage"}) == []


def test_tlsx_fires_on_expired_self_signed_cert():
    old = _patch(tlsx_mod, tls_probe=lambda host, port=443, timeout=6.0:
                 EXPIRED_CERT if port == 443 else None)
    try:
        res = _run(tlsx_mod.TlsxPlugin().run(
            domain_target(), make_fixture_ctx(mode="active", seed=False)))
    finally:
        _restore(tlsx_mod, old)
    keys = {f.key for f in res.findings}
    assert "tlsx_certificate" in keys and "tlsx_expired" in keys
    assert "tlsx_self_signed" in keys


def test_tlsx_clean_cert_has_no_issue_findings():
    old = _patch(tlsx_mod, tls_probe=lambda host, port=443, timeout=6.0:
                 VALID_CERT if port == 443 else None)
    try:
        res = _run(tlsx_mod.TlsxPlugin().run(
            domain_target(), make_fixture_ctx(mode="active", seed=False)))
    finally:
        _restore(tlsx_mod, old)
    issue_keys = [f.key for f in res.findings if f.key != "tlsx_certificate"]
    assert issue_keys == []


def test_tlsx_no_tls_and_malformed():
    old = _patch(tlsx_mod, tls_probe=lambda host, port=443, timeout=6.0: None)
    try:
        res = _run(tlsx_mod.TlsxPlugin().run(
            domain_target(), make_fixture_ctx(mode="active", seed=False)))
    finally:
        _restore(tlsx_mod, old)
    assert res.findings == []
    res = _run(tlsx_mod.TlsxPlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


def test_tls_probe_decodes_real_localhost_cert(tmp_path):
    """tls_probe against a real local TLS server: subject/SAN/expiry
    must be populated (getpeercert() is {} under CERT_NONE, so the
    DER decode path is what is being proven here)."""
    import shutil
    import ssl
    import subprocess
    if not shutil.which("openssl"):
        return
    key = tmp_path / "k.pem"
    cert = tmp_path / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "365",
         "-subj", "/CN=localhost.test",
         "-addext", "subjectAltName=DNS:localhost.test,DNS:alt.test"],
        check=True, capture_output=True, timeout=30)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))

    async def main():
        async def handle(reader, writer):
            try:
                await asyncio.sleep(0.2)
            finally:
                writer.close()
        server = await asyncio.start_server(handle, "127.0.0.1", 0,
                                            ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        try:
            return await asyncio.to_thread(
                tlsx_mod.tls_probe, "127.0.0.1", port)
        finally:
            server.close()
    info = _run(main())
    assert info is not None
    assert "localhost.test" in info["subject"]
    assert "localhost.test" in info["san"]
    assert info["not_after"] and info["self_signed"]
    assert tlsx_mod.parse_cert_date(info["not_after"]) is not None


# ------------------------------------------------------------------ zmap
def test_zmap_fires_and_flags_partial_coverage():
    async def fake_state(ip, port, timeout=1.2):
        return "open" if ip == "127.0.0.1" else "closed"

    async def fake_resolve2(host, cap=8):
        return ["127.0.0.1", "127.0.0.2"]
    old = _patch(zmap_mod, resolve_ips=fake_resolve2, tcp_state=fake_state,
                 SWEEP_PORTS=[443])
    try:
        res = _run(zmap_mod.ZmapPlugin().run(
            domain_target(), make_fixture_ctx(mode="active", seed=False)))
    finally:
        _restore(zmap_mod, old)
    keys = {f.key for f in res.findings}
    assert "zmap_hit" in keys and "zmap_partial_coverage" in keys


def test_zmap_silent_when_nothing_answers_and_malformed():
    async def fake_state(ip, port, timeout=1.2):
        return "closed"
    old = _patch(zmap_mod, resolve_ips=_fake_resolve, tcp_state=fake_state)
    try:
        res = _run(zmap_mod.ZmapPlugin().run(
            domain_target(), make_fixture_ctx(mode="active", seed=False)))
    finally:
        _restore(zmap_mod, old)
    assert res.findings == []
    res = _run(zmap_mod.ZmapPlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# -------------------------------------------------------------- rustscan
def test_rustscan_fires_with_banner_on_localhost():
    async def main():
        server, port = await _listener(b"HELLO-SERVICE/1.2 ready\r\n")
        old = _patch(rustscan_mod, resolve_ips=_fake_resolve,
                     SCAN_PORTS=[port, _closed_port()])
        try:
            res = await rustscan_mod.RustscanPlugin().run(
                domain_target(), make_fixture_ctx(mode="active", seed=False))
        finally:
            _restore(rustscan_mod, old)
            server.close()
        return res
    res = _run(main())
    hits = [f for f in res.findings if f.key == "rustscan_open_port"]
    assert len(hits) == 1 and "HELLO-SERVICE" in hits[0].value


def test_rustscan_silent_when_closed_and_malformed():
    async def main():
        old = _patch(rustscan_mod, resolve_ips=_fake_resolve,
                     SCAN_PORTS=[_closed_port()])
        try:
            return await rustscan_mod.RustscanPlugin().run(
                domain_target(), make_fixture_ctx(mode="active", seed=False))
        finally:
            _restore(rustscan_mod, old)
    assert _run(main()).findings == []
    res = _run(rustscan_mod.RustscanPlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# ------------------------------------------------------------ feroxbuster
def test_feroxbuster_fires_on_fixture_site():
    res = _run(ferox_mod.FeroxbusterPlugin().run(
        url_target(), _active_ctx()))
    hits = [f for f in res.findings if f.key == "discovered_path"]
    assert hits, res.reason


def test_feroxbuster_silent_on_all_404_site():
    res = _run(ferox_mod.FeroxbusterPlugin().run(
        url_target(), _notfound_ctx()))
    assert [f for f in res.findings if f.key == "discovered_path"] == []


def test_feroxbuster_malformed_target_no_crash():
    res = _run(ferox_mod.FeroxbusterPlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# --------------------------------------------------------------- gobuster
def test_gobuster_fires_dir_and_dns_modes_on_fixture():
    async def fake_ips(name):
        return {"192.0.2.10"} if name == "www.fixture.test" else set()
    old = _patch(gobuster_mod, _dns_ips=fake_ips)
    try:
        res = _run(gobuster_mod.GobusterPlugin().run(
            url_target(), _active_ctx()))
    finally:
        _restore(gobuster_mod, old)
    keys = {f.key for f in res.findings}
    assert "hidden_path" in keys, res.reason
    assert "gobuster_dns_subdomain" in keys


def test_gobuster_dns_wildcard_answers_are_filtered():
    async def fake_ips(name):
        return {"192.0.2.99"}  # everything resolves to the same IPs
    old = _patch(gobuster_mod, _dns_ips=fake_ips)
    try:
        res = _run(gobuster_mod.GobusterPlugin().run(
            url_target(), _notfound_ctx()))
    finally:
        _restore(gobuster_mod, old)
    assert [f for f in res.findings
            if f.key == "gobuster_dns_subdomain"] == []


def test_gobuster_dns_fabricated_answers_are_suppressed():
    async def fake_ips(name):
        # intercepting resolver: every name resolves, each to a
        # distinct synthetic address (incl. the random baseline)
        return {f"198.18.0.{abs(hash(name)) % 200 + 1}"}
    old = _patch(gobuster_mod, _dns_ips=fake_ips)
    try:
        res = _run(gobuster_mod.GobusterPlugin().run(
            url_target(), _notfound_ctx()))
    finally:
        _restore(gobuster_mod, old)
    assert [f for f in res.findings
            if f.key == "gobuster_dns_subdomain"] == []
    assert "suppressed" in res.reason


def test_gobuster_silent_on_all_404_site():
    async def fake_ips(name):
        return set()
    old = _patch(gobuster_mod, _dns_ips=fake_ips)
    try:
        res = _run(gobuster_mod.GobusterPlugin().run(
            url_target(), _notfound_ctx()))
    finally:
        _restore(gobuster_mod, old)
    assert res.findings == []


def test_gobuster_malformed_target_no_crash():
    res = _run(gobuster_mod.GobusterPlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# -------------------------------------------------------------- dirsearch
def test_dirsearch_probe_list_expands_extensions():
    paths = dirsearch_mod.probe_paths()
    assert "backup.zip" in paths and "backup.bak" in paths
    assert ".env" in paths and len(paths) > 300
    assert len(paths) == len(set(paths))


def test_dirsearch_fires_on_fixture_backups_by_name_only():
    res = _run(dirsearch_mod.DirsearchPlugin().run(
        url_target(), _active_ctx()))
    hits = [f for f in res.findings if f.key == "dirsearch_path"]
    assert hits, res.reason
    # existence/status only: no backup contents in any finding value
    assert all("CREATE TABLE" not in f.value for f in hits)
    assert any("backup" in f.value or ".env" in f.value for f in hits)


def test_dirsearch_spa_fallback_fingerprint_filtered():
    plugin = dirsearch_mod.DirsearchPlugin()
    # SPA/catch-all baseline: random name -> 200, text/html, no size
    baseline = {"status": 200, "length": -1, "ctype": "text/html"}
    assert not plugin._is_hit(200, -1, baseline, "text/html")
    # a real archive has a different type fingerprint -> hit
    assert plugin._is_hit(200, -1, baseline, "application/zip")
    assert plugin._is_hit(200, 4096, baseline, "text/html")
    # classic soft-404 with matching size -> filtered
    sized = {"status": 200, "length": 512, "ctype": "text/html"}
    assert not plugin._is_hit(200, 512, sized, "text/html")
    assert not plugin._is_hit(404, -1, baseline, "text/html")


def test_dirsearch_silent_on_all_404_site():
    res = _run(dirsearch_mod.DirsearchPlugin().run(
        url_target(), _notfound_ctx()))
    assert res.findings == []


def test_dirsearch_malformed_target_no_crash():
    res = _run(dirsearch_mod.DirsearchPlugin().run(
        _weird_target(), make_fixture_ctx(mode="active", seed=False)))
    assert res.findings == []


# --------------------------------------------------------------- registry
def test_tier2_plugins_registered():
    from app.plugins.registry import discover
    reg = discover()
    for pid in ("naabu", "masscan", "nmap_nse", "httpx_probe", "tlsx",
                "zmap", "rustscan", "feroxbuster", "gobuster", "dirsearch"):
        assert pid in reg, pid
    assert len(reg) == 904
