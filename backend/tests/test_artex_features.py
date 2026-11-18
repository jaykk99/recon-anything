"""Behavior tests for the ARTEX port (2026-11-17).

Five new plugins (origin_ip, auth_pages, dns_cache_snoop,
tls_vuln_inference, subdomain_risk) + the emails.py obfuscation
extension + reporting.dual_perspective_summary. Network-free: canned
DNS/HTTP/socket responses, generated certs, fake clocks.
"""
import asyncio
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
import pytest  # noqa: E402

from app.plugins import base  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.reporting import dual_perspective_summary  # noqa: E402


# ---------------------------------------------------------------------------
# Harness (same shape as tests/test_new_plugins.py)
# ---------------------------------------------------------------------------

def _resp(url, status=200, headers=None, text="", json_data=None):
    req = httpx.Request("GET", url)
    if json_data is not None:
        import json as _json
        return httpx.Response(status, headers=headers or {},
                              text=_json.dumps(json_data), request=req)
    return httpx.Response(status, headers=headers or {}, text=text,
                          request=req)


class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None

    async def cached(self, source, target, fn, ttl=None):
        return await fn(), False


class CtxStub:
    def __init__(self, pages=None, probe_map=None, shared=None):
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
        self.shared = dict(shared or {})
        self.pages = pages or {}
        self.probe_map = probe_map or {}

    def publish(self, kind, item):
        b = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in b:
                b.append(item)
        else:
            b.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url, timeout=10):
        return self.pages.get(url) or self.pages.get(url.rstrip("/"))

    async def probe(self, url, timeout=8):
        hit = self.probe_map.get(url) or self.probe_map.get(url.rstrip("/"))
        if hit is not None:
            return dict(hit)
        return {"status": 0, "headers": {}, "text": "", "url": url}


def _target(raw, ttype="domain"):
    return base.Target(raw=raw, type=ttype, normalized=raw)


def _plugin(pid):
    return discover()[pid]()


def _keys(res):
    return [f.key for f in res.findings]


# ---------------------------------------------------------------------------
# origin_ip
# ---------------------------------------------------------------------------

from app.plugins import origin_ip as _origin_mod  # noqa: E402


def test_cdn_provider_for():
    assert _origin_mod.cdn_provider_for("104.16.0.1") == "cloudflare"
    assert _origin_mod.cdn_provider_for("23.0.0.1") == "akamai"
    assert _origin_mod.cdn_provider_for("8.8.8.8") is None
    assert _origin_mod.cdn_provider_for("not-an-ip") is None


def test_is_potentially_real_ip():
    assert _origin_mod.is_potentially_real_ip("93.184.216.34") is True
    assert _origin_mod.is_potentially_real_ip("10.0.0.1") is False
    assert _origin_mod.is_potentially_real_ip("192.168.1.1") is False
    assert _origin_mod.is_potentially_real_ip("104.16.0.1") is False
    assert _origin_mod.is_potentially_real_ip("127.0.0.1") is False


class _FakeAnswer:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class _FakeMxAnswer(_FakeAnswer):
    def __init__(self, exchange):
        super().__init__(exchange)
        self.exchange = exchange


class _FakeResolver:
    """dns.asyncresolver.Resolver stand-in driven by a map."""
    instances = []

    def __init__(self, dns_map=None):
        self.dns_map = dns_map or {}
        self.lifetime = 5
        self.nameservers = []
        _FakeResolver.instances.append(self)

    async def resolve(self, host, rtype):
        key = (host.lower(), rtype)
        if key not in self.dns_map:
            import dns.resolver as _r
            raise _r.NXDOMAIN()
        return self.dns_map[key]


def _install_fake_dns(monkeypatch, dns_map):
    def _factory(*a, **k):
        return _FakeResolver(dns_map)
    monkeypatch.setattr("dns.asyncresolver.Resolver", _factory)


def test_origin_ip_finds_leaked_origin(monkeypatch):
    dns_map = {
        ("example.com", "A"): [_FakeAnswer("104.16.0.1")],  # Cloudflare
        ("example.com", "AAAA"): [],
        ("direct.example.com", "A"): [_FakeAnswer("93.184.216.34")],
        ("example.com", "MX"): [_FakeMxAnswer("mail.example.com.")],
        ("mail.example.com", "A"): [_FakeAnswer("93.184.216.34")],
        ("ct.example.com", "A"): [_FakeAnswer("93.184.216.34")],
    }
    _install_fake_dns(monkeypatch, dns_map)

    async def _fake_fetch(http, limiter, method, url, **kw):
        return _resp(url, json_data=[
            {"name_value": "ct.example.com"},
            {"name_value": "www.example.com"},
        ])
    monkeypatch.setattr(_origin_mod, "fetch", _fake_fetch)

    def _fake_create_connection(addr, timeout=None):
        class _Sock:
            def close(self):
                pass
        if addr[0] == "93.184.216.34":
            return _Sock()
        raise OSError("refused")
    monkeypatch.setattr("socket.create_connection", _fake_create_connection)

    pages = {"https://example.com/": {"status_code": 200,
                                      "headers": {"X-Real-IP": "93.184.216.34"},
                                      "text": "", "url": "https://example.com/"}}
    ctx = CtxStub(pages=pages,
                  shared={"subdomains": ["direct.example.com"]})
    res = asyncio.run(_plugin("origin_ip").run(_target("example.com"), ctx))
    assert res.status.value == "ok"
    assert _keys(res) == ["origin_ip_exposed"]
    f = res.findings[0]
    assert "93.184.216.34" in f.value
    # subdomains 3 + headers 8 + CT 4 + mail 10 + multi-method 5*4=20
    # + responds 10 = 55
    assert f.evidence["score"] == 55
    assert set(f.evidence["methods"]) == {"subdomains", "http_headers",
                                          "cert_transparency", "mail_servers"}
    assert f.evidence["responds"] is True
    assert f.bounty_value == "high"
    assert "93.184.216.34" in ctx.consume("origin_ips")


def test_origin_ip_skips_direct_host(monkeypatch):
    dns_map = {("example.com", "A"): [_FakeAnswer("93.184.216.34")],
               ("example.com", "AAAA"): []}
    _install_fake_dns(monkeypatch, dns_map)
    ctx = CtxStub()
    res = asyncio.run(_plugin("origin_ip").run(_target("example.com"), ctx))
    assert res.findings == []
    assert "does not appear" in res.reason


def test_origin_ip_below_threshold_is_silent(monkeypatch):
    # Only the subdomains method (score 3) and no TCP answer: < 8.
    dns_map = {
        ("example.com", "A"): [_FakeAnswer("104.16.0.1")],
        ("example.com", "AAAA"): [],
        ("direct.example.com", "A"): [_FakeAnswer("93.184.216.34")],
        ("example.com", "MX"): [],
    }
    _install_fake_dns(monkeypatch, dns_map)

    async def _fake_fetch(http, limiter, method, url, **kw):
        return _resp(url, json_data=[])
    monkeypatch.setattr(_origin_mod, "fetch", _fake_fetch)
    monkeypatch.setattr("socket.create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    ctx = CtxStub(pages={"https://example.com/": {"status_code": 200,
                                                  "headers": {}, "text": "",
                                                  "url": "https://example.com/"}},
                  shared={"subdomains": ["direct.example.com"]})
    res = asyncio.run(_plugin("origin_ip").run(_target("example.com"), ctx))
    assert res.findings == []


# ---------------------------------------------------------------------------
# auth_pages
# ---------------------------------------------------------------------------

from app.plugins import auth_pages as _auth_mod  # noqa: E402


def test_classify_auth_page():
    assert _auth_mod.classify_auth_page(
        '<form><input type="password" name="pw"></form>', "/login") == "login"
    assert _auth_mod.classify_auth_page(
        "Reset your password — enter your email address", "/forgot") == "reset"
    assert _auth_mod.classify_auth_page(
        "Welcome to our blog, read the news", "/blog") == ""
    assert _auth_mod.classify_auth_page("", "/login") == ""


def test_auth_pages_finds_login_reset_and_idp():
    probe_map = {
        "https://example.com/login": {
            "status": 200, "headers": {},
            "text": '<form><input type="password"></form>',
            "url": "https://example.com/login"},
        "https://example.com/forgot-password": {
            "status": 200, "headers": {},
            "text": "Forgot your password? Enter your email to reset it.",
            "url": "https://example.com/forgot-password"},
        "https://login.microsoftonline.com/example.com": {
            "status": 200, "headers": {}, "text": "Microsoft sign in",
            "url": "https://login.microsoftonline.com/example.com"},
    }
    ctx = CtxStub(probe_map=probe_map)
    # url target: web_base returns it verbatim (no HEAD probe), so the
    # probe URLs stay https:// as mapped above.
    target = base.Target(raw="https://example.com", type="url",
                         normalized="https://example.com")
    res = asyncio.run(_plugin("auth_pages").run(target, ctx))
    assert sorted(_keys(res)) == ["auth_provider", "login_page",
                                  "password_reset_page"]
    idp = [f for f in res.findings if f.key == "auth_provider"][0]
    assert idp.evidence["provider"] == "office365"
    assert idp.evidence["severity"] == "medium"


def test_auth_pages_all_404_is_silent():
    ctx = CtxStub(probe_map={})
    target = base.Target(raw="https://example.com", type="url",
                         normalized="https://example.com")
    res = asyncio.run(_plugin("auth_pages").run(target, ctx))
    assert res.findings == []


# ---------------------------------------------------------------------------
# dns_cache_snoop
# ---------------------------------------------------------------------------

from app.plugins import dns_cache_snoop as _snoop_mod  # noqa: E402


class _Clock:
    """Fake monotonic clock yielding a scripted sequence of times."""

    def __init__(self, times):
        self._it = iter(times)

    def __call__(self):
        return next(self._it)


def test_one_round_cached(monkeypatch):
    plugin = _snoop_mod.DnsCacheSnoopPlugin()
    # first 300ms, target 20ms, second 30ms -> cached
    monkeypatch.setattr(_snoop_mod, "_now",
                        _Clock([0.0, 0.3, 0.3, 0.32, 0.32, 0.35]))

    class _R:
        async def resolve(self, host, rtype):
            return []

    async def _go():
        return await plugin._one_round(_R(), "example.com")
    out = asyncio.run(_go())
    assert out is not None and out["cached"] is True


def test_one_round_not_cached(monkeypatch):
    plugin = _snoop_mod.DnsCacheSnoopPlugin()
    # second query still slow -> not cached
    monkeypatch.setattr(_snoop_mod, "_now",
                        _Clock([0.0, 0.3, 0.3, 0.32, 0.32, 0.57]))

    class _R:
        async def resolve(self, host, rtype):
            return []

    async def _go():
        return await plugin._one_round(_R(), "example.com")
    out = asyncio.run(_go())
    assert out is not None and out["cached"] is False


def test_one_round_too_fast_is_invalid(monkeypatch):
    plugin = _snoop_mod.DnsCacheSnoopPlugin()
    monkeypatch.setattr(_snoop_mod, "_now",
                        _Clock([0.0, 0.01, 0.01, 0.02, 0.02, 0.03]))

    class _R:
        async def resolve(self, host, rtype):
            return []

    async def _go():
        return await plugin._one_round(_R(), "example.com")
    assert asyncio.run(_go()) is None


def _snoop_run(monkeypatch, times):
    plugin = _snoop_mod.DnsCacheSnoopPlugin()
    monkeypatch.setattr(_snoop_mod, "_now", _Clock(times))

    async def _fake_ns(self, domain):
        return "1.2.3.4"
    monkeypatch.setattr(_snoop_mod.DnsCacheSnoopPlugin, "_first_ns_ip",
                        _fake_ns)

    class _R:
        lifetime = 8
        nameservers = ["1.2.3.4"]

        async def resolve(self, host, rtype):
            return []
    monkeypatch.setattr(_snoop_mod.DnsCacheSnoopPlugin, "_resolver",
                        lambda self, ns: _R())
    ctx = CtxStub()
    return asyncio.run(plugin.run(_target("example.com"), ctx))


def test_dns_cache_snoop_finds_caching_resolver(monkeypatch):
    # two rounds, both cached
    res = _snoop_run(monkeypatch, [0.0, 0.3, 0.3, 0.32, 0.32, 0.35,
                                   1.0, 1.3, 1.3, 1.31, 1.31, 1.33])
    assert _keys(res) == ["dns_cache_snoop"]
    assert res.findings[0].evidence["nameserver"] == "1.2.3.4"


def test_dns_cache_snoop_silent_when_not_cached(monkeypatch):
    res = _snoop_run(monkeypatch, [0.0, 0.3, 0.3, 0.32, 0.32, 0.57,
                                   1.0, 1.3, 1.3, 1.31, 1.31, 1.60])
    assert res.findings == []


# ---------------------------------------------------------------------------
# tls_vuln_inference
# ---------------------------------------------------------------------------

from app.plugins import tls_vuln_inference as _tls_mod  # noqa: E402


def _make_cert(key_bits=2048, sig_hash="sha256", with_aia=True,
               with_crl=True):
    """Build a real DER cert with cryptography (test-only helper)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537,
                                   key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         "example.com")])
    hash_alg = {"sha256": hashes.SHA256(), "sha1": hashes.SHA1(),
                "md5": hashes.MD5()}[sig_hash]
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
               .not_valid_after(datetime.datetime.now(datetime.timezone.utc)
                                + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                              critical=True))
    if with_aia:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.OID_OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example.com")),
            ]), critical=False)
    if with_crl:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        "http://crl.example.com/ca.crl")],
                    relative_name=None, reasons=None,
                    crl_issuer=None),
            ]), critical=False)
    cert = builder.sign(key, hash_alg)
    return cert.public_bytes(serialization.Encoding.DER)


def test_analyze_cert_reads_key_and_sig():
    der = _make_cert(key_bits=1024, sig_hash="sha256")
    info = _tls_mod.analyze_cert(der)
    assert info["key_size"] == 1024
    assert "RSA" in (info["key_type"] or "")
    assert info["sig_alg"].lower().startswith("sha256")
    assert info["ocsp_urls"] == ["http://ocsp.example.com"]
    assert info["has_crl_dp"] is True


def test_analyze_cert_bad_der_is_empty():
    assert _tls_mod.analyze_cert(b"not a cert") == {}


def test_infer_vulns_protocol_and_cipher():
    cert = {"key_size": 2048, "key_type": "RSAPublicKey",
            "sig_alg": "sha256WithRSAEncryption",
            "ocsp_urls": ["http://ocsp.example.com"], "has_crl_dp": True}
    specs = _tls_mod.infer_vulns("SSLv3", "ECDHE-RSA-AES256-SHA", cert, None)
    names = {s["name"] for s in specs}
    assert "poodle" in names and "drown" in names
    assert "ocsp_not_stapled" in names  # AIA present, nothing stapled
    specs = _tls_mod.infer_vulns("TLSv1", "ECDHE-RSA-DES-CBC3-SHA", cert, b"resp")
    names = {s["name"] for s in specs}
    assert "beast" in names and "sweet32" in names
    assert "ocsp_not_stapled" not in names  # stapled response present
    specs = _tls_mod.infer_vulns("TLSv1.3", "EXP-RC4-MD5", cert, None)
    names = {s["name"] for s in specs}
    assert "freak" in names and "logjam" in names


def test_infer_vulns_weak_key_and_sig():
    weak = {"key_size": 512, "key_type": "RSAPublicKey",
            "sig_alg": "sha256WithRSAEncryption",
            "ocsp_urls": [], "has_crl_dp": False}
    names = {s["name"] for s in
             _tls_mod.infer_vulns("TLSv1.2", "AES256-SHA", weak, None)}
    assert "weak_rsa_key" in names
    assert "ocsp_missing" in names and "crl_dp_missing" in names
    sha1 = {"key_size": 2048, "key_type": "RSAPublicKey",
            "sig_alg": "sha1WithRSAEncryption",
            "ocsp_urls": ["http://ocsp.example.com"], "has_crl_dp": True}
    names = {s["name"] for s in
             _tls_mod.infer_vulns("TLSv1.2", "AES256-SHA", sha1, None)}
    assert "weak_signature" in names
    assert "weak_key" not in names and "weak_rsa_key" not in names


def test_tls_vuln_run_end_to_end(monkeypatch):
    der = _make_cert(key_bits=2048, sig_hash="sha256")
    plugin = _tls_mod.TlsVulnInferencePlugin()
    monkeypatch.setattr(plugin, "_handshake", lambda host: {
        "version": "TLSv1", "cipher": "ECDHE-RSA-DES-CBC3-SHA",
        "der": der, "ocsp_response": None})
    res = asyncio.run(plugin.run(_target("example.com"), CtxStub()))
    names = {f.evidence["vuln"] for f in res.findings}
    assert names == {"beast", "sweet32", "ocsp_not_stapled"}
    assert all(f.evidence["severity"] in ("high", "low")
               for f in res.findings)


def test_tls_vuln_run_modern_clean(monkeypatch):
    der = _make_cert(key_bits=2048, sig_hash="sha256")
    plugin = _tls_mod.TlsVulnInferencePlugin()
    monkeypatch.setattr(plugin, "_handshake", lambda host: {
        "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
        "der": der, "ocsp_response": b"stapled"})
    res = asyncio.run(plugin.run(_target("example.com"), CtxStub()))
    assert res.findings == []


# ---------------------------------------------------------------------------
# subdomain_risk
# ---------------------------------------------------------------------------

from app.plugins import subdomain_risk as _risk_mod  # noqa: E402


def test_classify_subdomain_risk():
    c = _risk_mod.classify_subdomain_risk("admin.example.com")
    assert c["tier"] == "critical" and c["category"] == "admin"
    assert c["indicator"] == "admin_panels" and c["risk_score"] == 50
    c = _risk_mod.classify_subdomain_risk("db2.example.com")
    assert c["tier"] == "critical" and c["category"] == "database"
    assert c["indicator"] == "database_interfaces" and c["risk_score"] == 60
    c = _risk_mod.classify_subdomain_risk("api.example.com")
    assert c["tier"] == "high" and c["indicator"] == "api_endpoints"
    assert c["risk_score"] == 40
    c = _risk_mod.classify_subdomain_risk("dev01.example.com")
    assert c["tier"] == "high" and c["category"] == "development"
    assert c["risk_score"] == 45
    c = _risk_mod.classify_subdomain_risk("www.example.com")
    assert c["tier"] == "info"  # classified, but never a finding
    assert _risk_mod.classify_subdomain_risk("random.example.com") is None
    assert _risk_mod.classify_subdomain_risk("") is None


def test_response_anomaly():
    assert "plaintext-only" in _risk_mod.response_anomaly(200, 0)
    assert "503" in _risk_mod.response_anomaly(200, 503)
    assert _risk_mod.response_anomaly(200, 200) == ""
    assert _risk_mod.response_anomaly(0, 0) == ""


def test_subdomain_risk_run():
    subs = ["admin.example.com", "api.example.com", "www.example.com",
            "random.example.com"]
    probe_map = {}
    for s in subs:
        probe_map[f"https://{s}/"] = {"status": 200, "headers": {},
                                      "text": "", "url": f"https://{s}/"}
        probe_map[f"http://{s}/"] = {"status": 200, "headers": {},
                                     "text": "", "url": f"http://{s}/"}
    probe_map["https://api.example.com/"]["status"] = 500
    ctx = CtxStub(probe_map=probe_map, shared={"subdomains": subs})
    res = asyncio.run(_plugin("subdomain_risk").run(_target("example.com"),
                                                    ctx))
    assert len(res.findings) == 2
    # sorted by risk score desc: admin 50 first, api 40 second
    assert res.findings[0].value.startswith("admin.example.com")
    assert res.findings[0].evidence["risk_score"] == 50
    api = res.findings[1]
    assert api.evidence["https_status"] == 500
    assert "500" in api.evidence["anomaly"]
    assert "1 critical, 1 high" in res.reason


def test_subdomain_risk_empty_bus_no_crtsh(monkeypatch):
    async def _no_fetch(*a, **k):
        raise RuntimeError("no network in tests")
    monkeypatch.setattr(_risk_mod, "fetch", _no_fetch)
    ctx = CtxStub()
    res = asyncio.run(_plugin("subdomain_risk").run(_target("example.com"),
                                                    ctx))
    assert res.findings == []


# ---------------------------------------------------------------------------
# emails obfuscation
# ---------------------------------------------------------------------------

from app.plugins.emails import deobfuscate_emails  # noqa: E402
import app.plugins.emails as _emails_mod  # noqa: E402


def test_deobfuscate_emails():
    assert deobfuscate_emails(
        "Contact jane [at] example [dot] com for help") == ["jane@example.com"]
    assert deobfuscate_emails(
        "Write to bob(at)example(dot)org today") == ["bob@example.org"]
    assert deobfuscate_emails(
        "reach us at sales at example dot co dot uk") == ["sales@example.co.uk"]
    assert deobfuscate_emails(
        "JANE [AT] EXAMPLE [DOT] COM") == ["jane@example.com"]
    # prose must not match
    assert deobfuscate_emails("meet at noon, see you there") == []
    assert deobfuscate_emails("look at this dot the end") == []
    # dedupe + multiple
    assert deobfuscate_emails(
        "a [at] b [dot] com and a [at] b [dot] com") == ["a@b.com"]


def test_emails_plugin_finds_obfuscated(monkeypatch):
    async def _fake_fetch(http, limiter, method, url, **kw):
        if url.endswith("/contact"):
            return _resp(url, text="Email jane [at] example [dot] org")
        return _resp(url, text="nothing here")
    monkeypatch.setattr(_emails_mod, "fetch", _fake_fetch)
    monkeypatch.setattr("dns.asyncresolver.Resolver",
                        lambda *a, **k: (_ for _ in ()).throw(Exception("no dns")))
    ctx = CtxStub()
    target = base.Target(raw="https://example.org", type="url",
                         normalized="https://example.org")
    res = asyncio.run(_plugin("emails").run(target, ctx))
    found = [f for f in res.findings if f.key == "email_found"]
    assert len(found) == 1
    assert "jane@example.org" in found[0].value
    assert "obfuscated" in found[0].value


# ---------------------------------------------------------------------------
# reporting.dual_perspective_summary
# ---------------------------------------------------------------------------

def _row(key, plugin="p", category="web", value="v", severity="low",
         bounty="low", confidence=80, suppressed=False, remediation=""):
    return {"plugin": plugin, "category": category, "key": key,
            "value": value, "confidence": confidence,
            "bounty_value": bounty, "suppressed": suppressed,
            "evidence": {"severity": severity, "remediation": remediation}}


def test_dual_perspective_summary():
    rows = [
        _row("exposed_aws_key", severity="high", bounty="critical",
             value="AKIA...", remediation="Rotate the key."),
        _row("origin_ip_exposed", severity="high", bounty="high"),
        _row("tls_beast", severity="high", bounty="high"),
        _row("login_page", severity="low", bounty="low"),
        _row("stale", severity="low", bounty="low", suppressed=True),
    ]
    out = dual_perspective_summary(rows)
    # 20 (critical) + 10 + 10 (high) = 40, no volume bonus
    assert out["risk_score"] == 40
    assert out["risk_band"] == "medium"
    assert out["total_findings"] == 4
    assert out["suppressed"] == 1
    assert out["by_severity"] == {"high": 3, "medium": 0, "low": 1}
    assert out["owner"]["top_fixes"][0]["key"] == "exposed_aws_key"
    assert "Rotate the key." in out["owner"]["top_fixes"][0]["remediation"]
    assert out["hunter"]["top_categories"][0]["category"] == "web"
    assert any("Origin IP" in n
               for n in out["hunter"]["chaining_notes"])
    assert any("TLS" in n for n in out["hunter"]["chaining_notes"])


def test_dual_perspective_summary_empty():
    out = dual_perspective_summary([])
    assert out == {"risk_score": 0, "risk_band": "low", "total_findings": 0,
                   "suppressed": 0,
                   "by_severity": {"high": 0, "medium": 0, "low": 0},
                   "owner": {"headline": "0 live finding(s): 0 high, "
                             "0 medium, 0 low. Nothing actionable found.",
                             "top_fixes": []},
                   "hunter": {"headline": "Attack surface spans 0 "
                              "categor(ies): . No clear targets.",
                              "top_categories": [], "top_targets": [],
                              "chaining_notes": []}}


def test_registry_has_five_new_plugins():
    reg = discover()
    for pid in ("origin_ip", "auth_pages", "dns_cache_snoop",
                "tls_vuln_inference", "subdomain_risk"):
        assert pid in reg, f"missing plugin {pid}"
    assert len(reg) == 1470
