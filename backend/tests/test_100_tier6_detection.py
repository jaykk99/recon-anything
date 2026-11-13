"""Tier-6 Exploitation-tool DETECTION variants (100-plugin expansion).

Per shipped plugin: fires on the VULN fixture, silent on the CLEAN
fixture, no crash on malformed input. HTTP plugins run over an httpx
MockTransport modeling a vulnerable site on vuln.test and a hardened
one on clean.test. Socket-level plugins (msf_auxiliary, smb_ldap_enum,
netexec_enum, llmnr_detect) substitute their module transport with
canned protocol bytes - the REAL parsers and run() logic execute;
only the wire is fake (same approach as Tier-4's a2sv pure layer).

Duplicate-of tools get a behavior check against the EXISTING plugin:
  sqli_detect  -> sqli  (error + boolean + time + UNION already there)
  xss_detect   -> xss   (reflected canary + context analysis + DOM
                         sink scan already there)
Shipped: msf_auxiliary, command_injection_detect (echo-marker
remainder of Commix), smb_ldap_enum, netexec_enum, llmnr_detect,
nosqli_detect (JSON-body remainder of NoSQLMap),
deserialization_detect (MAC-posture/endpoint/input remainder of
Ysoserial), interactsh_oob (verified-only remainder of Interactsh).
"""
import asyncio
import json
import os
import re
import struct
import sys
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

NEW_IDS = ["msf_auxiliary", "command_injection_detect", "smb_ldap_enum",
           "netexec_enum", "llmnr_detect", "nosqli_detect",
           "deserialization_detect", "interactsh_oob"]
DUP_IDS = ["sqli", "xss"]

VULN = "vuln.test"
CLEAN = "clean.test"

VULN_HOME = """<html><head><title>Vuln Corp</title></head><body>
<h1>Vuln Corp</h1>
<form action="/login" method="post">
<input type="hidden" name="__VIEWSTATE" value="/wEPDwULLTE2MTY2ODcyMjkPZBYCZg9kFgICAw9kFgICAQ8WAh4EVGV4dA==">
</form>
<a href="/search?q=test">Search</a>
<a href="/item?id=1">Item</a>
<a href="/go?data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==">Open state</a>
<script>fetch("/api/v1/users");</script>
<script>var q = location.search;
document.getElementById('r').innerHTML = q;</script>
</body></html>"""

CLEAN_HOME = """<html><head><title>Clean Corp</title></head><body>
<h1>Clean Corp</h1>
<form action="/login" method="post">
<input type="hidden" name="__VIEWSTATE" value="/wEPDwULLTE2MTY2ODcyMjkPZA==">
<input type="hidden" name="__EVENTVALIDATION" value="/wEdAAEAAAD+/w==">
</form>
<a href="/search?q=test">Search</a>
<a href="/item?id=1">Item</a>
<script>fetch("/api/v1/users");</script>
</body></html>"""

NOT_FOUND = "<html><head><title>404</title></head><body>nf</body></html>"
FIXED = "<html><body>fixed response body, nothing reflected</body></html>"

def _handler(request: httpx.Request) -> httpx.Response:
    url = urlparse(str(request.url))
    host, path = url.hostname or "", url.path or "/"
    q = parse_qs(url.query)

    if host == "poll.test":
        # interactsh poll stand-in: /poll/<token> has one interaction,
        # /empty/... has none.
        if path.startswith("/poll/"):
            token = path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={"data": [{
                "protocol": "http", "full-id": f"{token}.oob.test",
                "remote-address": "192.0.2.9",
                "time-stamp": "2026-11-05T00:00:00Z"}]}, request=request)
        return httpx.Response(200, json={"data": []}, request=request)

    vuln = host == VULN
    if not vuln and host != CLEAN:
        return httpx.Response(404, content="", request=request)

    # --- WinRM challenge (netexec_enum) ---
    if url.port == 5985 and path == "/wsman":
        schemes = ("Basic realm=\"WINRM\", Negotiate"
                   if vuln else "Negotiate, Kerberos")
        return httpx.Response(401, headers={
            "WWW-Authenticate": schemes}, content="", request=request)

    if path in ("/", "/index.html"):
        return httpx.Response(200, request=request,
                              content=VULN_HOME if vuln else CLEAN_HOME)

    if vuln:
        if path == "/search":
            val = (q.get("q") or [""])[0]
            m = re.search(r"echo\s+(cmk[0-9a-f]+)", val)
            if m:
                # simulated shell execution: bare token on its own line
                return httpx.Response(
                    200, request=request,
                    content=f"<html>output:\n{m.group(1)}\n</html>")
            return httpx.Response(
                200, request=request,
                content=f"<html>results for: {val}</body></html>")
        if path == "/item":
            val = (q.get("id") or [""])[0]
            if "'" in val:
                return httpx.Response(
                    200, request=request,
                    content=("<html>You have an error in your SQL "
                             "syntax; check the manual that "
                             "corresponds to your MySQL server "
                             "version</html>"))
            return httpx.Response(200, request=request,
                                  content="<html>item page</html>")
        if path == "/api/v1/users":
            if request.method == "POST":
                try:
                    body = json.loads(request.content or b"{}")
                except Exception:
                    body = {}
                def _has_op(v):
                    return isinstance(v, dict) and \
                        any(str(k).startswith("$") for k in v)
                if any(_has_op(v) for v in body.values()):
                    return httpx.Response(200, json=[
                        {"id": 1, "user": "admin", "role": "root"},
                        {"id": 2, "user": "guest", "role": "none"}],
                        request=request)
                return httpx.Response(401, json={"error": "invalid"},
                                      request=request)
            return httpx.Response(200, json=[{"id": 1}], request=request)
        if path == "/invoker/JMXInvokerServlet":
            return httpx.Response(
                200, request=request,
                content="<html>JMXInvoker org.jboss.invoker</html>")
        return httpx.Response(404, content=NOT_FOUND, request=request)

    # clean host: fixed bodies, fixed API rejection - no differentials
    if path == "/api/v1/users" and request.method == "POST":
        return httpx.Response(400, json={"error": "bad request"},
                              request=request)
    if path in ("/search", "/item"):
        return httpx.Response(200, content=FIXED, request=request)
    return httpx.Response(404, content=NOT_FOUND, request=request)


def make_ctx(mode="active", shared=None):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_handler),
        follow_redirects=True, trust_env=False,
        headers={"User-Agent": "ReconAnything-Test/1.0"})
    ctx = Ctx(run_id="tier6-test", mode=mode, http=client,
              cache=Cache(), keys={},
              limiter=RateLimiter(default_rps=10000.0),
              evidence_dir="/tmp", source_type="website")
    if shared:
        for kind, items in shared.items():
            for item in items:
                ctx.publish(kind, item)
    return ctx


def run(cls, target, mode="active", shared=None):
    async def _go():
        ctx = make_ctx(mode=mode, shared=shared)
        try:
            return await cls().run(target, ctx)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def domain(name):
    return Target(raw=name, type="domain", normalized=name)


def keys_of(res):
    return {f.key for f in res.findings}


@pytest.fixture(autouse=True)
def _no_oob_env(monkeypatch):
    monkeypatch.delenv("INTERACTSH_DOMAIN", raising=False)
    monkeypatch.delenv("INTERACTSH_POLL_URL", raising=False)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_count_tier6():
    reg = discover()
    assert len(reg) == 1414, f"registry size {len(reg)}, expected 1414"
    for pid in NEW_IDS + DUP_IDS:
        assert pid in reg, f"{pid} missing from registry"


# ---------------------------------------------------------------------------
# DUPLICATE-OF: sqli_detect -> existing sqli; xss_detect -> existing xss
# ---------------------------------------------------------------------------

def test_dup_sqli_fires_on_vuln():
    from app.plugins.sqli import SqliPlugin
    res = run(SqliPlugin, domain(VULN))
    assert any(k.startswith("sqli") for k in keys_of(res)), keys_of(res)


def test_dup_sqli_silent_on_clean():
    from app.plugins.sqli import SqliPlugin
    res = run(SqliPlugin, domain(CLEAN))
    assert not any(k.startswith("sqli") for k in keys_of(res)), \
        keys_of(res)


def test_dup_xss_fires_on_vuln():
    from app.plugins.xss import XssPlugin
    res = run(XssPlugin, domain(VULN))
    assert res.findings, "existing xss plugin should fire on vuln"


def test_dup_xss_silent_on_clean():
    from app.plugins.xss import XssPlugin
    res = run(XssPlugin, domain(CLEAN))
    assert res.findings == [], keys_of(res)


# ---------------------------------------------------------------------------
# command_injection_detect (echo-marker remainder)
# ---------------------------------------------------------------------------

def test_cmdi_detect_fires_on_vuln():
    from app.plugins.command_injection_detect import \
        CommandInjectionDetectPlugin
    res = run(CommandInjectionDetectPlugin, domain(VULN))
    assert "cmdi_echo_marker" in keys_of(res), keys_of(res)


def test_cmdi_detect_silent_on_clean():
    from app.plugins.command_injection_detect import \
        CommandInjectionDetectPlugin
    res = run(CommandInjectionDetectPlugin, domain(CLEAN))
    assert res.findings == [], keys_of(res)


def test_cmdi_detect_malformed_no_crash():
    from app.plugins.command_injection_detect import \
        CommandInjectionDetectPlugin
    res = run(CommandInjectionDetectPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# nosqli_detect (JSON-body remainder)
# ---------------------------------------------------------------------------

def test_nosqli_detect_fires_on_vuln():
    from app.plugins.nosqli_detect import NosqliDetectPlugin
    res = run(NosqliDetectPlugin, domain(VULN))
    assert "nosqli_json_differential" in keys_of(res), keys_of(res)


def test_nosqli_detect_silent_on_clean():
    from app.plugins.nosqli_detect import NosqliDetectPlugin
    res = run(NosqliDetectPlugin, domain(CLEAN))
    assert res.findings == [], keys_of(res)


def test_nosqli_detect_malformed_no_crash():
    from app.plugins.nosqli_detect import NosqliDetectPlugin
    res = run(NosqliDetectPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# deserialization_detect
# ---------------------------------------------------------------------------

def test_deser_detect_fires_on_vuln():
    from app.plugins.deserialization_detect import \
        DeserializationDetectPlugin
    res = run(DeserializationDetectPlugin, domain(VULN))
    ks = keys_of(res)
    assert "viewstate_mac_disabled" in ks, ks
    assert "deser_endpoint_exposed" in ks, ks
    assert "deser_input_surface" in ks, ks


def test_deser_detect_silent_on_clean():
    from app.plugins.deserialization_detect import \
        DeserializationDetectPlugin
    res = run(DeserializationDetectPlugin, domain(CLEAN))
    assert res.findings == [], keys_of(res)


def test_deser_detect_malformed_no_crash():
    from app.plugins.deserialization_detect import \
        DeserializationDetectPlugin
    res = run(DeserializationDetectPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# interactsh_oob (verified-only)
# ---------------------------------------------------------------------------

def test_interactsh_skips_without_config():
    from app.plugins.interactsh_oob import InteractshOobPlugin
    res = run(InteractshOobPlugin, domain(VULN))
    assert res.findings == []
    assert "needs config" in res.reason


def test_interactsh_fires_on_verified_callback(monkeypatch):
    monkeypatch.setenv("INTERACTSH_DOMAIN", "oob.test")
    monkeypatch.setenv("INTERACTSH_POLL_URL",
                       "https://poll.test/poll/{token}")
    from app.plugins.interactsh_oob import InteractshOobPlugin
    res = run(InteractshOobPlugin, domain(VULN))
    assert "oob_interaction_verified" in keys_of(res), keys_of(res)


def test_interactsh_silent_when_no_interaction(monkeypatch):
    monkeypatch.setenv("INTERACTSH_DOMAIN", "oob.test")
    monkeypatch.setenv("INTERACTSH_POLL_URL",
                       "https://poll.test/empty/{token}")
    from app.plugins.interactsh_oob import InteractshOobPlugin
    res = run(InteractshOobPlugin, domain(VULN))
    assert res.findings == [], keys_of(res)


def test_interactsh_malformed_no_crash(monkeypatch):
    monkeypatch.setenv("INTERACTSH_DOMAIN", "oob.test")
    from app.plugins.interactsh_oob import InteractshOobPlugin
    res = run(InteractshOobPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# Canned protocol bytes for the socket-level plugins
# ---------------------------------------------------------------------------

def _smb1_neg_response(signing_mode=0x04, status=0):
    buf = bytearray(160)
    buf[0:4] = b"\x00\x00\x00\x9c"          # NetBIOS length (fake)
    buf[4:8] = b"\xffSMB"
    buf[8] = 0x72
    struct.pack_into("<I", buf, 9, status)
    buf[4 + 32] = 17                        # WordCount
    struct.pack_into("<H", buf, 4 + 33, 0)  # dialect index
    buf[4 + 35] = signing_mode              # security mode byte
    return bytes(buf)


def _smb2_neg_response(security_mode=0x01, status=0):
    buf = bytearray(4 + 64 + 64)
    buf[4:8] = b"\xfeSMB"
    struct.pack_into("<I", buf, 4 + 8, status)
    struct.pack_into("<H", buf, 4 + 64 + 2, security_mode)
    struct.pack_into("<H", buf, 4 + 64 + 4, 0x0202)  # dialect
    return bytes(buf)


def _smb1_session_response(status=0):
    buf = bytearray(64)
    buf[4:8] = b"\xffSMB"
    buf[8] = 0x73
    struct.pack_into("<I", buf, 9, status)
    return bytes(buf)


def _ldap_bind_response(result_code=0):
    return bytes([0x30, 0x0C, 0x02, 0x01, 0x01, 0x61, 0x07,
                  0x0A, 0x01, result_code, 0x04, 0x00, 0x04, 0x00])


def _ssh_auth_packet(methods):
    def s(b):
        return struct.pack(">I", len(b)) + b
    payload = bytes([51]) + s(methods.encode()) + b"\x00"
    pad = 8 - ((len(payload) + 5) % 8)
    if pad < 4:
        pad += 8
    return (struct.pack(">I", len(payload) + pad + 1) + bytes([pad])
            + payload + b"\x00" * pad)


def _rdp_response(protocol):
    return (b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02"
            + b"\x02\x00\x08\x00" + struct.pack("<I", protocol))


def _mssql_response(encryption):
    entries = bytes([0x00, 0x00, 9, 6, 0x01, 0x00, 15, 1, 0xFF])
    body = entries + b"\x0f\x00\x00\x00" + b"\x00\x00" \
        + bytes([encryption])
    return bytes([0x04, 0x01]) + struct.pack(">H", 8 + len(body)) \
        + b"\x00\x00\x01\x00" + body


# ---------------------------------------------------------------------------
# msf_auxiliary
# ---------------------------------------------------------------------------

def _patch_msf(monkeypatch, banners):
    import app.plugins.msf_auxiliary as mod

    async def fake_grab(host, port, greeting):
        return banners.get((host, port), "")
    monkeypatch.setattr(mod, "_grab_banner", fake_grab)


def test_msf_auxiliary_fires_on_vuln(monkeypatch):
    _patch_msf(monkeypatch, {
        (VULN, 22): "SSH-2.0-OpenSSH_5.3",
        (VULN, 21): "220 (vsFTPd 2.3.4)",
        (VULN, 25): "220 mail ESMTP Exim 4.91",
    })
    from app.plugins.msf_auxiliary import MsfAuxiliaryPlugin
    res = run(MsfAuxiliaryPlugin, domain(VULN))
    cves = {f.evidence.get("cve") for f in res.findings}
    assert "CVE-2011-2523" in cves, cves
    assert "CVE-2019-10149" in cves, cves


def test_msf_auxiliary_silent_on_clean(monkeypatch):
    _patch_msf(monkeypatch, {
        (CLEAN, 22): "SSH-2.0-OpenSSH_9.6",
        (CLEAN, 21): "220 ProFTPD Server",
        (CLEAN, 25): "220 mail ESMTP Exim 4.97",
    })
    from app.plugins.msf_auxiliary import MsfAuxiliaryPlugin
    res = run(MsfAuxiliaryPlugin, domain(CLEAN))
    assert res.findings == [], keys_of(res)


def test_msf_auxiliary_malformed_no_crash(monkeypatch):
    _patch_msf(monkeypatch, {})
    from app.plugins.msf_auxiliary import MsfAuxiliaryPlugin
    res = run(MsfAuxiliaryPlugin, domain(""))
    assert res.findings == []


def test_msf_auxiliary_pure_matcher():
    from app.plugins.msf_auxiliary import match_cves, parse_banner
    assert parse_banner("FTP", "220 (vsFTPd 2.3.4)") == \
        ("vsFTPd", "2.3.4")
    assert match_cves("vsFTPd", "2.3.4")[0]["cve"] == "CVE-2011-2523"
    assert match_cves("OpenSSH", "9.6") == []


# ---------------------------------------------------------------------------
# smb_ldap_enum
# ---------------------------------------------------------------------------

def _patch_smb(monkeypatch, vuln=True):
    import app.plugins.smb_ldap_enum as mod

    async def fake_exchange(host, port, payload, timeout=4.0):
        if host != VULN:
            # clean host: SMBv1 refused, signing required, bind denied
            if payload[:1] == b"\x30":
                return _ldap_bind_response(49)
            if b"\xfeSMB" in payload:
                return _smb2_neg_response(security_mode=0x03)
            return b""
        if payload[:1] == b"\x30":
            return _ldap_bind_response(0)
        if b"\xfeSMB" in payload:
            return _smb2_neg_response(security_mode=0x01)
        if b"\xffSMB" in payload:
            cmd = payload[payload.find(b"\xffSMB") + 4]
            if cmd == 0x73:
                return _smb1_session_response(0)
            return _smb1_neg_response()
        return b""
    monkeypatch.setattr(mod, "_tcp_exchange", fake_exchange)


def test_smb_ldap_fires_on_vuln(monkeypatch):
    _patch_smb(monkeypatch)
    from app.plugins.smb_ldap_enum import SmbLdapEnumPlugin
    res = run(SmbLdapEnumPlugin, domain(VULN))
    ks = keys_of(res)
    assert "smbv1_enabled" in ks, ks
    assert "smb_null_session" in ks, ks
    assert "smb_signing_not_required" in ks, ks
    assert "ldap_anonymous_bind" in ks, ks


def test_smb_ldap_silent_on_clean(monkeypatch):
    _patch_smb(monkeypatch, vuln=False)
    from app.plugins.smb_ldap_enum import SmbLdapEnumPlugin
    res = run(SmbLdapEnumPlugin, domain(CLEAN))
    assert res.findings == [], keys_of(res)


def test_smb_ldap_malformed_no_crash(monkeypatch):
    _patch_smb(monkeypatch)
    from app.plugins.smb_ldap_enum import SmbLdapEnumPlugin
    res = run(SmbLdapEnumPlugin, domain(""))
    assert res.findings == []


def test_smb_ldap_parsers_pure():
    from app.plugins.smb_ldap_enum import (
        parse_ldap_bind_response, parse_smb1_negotiate,
        parse_smb2_negotiate)
    assert parse_smb1_negotiate(_smb1_neg_response())["status"] == 0
    neg2 = parse_smb2_negotiate(_smb2_neg_response(0x01))
    assert neg2["signing_enabled"] and not neg2["signing_required"]
    assert parse_ldap_bind_response(_ldap_bind_response(0)) == 0
    assert parse_ldap_bind_response(_ldap_bind_response(49)) == 49
    assert parse_ldap_bind_response(b"garbage") is None


# ---------------------------------------------------------------------------
# netexec_enum
# ---------------------------------------------------------------------------

def _patch_netexec(monkeypatch, vuln=True):
    import app.plugins.netexec_enum as mod

    async def fake_exchange(host, port, payloads, timeout=4.0):
        if port == 22:
            methods = "publickey,password" if vuln else \
                "publickey,keyboard-interactive"
            return b"SSH-2.0-OpenSSH_8.9\r\n" + _ssh_auth_packet(methods)
        if port == 3389:
            return _rdp_response(0 if vuln else 2)
        if port == 1433:
            return _mssql_response(0x02 if vuln else 0x03)
        return b""
    monkeypatch.setattr(mod, "_tcp_exchange", fake_exchange)


def test_netexec_fires_on_vuln(monkeypatch):
    _patch_netexec(monkeypatch, vuln=True)
    from app.plugins.netexec_enum import NetexecEnumPlugin
    res = run(NetexecEnumPlugin, domain(VULN))
    ks = keys_of(res)
    assert "ssh_password_auth" in ks, ks
    assert "rdp_nla_not_required" in ks, ks
    assert "winrm_basic_auth_http" in ks, ks
    assert "mssql_encryption_not_required" in ks, ks


def test_netexec_silent_on_clean(monkeypatch):
    _patch_netexec(monkeypatch, vuln=False)
    from app.plugins.netexec_enum import NetexecEnumPlugin
    res = run(NetexecEnumPlugin, domain(CLEAN))
    assert res.findings == [], keys_of(res)


def test_netexec_malformed_no_crash(monkeypatch):
    _patch_netexec(monkeypatch)
    from app.plugins.netexec_enum import NetexecEnumPlugin
    res = run(NetexecEnumPlugin, domain(""))
    assert res.findings == []


# ---------------------------------------------------------------------------
# llmnr_detect
# ---------------------------------------------------------------------------

def _patch_llmnr(monkeypatch, vuln=True):
    import app.plugins.llmnr_detect as mod

    async def fake_resolve(host):
        return host

    async def fake_udp(ip, port, payload, timeout=2.5):
        if not vuln:
            return b""
        qid = struct.unpack(">H", payload[0:2])[0]
        return struct.pack(">HHHHHH", qid, 0x8400, 1, 1, 0, 0) \
            + payload[12:]
    monkeypatch.setattr(mod, "_resolve", fake_resolve)
    monkeypatch.setattr(mod, "_udp_query", fake_udp)


def test_llmnr_fires_on_vuln(monkeypatch):
    _patch_llmnr(monkeypatch, vuln=True)
    from app.plugins.llmnr_detect import LlmnrDetectPlugin
    res = run(LlmnrDetectPlugin, domain(VULN))
    ks = keys_of(res)
    assert "llmnr_enabled" in ks, ks
    assert "nbt_ns_enabled" in ks, ks
    assert "mdns_enabled" in ks, ks


def test_llmnr_silent_on_clean(monkeypatch):
    _patch_llmnr(monkeypatch, vuln=False)
    from app.plugins.llmnr_detect import LlmnrDetectPlugin
    res = run(LlmnrDetectPlugin, domain(CLEAN))
    assert res.findings == [], keys_of(res)


def test_llmnr_malformed_no_crash(monkeypatch):
    _patch_llmnr(monkeypatch)
    from app.plugins.llmnr_detect import LlmnrDetectPlugin
    res = run(LlmnrDetectPlugin, domain(""))
    assert res.findings == []
