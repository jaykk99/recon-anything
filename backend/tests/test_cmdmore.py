"""Tests for the 2026-10-26 command-tools pack 2 plugins.

Network-free: _exec is stubbed, so no real command runs. The live
canary (real commands, real pipeline, local fixtures) is the proof
these tests support, not a replacement for it.
"""
import asyncio
import os
import sys

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


def test_cmdmore_host_validation_rejects_shell_metachars(monkeypatch):
    calls = []

    async def fake_exec(argv, timeout_s):
        calls.append(argv)
        return 0, "", ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdDnsRecursePlugin(), "example.com; rm -rf /")
    assert res.findings == []
    assert calls == [], "crafted target must never reach a command line"


def _dig_ns_fake(ns_map):
    """Fake dig: NS discovery + per-@server answers from ns_map."""
    async def fake_exec(argv, timeout_s):
        if argv[0] == "dig" and argv[1] == "-v":
            return 0, "DiG 9.18\n", ""
        if argv[0] == "dig" and argv[-1] == "NS":
            return 0, "".join(f"{ns}.\n" for ns in ns_map), ""
        if argv[0] == "dig":
            for arg in argv:
                if arg.startswith("@"):
                    ns = arg[1:]
                    if argv[-1] == "A":
                        return 0, ns_map.get(ns, ("", ""))[0], ""
                    if argv[-1] == "SOA":
                        return 0, ns_map.get(ns, ("", ""))[1], ""
        return 0, "", ""

    return fake_exec


def test_cmd_dns_recurse_fires_on_open_resolver(monkeypatch):
    ns_map = {
        "ns1.canary.test": ("93.184.216.34\n", ""),
        "ns2.canary.test": ("", ""),
    }
    monkeypatch.setattr(cmd, "_exec", _dig_ns_fake(ns_map))
    res = _run(cmd.CmdDnsRecursePlugin(), "canary.test")
    found = [f for f in res.findings if f.key == "open_resolver"]
    assert len(found) == 1
    assert "ns1.canary.test" in found[0].value
    assert found[0].evidence["severity"] == "medium"


def test_cmd_dns_recurse_skips_when_no_dig(monkeypatch):
    async def fake_exec(argv, timeout_s):
        return None

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdDnsRecursePlugin(), "canary.test")
    assert res.findings == [] and "dig not available" in res.reason


def test_cmd_dns_nscheck_lame_and_serial_mismatch(monkeypatch):
    soa1 = "ns1.canary.test. admin.canary.test. 2026102601 7200 3600 1209600 3600\n"
    soa2 = "ns2.canary.test. admin.canary.test. 2026102602 7200 3600 1209600 3600\n"
    ns_map = {
        "ns1.canary.test": ("", soa1),
        "ns2.canary.test": ("", soa2),
        "ns3.canary.test": ("", ""),
    }
    monkeypatch.setattr(cmd, "_exec", _dig_ns_fake(ns_map))
    res = _run(cmd.CmdDnsNscheckPlugin(), "canary.test")
    keys = {f.key for f in res.findings}
    assert "dns_lame_delegation" in keys
    assert "dns_serial_mismatch" in keys
    lame = [f for f in res.findings if f.key == "dns_lame_delegation"][0]
    assert "ns3.canary.test" in lame.value
    mismatch = [f for f in res.findings if f.key == "dns_serial_mismatch"][0]
    assert "2026102601" in mismatch.value and "2026102602" in mismatch.value


def test_cmd_dns_nscheck_consistent_ok(monkeypatch):
    soa = "ns1.canary.test. admin.canary.test. 2026102601 7200 3600 1209600 3600\n"
    ns_map = {"ns1.canary.test": ("", soa), "ns2.canary.test": ("", soa)}
    monkeypatch.setattr(cmd, "_exec", _dig_ns_fake(ns_map))
    res = _run(cmd.CmdDnsNscheckPlugin(), "canary.test")
    assert res.findings == [] and "consistently" in res.reason


def test_cmd_ocsp_no_stapling(monkeypatch):
    out = ("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
           "OCSP response:\n======================================\n"
           "no response sent\n")

    async def fake_exec(argv, timeout_s):
        assert "-status" in argv
        return 0, out, ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdOcspPlugin(), "example.com")
    found = [f for f in res.findings if f.key == "tls_ocsp_no_stapling"]
    assert len(found) == 1


def test_cmd_ocsp_stapled_successful(monkeypatch):
    out = ("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
           "OCSP response:\n======================================\n"
           "OCSP Response Data:\n"
           "    OCSP Response Status: successful (0x0)\n"
           "    Cert Status: good\n")

    async def fake_exec(argv, timeout_s):
        return 0, out, ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdOcspPlugin(), "example.com")
    found = [f for f in res.findings if f.key == "tls_ocsp_stapled"]
    assert len(found) == 1
    assert "good" in found[0].value


def test_cmd_ocsp_skips_when_no_openssl(monkeypatch):
    async def fake_exec(argv, timeout_s):
        return None

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdOcspPlugin(), "example.com")
    assert res.findings == [] and "openssl not available" in res.reason


def test_cmd_ocsp_skips_when_no_handshake(monkeypatch):
    async def fake_exec(argv, timeout_s):
        return 0, "connect: Connection refused\n", ""

    monkeypatch.setattr(cmd, "_exec", fake_exec)
    res = _run(cmd.CmdOcspPlugin(), "example.com")
    assert res.findings == [] and "could not complete" in res.reason
