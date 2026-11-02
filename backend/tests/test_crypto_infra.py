"""Tests for crypto_infra: live-infra grading logic, network mocked.

No live network anywhere: _tcp_open, _rpc_call, _get_json and
collect_texts are monkeypatched with canned answers, and the pure
helpers (module grading, key extraction, harvesting, CORS grading)
are exercised directly on fixtures.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.plugins import crypto_infra as ci  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402


def _ctx(mode="active"):
    return Ctx(run_id="test", mode=mode, http=None, cache=Cache(),
               keys={}, limiter=None, evidence_dir="/tmp")


# ---------------- pure: module grading ----------------

def test_grade_modules_admin_is_critical():
    grades = ci.grade_modules(["eth", "net", "web3", "admin"])
    assert grades == [("admin", "critical")]
    assert ci.worst_severity(grades) == "critical"


def test_grade_modules_personal_and_miner_critical():
    grades = dict(ci.grade_modules(["personal", "miner", "eth"]))
    assert grades == {"personal": "critical", "miner": "critical"}


def test_grade_modules_debug_txpool_clique_high():
    grades = dict(ci.grade_modules(["debug", "txpool", "clique"]))
    assert grades == {"debug": "high", "txpool": "high",
                      "clique": "high"}
    assert ci.worst_severity(list(grades.items())) == "high"


def test_grade_modules_clean_set_is_empty():
    assert ci.grade_modules(["eth", "net", "web3"]) == []
    assert ci.grade_modules([]) == []
    assert ci.worst_severity([]) is None


# ---------------- pure: key-in-URL extraction ----------------

def test_extract_key_infura_v3():
    url = "https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef"
    assert ci.extract_key_from_rpc_url(url) == \
        "0123456789abcdef0123456789abcdef"


def test_extract_key_alchemy_v2():
    url = "https://eth-mainnet.g.alchemy.com/v2/AbC123xYz-KEY_token987654"
    assert ci.extract_key_from_rpc_url(url) == "AbC123xYz-KEY_token987654"


def test_extract_key_userinfo():
    url = "https://nodeuser:nodepass123@rpc.example.com:8545/"
    assert ci.extract_key_from_rpc_url(url) == "nodeuser:nodepass123"


def test_extract_key_query_param():
    url = "https://rpc.example.com/?api_key=deadbeefcafe1234"
    assert ci.extract_key_from_rpc_url(url) == "deadbeefcafe1234"


def test_extract_key_ankr_style_trailing_token():
    tok = "a" * 64
    url = f"https://rpc.ankr.com/eth/{tok}"
    assert ci.extract_key_from_rpc_url(url) == tok


def test_extract_key_none_for_plain_endpoints():
    assert ci.extract_key_from_rpc_url(
        "https://ethereum.publicnode.com") is None
    assert ci.extract_key_from_rpc_url(
        "https://rpc.example.com:8545/") is None
    assert ci.extract_key_from_rpc_url(
        "https://mainnet.infura.io/v3/YOUR_PROJECT_ID") is None


# ---------------- pure: harvesting ----------------

_TEXTS = [
    ("page", """
     <script>
       const A = "https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef";
       const B = "https://rpc.example.com";
       const C = "wss://node.example.com:8546";
       const D = "https://api.mainnet-beta.solana.com";
       const E = "https://example.com/about";
       const F = "https://cdn.other-example.net/lib.js";
       const G = "https://example.com/team";
     </script>""", "https://example.com/"),
]


def test_harvest_endpoints_classifies():
    eps = ci.harvest_endpoints(_TEXTS, "example.com")
    by_url = {e["url"]: e for e in eps}
    assert "https://example.com/about" not in by_url
    assert "https://example.com/team" not in by_url
    assert "https://cdn.other-example.net/lib.js" not in by_url
    infura = by_url[
        "https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef"]
    assert infura["provider"] is True
    assert infura["key"] == "0123456789abcdef0123456789abcdef"
    own = by_url["https://rpc.example.com"]
    assert own["self_hosted"] is True and own["provider"] is False
    ws = by_url["wss://node.example.com:8546"]
    assert ws["self_hosted"] is True
    sol = by_url["https://api.mainnet-beta.solana.com"]
    assert sol["solana"] is True


# ---------------- pure: CORS grading ----------------

def test_grade_cors_wildcard():
    assert ci.grade_cors("*", None, ci.EVIL_ORIGIN) == \
        ("rpc_cors_wildcard", "medium")
    assert ci.grade_cors("*", "true", ci.EVIL_ORIGIN) == \
        ("rpc_cors_wildcard", "high")


def test_grade_cors_reflected():
    assert ci.grade_cors(ci.EVIL_ORIGIN, None, ci.EVIL_ORIGIN) == \
        ("rpc_cors_reflected", "medium")
    assert ci.grade_cors(ci.EVIL_ORIGIN, "true", ci.EVIL_ORIGIN) == \
        ("rpc_cors_reflected", "high")


def test_grade_cors_no_grant():
    assert ci.grade_cors(None, None, ci.EVIL_ORIGIN) is None
    assert ci.grade_cors("https://example.com", None,
                         ci.EVIL_ORIGIN) is None


# ---------------- ports plugin with mocked sockets ----------------

def _patch_rpc(monkeypatch, answers, headers=None):
    async def fake_rpc(ctx, url, method, params=None, origin=None,
                       timeout=6.0):
        return answers.get(method), (headers or {})
    monkeypatch.setattr(ci, "_rpc_call", fake_rpc)


def test_ports_plugin_evm_open_with_admin(monkeypatch):
    async def fake_tcp(host, port, timeout=2.5):
        return port == 8545
    monkeypatch.setattr(ci, "_tcp_open", fake_tcp)
    _patch_rpc(monkeypatch, {
        "web3_clientVersion": "Geth/v1.13.0-stable/linux",
        "rpc_modules": {"eth": "1.0", "net": "1.0", "web3": "1.0",
                        "admin": "1.0", "debug": "1.0"},
        "eth_chainId": "0x1",
    })
    plugin = ci.CryptoInfraPortsPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(plugin.run(target, _ctx()))
    keys = [f.key for f in res.findings]
    assert keys.count("node_rpc_port_open") == 1  # only 8545 open
    danger = [f for f in res.findings
              if f.key == "rpc_dangerous_modules"]
    assert len(danger) == 1
    assert "CRITICAL" in danger[0].value
    assert "admin" in danger[0].evidence["all_modules"]
    assert danger[0].evidence["client_version"].startswith("Geth/")
    opened = [f for f in res.findings if f.key == "node_rpc_port_open"]
    assert opened[0].evidence["port"] == 8545


def test_ports_plugin_all_closed_no_findings(monkeypatch):
    async def fake_tcp(host, port, timeout=2.5):
        return False
    monkeypatch.setattr(ci, "_tcp_open", fake_tcp)
    _patch_rpc(monkeypatch, {})
    plugin = ci.CryptoInfraPortsPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(plugin.run(target, _ctx()))
    assert res.findings == []


def test_ports_plugin_tendermint_status(monkeypatch):
    async def fake_tcp(host, port, timeout=2.5):
        return port == 26657
    monkeypatch.setattr(ci, "_tcp_open", fake_tcp)

    async def fake_get(ctx, url, timeout=6.0):
        return ({"result": {"node_info": {
            "id": "abc123", "network": "fixture-1",
            "version": "0.38.0", "moniker": "fixture-validator"}}}, 200)
    monkeypatch.setattr(ci, "_get_json", fake_get)
    plugin = ci.CryptoInfraPortsPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(plugin.run(target, _ctx()))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.evidence["port"] == 26657
    assert f.evidence["node_info"]["moniker"] == "fixture-validator"
    assert "fixture-validator" in f.value


def test_ports_plugin_solana_version(monkeypatch):
    async def fake_tcp(host, port, timeout=2.5):
        return port == 8899
    monkeypatch.setattr(ci, "_tcp_open", fake_tcp)
    _patch_rpc(monkeypatch, {
        "getVersion": {"solana-core": "1.18.0", "feature-set": 42},
        "getHealth": "ok",
    })
    plugin = ci.CryptoInfraPortsPlugin()
    target = Target(raw="10.0.0.9", type="ip", normalized="10.0.0.9")
    res = asyncio.run(plugin.run(target, _ctx()))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.evidence["port"] == 8899
    assert f.evidence["get_version"]["solana-core"] == "1.18.0"
    assert f.evidence["get_health"] == "ok"


def test_ports_plugin_passive_mode_never_connects(monkeypatch):
    called = []

    async def fake_tcp(host, port, timeout=2.5):
        called.append(port)
        return True
    monkeypatch.setattr(ci, "_tcp_open", fake_tcp)
    plugin = ci.CryptoInfraPortsPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(plugin.run(target, _ctx(mode="passive")))
    assert res.findings == []
    assert called == []


# ---------------- rpc plugin end-to-end (mocked) ----------------

def _patch_harvest_and_rpc(monkeypatch):
    async def fake_texts(ctx, target):
        return _TEXTS
    monkeypatch.setattr(ci, "collect_texts", fake_texts)

    async def fake_rpc(ctx, url, method, params=None, origin=None,
                       timeout=6.0):
        headers = {}
        if origin:
            headers = {"access-control-allow-origin": "*"}
        answers = {
            "web3_clientVersion": "Geth/v1.13.0-stable/linux",
            "eth_chainId": "0x1",
            "net_version": "1",
            "rpc_modules": {"eth": "1.0", "net": "1.0", "web3": "1.0",
                            "personal": "1.0", "debug": "1.0"},
            "getVersion": {"solana-core": "1.18.0"},
            "getHealth": "ok",
        }
        return answers.get(method), headers
    monkeypatch.setattr(ci, "_rpc_call", fake_rpc)


def test_rpc_plugin_full_grading(monkeypatch):
    _patch_harvest_and_rpc(monkeypatch)
    plugin = ci.CryptoInfraRpcPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(plugin.run(target, _ctx()))
    keys = [f.key for f in res.findings]
    # embedded Infura key flagged, in full
    leak = [f for f in res.findings if f.key == "rpc_url_embedded_key"]
    assert len(leak) == 1
    assert "0123456789abcdef0123456789abcdef" in leak[0].value
    assert leak[0].evidence["key"] == \
        "0123456789abcdef0123456789abcdef"
    # dangerous namespaces graded on probed endpoints
    danger = [f for f in res.findings
              if f.key == "rpc_dangerous_modules"]
    assert danger and all("personal" in f.evidence["all_modules"]
                          for f in danger)
    assert any("CRITICAL" in f.value for f in danger)
    # self-hosted endpoint answered -> public RPC finding
    assert "public_rpc_endpoint" in keys
    # wildcard CORS on RPC endpoints
    assert "rpc_cors_wildcard" in keys


def test_rpc_plugin_passive_mode_harvests_but_never_probes(monkeypatch):
    probed = []

    async def fake_texts(ctx, target):
        return _TEXTS
    monkeypatch.setattr(ci, "collect_texts", fake_texts)

    async def fake_rpc(ctx, url, method, params=None, origin=None,
                       timeout=6.0):
        probed.append(url)
        return None, {}
    monkeypatch.setattr(ci, "_rpc_call", fake_rpc)
    plugin = ci.CryptoInfraRpcPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(plugin.run(target, _ctx(mode="passive")))
    assert probed == []
    keys = [f.key for f in res.findings]
    assert "rpc_url_embedded_key" in keys
    assert "rpc_dangerous_modules" not in keys


def test_rpc_plugin_clean_modules_no_danger_finding(monkeypatch):
    async def fake_texts(ctx, target):
        return [("page", 'const B = "https://rpc.example.com";',
                 "https://example.com/")]
    monkeypatch.setattr(ci, "collect_texts", fake_texts)

    async def fake_rpc(ctx, url, method, params=None, origin=None,
                       timeout=6.0):
        answers = {
            "web3_clientVersion": "Geth/v1.13.0-stable/linux",
            "eth_chainId": "0x1",
            "net_version": "1",
            "rpc_modules": {"eth": "1.0", "net": "1.0", "web3": "1.0"},
        }
        return answers.get(method), {}
    monkeypatch.setattr(ci, "_rpc_call", fake_rpc)
    plugin = ci.CryptoInfraRpcPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(plugin.run(target, _ctx()))
    keys = [f.key for f in res.findings]
    assert "rpc_dangerous_modules" not in keys
    assert "public_rpc_endpoint" in keys  # answered, but clean


# ---------------- registry integration ----------------

def test_registry_discovers_crypto_infra_plugins():
    from app.plugins.registry import discover
    plugins = discover()  # {plugin_id: PluginClass}
    assert "crypto_infra_rpc" in plugins
    assert "crypto_infra_ports" in plugins
    assert "domain" in plugins["crypto_infra_rpc"].accepts
    assert "ip" in plugins["crypto_infra_ports"].accepts
