"""Crypto gap plugins + finding-chaining layer.

Covers, detection-only, no live network (stubbed ctx, local fixtures):
- the 5 new cp_* plugins each fire on a crafted fixture page/JS and
  stay silent on a clean page;
- the RPC misconfig plugin never matches a credential-bearing URL and
  never leaks the credential into a finding value;
- every CHAIN_RULES followup plugin id exists in the registry;
- plan_from_findings / plan_from_bus dedupe, cap, depth-limit, and
  scope-filter (out-of-scope hosts dropped, crypto.com refused);
- chain_followups (phase 2) executes same-target probes via the stub
  probe path and emits plan findings for delegated followups, without
  publishing anything back into the bus (no chain loop).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.cache import Cache  # noqa: E402
from app.finding_chain import (CHAIN_RULES, MAX_CHAIN_DEPTH,  # noqa: E402
                               plan_from_bus, plan_from_findings)
from app.plugins import cryptopack_web3_gaps as G  # noqa: E402
from app.plugins.base import Ctx, PageData, PluginStatus, Target  # noqa: E402
from app.plugins.chain_followups import ChainFollowupsPlugin  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

REG = discover()
DOMAIN = "fixture.test"
ADDR = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
IMPL_SLOT = ("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca"
             "505d382bbc")


def make_ctx(html, js=""):
    ctx = Ctx(run_id="chain-test", mode="passive", http=None,
              cache=Cache(), keys={})

    async def fetch_page(url, timeout=10):
        if url.endswith(".js"):
            return PageData({"status_code": 200, "headers": {},
                             "text": js, "url": url})
        return PageData({"status_code": 200, "headers": {},
                         "text": html, "url": f"https://{DOMAIN}/"})
    ctx.fetch_page = fetch_page
    return ctx


def run_plugin(cls, html, js=""):
    plugin = cls()
    ctx = make_ctx(html, js)
    target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
    result = asyncio.run(plugin.run(target, ctx))
    status = result.status.value if isinstance(result.status, PluginStatus) \
        else result.status
    assert status in ("ok", "skipped", "degraded"), (cls.id, status)
    return result.findings


def page(body):
    return ('<html><head><script src="/app.js"></script></head>'
            f'<body>{body}</body></html>')


def keys(findings):
    return {f.key for f in findings}


# --- Task 1: new crypto gap plugins -------------------------------------

def test_token_abi_metadata_and_privileged_fn():
    body = ('<script>const ABI=[{"type":"function","name":"mint"},'
            '{"type":"function","name":"pause"}];'
            'const META={"symbol":"TEST","decimals":18};</script>'
            '"abi": [{"type":"function"}]')
    findings = run_plugin(G.CpWeb3TokenAbi, page(body))
    assert "token_abi_metadata" in keys(findings)
    assert "token_abi_privileged_fn" in keys(findings)
    assert any("TEST (decimals 18)" in f.value for f in findings)
    assert any("mint" in f.value for f in findings)
    assert not run_plugin(G.CpWeb3TokenAbi, page("hello world"))


def test_wallet_roles():
    body = (f"owner: {ADDR} treasury={ADDR} "
            f"feeRecipient: {ADDR} vault: {ADDR}")
    findings = run_plugin(G.CpWeb3WalletRoles, page(body))
    ks = keys(findings)
    assert "wallet_role_owner" in ks
    assert "wallet_role_treasury" in ks
    assert "wallet_role_fee_recipient" in ks
    assert "wallet_role_vault" in ks
    assert all(ADDR in f.value for f in findings)
    assert not run_plugin(G.CpWeb3WalletRoles, page("no addresses here"))


def test_rpc_misconfig_http_localhost_and_methods():
    body = ("rpcUrl: http://rpc.fixture.test/v1 "
            "node: http://api.fixture.test:8545 "
            "local: http://localhost:8545 "
            "call: eth_sendTransaction personal_unlockAccount")
    mis = run_plugin(G.CpWeb3RpcMisconfig, page(body))
    assert "rpc_http_endpoint" in keys(mis)
    assert "rpc_http_port_endpoint" in keys(mis)
    assert "rpc_localhost_endpoint" in keys(mis)
    meth = run_plugin(G.CpWeb3RpcMethodRefs, page(body))
    assert "rpc_dangerous_method_ref" in keys(meth)
    assert not run_plugin(G.CpWeb3RpcMisconfig, page("hello world"))


def test_rpc_misconfig_never_matches_credential_url():
    body = "rpc: http://user:s3cretpass@rpc.fixture.test/v1"
    findings = run_plugin(G.CpWeb3RpcMisconfig, page(body))
    assert not any("s3cretpass" in f.value for f in findings)
    assert not any("user:" in f.value for f in findings)


def test_proxy_slots():
    body = f"slot {IMPL_SLOT} ProxyAdmin TransparentUpgradeableProxy"
    findings = run_plugin(G.CpWeb3ProxySlots, page(body))
    assert "proxy_eip1967_implementation_slot" in keys(findings)
    assert "proxy_admin_ref" in keys(findings)
    assert not run_plugin(G.CpWeb3ProxySlots, page("hello world"))


def test_new_plugins_registered():
    for pid in ("cp_web3_token_abi", "cp_web3_wallet_roles",
                "cp_web3_rpc_misconfig", "cp_web3_rpc_method_refs",
                "cp_web3_proxy_slots", "chain_followups"):
        assert pid in REG, f"{pid} missing from registry"
    assert len(REG) == 634, f"registry size {len(REG)}, expected 634"


# --- Task 2: chaining layer ----------------------------------------------

def test_chain_rules_followups_exist():
    missing = [r["followup_plugin"] for r in CHAIN_RULES
               if r["followup_plugin"] not in REG]
    assert not missing, f"chain rules point at missing plugins: {missing}"


def test_plan_from_findings_dedupe_and_depth():
    findings = [{"key": "subdomain", "value": "api.fixture.test"},
                {"key": "subdomain", "value": "api.fixture.test"},
                {"key": "token_contract", "value": ADDR}]
    plan, audit = plan_from_findings(findings)
    followups = {(s["item"], s["followup_plugin"]) for s in plan}
    assert ("api.fixture.test", "cmd_dns") in followups
    assert ("api.fixture.test", "cmd_http") in followups
    assert (ADDR, "contract_audit") in followups
    assert (ADDR, "chain_osint") in followups
    assert len(plan) == len(followups)  # deduped
    plan2, _ = plan_from_findings(findings, depth=MAX_CHAIN_DEPTH + 1)
    assert plan2 == []


def test_plan_from_bus_scope_and_blocked():
    bus = {"subdomains": ["api.fixture.test", "evil.example.com"],
           "endpoints": ["/api/v1", "https://other.example.com/x"]}
    plan, audit = plan_from_bus(bus, DOMAIN)
    items = {s["item"] for s in plan}
    assert "api.fixture.test" in items
    assert "/api/v1" in items
    assert "evil.example.com" not in items
    assert "https://other.example.com/x" not in items
    assert any(a["status"] == "skipped_out_of_scope" for a in audit)
    plan3, _ = plan_from_bus(bus, "crypto.com")
    assert plan3 == []


def test_plan_masks_secret_items_and_uses_nothing():
    secret = "0x" + "ab" * 32
    plan, audit = plan_from_bus({"endpoints": [secret]}, DOMAIN)
    assert plan == []
    assert any(a["status"] == "skipped_secret_masked" for a in audit)
    assert not any(secret in str(a) for a in audit)
    plan2, audit2 = plan_from_findings(
        [{"key": "wallet_private_key", "value": secret}])
    assert plan2 == []
    assert not any(secret in str(a) for a in audit2)


def test_chain_followups_follows_links_one_level_only():
    ctx = Ctx(run_id="chain-test", mode="passive", http=None,
              cache=Cache(), keys={})
    ctx.publish("endpoints", "/api/v1")
    probed = []

    async def probe(url, timeout=8):
        probed.append(url)
        if url.endswith("/api/v1"):
            return {"status": 200, "headers": {},
                    "text": ('<a href="/docs">docs</a> '
                            '<a href="https://evil.example.com/x">evil</a> '
                            '<a href="https://user:pass@fixture.test/x">cred</a>'),
                    "url": url, "length": 0}
        return {"status": 200, "headers": {}, "text": "", "url": url,
                "length": 0}
    ctx.probe = probe
    plugin = ChainFollowupsPlugin()
    target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
    result = asyncio.run(plugin.run(target, ctx))
    ks = keys(result.findings)
    assert "chain_endpoint_status" in ks
    assert "chain_subfinding_link" in ks
    assert any(u.endswith("/docs") for u in probed)
    assert not any("evil.example.com" in u for u in probed)
    assert not any("user:pass" in u for u in probed)
    assert any(a.get("depth") == 2 for a in ctx.shared.get("chain_audit", []))


def test_chain_followups_executes_and_plans_without_looping():
    ctx = Ctx(run_id="chain-test", mode="passive", http=None,
              cache=Cache(), keys={})
    ctx.publish("subdomains", "api.fixture.test")
    ctx.publish("contract_addresses", ADDR)
    probed = []

    async def probe(url, timeout=8):
        probed.append(url)
        return {"status": 200, "headers": {}, "text": "", "url": url,
                "length": 0}
    ctx.probe = probe
    plugin = ChainFollowupsPlugin()
    target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
    result = asyncio.run(plugin.run(target, ctx))
    ks = keys(result.findings)
    assert "chain_subdomain_live" in ks
    assert "chain_plan" in ks
    assert any("https://api.fixture.test" in u for u in probed)
    # No loop: the plugin publishes nothing new into the bus.
    assert "chain_subdomain_live" not in ctx.shared
    assert ctx.shared.get("chain_audit"), "audit trail missing"
    assert plugin.phase == 2
