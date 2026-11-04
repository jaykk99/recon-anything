"""Deep-audit batch-2 plugin run() end-to-end (chain stubbed).

Proves generated plugin classes work through the real
Plugin.run path: a vulnerable fixture source produces a finding
under the plugin's own id with validator-ready evidence, the
EIP-7702 bytecode lane fires on a live 0xef0100 designator
pointing at an unverified delegate, clean / non-designator
shapes produce none, and the no-verified-source path returns a
skip (no guessed findings).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit2_fixtures as fx  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x1111111111111111111111111111111111111111"
DELEGATE = "0x2222222222222222222222222222222222222222"
FOT = "fee_on_transfer_overcredit"
EIP = "eip7702_unverified_delegate"


class FakeCtx:
    def __init__(self, shared=None):
        self.keys = {}
        self.mode = "passive"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = "test"
        self.module_overrides = {}
        self.shared = shared or {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


def _patch(monkeypatch, source, code="0x60006000"):
    async def fake_get_code(ctx, chain, address):
        return code

    async def fake_source(ctx, chain, address, key=None):
        return source

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation",
                        fake_resolve)


def _meta(source):
    if source is None:
        return None
    return {"source": source, "contract_name": "Fixture",
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def _target():
    return Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                  normalized=f"ethereum:{ADDR}")


def test_run_flags_vulnerable_source_with_evidence(monkeypatch):
    _patch(monkeypatch, _meta(fx.VULN[FOT]))
    plugin = discover()[FOT]()
    res = asyncio.run(plugin.run(_target(), FakeCtx()))
    hits = [f for f in res.findings if f.key == FOT]
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["function"] == "deposit"
    assert ev["chain"] == "ethereum"
    assert ev["address"] == ADDR
    assert ev["code"]
    assert ev["kind"] == FOT
    assert ev["report_class"] == "candidate"
    assert ev["recipient"] == "CALLER"
    assert ev["gate_analysis"]


def test_run_clean_source_no_findings(monkeypatch):
    _patch(monkeypatch, _meta(fx.CLEAN[FOT]))
    plugin = discover()[FOT]()
    res = asyncio.run(plugin.run(_target(), FakeCtx()))
    assert [f for f in res.findings if f.key == FOT] == []


def test_run_no_source_is_a_skip_not_a_guess(monkeypatch):
    _patch(monkeypatch, None)
    plugin = discover()[FOT]()
    res = asyncio.run(plugin.run(_target(), FakeCtx()))
    assert [f for f in res.findings if f.key == FOT] == []
    assert "without verified source" in res.reason


def test_run_7702_designator_unverified_delegate(monkeypatch):
    code = "0xef0100" + DELEGATE[2:]
    _patch(monkeypatch, None, code=code)
    plugin = discover()[EIP]()
    res = asyncio.run(plugin.run(_target(), FakeCtx()))
    hits = [f for f in res.findings if f.key == EIP]
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["delegate_address"] == DELEGATE
    assert ev["recipient"] == "FIXED"
    assert ev["report_class"] == "trigger_only"
    assert ev["bytecode_only"] is True


def test_run_non_designator_code_no_7702_finding(monkeypatch):
    _patch(monkeypatch, None, code="0x60006000")
    plugin = discover()[EIP]()
    res = asyncio.run(plugin.run(_target(), FakeCtx()))
    assert [f for f in res.findings if f.key == EIP] == []
