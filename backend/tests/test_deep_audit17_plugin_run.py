"""Deep-audit batch-17 plugin run() end-to-end (chain stubbed).

Proves the generated plugin class works through the real
Plugin.run path: a vulnerable fixture source produces a finding
under the plugin's own id with validator-ready evidence plus the
live legs (native balance, creation age, freshness), clean shapes
produce none, the no-verified-source path returns a skip (no
guessed findings), and the live gates actually gate: old code is
suppressed, a payable-forward-only chain on a zero-balance
contract is suppressed, a dust-pool mint is suppressed - while
unknown freshness / balance / liquidity never suppresses.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit17_fixtures as fx  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import deep_audit17  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x1111111111111111111111111111111111111111"
PID = "zeroday_exploit_chain"
ONE_ETH = 10 ** 18

# Payable-forward-only shape: delegatecall to a caller-supplied
# target, payable, but NO fund move in the function. The value leg
# is msg.value forwarding only, so a KNOWN zero native balance
# must suppress it at run time.
_PAYABLE_ONLY = """
contract ZeroDayPayableOnly {
    function execute(address target, bytes calldata data) external payable {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
"""


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


def _patch(monkeypatch, source, code="0x60006000", balance=ONE_ETH,
           age=(5.0, 19000000, 19100000), liquidity=None):
    async def fake_get_code(ctx, chain, address):
        return code

    async def fake_source(ctx, chain, address, key=None):
        return source

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    async def fake_balance(ctx, chain, address):
        return balance

    async def fake_age(ctx, chain, address):
        return age

    async def fake_liquidity(ctx, address):
        return liquidity

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)
    monkeypatch.setattr(cc, "rpc_get_balance", fake_balance)
    monkeypatch.setattr(deep_audit17, "_creation_age_days", fake_age)
    monkeypatch.setattr(deep_audit17, "_token_liquidity_usd",
                        fake_liquidity)


def _meta(source):
    if source is None:
        return None
    return {"source": source, "contract_name": "Fixture",
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def _target():
    return Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                  normalized=f"ethereum:{ADDR}")


def _run(monkeypatch, source, **kw):
    _patch(monkeypatch, _meta(source), **kw)
    plugin = discover()[PID]()
    return asyncio.run(plugin.run(_target(), FakeCtx()))


def test_run_flags_vulnerable_source_with_evidence(monkeypatch):
    res = _run(monkeypatch, fx.VULN[PID])
    hits = [f for f in res.findings if f.key == PID]
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["function"] == "execute"
    assert ev["chain"] == "ethereum"
    assert ev["address"] == ADDR
    assert ev["code"]
    assert ev["kind"] == PID
    assert ev["report_class"] == "candidate"
    assert ev["recipient"] == "CALLER-SUPPLIED"
    assert ev["gate_analysis"]
    assert ev["leg"] == "delegatecall"
    assert ev["value_basis"] == "fund_move"
    assert ev["native_balance_wei"] == ONE_ETH
    assert ev["creation_age_days"] == 5.0
    assert ev["freshness"] == "fresh"


def test_run_clean_source_no_findings(monkeypatch):
    res = _run(monkeypatch, fx.CLEAN[PID])
    assert [f for f in res.findings if f.key == PID] == []


def test_run_no_source_is_a_skip_not_a_guess(monkeypatch):
    res = _run(monkeypatch, None)
    assert [f for f in res.findings if f.key == PID] == []
    assert "without verified source" in res.reason


def test_run_old_code_suppressed(monkeypatch):
    res = _run(monkeypatch, fx.VULN[PID],
               age=(400.0, 18000000, 19100000))
    assert [f for f in res.findings if f.key == PID] == []
    assert "suppressed" in res.reason
    assert "400 days old" in res.reason


def test_run_unknown_freshness_kept(monkeypatch):
    # The creation lookup failed: age unknown is NOT stale, the
    # finding is kept and marked unknown.
    res = _run(monkeypatch, fx.VULN[PID], age=(None, None, None))
    hits = [f for f in res.findings if f.key == PID]
    assert len(hits) == 1
    assert hits[0].evidence["freshness"] == "unknown"


def test_run_zero_balance_payable_only_suppressed(monkeypatch):
    res = _run(monkeypatch, _PAYABLE_ONLY, balance=0)
    assert [f for f in res.findings if f.key == PID] == []
    assert "suppressed" in res.reason


def test_run_zero_balance_fund_move_kept(monkeypatch):
    # A fund-move chain stays: the value is tokens, not native.
    res = _run(monkeypatch, fx.VULN[PID], balance=0)
    hits = [f for f in res.findings if f.key == PID]
    assert len(hits) == 1


def test_run_mint_dust_pool_suppressed(monkeypatch):
    res = _run(monkeypatch, fx.EXTRA_VULN[
        "zeroday_exploit_chain_mint"], liquidity=100.0)
    assert [f for f in res.findings if f.key == PID] == []
    assert "suppressed" in res.reason
    assert "dust" in res.reason


def test_run_mint_unknown_liquidity_kept(monkeypatch):
    res = _run(monkeypatch, fx.EXTRA_VULN[
        "zeroday_exploit_chain_mint"], liquidity=None)
    hits = [f for f in res.findings if f.key == PID]
    assert len(hits) == 1
    assert hits[0].evidence["leg"] == "mint"
    assert hits[0].evidence["token_liquidity_usd"] is None
