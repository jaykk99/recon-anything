"""Gate for the high-throughput batch contract scanner (app/batch_scan.py).

Proves both engines run a corpus end-to-end through the multiprocessing
pool, produce findings, and report throughput - and that the plugins
engine runs the real contract plugins fully offline without throwing.
Network-free by construction (the plugins engine kills the socket in each
worker).
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app.batch_scan as bs  # noqa: E402

_SRC = (
    "pragma solidity ^0.8.0;\n"
    "contract C {\n"
    "  address owner;\n"
    "  function withdraw(uint a) external {\n"
    "    (bool ok,) = msg.sender.call{value: a}(\"\"); require(ok);\n"
    "  }\n"
    "  function setOwner(address n) external { owner = n; }\n"
    "}\n"
) * 4


def _corpus(n):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "corpus.jsonl")
    with open(p, "w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(json.dumps({
                "address": f"0x{i:040x}", "chain": "ethereum",
                "source": _SRC}) + "\n")
    return p


def test_scan_source_returns_findings():
    findings = bs.scan_source(_SRC, {})
    assert isinstance(findings, list)
    assert findings, "expected at least one finding on a vulnerable sample"


def test_rules_engine_corpus_throughput():
    path = _corpus(120)
    summary = bs.scan_corpus(path, workers=2, engine="rules",
                             progress_every=0)
    assert summary["scanned"] == 120
    assert summary["contracts_per_sec"] > 0
    assert summary["projected_1m_minutes"] is not None


def test_plugins_engine_runs_offline():
    # The real contract plugins, run with network killed in each worker.
    # Must complete every contract and never throw.
    path = _corpus(20)
    summary = bs.scan_corpus(path, workers=2, engine="plugins",
                             target_type="crypto_wallet", progress_every=0)
    assert summary["scanned"] == 20
    assert summary["engine"] == "plugins"


def test_batchctx_seeds_chain_data_for_offline_plugins():
    """Pre-fetched bytecode/storage must be seeded into the caches the deep
    plugins read (_code_cache/_storage_cache), so rpc_get_code /
    rpc_get_storage_at serve from the corpus with zero live RPC - the whole
    point of running the deep pass at corpus speed instead of network speed.
    """
    import asyncio
    import app.plugins.contract_chain as cc

    addr = "0xABCdef0000000000000000000000000000000001"
    ctx = bs._BatchCtx("contract V {}", addr, "crypto_wallet",
                       bytecode="0x6080aa", storage={"0x0": "0x" + "11" * 32})

    async def boom(*a, **k):
        raise RuntimeError("network was called - not offline")
    orig = cc._rpc_post
    cc._rpc_post = boom
    try:
        class Chain:
            id = "ethereum"
            rpc_urls = ["https://rpc1"]

        async def run():
            code = await cc.rpc_get_code(ctx, Chain(), addr)
            word = await cc.rpc_get_storage_at(ctx, Chain(), addr, "0x0")
            assert code == "0x6080aa"
            assert word == "0x" + "11" * 32
        asyncio.run(run())
    finally:
        cc._rpc_post = orig


def test_tier1_escalates_only_matching_severity():
    """Tier-1 flags a contract (and carries its full record forward) only
    when a finding hits an escalate severity; otherwise it returns no
    record, so heavy source doesn't cross to tier 2 for the whole corpus."""
    bs._init_tier1_worker(("high", "critical"))
    # a finding at escalate severity -> escalates; patch scan_source so the
    # test is deterministic regardless of rule content.
    import app.batch_scan as _bs
    orig = _bs.scan_source
    try:
        _bs.scan_source = lambda src, meta=None: [
            {"severity": "high", "key": "x"}]
        a, c, n, finds, rec = _bs._scan_one_tier1(
            ("0xabc", "ethereum", "contract C {}",
             {"_bytecode": "0x60", "_storage": {}}))
        assert rec is not None and rec["bytecode"] == "0x60"
        # below-threshold severity -> no escalation, no record carried
        _bs.scan_source = lambda src, meta=None: [
            {"severity": "low", "key": "y"}]
        a, c, n, finds, rec = _bs._scan_one_tier1(
            ("0xabc", "ethereum", "contract C {}", {}))
        assert rec is None
    finally:
        _bs.scan_source = orig


def test_tiered_sweep_skips_tier2_when_nothing_flags():
    path = _corpus(40)
    summary = bs.scan_corpus(path, workers=2, engine="tiered",
                             escalate_severities=("__none__",),
                             progress_every=0)
    assert summary["engine"] == "tiered"
    assert summary["tier1"]["scanned"] == 40
    assert summary["tier1"]["flagged_for_escalation"] == 0
    assert summary["tier2_plugins"]["scanned"] == 0
