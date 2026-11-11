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


def test_tier1_escalates_on_confirmed_confidence_tier():
    """Tier-1 flags a contract (and carries its full record forward) only
    when a finding reaches the confirmed confidence tier - the selective
    signal that keeps the deep pass small. A likely-tier finding does not
    escalate."""
    import app.batch_scan as _bs
    _bs._init_tier1_worker(("high", "critical"), 1, ("confirmed",))
    orig = _bs.scan_source
    try:
        # an unambiguous drain reaches confirmed -> escalates
        _bs.scan_source = lambda src, meta=None: [
            {"kind": "selfdestruct", "severity": "high", "confidence": 80}]
        a, c, n, finds, rec = _bs._scan_one_tier1(
            ("0xabc", "ethereum", "contract C {}",
             {"_bytecode": "0x60", "_storage": {}}))
        assert rec is not None and rec["bytecode"] == "0x60"
        # a likely-tier finding (context, capped) does not escalate
        _bs.scan_source = lambda src, meta=None: [
            {"kind": "privileged_function", "severity": "high",
             "confidence": 70}]
        a, c, n, finds, rec = _bs._scan_one_tier1(
            ("0xabc", "ethereum", "contract C {}", {}))
        assert rec is None
    finally:
        _bs.scan_source = orig


def test_tiered_sweep_skips_tier2_when_nothing_flags():
    path = _corpus(40)
    # escalate on a tier no finding can have -> nothing flags, tier 2 skipped
    summary = bs.scan_corpus(path, workers=2, engine="tiered",
                             escalate_tiers=("__none__",),
                             progress_every=0)
    assert summary["engine"] == "tiered"
    assert summary["tier1"]["scanned"] == 40
    assert summary["tier1"]["flagged_for_escalation"] == 0
    assert summary["tier2_plugins"]["scanned"] == 0


def test_finding_filter_narrows_output():
    """Runtime FindingFilter keeps only matching findings, no code change."""
    path = _corpus(30)
    base = bs.scan_corpus(path, workers=2, engine="rules", progress_every=0)
    assert base["findings_total"] > 0

    # filter to a kind that the sample contract does produce
    kinds = {f.get("kind") or f.get("key")
             for f in bs.scan_source(_SRC, {})}
    some_kind = next(iter(k for k in kinds if k))
    flt = bs.FindingFilter(kinds={some_kind})
    r = bs.scan_corpus(path, workers=2, engine="rules",
                       find_filter=flt, progress_every=0)
    assert r["filtered"] is True
    assert 0 < r["findings_total"] <= base["findings_total"]
    assert r["matched_contracts"] <= r["scanned"]

    # a kind that cannot occur -> nothing matches
    none = bs.scan_corpus(path, workers=2, engine="rules",
                          find_filter=bs.FindingFilter(kinds={"__nope__"}),
                          progress_every=0)
    assert none["findings_total"] == 0
    assert none["matched_contracts"] == 0


def test_scan_source_includes_audit_source_drain_checks():
    """The fast batch path runs the contract_audit checks too, so drain-class
    issues are caught without escalating to the full plugin engine."""
    src = ('pragma solidity 0.8.19;\n'
           'contract Vault { mapping(address=>uint) bal;\n'
           ' function withdrawAll(address to) external {'
           ' (bool ok,)=to.call{value:address(this).balance}(""); }\n'
           ' function claim() external {'
           ' (bool ok,)=msg.sender.call{value:bal[msg.sender]}("");'
           ' bal[msg.sender]=0; }\n}')
    kinds = {f.get("kind") for f in bs.scan_source(src, {})}
    # audit_source contributes these; analyzer alone did not
    assert "fund_drain" in kinds or "reentrancy" in kinds
    assert not any(f.get("kind") == "error" for f in bs.scan_source(src, {}))


def test_audit_crash_surfaces_as_error_not_empty(monkeypatch):
    """A crashing audit must produce an error finding, never a silent clean."""
    import app.plugins.contract_audit as ca

    def boom(_src):
        raise ValueError("kaboom")

    monkeypatch.setattr(ca, "audit_source", boom)
    findings = bs.scan_source("contract C {}", {})
    assert any(f.get("kind") == "error" and "kaboom" in f.get("detail", "")
               for f in findings)


def test_scan_bytecode_finds_issues_without_source():
    """No-source candidates still produce findings from bytecode alone
    instead of being dropped unscanned."""
    code = "0x" + bytes([0x60, 0x00, 0xf4, 0xff]).hex()  # DELEGATECALL+SELFDESTRUCT
    kinds = {f["kind"] for f in bs.scan_bytecode(code)}
    assert "bytecode_selfdestruct" in kinds
    assert "bytecode_delegatecall" in kinds
    assert "bytecode_unverified" in kinds


def test_scan_bytecode_handles_empty_and_invalid():
    assert bs.scan_bytecode("0x") == []
    assert bs.scan_bytecode("") == []
    assert bs.scan_bytecode("zzz") == []   # invalid hex -> no crash, no finding


def test_scan_bytecode_minimal_proxy_points_at_impl():
    proxy = ("0x363d3d373d3d3d363d73" + "be" * 20 +
             "5af43d82803e903d91602b57fd5bf3")
    kinds = {f["kind"] for f in bs.scan_bytecode(proxy)}
    assert "bytecode_minimal_proxy" in kinds
    assert "bytecode_delegatecall" not in kinds
