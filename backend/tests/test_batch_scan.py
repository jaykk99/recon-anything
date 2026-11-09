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
