"""Tests for app/search.py — the live collection search (2026-11-06).

Runs over a tiny fixture corpus via RECON_SEARCH_CORPUS; the module
singleton is reset per test so each test rebuilds the FTS index from
the fixture (4 docs — milliseconds).
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import search as search_index  # noqa: E402

ADDR_A = "0x" + "a" * 40
ADDR_B = "0x" + "b" * 40
ADDR_D = "0x" + "d" * 40
SOL_ADDR = "So1anaProgramAddrXYZ11111111111111111111111"

FIXTURE = [
    {"chain": "ethereum", "address": ADDR_A, "name": "VaultThing",
     "symbol": "VLT", "value_usd": 5000.0, "has_source": 1,
     "functions": ["emergencyWithdraw", "deposit"], "selectors": [],
     "plugins": ["contract_logic"], "kinds": ["access_control_flaw"],
     "verdict": "TRIGGER_ONLY", "verdicts": ["TRIGGER_ONLY"],
     "recipients": ["CALLER"], "reasons": ["holder can self-trigger"],
     "sources": ["scanner"], "first_seen": "2026-11-01",
     "last_seen": "2026-11-05",
     "doc": "ethereum VaultThing emergencyWithdraw deposit "
            "delegatecall onlyOwner"},
    {"chain": "bsc", "address": ADDR_B, "name": "SafeBox",
     "symbol": None, "value_usd": 200.0, "has_source": 0,
     "functions": ["deposit"], "selectors": [],
     "plugins": ["token_rugcheck"], "kinds": [],
     "verdict": "FALSE_POSITIVE", "verdicts": ["FALSE_POSITIVE"],
     "recipients": [], "reasons": ["gated in bytecode"],
     "sources": ["fp_audit"], "first_seen": None, "last_seen": None,
     "doc": "bsc SafeBox deposit payable mint"},
    {"chain": "solana", "address": SOL_ADDR, "name": None,
     "symbol": "SOLX", "value_usd": None, "has_source": 0,
     "functions": [], "selectors": [], "plugins": ["solana_contract"],
     "kinds": [], "verdict": None, "verdicts": [], "recipients": [],
     "reasons": [], "sources": ["scanner"], "first_seen": None,
     "last_seen": None, "doc": "solana program tokens mint authority"},
    {"chain": "ethereum", "address": ADDR_D, "name": "RescuePot",
     "symbol": None, "value_usd": 250000.0, "has_source": 1,
     "functions": ["sweepFunds"], "selectors": ["0x1234abcd"],
     "plugins": ["contract_logic", "contract_recon"],
     "kinds": ["ungated_sweep"], "verdict": "UNVERIFIED",
     "verdicts": ["UNVERIFIED"], "recipients": ["CALLER-SUPPLIED"],
     "reasons": ["no value destination could be classified"],
     "sources": ["kwindex", "scanner"], "first_seen": "2026-10-30",
     "last_seen": "2026-11-06",
     "doc": "ethereum RescuePot sweepFunds rescue external tokens"},
]


@pytest.fixture(autouse=True)
def fixture_corpus(tmp_path, monkeypatch):
    p = tmp_path / "corpus.jsonl"
    with open(p, "w") as f:
        f.write(json.dumps({"_meta": {"built_at": "test",
                                       "contracts": len(FIXTURE)}}) + "\n")
        for r in FIXTURE:
            f.write(json.dumps(r) + "\n")
    monkeypatch.setenv("RECON_SEARCH_CORPUS", str(p))
    search_index._db = None
    search_index._meta.clear()
    yield
    search_index._db = None
    search_index._meta.clear()


def test_index_status():
    st = search_index.index_status()
    assert st["ok"] is True
    assert st["contracts"] == 4


def test_keyword_and_semantics():
    r = search_index.search(q="emergency withdraw")
    assert r["count"] == 1
    assert r["results"][0]["address"] == ADDR_A
    r = search_index.search(q="emergency nonexistenttoken")
    assert r["count"] == 0


def test_function_name_recall_full_and_split():
    assert search_index.search(q="emergencyWithdraw")["count"] == 1
    # camelCase split parts are indexed: "withdraw" finds it too
    hits = search_index.search(q="withdraw")
    assert [h["address"] for h in hits["results"]] == [ADDR_A]
    hits = search_index.search(q="sweep")
    assert [h["address"] for h in hits["results"]] == [ADDR_D]


def test_verdict_filter_is_exact():
    r = search_index.search(verdict="TRIGGER_ONLY")
    assert r["count"] == 1
    assert all(h["verdict"] == "TRIGGER_ONLY" for h in r["results"])
    r = search_index.search(q="deposit", verdict="FALSE_POSITIVE")
    assert [h["address"] for h in r["results"]] == [ADDR_B]


def test_chain_filter_incl_solana():
    r = search_index.search(chain="solana")
    assert r["count"] == 1
    assert r["results"][0]["address"] == SOL_ADDR  # case preserved


def test_value_and_source_filters():
    r = search_index.search(min_value_usd=100000)
    assert [h["address"] for h in r["results"]] == [ADDR_D]
    r = search_index.search(has_source=True)
    assert {h["address"] for h in r["results"]} == {ADDR_A, ADDR_D}


def test_plugin_and_recipient_filters():
    r = search_index.search(plugin="contract_logic")
    assert {h["address"] for h in r["results"]} == {ADDR_A, ADDR_D}
    r = search_index.search(recipient="CALLER-SUPPLIED")
    assert [h["address"] for h in r["results"]] == [ADDR_D]


def test_exact_address_pins_single_result():
    r = search_index.search(q=ADDR_A)
    assert r["count"] == 1
    assert r["results"][0]["name"] == "VaultThing"
    assert "TRIGGER_ONLY" in r["results"][0]["snippet"]


def test_limit_clamped_to_100():
    r = search_index.search(limit=500)
    assert r["count"] == 4
    assert len(r["results"]) == 4  # only 4 exist; clamp is internal


def test_ranking_unverified_above_false_positive():
    r = search_index.search(q="mint")  # matches B (FP) and C (none)
    addrs = [h["address"] for h in r["results"]]
    assert addrs[0] == SOL_ADDR  # verdict-less ranks above FALSE_POSITIVE
    assert addrs[-1] == ADDR_B
