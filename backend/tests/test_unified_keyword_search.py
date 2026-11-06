"""Unified Keyword Search plugin (unified_keyword_search).

One search, multiple keywords, all three lanes at once:
  keyword_index (FTS5 code corpus) + scanner (batches + queues) +
  transition_watch (watchlist + snapshots + events), deduped by
  (chain, address). Fixtures here build a tiny index.db with the real
  kwindex schema and a tiny recon-continuous home, so the semantics
  are proven without the live corpus.
"""
import asyncio
import json
import os
import sqlite3
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.plugins.unified_keyword_search import (  # noqa: E402
    Keyword, UnifiedKeywordSearchPlugin, parse_keywords, unified_search)

ADDR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # both keywords
ADDR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  # delegatecall only
ADDR_C = "0xcccccccccccccccccccccccccccccccccccccccc"  # phrase only
ADDR_D = "0xdddddddddddddddddddddddddddddddddddddddd"  # scanner + watch

SRC_A = ("contract A {\n"
         "  function f(address t) public { t.delegatecall(''); }\n"
         "  function g() public { require(tx.origin == msg.sender); }\n"
         "}\n")
SRC_B = "contract B { function f(address t) public { t.delegatecall(''); } }"
SRC_C = ("contract C {\n"
         "  function withdraw(uint amount) public { payout(amount); }\n"
         "}\n")


def _make_index(path):
    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE contracts("
        "  chain TEXT, address TEXT, name TEXT, origin TEXT,"
        "  has_source INTEGER, source_len INTEGER,"
        "  value_usd REAL, value_src TEXT,"
        "  native_balance_wei TEXT, indexed_at TEXT,"
        "  PRIMARY KEY(chain, address))")
    con.execute(
        "CREATE VIRTUAL TABLE src_fts USING fts5("
        "  chain UNINDEXED, address UNINDEXED, text)")
    rows = [
        ("ethereum", ADDR_A, "TokenA", 500000.0, SRC_A),
        ("ethereum", ADDR_B, "TokenB", 500.0, SRC_B),
        ("bsc", ADDR_C, "TokenC", 250000.0, SRC_C),
    ]
    for chain, addr, name, value, src in rows:
        con.execute(
            "INSERT INTO contracts VALUES (?,?,?,?,1,?,?,?,NULL,"
            "'2026-11-04')", (chain, addr, name, "test", len(src),
                              value, "test"))
        con.execute("INSERT INTO src_fts VALUES (?,?,?)",
                    (chain, addr, src))
    con.commit()
    con.close()


def _make_home(root):
    home = root / "recon-continuous"
    (home / "results").mkdir(parents=True)
    (home / "state" / "queues").mkdir(parents=True)
    batch = {
        "queue": "market_deep", "chain": "ethereum", "address": ADDR_D,
        "symbol": "tokend", "stake_usd": 150000.0, "status": "genuine",
        "plugins_run": ["contract_recon"], "findings_count": 1,
        "findings": [{
            "plugin": "contract_recon", "key": "contract_delegatecall_code",
            "severity": "high", "value": "delegatecall used in fallback",
            "evidence": {"note": "tx.origin check present"}}]}
    (home / "results" / "batches.jsonl").write_text(
        json.dumps(batch) + "\n")
    queue_row = {"chain": "bsc", "address": ADDR_C, "symbol": "TokenC",
                 "stake_usd": 250000.0, "queue": "keyword_search",
                 "label": "keyword-search", "term": "delegatecall"}
    (home / "state" / "queues" / "keyword_search.jsonl").write_text(
        json.dumps(queue_row) + "\n")
    fresh_row = {"chain": "bsc", "address": ADDR_C, "symbol": "TokenC",
                 "stake_usd": 250000.0, "queue": "fresh",
                 "label": "rescan withdraw candidate"}
    (home / "state" / "queues" / "fresh.jsonl").write_text(
        json.dumps(fresh_row) + "\n")
    watch = {"chain": "ethereum", "address": ADDR_D, "symbol": "tokend",
             "stake_usd": 150000.0}
    (home / "state" / "watchlist.jsonl").write_text(
        json.dumps(watch) + "\n")
    (home / "state" / "watch_state.json").write_text(json.dumps(
        {"seen": {f"ethereum|{ADDR_D}": {
            "impl": None, "admin": None,
            "owner": "0x1111111111111111111111111111111111111111",
            "code_hash": "0xabc", "checked_at": "2026-11-04"}}}))
    event = {"chain": "ethereum", "address": ADDR_D, "symbol": "tokend",
             "stake_usd": 150000.0, "changed": ["owner"],
             "before": {"owner": "0x2222222222222222222222222222222222222222"},
             "after": {"owner": "0x1111111111111111111111111111111111111111"},
             "detected_at": "2026-11-04", "block": 123}
    (home / "state" / "transition_events.jsonl").write_text(
        json.dumps(event) + "\n")
    return home


def _setup(tmp_path):
    db = tmp_path / "index.db"
    _make_index(db)
    home = _make_home(tmp_path)
    return db, home


def _keys(result):
    return {(h["chain"], h["address"]) for h in result["hits"]}


# -- parsing ----------------------------------------------------------

def test_parse_keywords_phrase_forms():
    kws = parse_keywords('delegatecall, "function withdraw", '
                         'phrase:onlyOwner, delegatecall')
    assert [k.text for k in kws] == [
        "delegatecall", "function withdraw", "onlyOwner"]
    assert [k.phrase for k in kws] == [False, True, True]


# -- lane semantics ----------------------------------------------------

def test_multi_keyword_and(tmp_path):
    db, home = _setup(tmp_path)
    r = unified_search(parse_keywords("delegatecall, tx.origin"),
                       index_db=db, continuous_home=home, limit=50)
    keys = _keys(r)
    # A has both in source; D has both across scanner findings.
    assert ("ethereum", ADDR_A) in keys
    assert ("ethereum", ADDR_D) in keys
    # B has delegatecall only -> excluded under AND.
    assert ("ethereum", ADDR_B) not in keys
    assert r["lane_status"]["keyword_index"].startswith("ok")


def test_or_mode(tmp_path):
    db, home = _setup(tmp_path)
    r = unified_search(parse_keywords("delegatecall, tx.origin"),
                       mode="or", index_db=db, continuous_home=home,
                       limit=50)
    keys = _keys(r)
    assert ("ethereum", ADDR_B) in keys  # delegatecall alone is enough


def test_phrase_keyword(tmp_path):
    db, home = _setup(tmp_path)
    r = unified_search(parse_keywords('"function withdraw"'),
                       index_db=db, continuous_home=home, limit=50)
    hit = [h for h in r["hits"] if h["address"] == ADDR_C]
    assert hit and "keyword_index" in hit[0]["lanes"]
    assert hit[0]["line"] == 2
    assert "function withdraw" in hit[0]["snippets"]["keyword_index"]


def test_cross_lane_dedupe(tmp_path):
    db, home = _setup(tmp_path)
    # ADDR_D: symbol "tokend" is in both the scanner's batches and the
    # transition watchlist -> one deduped hit carrying both lanes.
    r = unified_search(parse_keywords("tokend"),
                       index_db=db, continuous_home=home, limit=50)
    d_hits = [h for h in r["hits"] if h["address"] == ADDR_D]
    assert len(d_hits) == 1  # one deduped hit, not one per lane
    assert set(d_hits[0]["lanes"]) == {"scanner", "transition_watch"}
    assert d_hits[0]["events"] and \
        d_hits[0]["events"][0]["changed"] == ["owner"]
    # ADDR_C: "withdraw" is in its indexed source AND in a scanner
    # queue row -> one hit, keyword_index + scanner.
    r = unified_search(parse_keywords("withdraw"),
                       index_db=db, continuous_home=home, limit=50)
    c_hits = [h for h in r["hits"] if h["address"] == ADDR_C]
    assert len(c_hits) == 1
    assert set(c_hits[0]["lanes"]) == {"keyword_index", "scanner"}


def test_chain_and_min_value_filters(tmp_path):
    db, home = _setup(tmp_path)
    r = unified_search(parse_keywords("delegatecall"),
                       chains={"bsc"}, index_db=db,
                       continuous_home=home, limit=50)
    assert _keys(r) == {("bsc", ADDR_C)}
    r = unified_search(parse_keywords("delegatecall"),
                       min_value=100000, index_db=db,
                       continuous_home=home, limit=50)
    keys = _keys(r)
    assert ("ethereum", ADDR_B) not in keys  # 500 < 100k
    assert ("ethereum", ADDR_A) in keys      # 500k
    assert ("ethereum", ADDR_D) in keys      # 150k


def test_missing_index_degrades(tmp_path):
    _, home = _setup(tmp_path)
    r = unified_search(parse_keywords("delegatecall"),
                       index_db=tmp_path / "nope.db",
                       continuous_home=home, limit=50)
    assert r["lane_status"]["keyword_index"].startswith("unavailable")
    # Other lanes still return their hits.
    assert ("ethereum", ADDR_D) in _keys(r)
    assert r["lane_status"]["scanner"].startswith("ok")


def test_enqueue_dedupes(tmp_path):
    db, home = _setup(tmp_path)
    r = unified_search(parse_keywords("delegatecall"),
                       index_db=db, continuous_home=home, limit=50,
                       enqueue=True)
    # A (500k) is new; C is already in the keyword_search queue;
    # D (150k) is already in batches.jsonl. Only A is enqueued.
    assert r["enqueued"] == 1
    rows = [json.loads(x) for x in
            (home / "state" / "queues" / "keyword_search.jsonl")
            .read_text().splitlines() if x.strip()]
    added = [x for x in rows if x["address"] == ADDR_A]
    assert added and added[0]["queue"] == "keyword_search"
    assert added[0]["term"].startswith("unified:")


# -- plugin wrapper -----------------------------------------------------

def _ctx():
    return Ctx(run_id="t", mode="passive", http=None, cache=None,
               keys={})


def test_plugin_no_query_is_quiet_ok(tmp_path):
    plugin = UnifiedKeywordSearchPlugin()
    res = asyncio.run(plugin.run(
        Target(raw="example.com", type="domain"), _ctx()))
    assert res.status.value == "ok"
    assert res.findings == []
    assert "no keyword query" in res.reason


def test_plugin_runs_search(tmp_path, monkeypatch):
    db, home = _setup(tmp_path)
    monkeypatch.setenv("RECON_KW_INDEX_DB", str(db))
    monkeypatch.setenv("RECON_CONTINUOUS_HOME", str(home))
    plugin = UnifiedKeywordSearchPlugin()
    res = asyncio.run(plugin.run(
        Target(raw="delegatecall, tx.origin", type="keyword_search"),
        _ctx()))
    assert res.status.value == "ok"
    addrs = {f.evidence["address"] for f in res.findings}
    assert ADDR_A in addrs and ADDR_D in addrs
    for f in res.findings:
        assert f.key == "unified_keyword_match"
        assert f.value.startswith("LEAD:")
        assert f.evidence["lanes"]


def test_registry_count_includes_unified_search():
    reg = discover()
    assert "unified_keyword_search" in reg
    assert len(reg) == 1106  # 841 + this plugin + 5 deep-audit batch-10 detectors (deep_audit10) + 6 beyond-recon plugins (nuclei_templates, lifecycle, content_discovery, param_discovery_arjun, js_linkfinder, wayback_surface) + 5 sec_* secret-exposure detectors (secretpack) + 1 idorleak detector (idor-error-leak) + 1 meta_orchestrator plugin (PR #77) + 10 Tier-1 OSINT plugins (PR #119) + 8 Tier-2 Enumeration plugins (PR #124) + 6 Tier-3 Fuzzing plugins (PR #121) + 10 Tier-4 Vuln/CVE plugins (PR #125) + 10 Tier-5 Orchestration plugins (PR #123) + 8 Tier-6 Detection plugins (PR #126) + 10 Tier-7 Blockchain Ingestion plugins (PR #127) + 5 Tier-8 Static Analysis plugins (PR #129) + 8 Tier-9 plugins (PR #128) + 10 Tier-10 Mempool/MEV plugins (PR #130)
