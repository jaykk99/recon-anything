"""Offline tests for the fund-flow tracer (app/fundflow.py).

No network: every test runs on recorded Blockscout responses saved
under tests/fixtures/fundflow/ or on synthetic items. Run from the
repo root (backend/) with ``pytest tests/test_fundflow.py -q``.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.fundflow import (  # noqa: E402
    build_graph,
    dedupe_edges,
    in_window,
    parse_token_transfer,
    parse_transaction,
    parse_transfer_log,
    render_summary,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "fundflow")

USDG_PROXY = "0xe343167631d89b6ffc58b88d6b7fb0228795491d"
KBTC_PROXY = "0x73e0c0d45e048d25fc26fa3159b0aa04bfa4db98"

# Verified live totals (Nov 11, 2026): tracer matched an independent
# direct Blockscout fetch for the same windows exactly. These are the
# labeled-test expectations; if Blockscout's history ever changes, the
# fixtures (not the numbers) are what to re-record.
USDG_EXPECTED_IN = {
    "0xe343167631d89b6ffc58b88d6b7fb0228795491d": 617506317,
    "0x0558d600cebb05c34f693b9df8a3b3d0a2f16698": 20000000000000000000,
    "0x3c89df6c17ca5c735498712d343387198e573383": 5000000000000000000,
    "0x53fdca91fd33b9131b5ceade42a3edbd9b38edff": 1000000000000000000,
    "0x2b591e99afe9f32eaa6214f7b7629768c40eeb39": 100000000,
    "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce": 3892530240000000000000000,
}
KBTC_EXPECTED_IN = {
    "0x73e0c0d45e048d25fc26fa3159b0aa04bfa4db98": 46893,
    "0xa49dc04d118bdf4a3471f593c1bba0c99b2187ea": 1029590000000000000000,
    "0x2b591e99afe9f32eaa6214f7b7629768c40eeb39": 100000000,
    "0xaea46a60368a7bd060eec7df8cba43b7ef41ad85": 1100100000000000,
}


def _load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return json.load(fh)


def _usdg_item(**over):
    item = {
        "from": {"hash": "0xeaeaa6d1891037f74ce54db935eef03212e6036b"},
        "to": {"hash": USDG_PROXY},
        "total": {"value": "617506317", "decimals": "6"},
        "token": {"address_hash": USDG_PROXY, "symbol": "USDG",
                  "decimals": "6"},
        "block_number": 25954844,
        "transaction_hash": "0x" + "ab" * 32,
        "log_index": 7,
    }
    item.update(over)
    return item


def test_parse_token_transfer_scales_by_decimals():
    edge = parse_token_transfer(_usdg_item(), hop=1)
    assert edge is not None
    assert edge["amount_raw"] == 617506317
    assert edge["amount"] == pytest.approx(617.506317)
    assert edge["decimals"] == 6
    assert edge["asset"] == USDG_PROXY
    assert edge["symbol"] == "USDG"
    assert edge["log_index"] == 7


def test_parse_token_transfer_distinct_tokens_same_symbol():
    # Two contracts can share a symbol (USDG). Totals must key on the
    # token contract address, never the symbol.
    a = parse_token_transfer(_usdg_item(), hop=1)
    b = parse_token_transfer(_usdg_item(
        token={"address_hash": "0x0558d600cebb05c34f693b9df8a3b3d0a2f16698",
               "symbol": "USDG", "decimals": "18"},
        total={"value": "20000000000000000000", "decimals": "18"}), hop=1)
    assert a["asset"] != b["asset"]
    assert a["symbol"] == b["symbol"] == "USDG"
    assert b["amount"] == pytest.approx(20.0)


def test_parse_token_transfer_zero_value_skipped():
    assert parse_token_transfer(_usdg_item(total={"value": "0", "decimals": "6"}), 1) is None


def test_parse_transaction_native_only():
    native = {
        "from": {"hash": "0x1111111111111111111111111111111111111111"},
        "to": {"hash": "0x2222222222222222222222222222222222222222"},
        "value": "1000000000000000000",
        "block_number": 26000000,
        "hash": "0x" + "cd" * 32,
    }
    edge = parse_transaction(native, hop=1, native_symbol="ETH")
    assert edge is not None
    assert edge["amount_raw"] == 10 ** 18
    assert edge["amount"] == pytest.approx(1.0)
    assert edge["asset"] == "ETH"
    assert parse_transaction(dict(native, value="0"), 1, "ETH") is None
    assert parse_transaction(dict(native, block_number=None), 1, "ETH") is None
    assert parse_transaction(dict(native, to=None), 1, "ETH") is None


def test_parse_transfer_log_signature_gate():
    transfer_topic = ("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
    log = {
        "address": USDG_PROXY,
        "topics": [transfer_topic,
                   "0x000000000000000000000000eaeaa6d1891037f74ce54db935eef03212e6036b",
                   "0x000000000000000000000000e343167631d89b6ffc58b88d6b7fb0228795491d"],
        "data": "0x0000000000000000000000000000000000000000000000000000000024ce660d",
        "blockNumber": "0x18bfe3c",
        "logIndex": "0x7",
        "transactionHash": "0x" + "ef" * 32,
    }
    edge = parse_transfer_log(log, hop=1)
    assert edge is not None
    assert edge["amount_raw"] == 617506317
    assert edge["from"] == "0xeaeaa6d1891037f74ce54db935eef03212e6036b"
    assert edge["to"] == USDG_PROXY
    wrong_topic = dict(log, topics=["0x" + "00" * 32] + log["topics"][1:])
    assert parse_transfer_log(wrong_topic, 1) is None
    assert parse_transfer_log(dict(log, topics=log["topics"][:2]), 1) is None


def test_in_window():
    assert in_window({"block_number": 100}, 90, 110)
    assert not in_window({"block_number": 89}, 90, 110)
    assert not in_window({"block_number": None}, 90, 110)
    assert not in_window({}, 90, 110)


def test_dedupe_edges_log_index():
    a = _usdg_item()
    e1 = parse_token_transfer(a, 1)
    e2 = parse_token_transfer(a, 1)  # exact duplicate
    e3 = parse_token_transfer(_usdg_item(log_index=8), 1)  # same tx, other log
    assert len(dedupe_edges([e1, e2])) == 1
    assert len(dedupe_edges([e1, e3])) == 2


def test_build_graph_seed_totals():
    edges = [
        parse_token_transfer(_usdg_item(), 1),
        parse_token_transfer(_usdg_item(
            **{"from": {"hash": "0x3333333333333333333333333333333333333333"},
               "total": {"value": "1000000", "decimals": "6"}}), 1),
    ]
    graph = build_graph(USDG_PROXY, edges,
                        kinds={USDG_PROXY: "contract"})
    assert graph["summary"]["seed_total_in_raw"] == {USDG_PROXY: 618506317}
    assert graph["summary"]["seed_total_out_raw"] == {}
    assert graph["nodes"][USDG_PROXY]["kind"] == "contract"
    assert graph["nodes"][USDG_PROXY]["tx_count"] == 2


def test_full_recorded_fixture_totals_usdg():
    data = _load_fixture("usdg_proxy_token_transfers.json")
    edges = [parse_token_transfer(i, 1) for i in data["items"]]
    edges = [e for e in edges if e is not None]
    graph = build_graph(USDG_PROXY, edges)
    assert len(graph["edges"]) == 19
    assert graph["summary"]["seed_total_in_raw"] == USDG_EXPECTED_IN
    assert graph["summary"]["seed_total_out_raw"] == {}
    assert len(graph["nodes"]) == 14


def test_full_recorded_fixture_totals_kbtc():
    data = _load_fixture("kbtc_proxy_token_transfers.json")
    edges = [parse_token_transfer(i, 1) for i in data["items"]]
    edges = [e for e in edges if e is not None]
    graph = build_graph(KBTC_PROXY, edges)
    assert len(graph["edges"]) == 7
    assert graph["summary"]["seed_total_in_raw"] == KBTC_EXPECTED_IN
    assert graph["summary"]["seed_total_out_raw"] == {}
    assert len(graph["nodes"]) == 6


def test_render_summary_names_top_counterparties():
    data = _load_fixture("usdg_proxy_token_transfers.json")
    edges = [e for e in (parse_token_transfer(i, 1) for i in data["items"]) if e]
    graph = build_graph(USDG_PROXY, edges,
                        kinds={USDG_PROXY: "contract"})
    text = render_summary(graph, "ethereum", 22367928, 25954844, 1)
    assert USDG_PROXY in text
    assert "19 edges" in text
    assert "No attribution" in text
    # Top counterparty (most edges) is named, with its kind.
    assert "0xeaeaa6d1891037f74ce54db935eef03212e6036b" in text
