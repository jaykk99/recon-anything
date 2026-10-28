"""Unit gate for multi-chain enrichment parsers + address labeling.

Pure-stdlib (no network, no app deps beyond the two modules), so it runs
anywhere. Validates the explorer-response parsers on fixtures, the
chain-routing registry, and the public label set / heuristics.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.chaindata import (
    CHAINS, parse_blockchair, parse_tron, parse_xrp, parse_solana_balance,
)
from app.cryptolabels import labels_for, summarize_label, LABELS


# ---- parsers --------------------------------------------------------------

def test_parse_blockchair():
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    data = {"data": {addr: {"address": {
        "balance": 1500000000,  # 15 BTC in sats
        "transaction_count": 42,
        "received": 2000000000, "spent": 500000000,
        "first_seen_receiving": "2011-01-03 18:15:05",
        "last_seen_spending": "2024-06-01 10:00:00"}}}}
    p = parse_blockchair(data, addr)
    assert p["balance"] == 15.0, p
    assert p["tx_count"] == 42
    assert p["received"] == 20.0 and p["spent"] == 5.0
    assert p["first_seen"] == "2011-01-03"
    assert p["last_seen"] == "2024-06-01"


def test_parse_blockchair_miss():
    assert parse_blockchair({"data": {}}, "x") == {}
    assert parse_blockchair({}, "x") == {}


def test_parse_tron():
    p = parse_tron({"balance": 12345678, "totalTransactionCount": 7,
                    "date_created": 1609459200000})
    assert p["balance"] == 12.345678
    assert p["tx_count"] == 7
    assert p["first_seen"] == "2021-01-01"


def test_parse_xrp():
    p = parse_xrp({"xrpBalance": "25.5", "sequence": 10, "inception": "2020-05-01T00:00:00Z"})
    assert p["balance"] == 25.5
    assert p["tx_count"] == 10
    assert p["first_seen"] == "2020-05-01"


def test_parse_solana():
    assert parse_solana_balance({"result": {"value": 2500000000}})["balance"] == 2.5
    assert parse_solana_balance({"result": {"value": None}}) == {}
    assert parse_solana_balance({}) == {}


def test_chain_registry():
    assert CHAINS["btc"]["kind"] == "blockchair" and CHAINS["btc"]["slug"] == "bitcoin"
    assert CHAINS["doge"]["slug"] == "dogecoin"
    assert CHAINS["sol"]["kind"] == "solana"
    assert CHAINS["trx"]["kind"] == "tron"
    assert CHAINS["xmr"]["kind"] == "label_only"
    assert CHAINS["eth"]["kind"] == "label_only"  # chain_osint owns ETH balance


# ---- labels ---------------------------------------------------------------

def test_null_address_is_burn():
    labs = labels_for("0x0000000000000000000000000000000000000000", "eth")
    assert labs and labs[0]["category"] == "burn"


def test_tornado_is_sanctioned():
    labs = labels_for("0x8589427373d6d84e98730d7795d8f6f8731fda16", "eth")
    assert any(l["category"] == "sanctioned" and l["severity"] == "high" for l in labs)


def test_exchange_label():
    labs = labels_for("0x28c6c06298d514db089934071355e5743bf21d60", "eth")
    assert any(l["category"] == "exchange" for l in labs)


def test_mixer_by_contract_name():
    labs = labels_for("0xabc0000000000000000000000000000000000001", "eth",
                      contract_name="TornadoCashProxy", verified=True)
    assert any(l["category"] == "mixer" and l["severity"] == "high" for l in labs)


def test_bridge_by_contract_name():
    labs = labels_for("0xabc0000000000000000000000000000000000002", "eth",
                      contract_name="WormholeBridge", verified=True)
    assert any(l["category"] == "bridge" for l in labs)


def test_burnish_heuristic():
    labs = labels_for("0x000000000000abcdef0000000000000000000000", "eth")
    assert any(l["category"] == "burn" for l in labs)


def test_unknown_address_no_labels():
    assert labels_for("0x1234567890abcdef1234567890abcdef12345678", "eth") == []
    assert labels_for("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc") == []


def test_summarize():
    labs = labels_for("0x8589427373d6d84e98730d7795d8f6f8731fda16", "eth")
    s = summarize_label(labs)
    assert s and "sanctioned" in s
    assert summarize_label([]) is None


def test_label_set_is_lowercased_and_valid():
    for addr, meta in LABELS.items():
        assert addr == addr.lower(), addr
        assert meta.get("label") and meta.get("category") and meta.get("severity")


def test_labels_never_raise():
    for bad in (None, "", 123, "notanaddr", {"x": 1}):
        try:
            labels_for(bad)  # type: ignore
        except Exception as e:
            raise AssertionError(f"labels_for raised on {bad!r}: {e}")


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} chain-enrich tests passed")


if __name__ == "__main__":
    _run_all()
