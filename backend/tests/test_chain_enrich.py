"""Unit gate for multi-chain enrichment parsers + address labeling.

Pure-stdlib (no network, no app deps beyond the two modules), so it runs
anywhere. Validates the explorer-response parsers on fixtures, the
chain-routing registry, and the public label set / heuristics.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.chaindata import (
    CHAINS, parse_aptos, parse_blockchair, parse_dash_insight,
    parse_dogechain, parse_esplora, parse_koios, parse_solana_balance,
    parse_sui, parse_ton, parse_tron, parse_trongrid, parse_xrp,
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


def test_parse_esplora():
    data = {"address": "bc1x", "chain_stats": {
        "funded_txo_sum": 250000000, "spent_txo_sum": 50000000,
        "tx_count": 9}, "mempool_stats": {"tx_count": 1}}
    p = parse_esplora(data, "bc1x")
    assert p["balance"] == 2.0 and p["received"] == 2.5
    assert p["tx_count"] == 10
    assert parse_esplora({}, "x") == {}


def test_parse_dogechain():
    assert parse_dogechain({"success": 1, "balance": "12.5"})["balance"] == 12.5
    assert parse_dogechain({"success": 0}) == {}


def test_parse_dash_insight():
    p = parse_dash_insight({"balanceSat": 150000000, "txApperances": 4,
                            "totalReceivedSat": 300000000})
    assert p["balance"] == 1.5 and p["tx_count"] == 4
    assert parse_dash_insight({}) == {}


def test_parse_trongrid():
    p = parse_trongrid({"data": [{"balance": 2500000,
                                   "totalTransactionCount": 3}]})
    assert p["balance"] == 2.5 and p["tx_count"] == 3
    assert parse_trongrid({"data": []}) == {}


def test_parse_koios():
    assert parse_koios([{"balance": "2500000"}])["balance"] == 2.5
    assert parse_koios([]) == {}


def test_parse_ton():
    assert parse_ton({"ok": True, "result": {"balance": "2000000000"}})["balance"] == 2.0
    assert parse_ton({"ok": False}) == {}


def test_parse_sui():
    p = parse_sui({"data": {"address": {"balance": {"totalBalance": "2400000000"}}}})
    assert p["balance"] == 2.4
    assert parse_sui({"errors": []}) == {}


def test_parse_aptos():
    rows = [{"type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
             "data": {"coin": {"value": "150000000"}}}]
    assert parse_aptos(rows)["balance"] == 1.5
    # A live account with resources but no native coin store holds 0 APT.
    assert parse_aptos([{"type": "0x1::other::Thing"}]) == {"balance": 0.0}
    assert parse_aptos({"error_code": "resource_not_found"}) == {}


def test_chain_registry():
    # Keyless-first sources: Blockchair now 430s without a key, so
    # BTC/LTC route to Esplora and DOGE to dogechain.info.
    assert CHAINS["btc"]["kind"] == "esplora"
    assert "mempool.space" in CHAINS["btc"]["base"]
    assert CHAINS["ltc"]["kind"] == "esplora"
    assert CHAINS["doge"]["kind"] == "dogechain"
    assert CHAINS["dash"]["kind"] == "dash"
    assert CHAINS["bch"]["kind"] == "blockchair"  # no keyless source left
    assert CHAINS["sol"]["kind"] == "solana"
    assert CHAINS["trx"]["kind"] == "tron"
    assert CHAINS["ada"]["kind"] == "cardano"
    assert CHAINS["ton"]["kind"] == "ton"
    assert CHAINS["sui"]["kind"] == "sui"
    assert CHAINS["aptos"]["kind"] == "aptos"
    assert CHAINS["xmr"]["kind"] == "label_only"
    assert CHAINS["dot"]["kind"] == "label_only"  # Subscan is key-gated
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
