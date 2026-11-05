"""Pure chain-OSINT data: the chain registry + explorer-response parsers.

Split out of the chain_enrich plugin so it carries no httpx/network
import and unit-tests on its own. The plugin does the HTTP; this module
only knows how to route a chain tag and parse what each source returns.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Dict, Optional

# Chain tag (from the detector key prefix) -> how to enrich it.
# kind: blockchair | tron | xrp | solana | label_only
CHAINS: Dict[str, Dict[str, str]] = {
    "btc":   {"kind": "blockchair", "slug": "bitcoin",      "name": "Bitcoin"},
    "bch":   {"kind": "blockchair", "slug": "bitcoin-cash", "name": "Bitcoin Cash"},
    "ltc":   {"kind": "blockchair", "slug": "litecoin",     "name": "Litecoin"},
    "doge":  {"kind": "blockchair", "slug": "dogecoin",     "name": "Dogecoin"},
    "dash":  {"kind": "blockchair", "slug": "dash",         "name": "Dash"},
    "zec":   {"kind": "blockchair", "slug": "zcash",        "name": "Zcash"},
    "grs":   {"kind": "blockchair", "slug": "groestlcoin",  "name": "Groestlcoin"},
    "trx":   {"kind": "tron",       "slug": "",             "name": "Tron"},
    "xrp":   {"kind": "xrp",        "slug": "",             "name": "XRP Ledger"},
    "sol":   {"kind": "solana",     "slug": "",             "name": "Solana"},
    "xmr":   {"kind": "label_only", "slug": "", "name": "Monero"},
    "ada":   {"kind": "label_only", "slug": "", "name": "Cardano"},
    "dot":   {"kind": "label_only", "slug": "", "name": "Polkadot"},
    "ton":   {"kind": "label_only", "slug": "", "name": "TON"},
    "xlm":   {"kind": "label_only", "slug": "", "name": "Stellar"},
    "kaspa": {"kind": "label_only", "slug": "", "name": "Kaspa"},
    "eth":   {"kind": "label_only", "slug": "", "name": "Ethereum"},
}

BLOCKCHAIR = "https://api.blockchair.com/{slug}/dashboards/address/{addr}"
TRONSCAN = "https://apilist.tronscanapi.com/api/account?address={addr}"
XRPSCAN = "https://api.xrpscan.com/api/v1/account/{addr}"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"


def _coin(v: Any, decimals: int = 8) -> float:
    try:
        return int(v) / (10 ** decimals)
    except (TypeError, ValueError):
        return 0.0


def parse_blockchair(data: Dict[str, Any], addr: str) -> Dict[str, Any]:
    info = ((data.get("data") or {}).get(addr) or {})
    a = info.get("address") or {}
    if not a:
        return {}
    return {
        "balance": round(_coin(a.get("balance") or 0), 8),
        "tx_count": int(a.get("transaction_count") or 0),
        "received": round(_coin(a.get("received") or 0), 8),
        "spent": round(_coin(a.get("spent") or 0), 8),
        "first_seen": str(a.get("first_seen_receiving") or "")[:10],
        "last_seen": str(a.get("last_seen_spending")
                         or a.get("last_seen_receiving") or "")[:10],
    }


def parse_tron(data: Dict[str, Any]) -> Dict[str, Any]:
    if not data:
        return {}
    bal = 0.0
    try:
        bal = int(data.get("balance") or 0) / 1e6
    except (TypeError, ValueError):
        pass
    created = data.get("date_created")
    first = ""
    if created:
        try:
            first = dt.datetime.fromtimestamp(
                int(created) / 1000, dt.timezone.utc).date().isoformat()
        except Exception:
            first = ""
    return {
        "balance": round(bal, 6),
        "tx_count": int(data.get("totalTransactionCount")
                        or data.get("transactions") or 0),
        "first_seen": first,
    }


def parse_xrp(data: Dict[str, Any]) -> Dict[str, Any]:
    if not data:
        return {}
    bal = 0.0
    raw = data.get("xrpBalance") or data.get("Balance")
    try:
        bal = float(raw) if "." in str(raw) else int(raw) / 1e6
    except (TypeError, ValueError):
        pass
    return {
        "balance": round(bal, 6),
        "tx_count": int(data.get("sequence") or 0),
        "first_seen": str(data.get("inception") or "")[:10],
    }


def parse_solana_balance(data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        lamports = (data.get("result") or {}).get("value")
        if lamports is None:
            return {}
        return {"balance": round(int(lamports) / 1e9, 9)}
    except Exception:
        return {}


def explorer_url(addr: str, chain: str) -> Optional[str]:
    urls = {
        "btc": f"https://blockchair.com/bitcoin/address/{addr}",
        "bch": f"https://blockchair.com/bitcoin-cash/address/{addr}",
        "ltc": f"https://blockchair.com/litecoin/address/{addr}",
        "doge": f"https://blockchair.com/dogecoin/address/{addr}",
        "dash": f"https://blockchair.com/dash/address/{addr}",
        "zec": f"https://blockchair.com/zcash/address/{addr}",
        "trx": f"https://tronscan.org/#/address/{addr}",
        "xrp": f"https://xrpscan.com/account/{addr}",
        "sol": f"https://solscan.io/account/{addr}",
        "eth": f"https://etherscan.io/address/{addr}",
        "ada": f"https://cardanoscan.io/address/{addr}",
        "xmr": None,
    }
    return urls.get(chain)
