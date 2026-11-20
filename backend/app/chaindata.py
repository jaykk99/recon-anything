"""Pure chain-OSINT data: the chain registry + explorer-response parsers.

Split out of the chain_enrich plugin so it carries no httpx/network
import and unit-tests on its own. The plugin does the HTTP; this module
only knows how to route a chain tag and parse what each source returns.

Sources are keyless-first (2026-11-14): Blockchair now answers HTTP 430
without an API key and Tronscan 429s at its keyless quota, so those are
no longer the only route. Bitcoin/Litecoin use Esplora (mempool.space /
litecoinspace), Dogecoin uses dogechain.info, Dash uses its Insight API,
Tron uses TronGrid before Tronscan, and Cardano/TON/Sui/Aptos gained
live lanes (Koios / Toncenter / Sui GraphQL / Aptos fullnode). Chains
with no keyless API left (BCH, ZEC, and Polkadot's key-gated Subscan)
fall back to Blockchair and report degradation honestly instead of
looking clean.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional

# Chain tag (from the detector key prefix) -> how to enrich it.
# kind: esplora | blockchair | dogechain | dash | tron | xrp | solana |
#       cardano | ton | sui | aptos | label_only
CHAINS: Dict[str, Dict[str, str]] = {
    "btc":   {"kind": "esplora", "base": "https://mempool.space/api",
              "name": "Bitcoin"},
    "bch":   {"kind": "blockchair", "slug": "bitcoin-cash",
              "name": "Bitcoin Cash"},
    "ltc":   {"kind": "esplora", "base": "https://litecoinspace.org/api",
              "name": "Litecoin"},
    "doge":  {"kind": "dogechain", "name": "Dogecoin"},
    "dash":  {"kind": "dash", "name": "Dash"},
    "zec":   {"kind": "blockchair", "slug": "zcash", "name": "Zcash"},
    "grs":   {"kind": "label_only", "slug": "groestlcoin",
              "name": "Groestlcoin"},
    "trx":   {"kind": "tron", "slug": "", "name": "Tron"},
    "xrp":   {"kind": "xrp", "slug": "", "name": "XRP Ledger"},
    "sol":   {"kind": "solana", "slug": "", "name": "Solana"},
    "ada":   {"kind": "cardano", "name": "Cardano"},
    "ton":   {"kind": "ton", "name": "TON"},
    "sui":   {"kind": "sui", "name": "Sui"},
    "aptos": {"kind": "aptos", "name": "Aptos"},
    "xmr":   {"kind": "label_only", "slug": "", "name": "Monero"},
    # Polkadot's only public account API (Subscan) is key-gated
    # (HTTP 403 unauthenticated), so there is nothing keyless to call.
    "dot":   {"kind": "label_only", "slug": "", "name": "Polkadot"},
    "xlm":   {"kind": "label_only", "slug": "", "name": "Stellar"},
    "kaspa": {"kind": "label_only", "slug": "", "name": "Kaspa"},
    "eth":   {"kind": "label_only", "slug": "", "name": "Ethereum"},
}

BLOCKCHAIR = "https://api.blockchair.com/{slug}/dashboards/address/{addr}"
TRONSCAN = "https://apilist.tronscanapi.com/api/account?address={addr}"
TRONGRID = "https://api.trongrid.io/v1/accounts/{addr}"
XRPSCAN = "https://api.xrpscan.com/api/v1/account/{addr}"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
DOGECHAIN = "https://dogechain.info/api/v1/address/balance/{addr}"
DASH_INSIGHT = "https://insight.dash.org/insight-api/addr/{addr}"
KOIOS = "https://api.koios.rest/api/v1/address_info"
TONCENTER = "https://toncenter.com/api/v2/getAddressInformation?address={addr}"
SUI_GRAPHQL = "https://graphql.mainnet.sui.io/graphql"
SUI_COIN_TYPE = "0x2::sui::SUI"
APTOS_ACCOUNTS = ("https://fullnode.mainnet.aptoslabs.com/v1/accounts/"
                  "{addr}/resources")
APTOS_COIN_STORE = "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"

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


def parse_esplora(data: Dict[str, Any], addr: str) -> Dict[str, Any]:
    """Esplora/mempool.space address payload (Bitcoin, Litecoin)."""
    stats = (data or {}).get("chain_stats") or {}
    if not stats:
        return {}
    funded = int(stats.get("funded_txo_sum") or 0)
    spent = int(stats.get("spent_txo_sum") or 0)
    mem = (data or {}).get("mempool_stats") or {}
    return {
        "balance": round((funded - spent) / 1e8, 8),
        "tx_count": int(stats.get("tx_count") or 0)
                    + int(mem.get("tx_count") or 0),
        "received": round(funded / 1e8, 8),
        "spent": round(spent / 1e8, 8),
    }


def parse_dogechain(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict) or not data.get("success"):
        return {}
    try:
        bal = float(data.get("balance") or 0)
    except (TypeError, ValueError):
        return {}
    return {"balance": round(bal, 8)}


def parse_dash_insight(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict) or "balanceSat" not in data:
        return {}
    # Insight spells the field "txApperances" (sic) in several builds.
    count = (data.get("txApperances") or data.get("txAppearances")
             or len(data.get("transactions") or []))
    return {
        "balance": round(_coin(data.get("balanceSat") or 0), 8),
        "tx_count": int(count or 0),
        "received": round(_coin(data.get("totalReceivedSat") or 0), 8),
    }


def parse_trongrid(data: Dict[str, Any]) -> Dict[str, Any]:
    """TronGrid /v1/accounts payload."""
    rows = (data or {}).get("data") or []
    if not rows or not isinstance(rows[0], dict):
        return {}
    row = rows[0]
    return {
        "balance": round(_coin(row.get("balance") or 0, 6), 6),
        "tx_count": int(row.get("totalTransactionCount")
                        or row.get("transactions") or 0),
        "first_seen": str(row.get("date_created") or "")[:10],
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


def parse_koios(data: Any) -> Dict[str, Any]:
    """Koios address_info: [{balance, ...}] - balance is lovelace."""
    try:
        rows = data if isinstance(data, list) else []
        if not rows or not isinstance(rows[0], dict):
            return {}
        row = rows[0]
        return {
            "balance": round(_coin(row.get("balance") or 0, 6), 6),
            "tx_count": int(row.get("tx_count") or 0),
        }
    except Exception:
        return {}


def parse_ton(data: Dict[str, Any]) -> Dict[str, Any]:
    res = (data.get("result") or {}) if isinstance(data, dict) else {}
    if not res or data.get("ok") is not True:
        return {}
    return {"balance": round(_coin(res.get("balance") or 0, 9), 9)}


def parse_sui(data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        bal = (((data.get("data") or {}).get("address") or {})
               .get("balance") or {}).get("totalBalance")
        if bal is None:
            return {}
        return {"balance": round(int(bal) / 1e9, 9)}
    except Exception:
        return {}


def parse_aptos(data: Any) -> Dict[str, Any]:
    """Aptos /accounts/{addr}/resources: find the native coin store."""
    rows = data if isinstance(data, list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("type", "")) != APTOS_COIN_STORE:
            continue
        val = (((row.get("data") or {}).get("coin") or {}).get("value"))
        try:
            return {"balance": round(int(val) / 1e8, 8)}
        except (TypeError, ValueError):
            return {}
    # A live account with no coin store simply holds no APT.
    return {"balance": 0.0} if rows else {}


def explorer_url(addr: str, chain: str) -> Optional[str]:
    urls = {
        "btc": f"https://mempool.space/address/{addr}",
        "bch": f"https://blockchair.com/bitcoin-cash/address/{addr}",
        "ltc": f"https://litecoinspace.org/address/{addr}",
        "doge": f"https://dogechain.info/address/{addr}",
        "dash": f"https://insight.dash.org/insight/address/{addr}",
        "zec": f"https://blockchair.com/zcash/address/{addr}",
        "trx": f"https://tronscan.org/#/address/{addr}",
        "xrp": f"https://xrpscan.com/account/{addr}",
        "sol": f"https://solscan.io/account/{addr}",
        "eth": f"https://etherscan.io/address/{addr}",
        "ada": f"https://cardanoscan.io/address/{addr}",
        "ton": f"https://tonviewer.com/{addr}",
        "sui": f"https://suivision.xyz/account/{addr}",
        "aptos": f"https://explorer.aptoslabs.com/account/{addr}",
        "dot": f"https://polkadot.subscan.io/account/{addr}",
        "avax": f"https://snowtrace.io/address/{addr}",
        "xmr": None,
    }
    return urls.get(chain)
