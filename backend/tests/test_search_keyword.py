"""Keyword search must find contracts by vulnerability kind, symbol and
plugin - not only by function/name text. Regression guard for the index
coverage: without the kinds/symbol/plugins being indexed, a search for
"selfdestruct" or "delegatecall" returns nothing even when contracts carry
those finding kinds.
"""
import gzip
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app.search as search  # noqa: E402

_ROWS = [
    {"chain": "ethereum", "address": "0x" + "1" * 40, "name": "VaultToken",
     "symbol": "VLT", "functions": ["withdrawAll", "setOwner"],
     "kinds": ["full_balance_withdraw", "selfdestruct"],
     "plugins": ["contract_chain"], "doc": "vault"},
    {"chain": "bsc", "address": "0x" + "2" * 40, "name": "SafeCoin",
     "symbol": "SAFE", "functions": ["transfer"], "kinds": [],
     "plugins": ["erc20"], "doc": "token"},
    {"chain": "base", "address": "0x" + "3" * 40, "name": "ProxyThing",
     "symbol": "PRX", "functions": ["forward"], "kinds": ["delegatecall"],
     "plugins": ["proxy"], "doc": "proxy"},
]


def _corpus():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "corpus.jsonl.gz")
    with gzip.open(p, "wt") as f:
        for r in _ROWS:
            f.write(json.dumps(r) + "\n")
    return p


def test_search_by_kind_symbol_and_plugin(monkeypatch):
    monkeypatch.setenv("RECON_SEARCH_CORPUS", _corpus())
    # force a fresh index bound to our corpus
    search._db = None

    def addrs(q):
        return {r["address"] for r in search.search(q=q, limit=10)["results"]}

    assert addrs("selfdestruct") == {"0x" + "1" * 40}
    assert addrs("delegatecall") == {"0x" + "3" * 40}
    assert addrs("withdraw") == {"0x" + "1" * 40}   # split of withdrawAll
    assert addrs("balance") == {"0x" + "1" * 40}    # split of full_balance_*
    assert addrs("safe") == {"0x" + "2" * 40}       # symbol / name
    search._db = None
