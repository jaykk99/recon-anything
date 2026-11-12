"""Keyless sources for fund-flow tracing (Blockscout + public RPC).

KEYLESS ONLY. No API keys, no sign-ins, no paid routes, no new accounts.
Every call here works with no credentials at all; a 401/403 from any
source raises SourceError and the tracer refuses to use that source,
rather than reaching for a key.

Primary: Blockscout v2 REST, per chain
    /api/v2/addresses/{address}/token-transfers
    /api/v2/addresses/{address}/transactions
    /api/v2/addresses/{address}            (is_contract)
Fallback: public RPC eth_getLogs (Transfer events) + eth_getCode.
    Only these read-only methods are ever called:
    eth_getCode, eth_getLogs, eth_blockNumber, eth_chainId,
    eth_getBlockByNumber. Nothing else. No signing, no sending.

Blockscout facts learned live (Nov 2026, do not re-derive by guessing):
  - ``page_size`` is rejected ("Unexpected field: page_size"); the
    default page is 50 items and paging uses ``next_page_params``.
  - Token items use ``token.address_hash`` (there is no
    ``token.address``); ``total.value`` is the raw amount string and
    ``total.decimals`` / ``token.decimals`` are strings.
  - The transactions endpoint returns pending txs with
    ``block_number: null``; callers must drop those.
  - Two different contracts can share a symbol (USDG); totals must key
    on the token contract address, never the symbol.
  - Items arrive newest-first; paging stops when a page's oldest item
    falls below the window floor, or when next_page_params is absent.
"""

import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

try:
    from .net import sync_client  # type: ignore
except Exception:  # pragma: no cover - standalone / offline use
    sync_client = None  # type: ignore

try:
    from .rpc_guard import (  # type: ignore
        RpcWriteBlocked,
        assert_payload_read_only,
        enforce_read_only_env,
    )
except Exception:  # pragma: no cover - standalone / offline use
    RpcWriteBlocked = RuntimeError  # type: ignore

    def assert_payload_read_only(payload: Any) -> None:
        return None

    def enforce_read_only_env(environ=None) -> None:
        return None


class SourceError(Exception):
    """A keyless source failed, or demanded auth (caller must not retry
    with a key)."""


# Read-only methods the tracer is allowed to call, anywhere.
RPC_ALLOWLIST = frozenset({
    "eth_getCode", "eth_getLogs", "eth_blockNumber",
    "eth_chainId", "eth_getBlockByNumber",
})

# Default pages (50 items each) fetched per address when the caller does
# not cap it. Hop-specific caps live in the CLI.
MAX_PAGES_PER_ADDRESS = 10
TIMEOUT_S = 30.0

CHAINS: Dict[str, Dict[str, Any]] = {
    "ethereum": {
        "blockscout": "https://eth.blockscout.com",
        "native": "ETH",
        "rpc": [
            "https://ethereum-rpc.publicnode.com",
            "https://rpc.flashbots.net",
            "https://eth-mainnet.public.blastapi.io",
        ],
    },
    "bsc": {
        "blockscout": "https://bscscan.com",
        "native": "BNB",
        "rpc": [
            "https://bsc-rpc.publicnode.com",
            "https://bsc-dataseed.binance.org",
        ],
    },
    "base": {
        "blockscout": "https://base.blockscout.com",
        "native": "ETH",
        "rpc": ["https://base-rpc.publicnode.com"],
    },
    "arbitrum": {
        "blockscout": "https://arbitrum.blockscout.com",
        "native": "ETH",
        "rpc": ["https://arbitrum-rpc.publicnode.com"],
    },
    "polygon": {
        "blockscout": "https://polygon.blockscout.com",
        "native": "MATIC",
        "rpc": ["https://polygon-rpc.com"],
    },
    "optimism": {
        "blockscout": "https://optimism.blockscout.com",
        "native": "ETH",
        "rpc": ["https://optimism-rpc.publicnode.com"],
    },
}


def chain_config(chain: str) -> Dict[str, Any]:
    key = chain.lower()
    if key not in CHAINS:
        raise SourceError(f"unsupported chain {chain!r}; supported: "
                          f"{', '.join(sorted(CHAINS))}")
    return CHAINS[key]


def _client() -> httpx.Client:
    """An httpx client: the repo's shared client inside the app (which
    carries the read-only RPC hardblock), plain httpx standalone.

    The sandbox proxy list in the environment contains bracketed IPv6
    entries that plain httpx.Client() chokes on, so the proxy URL is
    read explicitly and trust_env is off.
    """
    if sync_client is not None:
        return sync_client(timeout=TIMEOUT_S)
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") \
        or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    return httpx.Client(timeout=TIMEOUT_S, trust_env=False,
                        proxy=proxy or None)


def _get_json(client: httpx.Client, url: str, params: Optional[dict] = None,
              retries: int = 3) -> dict:
    """GET JSON with retries on 429/5xx and transport errors.

    A 401/403 is fatal immediately: it means the source demands auth,
    and keyless tracing must not fall back to a key.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            resp = client.get(url, params=params)
        except httpx.TransportError as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue
            raise SourceError(f"{url} transport failed: {exc}") from exc
        if resp.status_code in (401, 403):
            raise SourceError(
                f"{url} returned {resp.status_code}: source demands auth; "
                "keyless tracing cannot use it")
        if resp.status_code in (429, 500, 502, 503, 504) and attempt < retries:
            time.sleep(2 * (attempt + 1))
            continue
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise SourceError(f"{url} returned {resp.status_code}") from exc
        try:
            data = resp.json()
        except ValueError as exc:
            raise SourceError(f"{url} returned non-JSON") from exc
        if isinstance(data, dict) and data.get("errors"):
            raise SourceError(f"{url} returned API error: {data['errors']}")
        if not isinstance(data, dict):
            raise SourceError(f"{url} returned unexpected JSON shape")
        return data
    raise SourceError(f"{url} failed after retries: {last_exc}")


def _paginate(client: httpx.Client, url: str, from_block: int,
              max_pages: int = MAX_PAGES_PER_ADDRESS
              ) -> Tuple[List[dict], str, bool, Optional[int]]:
    """Follow Blockscout next_page_params until the window floor is hit.

    Items arrive newest-first. Paging stops when a page's oldest item is
    below from_block, or when next_page_params is absent. Returns
    (items, source, truncated, oldest_block_seen): ``truncated`` is True
    when the page cap stopped the fetch while items newer than the window
    floor were still arriving, i.e. coverage below the oldest seen block
    is NOT established. Callers must surface that, never imply full
    window coverage they do not have.
    """
    items: List[dict] = []
    params: Optional[dict] = None
    pages = 0
    oldest_seen: Optional[int] = None
    while pages < max_pages:
        data = _get_json(client, url, params=params)
        page_items = data.get("items") or []
        items.extend(page_items)
        pages += 1
        blocks = [i.get("block_number") for i in page_items
                  if isinstance(i.get("block_number"), int)]
        if blocks:
            page_oldest = min(blocks)
            oldest_seen = page_oldest if oldest_seen is None else min(oldest_seen, page_oldest)
        nxt = data.get("next_page_params")
        if not nxt:
            return items, "blockscout", False, oldest_seen
        if blocks and min(blocks) < from_block:
            return items, "blockscout", False, oldest_seen
        params = dict(nxt)
    # Page cap hit with more pages available.
    return items, "blockscout", True, oldest_seen


def fetch_token_transfers(chain: str, address: str, from_block: int,
                         to_block: int,
                         max_pages: int = MAX_PAGES_PER_ADDRESS
                         ) -> Tuple[List[dict], str, bool, Optional[int]]:
    """Token transfers for one address inside [from_block, to_block].

    Returns (items, source, truncated, oldest_block_seen). ``truncated``
    means the page cap stopped the fetch before the window floor: coverage
    below ``oldest_block_seen`` is not established.
    """
    from .fundflow import in_window  # local import: keeps module importable
    cfg = chain_config(chain)
    url = f"{cfg['blockscout']}/api/v2/addresses/{address}/token-transfers"
    with _client() as client:
        items, source, truncated, oldest = _paginate(client, url, from_block, max_pages)
    return [i for i in items if in_window(i, from_block, to_block)], source, truncated, oldest


def fetch_transactions(chain: str, address: str, from_block: int,
                      to_block: int,
                      max_pages: int = MAX_PAGES_PER_ADDRESS
                      ) -> Tuple[List[dict], str, bool, Optional[int]]:
    """Transactions for one address inside [from_block, to_block].

    Returns (items, source, truncated, oldest_block_seen); see
    :func:`fetch_token_transfers` for what ``truncated`` means.
    """
    from .fundflow import in_window
    cfg = chain_config(chain)
    url = f"{cfg['blockscout']}/api/v2/addresses/{address}/transactions"
    with _client() as client:
        items, source, truncated, oldest = _paginate(client, url, from_block, max_pages)
    return [i for i in items if in_window(i, from_block, to_block)], source, truncated, oldest


def fetch_address_kind(chain: str, address: str) -> Tuple[str, str]:
    """Contract vs EOA for one address (Blockscout address endpoint).

    Falls back to eth_getCode when Blockscout fails. Returns
    (kind, source). Unknown on total failure only when the caller
    catches SourceError; here a failure raises.
    """
    cfg = chain_config(chain)
    url = f"{cfg['blockscout']}/api/v2/addresses/{address}"
    try:
        with _client() as client:
            data = _get_json(client, url)
        return ("contract" if data.get("is_contract") else "eoa"), "blockscout"
    except SourceError:
        return rpc_get_code_kind(chain, address)


def rpc_call(chain: str, method: str, params: List[Any]) -> Any:
    """One read-only JSON-RPC call against the first working public RPC.

    Refuses any method outside RPC_ALLOWLIST and refuses to run when
    signing material is present in the environment (the repo guard).
    """
    if method not in RPC_ALLOWLIST:
        raise SourceError(f"refused RPC method {method!r}: not read-only")
    enforce_read_only_env()
    cfg = chain_config(chain)
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    assert_payload_read_only(payload)
    last_exc: Optional[Exception] = None
    for rpc_url in cfg["rpc"]:
        try:
            with _client() as client:
                resp = client.post(rpc_url, json=payload)
            if resp.status_code in (401, 403):
                raise SourceError(f"{rpc_url} returned {resp.status_code}: demands auth")
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001 - try next RPC
            last_exc = exc
            continue
        if isinstance(data, dict) and data.get("error"):
            raise SourceError(f"{rpc_url} RPC error: {data['error']}")
        return data.get("result") if isinstance(data, dict) else None
    raise SourceError(f"all public RPCs failed for {method}: {last_exc}")


def rpc_get_code_kind(chain: str, address: str) -> Tuple[str, str]:
    code = rpc_call(chain, "eth_getCode", [address, "latest"])
    if isinstance(code, str) and code not in ("0x", "0x0", ""):
        return "contract", "rpc:eth_getCode"
    return "eoa", "rpc:eth_getCode"


def rpc_get_code_kinds(chain: str, addresses: List[str]) -> Dict[str, str]:
    """Classify many addresses with batched eth_getCode (one HTTP call).

    Public RPCs accept a JSON-RPC batch array. Chunked to 50 calls per
    batch. Returns {address: "contract" | "eoa"} for the addresses the
    batch answered; anything unanswered is absent (caller falls back
    per address). The repo's rpc_guard explicitly handles batch lists.
    """
    enforce_read_only_env()
    cfg = chain_config(chain)
    addrs = sorted({a.lower() for a in addresses})
    out: Dict[str, str] = {}
    for start in range(0, len(addrs), 50):
        chunk = addrs[start:start + 50]
        batch = [{"jsonrpc": "2.0", "method": "eth_getCode",
                  "params": [a, "latest"], "id": i}
                 for i, a in enumerate(chunk)]
        assert_payload_read_only(batch)
        for rpc_url in cfg["rpc"]:
            try:
                with _client() as client:
                    resp = client.post(rpc_url, json=batch)
                if resp.status_code in (401, 403):
                    raise SourceError(f"{rpc_url} returned {resp.status_code}: demands auth")
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, list):
                    continue
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    idx = item.get("id")
                    if not isinstance(idx, int) or idx >= len(chunk):
                        continue
                    code = item.get("result")
                    out[chunk[idx]] = ("contract" if isinstance(code, str)
                                       and code not in ("0x", "0x0", "")
                                       else "eoa")
                break
            except Exception:
                continue
    return out


def rpc_transfer_logs(chain: str, address: str, from_block: int,
                     to_block: int) -> Tuple[List[dict], str]:
    """Raw Transfer logs for one address via public RPC eth_getLogs.

    Fallback only, when Blockscout is unreachable. Chunked to 10,000
    blocks per call (public RPCs cap log ranges). The topic is the
    Transfer signature; topics[1] is the address as an indexed topic.
    """
    from .fundflow import TRANSFER_TOPIC
    cfg = chain_config(chain)
    topic_addr = "0x000000000000000000000000" + address.lower()[2:]
    logs: List[dict] = []
    step = 10_000
    start = from_block
    while start <= to_block:
        end = min(start + step - 1, to_block)
        flt = {
            "fromBlock": hex(start),
            "toBlock": hex(end),
            "topics": [TRANSFER_TOPIC, topic_addr],
        }
        result = rpc_call(chain, "eth_getLogs", [flt])
        if isinstance(result, list):
            logs.extend(result)
        start = end + 1
    return logs, "rpc:eth_getLogs"


def verify_keyless() -> List[str]:
    """Check the environment for anything that looks like signing
    material or an API credential.

    Returns the offending names (empty list = clean). The tracer never
    reads these; it refuses to run with signing material present.
    Delegates to the repo's rpc_guard when available (it knows the
    runtime's own infra vars, e.g. JARVIS_*, are not signing material);
    standalone, uses a narrow pattern set for the same reason.
    """
    try:
        from .rpc_guard import signing_material_env  # type: ignore
        return signing_material_env()
    except Exception:
        pass
    patterns = ("PRIVATE_KEY", "SEED", "MNEMONIC", "SIGNING_KEY",
                "WALLET_KEY", "ETHERSCAN_API_KEY", "BLOCKSCOUT_API_KEY")
    offenders = []
    for name, value in os.environ.items():
        if not value or not str(value).strip():
            continue
        upper = name.upper()
        if any(p in upper for p in patterns):
            offenders.append(name)
    return offenders
