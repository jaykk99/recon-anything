"""Shared read-only helpers for Tier-10 mempool / MEV monitoring plugins.

MONITORING / ANALYSIS ONLY. Everything here is an eth_call, a block /
receipt / trace READ, or a public status-endpoint GET. Nothing in this
module builds, signs, broadcasts or submits a transaction or bundle,
and no Tier-10 plugin may do so either.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Public, keyless Ethereum mainnet RPCs (HTTPS polling; WebSocket
# endpoints are not reachable through every egress proxy, so Tier-10
# is designed around HTTP polling fallbacks).
RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://eth.llamarpc.com",
]

ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HASH_RE = re.compile(r"0x[a-fA-F0-9]{64}")

WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
DAI = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
TOKENS = {"WETH": WETH, "USDT": USDT, "USDC": USDC, "DAI": DAI}
TOKEN_DECIMALS = {WETH: 18, USDT: 6, USDC: 6, DAI: 18}

UNI_V2_ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
UNI_V3_ROUTER = "0xE592427A0AEce92De3Edee1F18E0157C05861564"
UNI_V3_QUOTER_V2 = "0x61fFE014bA17989E743c5F6cB21bF9697530B21e"
UNI_V3_QUOTER_V1 = "0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6"
AAVE_V3_POOL = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
SEAPORT = "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC"

WATCHED_CONTRACTS = {
    UNI_V2_ROUTER.lower(): "Uniswap V2 Router",
    UNI_V3_ROUTER.lower(): "Uniswap V3 SwapRouter",
    AAVE_V3_POOL.lower(): "Aave V3 Pool",
    PERMIT2.lower(): "Permit2",
    WETH.lower(): "WETH",
}

SPENDERS = {
    UNI_V2_ROUTER: "Uniswap V2 Router",
    UNI_V3_ROUTER: "Uniswap V3 SwapRouter",
    PERMIT2: "Permit2",
    AAVE_V3_POOL: "Aave V3 Pool",
    SEAPORT: "Seaport",
}

# 4-byte selectors (reads + pending-tx classification only).
SEL = {
    "approve": "095ea7b3",
    "transfer": "a9059cbb",
    "transferFrom": "23b872dd",
    "setApprovalForAll": "a22cb465",
    "increaseAllowance": "39509351",
    "swapExactTokensForTokens": "38ed1739",
    "swapExactETHForTokens": "7ff36ab5",
    "swapTokensForExactTokens": "8803dbee",
    "exactInputSingle": "414bf389",
    "exactInput": "c04b8d59",
    "multicall": "ac9650d8",
    "balanceOf": "70a08231",
    "allowance": "dd62ed3e",
    "getReservesList": "d1946dbc",
    "getReserveData": "35ea6a75",
    "quoteExactInputSingleV1": "f7729d43",
    "getAmountsOut": "d06ca61f",
}
SWAP_SELECTORS = {SEL[k] for k in (
    "swapExactTokensForTokens", "swapExactETHForTokens",
    "swapTokensForExactTokens", "exactInputSingle", "exactInput")}
MAX_UINT = (1 << 256) - 1
LARGE_VALUE_WEI = 10 * 10**18

TRANSFER_TOPIC = ("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55"
                  "a4df523b3ef")
SWAP_V3_TOPIC = ("0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed80"
                 "04e115fbcca67")
SYNC_TOPIC = ("0x1c411e9a96e071241c2f21f7726b17ae89e3c4c753a061afd53bf33"
              "8c177e0f")


def target_address(target) -> Optional[str]:
    """First 20-byte address in the target string, if any."""
    m = ADDR_RE.search(getattr(target, "raw", "") or "")
    if m:
        return m.group(0)
    m = ADDR_RE.search(getattr(target, "normalized", "") or "")
    return m.group(0) if m else None


def target_hash(target) -> Optional[str]:
    """First 32-byte hash in the target string, if any."""
    for text in (getattr(target, "raw", "") or "",
                 getattr(target, "normalized", "") or ""):
        m = HASH_RE.search(text)
        if m:
            return m.group(0)
    return None


def pad_addr(addr: str) -> str:
    return addr.lower().replace("0x", "").rjust(64, "0")


def pad_uint(n: int) -> str:
    return format(int(n), "064x")


def decode_uint(data_hex: Any, word: int = 0) -> Optional[int]:
    if not isinstance(data_hex, str) or not data_hex.startswith("0x"):
        return None
    h = data_hex[2:]
    if len(h) < (word + 1) * 64:
        return None
    try:
        return int(h[word * 64:(word + 1) * 64], 16)
    except ValueError:
        return None


def decode_addr(data_hex: Any, word: int = 0) -> Optional[str]:
    if not isinstance(data_hex, str) or not data_hex.startswith("0x"):
        return None
    h = data_hex[2:]
    if len(h) < (word + 1) * 64:
        return None
    return "0x" + h[word * 64 + 24:(word + 1) * 64]


async def rpc(ctx, method: str, params: list,
              timeout: int = 15) -> Tuple[Any, str]:
    """One JSON-RPC read across the public RPC list.

    Returns (result, "") on success, (None, last_error) otherwise.
    Never raises.
    """
    last = "no RPC tried"
    for url in RPCS:
        try:
            resp = await ctx.http.post(url, json={
                "jsonrpc": "2.0", "id": 1, "method": method,
                "params": params}, timeout=timeout)
        except Exception as e:  # network / proxy failure
            last = f"{url}: {type(e).__name__} {str(e)[:120]}"
            continue
        if resp.status_code != 200:
            last = f"{url}: HTTP {resp.status_code}"
            continue
        try:
            data = resp.json()
        except Exception:
            last = f"{url}: non-JSON response"
            continue
        if not isinstance(data, dict):
            last = f"{url}: malformed response"
            continue
        if data.get("error"):
            err = data["error"]
            last = f"{url}: RPC error {str(err)[:160]}"
            continue
        if "result" in data:
            return data["result"], ""
        last = f"{url}: no result field"
    return None, last


async def eth_call(ctx, to: str, data: str,
                   timeout: int = 15) -> Tuple[Optional[str], str]:
    result, err = await rpc(ctx, "eth_call",
                            [{"to": to, "data": data}, "latest"], timeout)
    if isinstance(result, str) and result.startswith("0x") \
            and result != "0x":
        return result, ""
    return None, err or "empty eth_call result"


def classify_tx(tx: Dict[str, Any]) -> Dict[str, Any]:
    """Classify one pending transaction (analysis only)."""
    inp = (tx.get("input") or tx.get("data") or "0x")
    sel = inp[2:10].lower() if isinstance(inp, str) and len(inp) >= 10 \
        else ""
    to = (tx.get("to") or "").lower()
    try:
        value = int(tx.get("value") or "0x0", 16)
    except (TypeError, ValueError):
        value = 0
    cls = "other"
    if sel in SWAP_SELECTORS:
        cls = "swap"
    elif sel == SEL["approve"]:
        cls = "approval"
    elif sel in (SEL["transfer"], SEL["transferFrom"]):
        cls = "token_transfer"
    elif sel == SEL["multicall"]:
        cls = "multicall"
    elif not to:
        cls = "contract_creation"
    elif value and sel in ("", "0x"):
        cls = "eth_transfer"
    unlimited = False
    spender = None
    if cls == "approval" and len(inp) >= 138:
        spender = "0x" + inp[34:74]
        try:
            amount = int(inp[74:138], 16)
            unlimited = amount >= MAX_UINT - 1000
        except ValueError:
            amount = None
    return {"class": cls, "selector": sel, "to": to, "value_wei": value,
            "watched": WATCHED_CONTRACTS.get(to),
            "unlimited_approval": unlimited, "spender": spender}
