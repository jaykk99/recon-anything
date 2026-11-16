"""ERC721 unsafe transferFrom (r100 wave 1).

Solodit / Code4rena finding class: moving an ERC721 with
`transferFrom` instead of `safeTransferFrom` skips the receiver
check, so tokens can be locked forever in a contract that cannot
handle them (no `onERC721Received`). Marketplaces, staking and
bridges that use the unsafe call are the classic victims.

CWE-703 (Improper Check or Handling of Exceptional Conditions).
Static source detector; findings are candidates for triage, never
VERIFIED_REAL on their own.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_TRANSFER_FROM_RE = re.compile(r"transferFrom\s*\(")
_SAFE_RE = re.compile(r"\bsafeTransferFrom\s*\(")
_ERC721_CTX_RE = re.compile(r"\b(ERC721|IERC721|ERC721Enumerable|tokenId)\b")


def find_unsafe_erc721_transfers(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    if not _ERC721_CTX_RE.search(src):
        return []
    hits: List[Dict[str, Any]] = []
    for fn in C.functions(src):
        if fn["name"] == "transferFrom":
            continue  # the token's own implementation, not a caller
        body = fn.get("body") or ""
        if _SAFE_RE.search(body):
            continue  # this function uses the safe pattern
        m = _TRANSFER_FROM_RE.search(body)
        if not m:
            continue
        snippet = body[max(0, m.start() - 40):m.start() + 80].strip()
        snippet = re.sub(r"\s+", " ", snippet)
        hits.append(C.hit(
            "erc721_transferfrom_no_receiver_check",
            f"unsafe ERC721 transfer in {fn['name']}(): "
            f"`transferFrom` is used instead of `safeTransferFrom` - "
            f"the receiver is never checked for `onERC721Received`, "
            f"so the token can be locked in a contract that cannot "
            f"handle it.",
            "medium",
            "Use `safeTransferFrom` for every ERC721 move, or check "
            "the receiver implements `onERC721Received` before a "
            "plain `transferFrom`.",
            cwe="CWE-703", check="erc721_unsafe_transfer",
            function=fn["name"], snippet=snippet))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return find_unsafe_erc721_transfers(data.get("source", ""))


class Erc721UnsafeTransferPlugin(Plugin):
    id = "erc721_unsafe_transfer"
    label = "ERC721 Unsafe Transfer"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Flags ERC721 `transferFrom` calls made without the "
                   "`safeTransferFrom` receiver check (CWE-703).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, stamp=False,
            bytecode=False,
            no_input="no contract source to check for unsafe transfers")
