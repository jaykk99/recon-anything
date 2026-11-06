"""ERC721 Metadata Guard (Cat-1 #18, VARIANT of the ERC-721 detectors).

Delta: URI-mutability analysis. Who can call setTokenURI /
setBaseURI / setContractURI after mint, is there a freeze/lock
function and is it actually honoured by the setters, and do mint
loops assign per-token URIs straight from caller-supplied data?
An ungated URI setter means every minted NFT's metadata (and the
art it points to) can be swapped after sale - that is the finding;
a gated setter behind a used freeze flag stays silent.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_SETTERS = ("setTokenURI", "setBaseURI", "setContractURI",
            "_setTokenURI", "setBaseTokenURI")
_GATE = re.compile(r"onlyOwner|onlyRole|onlyAdmin|msg\.sender\s*==|"
                   r"require\s*\(\s*(owner|_isApprovedOrOwner|hasRole)")
_FREEZE = re.compile(r"freez|lock|sealed|immutable_uris|uriFrozen|"
                     r"metadataFrozen", re.I)


def analyze_erc721_metadata(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    hits: List[Dict[str, Any]] = []
    fns = {f["name"]: f for f in C.functions(src)}
    has_freeze_fn = any(_FREEZE.search(n) for n in fns) or \
        bool(_FREEZE.search(src.split("function")[0]))
    for name in _SETTERS:
        f = fns.get(name)
        if not f:
            continue
        gated = bool(_GATE.search(f["mods"] + " " + f["body"][:400]))
        freeze_checked = bool(_FREEZE.search(f["body"]))
        if not gated:
            hits.append(C.hit(
                "erc721_ungated_uri_setter",
                f"{name}() can be called by anyone: NFT metadata "
                f"URIs can be rewritten after mint/sale, swapping "
                f"the art or pointing it at hostile content.",
                "high",
                f"Gate {name}() behind owner/role access control.",
                function=name, check="erc721_metadata"))
        elif not has_freeze_fn or not freeze_checked:
            hits.append(C.hit(
                "erc721_mutable_uri_no_freeze",
                f"{name}() exists and no freeze/lock is honoured "
                f"by it: metadata stays mutable forever, so "
                f"buyers have no guarantee the URI will not change.",
                "medium",
                "Add a one-way freeze (e.g. freezeBaseURI) and "
                "check the frozen flag inside every URI setter.",
                function=name, check="erc721_metadata"))
    # mint loop with caller-supplied URI
    for f in C.functions(src):
        if "mint" in f["name"].lower():
            if re.search(r"for\s*\([^)]*\)\s*\{[^}]*_setTokenURI\s*\("
                         r"\s*\w+\s*,\s*\w*[Uu]ri", f["body"], re.S) or \
                    ("_setTokenURI(" in f["body"] and
                     re.search(r"string\s+(memory\s+)?\w*[Uu]ri",
                               f["args"])):
                hits.append(C.hit(
                    "erc721_mint_caller_uri",
                    f"mint path {f['name']}() assigns per-token "
                    f"URIs from caller-supplied data; a minter can "
                    f"attach arbitrary metadata to minted tokens.",
                    "medium",
                    "Derive URIs on-chain from the token id and a "
                    "fixed base, or validate caller URIs strictly.",
                    function=f["name"], check="erc721_metadata"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_erc721_metadata(data.get("source", ""))


class Erc721MetadataGuardPlugin(Plugin):
    id = "erc721_metadata_guard"
    label = "ERC721 Metadata Guard"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Post-mint URI-mutability analysis: who can "
                   "call the URI setters, whether a freeze/lock "
                   "exists and is honoured, and whether mint "
                   "assigns caller-supplied URIs.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, bytecode=False,
            no_input="no NFT contract source to audit metadata "
                     "mutability in")
