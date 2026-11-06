"""VARIANT 89: compound-leak correlation over supplied artifact sets."""
from __future__ import annotations
import re
from ._cat3_common import find_values, first, has, rx, run_cat3
from .base import Cost, Ctx, Plugin, PluginResult, Target


_XPUB = r"(?:xpub|ypub|zpub|tpub)[1-9A-HJ-NP-Za-km-z]{20,}"
_XPRV = r"(?:xprv|yprv|zprv|tprv)[1-9A-HJ-NP-Za-km-z]{20,}"

def analyze(text, objs):
    out = []
    blob = text + " " + " ".join(str(o) for o in (objs if isinstance(objs, list) else []))
    has_xpub = rx(blob, _XPUB)
    if not has_xpub:
        return out
    if rx(blob, _XPRV) or has(blob, "child private key", "child_priv"):
        out.append(("hd_xpub_plus_private_material",
                    "The same artifact set contains an extended public key AND private key material (xprv/child private key, values masked); with unhardened derivation this combination can expose the master private key",
                    "high", "Remove the private material from the artifact set immediately, rotate the wallet, and move funds to a fresh seed."))
    if rx(blob, r"derive\w*\s*\([^)]*m(?:/\d+){2,}(?![\d\']*\')"):
        out.append(("hd_unhardened_derivation_from_xpub",
                    "Code derives unhardened children from a master extended key present in the same artifacts; a leaked child private key plus the xpub yields the master private key",
                    "high", "Use hardened derivation below the account level and never co-locate xpub with child private keys."))
    return out[:6]


class HdWalletLeakScanner(Plugin):
    id = "hd_wallet_leak_scanner"
    label = "HD Wallet Compound-Leak Scanner"
    accepts = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Correlates supplied artifacts: an extended public key together with a child private key, extended private key, or unhardened derivation material for the same account escalates to master-private-key derivation risk."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_cat3(self, analyze, target, ctx)
