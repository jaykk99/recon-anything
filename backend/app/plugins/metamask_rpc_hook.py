"""MetaMask RPC hook (Cat-4 variant) - STATIC detector.

Statically flags window.ethereum.request / provider.send call sites in
operator-supplied JS bundles, inventories the RPC methods invoked, and
flags signing / transaction methods (eth_sendTransaction, eth_sign,
personal_sign, eth_signTypedData*) that are reachable from page code -
especially when they fire automatically (on load / timer) rather than
behind an explicit user gesture, the classic drainer pre-confirmation
pattern.

STATIC ANALYSIS ONLY: no live wallet hooking or request interception.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ._cat4_common import all_texts
from .base import Cost, Ctx, Plugin, PluginResult, Target

_REQ_RE = re.compile(
    r"""(?:window\.ethereum|ethereum|provider)\.request\s*\(\s*"""
    r"""\{[^}]{0,300}?method\s*:\s*['"]([a-zA-Z_]+)['"]""", re.S)
_SEND_RE = re.compile(
    r"""\.send\s*\(\s*['"](eth_[a-zA-Z_]+|personal_sign)['"]""")
_AUTO_HINTS = ("window.onload", "addEventListener('load'",
               'addEventListener("load"', "DOMContentLoaded",
               "setTimeout", "setInterval", "useEffect(() => { connect")
SIGNING_METHODS = {"eth_sendTransaction", "eth_sign",
                   "personal_sign", "eth_signTypedData",
                   "eth_signTypedData_v3", "eth_signTypedData_v4",
                   "wallet_sendCalls", "eth_signTransaction"}


def analyse_metamask_calls(text: str) -> List[Dict[str, Any]]:
    """Pure: ethereum.request / provider.send call sites + methods."""
    hits: List[Dict[str, Any]] = []
    if not isinstance(text, str) or not text:
        return hits
    methods: List[str] = [m.group(1) for m in _REQ_RE.finditer(text)]
    methods += [m.group(1) for m in _SEND_RE.finditer(text)]
    auto = any(h in text for h in _AUTO_HINTS)
    for method in sorted(set(methods)):
        hits.append({"method": method,
                     "signing": method in SIGNING_METHODS,
                     "auto_context": bool(auto and
                                          method in SIGNING_METHODS)})
    return hits


class MetamaskRpcHookPlugin(Plugin):
    id = "metamask_rpc_hook"
    label = "MetaMask RPC Call-Site Detector (static)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Static flagging of window.ethereum.request call "
                   "sites and the RPC methods invoked; signing methods "
                   "reachable pre-confirmation are flagged. No live "
                   "wallet hooking.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            for where, text, url in await all_texts(ctx, target):
                for hit in analyse_metamask_calls(text):
                    if not hit["signing"]:
                        continue
                    sev = "high" if hit["auto_context"] else "medium"
                    findings.append(self._f(
                        "web3", "metamask_signing_call_site",
                        f"Signing method {hit['method']} invoked via "
                        f"window.ethereum.request in frontend code"
                        + (" from an automatic (load/timer) context"
                           if hit["auto_context"] else ""),
                        source=f"metamask rpc detector: {where}",
                        source_url=url or None, confidence=80,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Only request signatures "
                            "from an explicit user click, and show the "
                            "user a decoded summary before the wallet "
                            "prompt appears."}))
            res = self._ok(findings,
                           f"{len(findings)} signing call sites found"
                           if findings else "no signing call sites")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
