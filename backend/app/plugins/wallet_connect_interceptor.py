"""WalletConnect interceptor (Cat-4 variant) - STATIC detector.

Detects WalletConnect session-proposal / sign-request payload shapes
and relay URLs inside operator-supplied JS bundles / page source:
wc: URIs carrying a symKey, relay endpoints, and signClient /
Web3Modal request calls carrying value-moving methods. A wc: URI with
an embedded symKey in shipped code means anyone can pair against (or
observe proposals for) that session topic.

STATIC ANALYSIS ONLY: no live bridge/relay interception is performed.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ._cat4_common import all_texts, mask_value
from .base import Cost, Ctx, Plugin, PluginResult, Target

_WC_URI_RE = re.compile(r"wc:[0-9a-fA-F-]{8,}@[12]\?[^\s'\"`]{10,400}")
_RELAY_RE = re.compile(
    r"(?:relay\.walletconnect\.com|relay\.walletconnect\.org|"
    r"wss?://[^\s'\"`]*walletconnect[^\s'\"`]*)")
_REQUEST_RE = re.compile(
    r"""(?:signClient|client|provider)\.(?:request|requestSession)"""
    r"""\s*\(\s*\{[^}]{0,600}?\}""", re.S)
_METHOD_RE = re.compile(
    r"""method\s*:\s*['"]([a-zA-Z_]+)['"]""")
_VALUE_METHODS = {"eth_sendTransaction", "eth_signTransaction",
                  "eth_sign", "personal_sign", "eth_signTypedData",
                  "eth_signTypedData_v4", "wallet_sendCalls"}


def analyse_walletconnect(text: str) -> List[Dict[str, Any]]:
    """Pure: WalletConnect session/sign shapes in one bundle's text."""
    hits: List[Dict[str, Any]] = []
    if not isinstance(text, str) or not text:
        return hits
    for m in _WC_URI_RE.finditer(text):
        uri = m.group(0)
        hits.append({"kind": "wc_uri_with_symkey" if "symKey=" in uri
                     else "wc_uri",
                     "masked": mask_value(uri, keep=14),
                     "has_symkey": "symKey=" in uri})
    relays = sorted(set(_RELAY_RE.findall(text)))
    for r in relays[:4]:
        hits.append({"kind": "relay_endpoint", "relay": r[:120]})
    for m in _REQUEST_RE.finditer(text):
        mm = _METHOD_RE.search(m.group(0))
        method = mm.group(1) if mm else ""
        if method in _VALUE_METHODS or "topic" in m.group(0):
            hits.append({"kind": "sign_request_shape", "method": method})
    return hits


class WalletConnectInterceptorPlugin(Plugin):
    id = "wallet_connect_interceptor"
    label = "WalletConnect Session/Sign Detector (static)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Static detector for WalletConnect session-proposal "
                   "and sign-request payload shapes and relay URLs in "
                   "supplied bundles. No live bridge interception.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            for where, text, url in await all_texts(ctx, target):
                for hit in analyse_walletconnect(text):
                    if hit["kind"] == "wc_uri_with_symkey":
                        findings.append(self._f(
                            "web3", "walletconnect_symkey_in_code",
                            "WalletConnect pairing URI with embedded "
                            f"symKey shipped in code: {hit['masked']}",
                            source=f"walletconnect detector: {where}",
                            source_url=url or None, confidence=85,
                            evidence={
                                "severity": "high", "hit": hit,
                                "remediation": "Never ship wc: pairing "
                                "URIs or symKeys in frontend code; "
                                "generate pairings at runtime per user."}))
                    elif hit["kind"] == "sign_request_shape" and \
                            hit.get("method"):
                        findings.append(self._f(
                            "web3", "walletconnect_sign_request_shape",
                            "WalletConnect sign request for "
                            f"{hit['method']} built in frontend code",
                            source=f"walletconnect detector: {where}",
                            source_url=url or None, confidence=70,
                            evidence={
                                "severity": "medium", "hit": hit,
                                "remediation": "Ensure sign requests are "
                                "only issued from explicit user actions "
                                "and show the decoded payload before "
                                "asking the wallet to sign."}))
                    elif hit["kind"] == "relay_endpoint":
                        findings.append(self._f(
                            "web3", "walletconnect_relay_endpoint",
                            f"WalletConnect relay endpoint referenced: "
                            f"{hit['relay']}",
                            source=f"walletconnect detector: {where}",
                            source_url=url or None, confidence=55,
                            evidence={
                                "severity": "low", "hit": hit,
                                "remediation": "Inventory only: confirm "
                                "the relay is the official WalletConnect "
                                "relay, not a look-alike endpoint."}))
            res = self._ok(findings,
                           f"{len(findings)} WalletConnect shapes found"
                           if findings else "no WalletConnect shapes")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
