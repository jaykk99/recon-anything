"""Ethers provider spy (Cat-4 variant) - STATIC analysis.

Statically maps the ethers.js provider/listener architecture in
operator-supplied JS bundles: JsonRpcProvider / WebSocketProvider /
BrowserProvider construction, .on(...) subscriptions and contract
event listeners. Flags the exposure shapes that matter: RPC URLs with
embedded API keys shipped to every visitor, and providers pointed at
plaintext-http or localhost endpoints.

STATIC ANALYSIS ONLY: no live event interception.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ._cat4_common import all_texts, mask_value
from .base import Cost, Ctx, Plugin, PluginResult, Target

_PROVIDER_RE = re.compile(
    r"""new\s+(?:ethers\.)?(JsonRpcProvider|WebSocketProvider|"""
    r"""BrowserProvider|FallbackProvider)\s*\(\s*['"`]([^'"`]{0,200})['"`]""")
_LISTENER_RE = re.compile(
    r"""\.on\s*\(\s*['"]([A-Za-z0-9_]{2,40})['"]""")
_KEY_IN_URL_RE = re.compile(
    r"(?:/v[23]/|api[-_]?key=|apikey=)([A-Za-z0-9_\-]{16,})", re.I)


def analyse_ethers(text: str) -> List[Dict[str, Any]]:
    """Pure: ethers provider constructions + listeners in one bundle."""
    hits: List[Dict[str, Any]] = []
    if not isinstance(text, str) or not text:
        return hits
    listeners = sorted(set(_LISTENER_RE.findall(text)))[:20]
    for m in _PROVIDER_RE.finditer(text):
        kind, url = m.group(1), m.group(2) or ""
        hit: Dict[str, Any] = {"provider": kind, "url": url[:120],
                               "listeners": listeners}
        km = _KEY_IN_URL_RE.search(url)
        if km:
            hit["embedded_key"] = mask_value(km.group(1))
            hit["url"] = url.replace(km.group(1), "***")[:120]
        if url.startswith("http://"):
            hit["plaintext"] = True
        if "localhost" in url or "127.0.0.1" in url:
            hit["localhost"] = True
        hits.append(hit)
    return hits


class EthersProviderSpyPlugin(Plugin):
    id = "ethers_provider_spy"
    label = "Ethers Provider/Listener Map (static)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Static map of ethers.js providers and event "
                   "listeners in supplied bundles; flags RPC URLs with "
                   "embedded API keys and plaintext/localhost endpoints.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            for where, text, url in await all_texts(ctx, target):
                for hit in analyse_ethers(text):
                    if hit.get("embedded_key"):
                        findings.append(self._f(
                            "web3", "ethers_rpc_key_embedded",
                            f"{hit['provider']} RPC URL ships an "
                            f"embedded API key to every visitor: "
                            f"{hit['embedded_key']}",
                            source=f"ethers provider map: {where}",
                            source_url=url or None, confidence=85,
                            evidence={
                                "severity": "medium", "hit": hit,
                                "remediation": "Use a keyless public RPC "
                                "or a domain-restricted proxy key; treat "
                                "the exposed key as public and rotate "
                                "or restrict it."}))
                    elif hit.get("plaintext") or hit.get("localhost"):
                        findings.append(self._f(
                            "web3", "ethers_rpc_insecure_endpoint",
                            f"{hit['provider']} points at an insecure "
                            f"endpoint: {hit['url']}",
                            source=f"ethers provider map: {where}",
                            source_url=url or None, confidence=80,
                            evidence={
                                "severity": "medium", "hit": hit,
                                "remediation": "Use https/wss RPC "
                                "endpoints in production builds; never "
                                "ship localhost endpoints."}))
            res = self._ok(findings,
                           f"{len(findings)} provider exposures found"
                           if findings else "no provider exposures")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
