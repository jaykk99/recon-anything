"""Web3.js payload dumper (Cat-4 variant) - STATIC analysis.

Statically extracts web3.js contract-method invocations from
operator-supplied JS bundles - new web3.eth.Contract(abi, address)
bindings and .methods.foo(args).call()/.send() call sites - decodes
their parameter shapes, and flags value-moving or approval-granting
methods invoked via .send() (approve with a huge allowance, transfer,
setApprovalForAll), the payloads a drainer hides inside a DApp bundle.

STATIC ANALYSIS ONLY: nothing is executed or submitted.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ._cat4_common import all_texts
from .base import Cost, Ctx, Plugin, PluginResult, Target

_CONTRACT_RE = re.compile(
    r"""new\s+(?:web3\.eth\.Contract|Contract)\s*\([^,]{0,300}?,"""
    r"""\s*['"](0x[0-9a-fA-F]{40})['"]""", re.S)
_METHOD_RE = re.compile(
    r"""\.methods\.([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]{0,300})\)\s*\."""
    r"""\s*(call|send)\s*\(""")
RISKY_METHODS = {"approve", "transfer", "transferFrom",
                 "setApprovalForAll", "safeTransferFrom",
                 "increaseAllowance"}
HUGE = ("115792089237316195423570985008687907853269984665640564039457"
        "584007913129639935", "2**256", "ethers.MaxUint256",
        "MAX_UINT256", "ffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffff")


def analyse_web3js(text: str) -> List[Dict[str, Any]]:
    """Pure: web3.js contract bindings + method call sites."""
    hits: List[Dict[str, Any]] = []
    if not isinstance(text, str) or not text:
        return hits
    contracts = sorted(set(_CONTRACT_RE.findall(text)))
    for m in _METHOD_RE.finditer(text):
        name, args, mode = m.group(1), m.group(2) or "", m.group(3)
        hit: Dict[str, Any] = {"method": name, "mode": mode,
                               "contracts": contracts[:4],
                               "args_preview": args[:120]}
        if name in RISKY_METHODS and mode == "send":
            hit["risky"] = True
            if any(h in args for h in HUGE):
                hit["unlimited"] = True
        hits.append(hit)
    return hits


class Web3jsPayloadDumperPlugin(Plugin):
    id = "web3js_payload_dumper"
    label = "Web3.js Payload Dumper (static)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Static extraction of web3.js Contract bindings and "
                   ".methods.*.call/send payloads from supplied "
                   "bundles; flags risky .send() payloads.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            for where, text, url in await all_texts(ctx, target):
                for hit in analyse_web3js(text):
                    if not hit.get("risky"):
                        continue
                    sev = "high" if hit.get("unlimited") else "medium"
                    findings.append(self._f(
                        "web3", "web3js_risky_send_payload",
                        f"web3.js .methods.{hit['method']}("
                        f"{hit['args_preview']}).send() in frontend "
                        f"code" + (" with an unlimited allowance"
                                   if hit.get("unlimited") else ""),
                        source=f"web3.js payload dump: {where}",
                        source_url=url or None, confidence=80,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Cap allowances to the exact "
                            "amount needed, and only build send payloads "
                            "from explicit user-confirmed actions."}))
            res = self._ok(findings,
                           f"{len(findings)} risky send payloads found"
                           if findings else "no risky send payloads")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
