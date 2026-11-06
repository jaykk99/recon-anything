"""DApp state sniffer (Cat-4 variant of js_endpoints).

Statically decodes EVM provider READ calls (eth_call, eth_getBalance,
eth_getStorageAt) found in operator-supplied JS bundles / page source
into a contract+method+args read map, and flags direct storage-slot
probing (eth_getStorageAt), which reveals the DApp reads raw contract
storage - often private-variable slots - instead of public getters.

STATIC ANALYSIS ONLY: no live provider interception, no calls are
made to any provider on behalf of the target. Detection only.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ._cat4_common import all_texts, selector_name
from .base import Cost, Ctx, Plugin, PluginResult, Target

READ_METHODS = ("eth_call", "eth_getBalance", "eth_getStorageAt",
                "eth_getCode", "eth_getBlockByNumber")
_CALL_RE = re.compile(
    r"""method\s*:\s*['"](eth_call|eth_getBalance|eth_getStorageAt"""
    r"""|eth_getCode)['"]\s*,\s*params\s*:\s*\[([^\]]{0,400})\]""", re.S)
_DIRECT_RE = re.compile(
    r"""\.(eth_getBalance|eth_getStorageAt|eth_getCode|eth_call)\s*\(\s*"""
    r"""['"](0x[0-9a-fA-F]{40})['"]""")
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_DATA_RE = re.compile(r"data\s*:\s*['\"]0x([0-9a-fA-F]{8,})")


def analyse_dapp_reads(text: str) -> List[Dict[str, Any]]:
    """Pure: extract provider read calls from one bundle's text."""
    reads: List[Dict[str, Any]] = []
    if not isinstance(text, str) or not text:
        return reads
    for m in _CALL_RE.finditer(text):
        method, params = m.group(1), m.group(2) or ""
        addrs = _ADDR_RE.findall(params)
        entry: Dict[str, Any] = {"method": method,
                                 "to": addrs[0] if addrs else ""}
        dm = _DATA_RE.search(params)
        if method == "eth_call" and dm:
            sel = dm.group(1)[:8].lower()
            entry["selector"] = "0x" + sel
            entry["decoded"] = selector_name(sel) or "unknown selector"
        if method == "eth_getStorageAt":
            slots = re.findall(r"['\"](0x[0-9a-fA-F]{1,64})['\"]", params)
            entry["slots"] = slots[1:3]
        reads.append(entry)
    for m in _DIRECT_RE.finditer(text):
        reads.append({"method": m.group(1), "to": m.group(2)})
    # dedupe, keep order
    seen, out = set(), []
    for r in reads:
        k = (r.get("method"), r.get("to"), r.get("selector"))
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


class DappStateSnifferPlugin(Plugin):
    id = "dapp_state_sniffer"
    label = "DApp State Sniffer (static read-map)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Static decode of provider read calls (eth_call, "
                   "eth_getBalance, eth_getStorageAt) in supplied JS "
                   "bundles into a contract read map; flags raw "
                   "storage-slot probing. Static analysis only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            texts = await all_texts(ctx, target)
            total_reads = 0
            for where, text, url in texts:
                for read in analyse_dapp_reads(text):
                    total_reads += 1
                    if read["method"] == "eth_getStorageAt":
                        findings.append(self._f(
                            "web3", "dapp_storage_slot_probe",
                            f"DApp reads raw storage slots of "
                            f"{read.get('to') or 'a contract'} via "
                            f"eth_getStorageAt (slots: "
                            f"{', '.join(read.get('slots') or ['?'])})",
                            source=f"dapp state sniffer: {where}",
                            source_url=url or None, confidence=80,
                            evidence={
                                "severity": "medium",
                                "read": read,
                                "remediation": "Prefer public getter "
                                "functions over raw slot reads; assume "
                                "any slot read client-side is public "
                                "knowledge and never store secrets in "
                                "'private' variables."}))
                    elif read["method"] == "eth_call" and read.get("to"):
                        findings.append(self._f(
                            "web3", "dapp_read_map_entry",
                            f"DApp read map: eth_call to {read['to']} "
                            f"selector {read.get('selector', '?')} "
                            f"({read.get('decoded', '')})",
                            source=f"dapp state sniffer: {where}",
                            source_url=url or None, confidence=65,
                            evidence={"severity": "low", "read": read,
                                      "remediation": "Inventory only: "
                                      "confirm the DApp only reads the "
                                      "contracts it claims to use."}))
            res = self._ok(findings,
                           f"{total_reads} provider reads mapped"
                           if findings else "no provider reads found")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
