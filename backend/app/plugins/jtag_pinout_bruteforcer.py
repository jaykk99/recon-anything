"""JTAG pinout bruteforcer - DETECTION ONLY adaptation.

Statically detects debug-interface exposure in an operator-supplied
firmware image/config set: JTAG/SWD enablement in the device tree and
board config, debug fuses / readout-protection posture recorded in the
firmware, UART/JTAG references in boot config. NO pin brute-forcing, no
hardware probing of any kind.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, parse_dtb, prop_str, text_of

_PATTERNS = [
    (re.compile(r"jtag[_\-]?(enable|enabled|on)\b", re.I),
     "jtag_debug_enabled", "high", "JTAG debug interface left enabled"),
    (re.compile(r"\bswd[_\-]?(enable|enabled)\b", re.I),
     "jtag_debug_enabled", "high", "SWD debug interface left enabled"),
    (re.compile(r"readout[_\- ]?protection[^.\n]{0,30}"
                r"(disabled|off|level\s*0|none)", re.I),
     "jtag_rdp_disabled", "high",
     "Flash readout protection disabled / level 0 in firmware config"),
    (re.compile(r"debug[_\-]?fuse[^.\n]{0,20}(blown|set|enabled)", re.I),
     "jtag_debug_fuse", "medium", "Debug fuse state recorded in firmware"),
    (re.compile(r"\bJTAG\b[^.\n]{0,40}\b(unlocked|open|exposed)\b", re.I),
     "jtag_debug_enabled", "medium", "JTAG described as unlocked/open"),
]


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    seen = set()
    dtb = parse_dtb(data)
    for node in dtb.get("nodes", []):
        lname = node["name"].lower()
        if any(w in lname for w in ("jtag", "swd", "debug", "coresight",
                                   "etm", "tpiu")):
            status = prop_str(node["props"].get("status", b""))
            if status != "disabled" and node["path"] not in seen:
                seen.add(node["path"])
                hits.append({
                    "key": "jtag_dt_node_enabled", "severity": "high",
                    "value": f"Debug node {node['path']} present in the "
                             f"device tree and not disabled "
                             f"(status={status or 'default'})",
                    "evidence": {"node": node["path"], "status": status}})
    text = text_of(data)
    for rx, key, sev, label in _PATTERNS:
        if key in seen:
            continue
        if rx.search(text):
            seen.add(key)
            hits.append({"key": key, "severity": sev,
                         "value": label + " (static config detection)",
                         "evidence": {"detection": "config-string"}})
    return hits[:10]


class JtagPinoutBruteforcerPlugin(Plugin):
    id = "jtag_pinout_bruteforcer"
    label = "JTAG/SWD Exposure Detector"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Detection only: JTAG/SWD/debug exposure recorded in "
                   "supplied firmware config and device tree. No pin "
                   "probing or brute force is performed.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
