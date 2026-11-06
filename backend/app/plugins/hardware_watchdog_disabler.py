"""Hardware watchdog disabler - DETECTION ONLY adaptation: detect
watchdog posture in an operator-supplied firmware image/config set -
watchdog nodes in the device tree, bootloader watchdog settings,
init/supervisor configuration - and flag watchdog disabled, absent or
set to an ineffective timeout in the shipped configuration. Nothing is
disabled and no keep-alive loops are sent.
"""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, parse_dtb, prop_str, text_of

_PATTERNS = [
    (re.compile(r"\bnowatchdog\b", re.I), "watchdog_disabled_bootargs",
     "high", "Kernel bootargs carry 'nowatchdog' - watchdog disabled "
             "at boot"),
    (re.compile(r"CONFIG_(HW_)?WATCHDOG is not set|CONFIG_WATCHDOG=n",
                re.I), "watchdog_not_compiled", "medium",
     "Kernel config builds with the watchdog driver disabled"),
    (re.compile(r"watchdog[_\-]?timeout\s*[:=]\s*0\b", re.I),
     "watchdog_timeout_zero", "high",
     "Watchdog timeout configured to 0 (ineffective)"),
    (re.compile(r"watchdog\s*[:=]\s*(off|disabled|none)", re.I),
     "watchdog_disabled_config", "high",
     "Supervisor/init configuration disables the watchdog"),
]


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    seen = set()
    dtb = parse_dtb(data)
    wdt_nodes = [n for n in dtb.get("nodes", [])
                 if "watchdog" in n["name"].lower()
                 or "wdt" in n["name"].lower()]
    for node in wdt_nodes:
        status = prop_str(node["props"].get("status", b""))
        if status == "disabled" and node["path"] not in seen:
            seen.add(node["path"])
            hits.append({
                "key": "watchdog_dt_disabled", "severity": "high",
                "value": f"Watchdog node {node['path']} is marked "
                         "status=disabled in the shipped device tree "
                         "- hung firmware will never be reset",
                "evidence": {"node": node["path"]}})
        timeout = node["props"].get("timeout-sec")
        if timeout and len(timeout) >= 4:
            secs = struct.unpack(">I", timeout[:4])[0]
            if secs == 0 or secs > 3600:
                hits.append({
                    "key": "watchdog_ineffective_timeout",
                    "severity": "medium",
                    "value": f"Watchdog node {node['path']} has an "
                             f"ineffective timeout-sec of {secs}",
                    "evidence": {"node": node["path"],
                                 "timeout_sec": secs}})
    text = text_of(data)
    for rx, key, sev, label in _PATTERNS:
        if key in seen:
            continue
        if rx.search(text):
            seen.add(key)
            hits.append({"key": key, "severity": sev,
                         "value": label + " (config detection only)",
                         "evidence": {"detection": "config-string"}})
    return hits[:10]


class HardwareWatchdogDisablerPlugin(Plugin):
    id = "hardware_watchdog_disabler"
    label = "Hardware Watchdog Posture Detector"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Detection only: watchdog disabled/absent/"
                   "ineffective-timeout posture in supplied firmware "
                   "config and device tree. Nothing is disabled.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
