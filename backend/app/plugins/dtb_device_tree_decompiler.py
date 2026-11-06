"""DTB device-tree decompiler (variant of da_firmware_image):
da_firmware_image recognizes the FDT magic only. This fully parses an
operator-supplied DTB - structure + strings blocks into a component map
(chosen/bootargs, memory, peripherals, uart/debug nodes) - and flags
debug-enabled nodes and console exposure. Pure Python, offline.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, parse_dtb, prop_str


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    dtb = parse_dtb(data)
    if not dtb.get("ok"):
        return hits
    nodes = dtb["nodes"]
    inventory = {
        "key": "dtb_component_map", "severity": "low",
        "value": f"Device tree decompiled: {len(nodes)} nodes "
                 f"({', '.join(n['path'] for n in nodes[:6])})",
        "evidence": {"node_count": len(nodes)}}
    for node in nodes:
        props = node["props"]
        status = prop_str(props.get("status", b""))
        lname = node["name"].lower()
        if node["name"] == "chosen":
            bootargs = prop_str(props.get("bootargs", b""))
            if "init=/bin/sh" in bootargs or bootargs.rstrip().endswith(
                    "single"):
                hits.append({
                    "key": "dtb_bootargs_shell", "severity": "high",
                    "value": "DT chosen/bootargs boot to a shell or "
                             "single-user mode",
                    "evidence": {"node": node["path"]}})
            elif "console=" in bootargs:
                hits.append({
                    "key": "dtb_console_exposure", "severity": "medium",
                    "value": "DT chosen/bootargs expose a serial "
                             "console: " + bootargs[:80],
                    "evidence": {"node": node["path"]}})
        if status != "disabled" and any(
                w in lname for w in ("uart", "serial", "debug", "jtag")):
            hits.append({
                "key": "dtb_debug_node_enabled", "severity": "medium",
                "value": f"Debug/serial node {node['path']} enabled in "
                         f"the shipped device tree",
                "evidence": {"node": node["path"],
                             "status": status or "default"}})
        if "secure-status" in props and prop_str(
                props["secure-status"]) == "disabled":
            hits.append({
                "key": "dtb_secure_status_disabled", "severity": "high",
                "value": f"Node {node['path']} records secure-status "
                         "= disabled in the device tree",
                "evidence": {"node": node["path"]}})
    if hits:
        hits.insert(0, inventory)
    return hits[:10]


class DtbDeviceTreeDecompilerPlugin(Plugin):
    id = "dtb_device_tree_decompiler"
    label = "DTB Device Tree Decompiler"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of da_firmware_image: full DTB parse of a "
                   "supplied blob into a component map; flags debug "
                   "nodes, console bootargs and disabled secure-status.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
