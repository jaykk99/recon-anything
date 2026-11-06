"""BLE GATT characteristic explorer: analyse an operator-supplied GATT
enumeration capture (bleak/gatttool-style text dump of a device the
operator owns) - services/characteristics/descriptors inventoried,
sensitive characteristics that are readable/writable without
pairing/encryption flagged (device-info writes, OTA chars, UART-bridge
chars). Enumeration only. Live BLE needs a host adapter + library;
when neither is present the plugin reports a clean degraded note.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, load_artifacts

_CHAR_RE = re.compile(
    r"char\w*\s+([0-9a-fA-F-]{4,36})[^\n]*?propert\w*[:= ]+([a-z, ]+)",
    re.I)
_OTA_UUIDS = ("0000fe59", "49535343", "00001530", "6e400001", "fff")
_SENSITIVE_HINTS = ("uart", "ota", "dfu", "serial", "command", "config",
                    "device name", "firmware")


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = data.decode("utf-8", "ignore")
    low = text.lower()
    if "gatt" not in low and "characteristic" not in low \
            and "char " not in low:
        return hits
    chars = []
    for m in _CHAR_RE.finditer(text):
        uuid = m.group(1).lower()
        props = m.group(2).lower()
        chars.append((uuid, props))
        writable = "write" in props
        authed = any(w in low[max(0, m.start() - 200):m.end() + 200]
                     for w in ("auth=required", "encrypt", "bonded",
                               "pairing required", "mitm"))
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        ctx_line = text[line_start:line_end if line_end >= 0
                        else len(text)].lower()
        sensitive = any(h in ctx_line for h in _SENSITIVE_HINTS) or \
            any(p in uuid for p in _OTA_UUIDS)
        if writable and sensitive and not authed:
            hits.append({
                "key": "ble_sensitive_char_writable", "severity": "high",
                "value": f"BLE characteristic {uuid} is writable "
                         "without pairing/encryption and looks "
                         "sensitive (OTA/UART/config class)",
                "evidence": {"uuid": uuid, "properties": props[:40]}})
        elif writable and not authed:
            hits.append({
                "key": "ble_char_writable_noauth", "severity": "medium",
                "value": f"BLE characteristic {uuid} is writable "
                         "without pairing/encryption",
                "evidence": {"uuid": uuid, "properties": props[:40]}})
    if chars and not hits:
        hits.append({
            "key": "ble_gatt_inventory", "severity": "low",
            "value": f"BLE GATT inventory from supplied capture: "
                     f"{len(chars)} characteristics enumerated, none "
                     "writable-without-auth in a sensitive class",
            "evidence": {"characteristics": len(chars)}})
        # inventory alone is informational; only report it when a
        # writable surface exists at all
        if not any("write" in p for _u, p in chars):
            return []
    return hits[:10]


class BleGattCharExplorerPlugin(Plugin):
    id = "ble_gatt_char_explorer"
    label = "BLE GATT Characteristic Explorer"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("GATT posture from a supplied enumeration capture of "
                   "an operator-owned BLE device: sensitive "
                   "characteristics writable without pairing/encryption "
                   "flagged. Live scan needs a local BLE adapter/library "
                   "and degrades cleanly without one.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            if load_artifacts(target, ctx):
                return collect(self, target, ctx, analyze)
            try:
                import bleak  # noqa: F401
                return self._ok(
                    [], "BLE library present but live enumeration is "
                    "operator-triggered; supply a GATT capture artifact "
                    "for analysis")
            except Exception:
                return self._ok(
                    [], "no BLE adapter/library on this host and no "
                    "supplied GATT capture; nothing to enumerate")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
