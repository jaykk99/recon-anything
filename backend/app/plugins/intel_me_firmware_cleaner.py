"""Intel ME firmware cleaner - INVENTORY ONLY adaptation: parse the
ME region of an operator-supplied BIOS/ME firmware image - Flash
Partition Table ($FPT) entries, ME partition inventory and recorded
configuration posture (incl. HAP / AltMeDisable-style bits as RECORDED
in the image) - and flag unexpected/unknown partitions. The image is
never modified, cleaned or rewritten.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, find_all, strings_only

_KNOWN_PARTS = {"FTPR", "NFTP", "DLMP", "ISHC", "PCHC", "SMIP", "RBEP",
                "BUP ", "CIL ", "EFFS", "KRML", "MFS ", "PMCP", "ROMB",
                "WCOD", "LOCL", "FITC", "UTOK", "FLOG", "AFSP", "IVBP",
                "MMOD", "INDP"}


def parse_fpt(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False, "partitions": [], "version": ""}
    idxs = find_all(data, b"$FPT", limit=2)
    if not idxs:
        return out
    base = idxs[0]
    try:
        if base + 32 > len(data):
            return out
        (count,) = struct.unpack_from("<I", data, base + 4)
        if count > 64:
            count = 64
        pos = base + 32
        for _i in range(count):
            if pos + 32 > len(data):
                break
            name = data[pos:pos + 4].decode("ascii", "ignore")
            _owner = data[pos + 4:pos + 8]
            off, size = struct.unpack_from("<II", data, pos + 8)
            if name.strip():
                out["partitions"].append(
                    {"name": name, "offset": off, "size": size})
            pos += 32
        out["ok"] = bool(out["partitions"])
    except Exception:
        pass
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    fpt = parse_fpt(data)
    if not fpt.get("ok"):
        return hits
    names = [p["name"] for p in fpt["partitions"]]
    hits.append({
        "key": "intel_me_partition_inventory", "severity": "low",
        "value": f"Intel ME region inventoried (read-only): "
                 f"{len(names)} FPT partitions: "
                 + ", ".join(names[:10]),
        "evidence": {"partitions": names[:12]}})
    for p in fpt["partitions"]:
        if p["name"] not in _KNOWN_PARTS:
            hits.append({
                "key": "intel_me_unknown_partition", "severity":
                "medium",
                "value": f"Unknown/unexpected ME partition "
                         f"'{p['name']}' (offset {p['offset']:#x}, "
                         f"size {p['size']}) in the FPT - not a "
                         "standard ME partition name",
                "evidence": {"partition": p["name"]}})
    strs = strings_only(data, 6)
    posture = [s for s in strs if "AltMeDisable" in s or "HAP" in s
               and "strap" in s.lower()]
    if posture:
        hits.append({
            "key": "intel_me_hap_posture", "severity": "low",
            "value": "ME disable posture (HAP/AltMeDisable) is "
                     "recorded in the image's configuration strings "
                     "(recorded posture only - image untouched)",
            "evidence": {"markers": posture[:3]}})
    return hits[:10]


class IntelMeFirmwareCleanerPlugin(Plugin):
    id = "intel_me_firmware_cleaner"
    label = "Intel ME Firmware Inventory"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Inventory only: ME region / FPT partition map and "
                   "recorded HAP posture of a supplied BIOS/ME image; "
                   "unknown partitions flagged. The image is never "
                   "modified or cleaned.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
