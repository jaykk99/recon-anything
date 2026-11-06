"""CAN bus ID mapper: inventory an operator-supplied CAN capture
(candump log text or binary frames) - arbitration IDs, cycle counts,
payload variety - label diagnostic ranges (OBD-II 0x7DF/0x7E8, UDS)
and flag unexpected IDs and UDS SecurityAccess exchanges. Offline
first, keyless; no frames are ever transmitted by the analysis path.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, shannon_entropy

_LINE_RE = re.compile(
    r"(?:can\d+|vcan\d+)\s+([0-9A-Fa-f]{3,8})\s+\[(\d)\]\s*"
    r"((?:[0-9A-Fa-f]{2}\s*){0,8})")


def parse_candump(text: str) -> Dict[int, Dict[str, Any]]:
    frames: Dict[int, Dict[str, Any]] = {}
    for m in _LINE_RE.finditer(text):
        cid = int(m.group(1), 16)
        payload = bytes(int(b, 16) for b in m.group(3).split())
        rec = frames.setdefault(cid, {"count": 0, "payloads": []})
        rec["count"] += 1
        if len(rec["payloads"]) < 16:
            rec["payloads"].append(payload)
    return frames


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    frames = parse_candump(data.decode("utf-8", "ignore"))
    if not frames:
        return hits
    ids = sorted(frames)
    inventory = {
        "key": "can_id_inventory", "severity": "low",
        "value": f"CAN capture mapped: {len(ids)} arbitration IDs "
                 f"({sum(f['count'] for f in frames.values())} frames)"
                 f" - {', '.join(hex(i) for i in ids[:10])}",
        "evidence": {"ids": len(ids)}}
    if 0x7DF in frames or 0x7E8 in frames:
        hits.append({
            "key": "can_diagnostic_traffic", "severity": "medium",
            "value": "OBD-II/UDS diagnostic traffic present in the "
                    "capture (0x7DF functional request / 0x7E8 "
                    "response) on a bus segment where it was mapped",
            "evidence": {"ids": [hex(i) for i in (0x7DF, 0x7E8)
                                 if i in frames]}})
    for cid, rec in frames.items():
        for p in rec["payloads"]:
            # UDS service byte is first, or second behind the
            # single-frame PCI length byte in candump payloads.
            if len(p) >= 2 and (p[0] == 0x27
                                or (p[1] == 0x27 and p[0] <= 8)):
                hits.append({
                    "key": "can_uds_security_access", "severity": "high",
                    "value": f"UDS SecurityAccess (service 0x27) "
                             f"exchange observed on ID {cid:#x} - "
                             "seed/key diagnostic unlock traffic",
                    "evidence": {"id": hex(cid)}})
                break
        else:
            continue
        break
    ext = [i for i in ids if i > 0x7FF]
    if ext:
        hits.append({
            "key": "can_extended_ids", "severity": "medium",
            "value": "Extended (29-bit) CAN IDs present outside the "
                     "standard 11-bit map: "
                     + ", ".join(hex(i) for i in ext[:6]),
            "evidence": {"ids": [hex(i) for i in ext[:6]]}})
    for cid, rec in frames.items():
        joined = b"".join(rec["payloads"])
        if rec["count"] <= 2 and len(joined) >= 8 and \
                shannon_entropy(joined) >= 4.5:
            hits.append({
                "key": "can_rare_high_entropy_id", "severity": "medium",
                "value": f"Rare CAN ID {cid:#x} ({rec['count']} "
                         "frame(s)) carries high-entropy payloads - "
                         "unexpected node or payload channel",
                "evidence": {"id": hex(cid), "frames": rec["count"]}})
            break
    if hits:
        hits.insert(0, inventory)
    return hits[:10]


class CanBusIdMapperPlugin(Plugin):
    id = "can_bus_id_mapper"
    label = "CAN Bus ID Mapper"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Maps arbitration IDs in a supplied CAN capture; "
                   "labels OBD-II/UDS diagnostic ranges and flags "
                   "SecurityAccess exchanges and unexpected IDs. "
                   "Offline analysis only.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
