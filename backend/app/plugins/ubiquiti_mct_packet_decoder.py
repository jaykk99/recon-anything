"""Ubiquiti MCT packet decoder: decode Ubiquiti discovery/management
broadcasts in an operator-supplied pcap (UDP 10001 payloads: TLV fields
for MAC, IP, model, firmware, device name) into a device inventory;
flag management-info disclosure and legacy firmware. Offline pcap
parsing, keyless.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, parse_pcap, udp_payloads

_FIELD_NAMES = {0x01: "mac", 0x02: "ip", 0x03: "mac2", 0x0A: "uptime",
                0x0B: "hostname", 0x0C: "model", 0x0D: "essid?",
                0x14: "firmware", 0x15: "name"}


def decode_ubnt(payload: bytes) -> Dict[str, str]:
    """Parse a Ubiquiti discovery v2 payload (02 06 ...) TLV stream."""
    out: Dict[str, str] = {}
    if len(payload) < 4 or payload[0] != 0x02:
        return out
    pos = 4
    while pos + 3 <= len(payload):
        ftype = payload[pos]
        (flen,) = struct.unpack_from(">H", payload, pos + 1)
        pos += 3
        if flen > len(payload) - pos:
            break
        raw = payload[pos:pos + flen]
        pos += flen
        field = _FIELD_NAMES.get(ftype, f"field_{ftype:#x}")
        if ftype == 0x01 and flen == 6:
            out[field] = ":".join(f"{b:02x}" for b in raw)
        elif ftype == 0x02 and flen == 6:
            out[field] = ".".join(str(b) for b in raw[2:6])
        else:
            out[field] = raw.split(b"\x00")[0].decode(
                "utf-8", "ignore")
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    pcap = parse_pcap(data)
    devices = []
    if pcap.get("ok"):
        for _sp, dport, payload in udp_payloads(pcap):
            if dport == 10001 or payload[:1] == b"\x02":
                dev = decode_ubnt(payload)
                if dev:
                    devices.append(dev)
    if not devices and data[:1] == b"\x02":
        dev = decode_ubnt(data)
        if dev:
            devices.append(dev)
    for dev in devices[:6]:
        desc = ", ".join(f"{k}={v}" for k, v in list(dev.items())[:5])
        hits.append({
            "key": "ubiquiti_discovery_disclosure", "severity": "medium",
            "value": f"Ubiquiti discovery broadcast discloses device "
                     f"management info in plaintext: {desc}",
            "evidence": {"model": dev.get("model", "")[:40],
                         "firmware": dev.get("firmware", "")[:40]}})
        fw = dev.get("firmware", "")
        if fw and fw[0:1].isdigit() and int(fw.split(".")[0]) < 8:
            hits.append({
                "key": "ubiquiti_legacy_firmware", "severity": "low",
                "value": f"Ubiquiti device broadcasts legacy firmware "
                         f"version {fw}",
                "evidence": {"firmware": fw[:40]}})
    return hits[:10]


class UbiquitiMctPacketDecoderPlugin(Plugin):
    id = "ubiquiti_mct_packet_decoder"
    label = "Ubiquiti MCT Packet Decoder"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Decodes Ubiquiti discovery/management broadcasts "
                   "from a supplied pcap into a device inventory; "
                   "flags plaintext management-info disclosure and "
                   "legacy firmware.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
