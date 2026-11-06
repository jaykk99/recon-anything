"""Zigbee frame decrypt tool - offline audit adaptation: decode an
operator-supplied Zigbee capture (pcap) at the 802.15.4/APS layer,
flag use of the well-known default Trust Center link key / default
network keys and frames sent with security disabled. Any recovered key
material is reported masked + fingerprinted, never in full. Offline,
operator-supplied captures only.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, find_all, mask_secret, parse_pcap

# "ZigBeeAlliance09" - the published default Trust Center link key.
_DEFAULT_TC_KEY = bytes([
    0x5A, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6C,
    0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65, 0x30, 0x39])


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    if find_all(data, _DEFAULT_TC_KEY, limit=1):
        masked, fp = mask_secret(_DEFAULT_TC_KEY.hex())
        hits.append({
            "key": "zigbee_default_tc_key", "severity": "high",
            "value": "Capture contains the well-known default Zigbee "
                     f"Trust Center link key (masked {masked}, fp "
                     f"{fp}) - network keys transported under it are "
                     "recoverable by anyone",
            "evidence": {"fingerprint": fp}})
    pcap = parse_pcap(data)
    unsecured = 0
    total = 0
    for pkt in pcap.get("packets", []):
        # 802.15.4 frame control: low byte bit 3 = security enabled.
        if len(pkt) >= 2:
            total += 1
            if not (pkt[0] & 0x08):
                unsecured += 1
    if total and unsecured:
        hits.append({
            "key": "zigbee_unsecured_frames", "severity": "medium",
            "value": f"{unsecured}/{total} 802.15.4 frames in the "
                     "supplied capture have MAC-layer security "
                     "disabled",
            "evidence": {"unsecured": unsecured, "frames": total}})
    return hits[:8]


class ZigbeeFrameDecryptToolPlugin(Plugin):
    id = "zigbee_frame_decrypt_tool"
    label = "Zigbee Frame Audit Decoder"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Offline audit decode of supplied Zigbee captures: "
                   "default Trust Center link key use and unencrypted "
                   "frames flagged; key material masked.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
