"""TLV packet structure parser: recursive TLV walker over an
operator-supplied capture or binary dump of a hardware-channel stream
(tag/length profiles: 1-byte tag + 1-byte length, or 1-byte tag +
2-byte big-endian length). Produces a decoded block tree, flags
high-entropy opaque value blocks, and renders credential-shaped
values masked. Offline, keyless.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, mask_secret, shannon_entropy

_CRED_RE = re.compile(
    r"(password|passwd|token|secret|api[-_]?key|psk)\s*[:=]\s*(\S{4,})",
    re.I)
_CONTAINER_TAGS = {0x30, 0xA0, 0xE1, 0x62, 0x63}


def walk(data: bytes, len_bytes: int, depth: int = 0,
         base: int = 0) -> List[Dict[str, Any]]:
    """Walk one TLV level; returns [] if the stream doesn't parse."""
    blocks: List[Dict[str, Any]] = []
    pos = 0
    while pos < len(data):
        if pos + 1 + len_bytes > len(data):
            return [] if depth == 0 and blocks else blocks
        tag = data[pos]
        if len_bytes == 1:
            ln = data[pos + 1]
        else:
            ln = int.from_bytes(data[pos + 1:pos + 3], "big")
        hdr = 1 + len_bytes
        if ln > len(data) - pos - hdr:
            return [] if depth == 0 else blocks
        value = data[pos + hdr:pos + hdr + ln]
        block = {"tag": tag, "offset": base + pos, "length": ln,
                 "value": value, "children": []}
        if tag in _CONTAINER_TAGS and depth < 3 and ln >= 2:
            block["children"] = walk(value, len_bytes, depth + 1,
                                     base + pos + hdr)
        blocks.append(block)
        pos += hdr + ln
    return blocks


def parse_tlv(data: bytes) -> List[Dict[str, Any]]:
    for len_bytes in (1, 2):
        blocks = walk(data, len_bytes)
        if blocks:
            return blocks
    return []


def _flatten(blocks):
    for b in blocks:
        yield b
        yield from _flatten(b.get("children") or [])


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data or len(data) < 4:
        return hits
    blocks = parse_tlv(data)
    if not blocks:
        return hits
    flat = list(_flatten(blocks))
    for b in flat:
        value = b["value"]
        text = value.decode("utf-8", "ignore")
        m = _CRED_RE.search(text)
        if m:
            masked, fp = mask_secret(m.group(2))
            hits.append({
                "key": "tlv_credential_value", "severity": "high",
                "value": f"Credential-shaped value inside TLV tag "
                         f"{b['tag']:#x} at offset {b['offset']:#x} "
                         f"({m.group(1)} = masked {masked}, fp {fp})",
                "evidence": {"tag": hex(b["tag"]), "fingerprint": fp}})
        elif len(value) >= 32 and shannon_entropy(value) >= 7.2:
            hits.append({
                "key": "tlv_high_entropy_block", "severity": "medium",
                "value": f"Opaque high-entropy value block in TLV "
                         f"tag {b['tag']:#x} at offset "
                         f"{b['offset']:#x} ({len(value)} bytes, "
                         "entropy >= 7.2) - encrypted or key material",
                "evidence": {"tag": hex(b["tag"]),
                             "length": len(value)}})
    if not hits:
        hits.append({
            "key": "tlv_structure_decoded", "severity": "low",
            "value": f"TLV stream decoded: {len(flat)} blocks across "
                     f"{len(blocks)} top-level tags "
                     f"({', '.join(hex(b['tag']) for b in blocks[:8])})",
            "evidence": {"blocks": len(flat)}})
        # structure alone on an arbitrary stream is not a finding
        return []
    return hits[:10]


class TlvPacketStructureParserPlugin(Plugin):
    id = "tlv_packet_structure_parser"
    label = "TLV Packet Structure Parser"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Recursive TLV walker over supplied hardware-"
                   "channel dumps: block tree, high-entropy opaque "
                   "blocks, credential-shaped values (masked).")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
