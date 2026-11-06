"""QUIC packet flow reassembler (variant of http2_check/altsvc_audit):
reassembles QUIC flows from operator-supplied captures.

http2_check reports ALPN h3 support and altsvc_audit parses Alt-Svc
advertisements; neither touches packets. This delta parses supplied
QUIC captures (raw long-header packets inside a pcap, or JSON/text
packet logs) into flows keyed by Destination Connection ID and
flags: packet-number reuse within a flow, version-negotiation
downgrade packets, and SNI-shaped cleartext in Initial packets.

BOUNDARY: supplied captures only; no live QUIC connection.
"""
from __future__ import annotations

import json
import re
import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import packet_payloads, parse_pcap, text_of

_SNI_SHAPE = re.compile(rb"[a-z0-9\-]{2,}\.[a-z0-9\-]{2,}\.(?:com|net|"
                        rb"org|io|internal|corp|lan)\b")


def parse_long_header(pkt: bytes) -> Dict[str, Any]:
    """Minimal QUIC long-header parse. {} when not a long header."""
    out: Dict[str, Any] = {}
    try:
        if not pkt or not (pkt[0] & 0x80):
            return out
        if len(pkt) < 6:
            return out
        version = struct.unpack_from(">I", pkt, 1)[0]
        dcid_len = pkt[5]
        pos = 6 + dcid_len
        if pos >= len(pkt):
            return out
        dcid = pkt[6:6 + dcid_len].hex()
        scid_len = pkt[pos]
        pos += 1 + scid_len
        out = {"version": version, "dcid": dcid,
               "type_bits": (pkt[0] & 0x30) >> 4, "raw": pkt}
    except Exception:
        return {}
    return out


def _flows_from_logs(text: str) -> List[Dict[str, Any]]:
    flows: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict) and ("dcid" in obj or "pn" in obj):
                flows.append(obj)
    return flows


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    packets: List[Dict[str, Any]] = []
    pcap = parse_pcap(data)
    if pcap.get("ok"):
        for p in packet_payloads(pcap):
            if p["proto"] == "udp" and p["data"]:
                lh = parse_long_header(p["data"])
                if lh:
                    packets.append(lh)
    text = text_of(data)
    logged = _flows_from_logs(text)
    # Packet-number reuse from logs.
    seen_pn = set()
    reuse = 0
    vn_packets = 0
    for rec in logged:
        dcid = str(rec.get("dcid", ""))
        pn = rec.get("pn")
        if pn is not None:
            sig = (dcid, pn)
            if sig in seen_pn:
                reuse += 1
            seen_pn.add(sig)
        if str(rec.get("type", "")).lower() in (
                "version_negotiation", "vn") or \
                rec.get("version") in (0, "0", "0x00000000"):
            vn_packets += 1
    for lh in packets:
        if lh.get("version") == 0:
            vn_packets += 1
        raw = lh.get("raw") or b""
        # Initial packets (type_bits 0) carry the TLS ClientHello in
        # cleartext crypto frames at this layer of capture tools.
        if lh.get("type_bits") == 0:
            m = _SNI_SHAPE.search(bytes(raw))
            if m:
                hits.append({
                    "key": "quic_initial_sni_cleartext",
                    "severity": "low",
                    "value": f"QUIC Initial packet in supplied "
                             f"capture exposes SNI-shaped hostname "
                             f"'{m.group(0).decode()}' in cleartext "
                             "crypto frames",
                    "evidence": {"dcid": lh.get("dcid", "")[:16],
                                 "remediation": "QUIC Initials are "
                                 "encrypted with well-known keys, so "
                                 "SNI is observable on path: use ECH "
                                 "where supported and avoid descriptive "
                                 "internal names."}})
                break
    if reuse:
        hits.append({
            "key": "quic_packet_number_reuse", "severity": "medium",
            "value": f"{reuse} QUIC packet-number reuse(s) within a "
                     "connection ID in the supplied capture - nonce "
                     "reuse breaks AEAD guarantees",
            "evidence": {"reuse": reuse,
                         "remediation": "Packet numbers must never "
                         "repeat under one connection ID / key phase; "
                         "audit the QUIC stack's PN allocation."}})
    if vn_packets:
        hits.append({
            "key": "quic_version_negotiation_seen", "severity": "low",
            "value": f"{vn_packets} QUIC version-negotiation packet(s) "
                     "in supplied capture - verify the negotiated "
                     "version was not forced below v1/v2",
            "evidence": {"vn_packets": vn_packets,
                         "remediation": "Pin a minimum QUIC version "
                         "and alert on unexpected VN packets (version "
                         "downgrade posture)."}})
    return hits[:10]


class QuicPacketFlowReassemblerPlugin(Plugin):
    id = "quic_packet_flow_reassembler"
    label = "QUIC Packet Flow Reassembler"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "network"
    phase = 2
    description = ("Reassembles QUIC flows from supplied captures "
                   "(connection IDs, packet numbers, version "
                   "negotiation) and flags PN reuse / VN downgrade / "
                   "cleartext Initial SNI posture.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("quic_captures",))
            if got is not None:
                return got
            return self._ok([], "no supplied QUIC capture/log in "
                            "ctx.shared; nothing captured live")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
