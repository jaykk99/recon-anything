"""STUN/TURN ICE candidate map (variant of port_audit): port_audit
only labels STUN/TURN ports open. This delta (1) sends ONE RFC 5389
Binding Request to the target's STUN port and parses the
XOR-MAPPED-ADDRESS (public mapping exposure), and (2) parses
operator-supplied SDP/session data for ICE candidates, flagging
srflx public-mapping disclosure and open TURN relay posture
(relay candidates reachable with embedded / non-TLS credentials).

Detection only: one binding request, no TURN allocation, no relay.
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import (collect, host_port_of, is_external_ip,
                           mask_secret, text_of)

_CAND_RE = re.compile(
    r"candidate:\S+\s+\d+\s+(udp|tcp)\s+\d+\s+(\S+)\s+(\d+)\s+typ\s+"
    r"(host|srflx|prflx|relay)", re.I)
_TURN_URL_RE = re.compile(
    r"(?i)\b(turns?:[a-z0-9.\-]+(?::\d+)?(?:\?transport=\w+)?)")


def build_binding_request() -> Tuple[bytes, bytes]:
    tid = os.urandom(12)
    return b"\x00\x01\x00\x00\x21\x12\xa4\x42" + tid, tid


def parse_binding_response(data: bytes, tid: bytes
                           ) -> Optional[Tuple[str, int]]:
    """(mapped_ip, mapped_port) from XOR-MAPPED-ADDRESS, or None."""
    try:
        if len(data) < 20 or data[:2] != b"\x01\x01":
            return None
        if data[8:20] != tid:
            return None
        mlen = struct.unpack_from(">H", data, 2)[0]
        pos = 20
        end = min(20 + mlen, len(data))
        cookie = 0x2112A442
        while pos + 4 <= end:
            atype, alen = struct.unpack_from(">HH", data, pos)
            val = data[pos + 4:pos + 4 + alen]
            if atype == 0x0020 and len(val) >= 8:  # XOR-MAPPED-ADDRESS
                fam = val[1]
                port = struct.unpack_from(">H", val, 2)[0] ^ (
                    cookie >> 16)
                if fam == 1:
                    raw = struct.unpack_from(">I", val, 4)[0] ^ cookie
                    ip = socket.inet_ntoa(struct.pack(">I", raw))
                    return ip, port
            pos += 4 + ((alen + 3) & ~3)
    except Exception:
        return None
    return None


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if not text:
        return hits
    srflx = set()
    relay = set()
    for m in _CAND_RE.finditer(text):
        ip, _port, typ = m.group(2), m.group(3), m.group(4).lower()
        if typ == "srflx" and is_external_ip(ip):
            srflx.add(ip)
        if typ == "relay":
            relay.add(ip)
    for ip in sorted(srflx)[:5]:
        hits.append({
            "key": "stun_srflx_mapping_disclosed", "severity": "low",
            "value": f"ICE srflx candidate in supplied SDP discloses "
                     f"the client's public mapping {ip} (STUN-derived)",
            "evidence": {"mapped_ip": ip,
                         "remediation": "Expected for srflx, but "
                         "confirm the app only shares candidates with "
                         "intended peers; it reveals the public IP "
                         "behind NAT."}})
    turn_urls = _TURN_URL_RE.findall(text)
    cred = re.search(r"(?i)turn[^\"'\s]*:[^\"'\s]+:[^@\"'\s]+@", text)
    plain_turn = [u for u in turn_urls if u.lower().startswith("turn:")]
    if relay and (cred or plain_turn):
        extra = ""
        if cred:
            masked, fp = mask_secret(cred.group(0))
            extra = f" (embedded credential material masked, fp {fp})"
        hits.append({
            "key": "turn_relay_open_posture", "severity": "medium",
            "value": f"ICE relay candidate(s) in supplied SDP with "
                     f"non-TLS TURN transport posture"
                     f"{extra} - relay path is exposed",
            "evidence": {"relay_candidates": sorted(relay)[:5],
                         "remediation": "Use turns: (TLS) URLs, "
                         "short-lived TURN credentials via the REST "
                         "API, and never embed static TURN passwords "
                         "in client config."}})
    return hits[:10]


def _probe(host: str, port: int, timeout: float = 3.0
           ) -> Optional[Tuple[str, int]]:
    req, tid = build_binding_request()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(req, (host, port))
            data, _ = s.recvfrom(2048)
            return parse_binding_response(data, tid)
    except Exception:
        return None


class StunTurnIceCandidateMapPlugin(Plugin):
    id = "stun_turn_ice_candidate_map"
    label = "STUN/TURN ICE Candidate Map"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("One RFC 5389 Binding Request (XOR-MAPPED-ADDRESS "
                   "exposure) + supplied-SDP ICE candidate mapping: "
                   "srflx disclosure, open TURN relay posture.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("sdp_data", "ice_candidates"))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        host, port = host_port_of(target, 3478)
        try:
            mapped = await asyncio.to_thread(_probe, host, port)
        except Exception:
            mapped = None
        if not mapped:
            return self._degraded(f"no STUN binding response from "
                                  f"{host}:{port}")
        ip, mport = mapped
        findings = [self._f(
            "infra", "stun_public_mapping_exposed",
            f"STUN server at {host}:{port} answered a Binding "
            f"Request from an arbitrary source and disclosed the "
            f"requester's public mapping {ip}:{mport}",
            source="STUN binding probe", confidence=90,
            evidence={"severity": "low", "mapped": f"{ip}:{mport}",
                      "remediation": "Expected for public STUN, but "
                      "confirm this server is meant to be public; a "
                      "private STUN/TURN should require auth or "
                      "network restrictions."},
            passive=False)]
        return self._ok(findings, "STUN binding response parsed")
