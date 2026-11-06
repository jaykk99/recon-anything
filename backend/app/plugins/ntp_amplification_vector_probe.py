"""NTP amplification vector probe: sends ONE standard UDP NTP
client request to the target's own host:123 and measures the
response/request size ratio; a mode-7 (monlist-shaped) response in
a supplied capture, or a large ratio, flags amplification posture.

No spoofing, no amplification traffic: a single 48-byte request
from our real source address, one packet per check. Mode-7 is
analysed from supplied captures only, never sent live.
"""
from __future__ import annotations

import asyncio
import socket
import struct
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, host_port_of

REQUEST = b"\x1b" + b"\x00" * 47  # LI=0, VN=3, Mode=3 (client)


def build_client_request() -> bytes:
    return REQUEST


def analyze_response(resp: bytes, request_len: int = 48
                     ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not resp:
        return hits
    mode = resp[0] & 0x07 if resp else 0
    ratio = (len(resp) / request_len) if request_len else 0
    if mode == 7 or len(resp) > 48 and ratio >= 4:
        hits.append({
            "key": "ntp_amplification_posture", "severity": "high",
            "value": f"NTP response is {len(resp)} bytes to a "
                     f"{request_len}-byte request (ratio "
                     f"{ratio:.1f}x) - an open responder with this "
                     "ratio is an amplification vector",
            "evidence": {"response_len": len(resp), "ratio":
                         round(ratio, 2),
                         "remediation": "Restrict NTP service to "
                         "trusted clients, disable mode-7 private "
                         "requests (noquery / disable monitor in "
                         "ntpd, 'restrict default noquery'), and "
                         "rate-limit UDP 123 at the border."}})
    if mode == 7:
        hits.append({
            "key": "ntp_mode7_private_response", "severity": "medium",
            "value": "NTP mode-7 (private / monlist-class) response "
                     "present - legacy ntpd monitor facilities answer "
                     "unauthenticated private requests",
            "evidence": {"mode": 7,
                         "remediation": "Disable the monitor "
                         "facility ('disable monitor') and restrict "
                         "mode-6/7 queries to localhost."}})
    return hits


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    return analyze_response(data or b"")


def _probe(host: str, port: int, timeout: float = 3.0
           ) -> Optional[bytes]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(REQUEST, (host, port))
            data, _ = s.recvfrom(4096)
            return data
    except Exception:
        return None


class NtpAmplificationVectorProbePlugin(Plugin):
    id = "ntp_amplification_vector_probe"
    label = "NTP Amplification Vector Probe"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("Single standard NTP client request to the "
                   "target's own UDP 123; flags large response "
                   "ratios / mode-7 monlist posture. One packet, no "
                   "spoofing, no amplification traffic.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("ntp_captures",))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        host, port = host_port_of(target, 123)
        try:
            resp = await asyncio.to_thread(_probe, host, port)
        except Exception:
            resp = None
        if resp is None:
            return self._degraded(f"no NTP response from "
                                  f"{host}:{port}")
        findings = []
        for hit in analyze_response(resp):
            ev = {"severity": hit["severity"]}
            ev.update(hit.get("evidence") or {})
            findings.append(self._f(
                "infra", hit["key"], hit["value"],
                source="NTP client probe", confidence=90,
                evidence=ev, passive=False))
        if not findings:
            findings.append(self._f(
                "infra", "ntp_open_responder",
                f"{host}:{port} answers standard NTP client "
                f"requests ({len(resp)}-byte response, ratio "
                f"{len(resp) / 48:.1f}x)",
                source="NTP client probe", confidence=80,
                evidence={"severity": "low", "response_len": len(resp),
                          "remediation": "An internet-facing NTP "
                          "responder is normal for public time "
                          "servers; otherwise restrict UDP 123 to "
                          "trusted clients."},
                passive=False))
            findings.pop()  # a normal 48-byte answer is clean
        return self._ok(findings, "NTP response measured")
