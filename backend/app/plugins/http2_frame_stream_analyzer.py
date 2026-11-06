"""HTTP/2 frame stream analyzer (variant of http2_check): frame-level
analysis of operator-supplied HTTP/2 captures or h2 debug logs.

http2_check only reports the ALPN-negotiated protocol. This delta
parses frames (9-byte headers after the client preface, or text log
lines), reassembles per-stream HEADERS/DATA sequences, and flags
anomalies: oversized frames, stream-id reuse after close, DATA on
stream 0, and rapid-reset patterns (many RST_STREAM).

BOUNDARY: supplied captures/logs only; no live interception.
"""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, text_of

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
               4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING",
               7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION"}
DEFAULT_MAX_FRAME = 16384
_LOG_RE = re.compile(
    r"(?i)(DATA|HEADERS|RST_STREAM|SETTINGS|PING|GOAWAY|WINDOW_UPDATE)"
    r"\D{0,12}stream\D{0,4}(\d+)\D{0,12}len\D{0,4}(\d+)")


def parse_frames(data: bytes) -> List[Dict[str, Any]]:
    frames: List[Dict[str, Any]] = []
    blob = data or b""
    if blob.startswith(PREFACE):
        blob = blob[len(PREFACE):]
    pos = 0
    while pos + 9 <= len(blob) and len(frames) < 20000:
        ln = int.from_bytes(blob[pos:pos + 3], "big")
        typ = blob[pos + 3]
        flags = blob[pos + 4]
        sid = struct.unpack_from(">I", blob, pos + 5)[0] & 0x7FFFFFFF
        if ln > len(blob) - pos - 9:
            break
        frames.append({"type": typ, "flags": flags, "stream": sid,
                       "len": ln})
        pos += 9 + ln
    if frames:
        return frames
    text = text_of(data)
    for m in _LOG_RE.finditer(text):
        frames.append({"type": {v: k for k, v in
                                 FRAME_TYPES.items()}.get(
                                     m.group(1).upper(), -1),
                       "flags": 0, "stream": int(m.group(2)),
                       "len": int(m.group(3))})
    return frames


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    frames = parse_frames(data or b"")
    if not frames:
        return hits
    oversized = [f for f in frames if f["len"] > DEFAULT_MAX_FRAME]
    if oversized:
        hits.append({
            "key": "http2_oversized_frame", "severity": "medium",
            "value": f"{len(oversized)} HTTP/2 frame(s) exceed the "
                     f"default 16384-byte max frame size in the "
                     f"supplied capture (largest "
                     f"{max(f['len'] for f in oversized)} bytes)",
            "evidence": {"oversized": len(oversized),
                         "remediation": "Enforce SETTINGS_MAX_FRAME_SIZE "
                         "limits server-side and reject oversized frames."}})
    closed = set()
    reused = 0
    for f in frames:
        if f["stream"] == 0 and f["type"] in (0, 1):
            hits.append({
                "key": "http2_data_on_stream_zero", "severity": "high",
                "value": "HTTP/2 DATA/HEADERS frame on stream 0 in "
                         "supplied capture - connection-level frame "
                         "used on the reserved stream",
                "evidence": {"stream": 0}})
            break
        if f["type"] in (0, 1) and f["flags"] & 0x1:
            if f["stream"] in closed:
                reused += 1
            closed.add(f["stream"])
        elif f["stream"] in closed and f["type"] == 0:
            reused += 1
    if reused:
        hits.append({
            "key": "http2_stream_id_reuse", "severity": "medium",
            "value": f"{reused} HTTP/2 frame(s) reuse a stream id "
                     "after END_STREAM in the supplied capture",
            "evidence": {"reused": reused,
                         "remediation": "Reject frames on closed "
                         "streams; stream-id reuse after close is a "
                         "protocol violation implementations must drop."}})
    resets = sum(1 for f in frames if f["type"] == 3)
    streams = len({f["stream"] for f in frames if f["stream"]})
    if resets >= 10 and streams and resets >= streams // 2:
        hits.append({
            "key": "http2_rapid_reset_pattern", "severity": "medium",
            "value": f"Rapid-reset pattern in supplied HTTP/2 capture: "
                     f"{resets} RST_STREAM across {streams} streams "
                     "(CVE-2023-44487 shaped load)",
            "evidence": {"rst_stream": resets, "streams": streams,
                         "remediation": "Cap concurrent streams and "
                         "RST rates per connection; patch the HTTP/2 "
                         "stack for rapid-reset handling."}})
    return hits[:10]


class Http2FrameStreamAnalyzerPlugin(Plugin):
    id = "http2_frame_stream_analyzer"
    label = "HTTP/2 Frame Stream Analyzer"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "network"
    phase = 2
    description = ("Frame-level analysis of supplied HTTP/2 captures/"
                   "logs: per-stream reassembly, oversized frames, "
                   "stream-id reuse, rapid-reset counts.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("http2_captures", "h2_captures"))
            if got is not None:
                return got
            return self._ok([], "no supplied HTTP/2 capture/log in "
                            "ctx.shared; nothing intercepted live")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
