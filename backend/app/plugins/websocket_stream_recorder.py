"""WebSocket stream recorder (variant of websocket_tester): frame-level
analysis of operator-supplied WebSocket captures / session logs.

websocket_tester only performs a connect-only Upgrade handshake.
This delta parses supplied capture records (JSON-lines or text log
lines carrying direction, opcode, payload) and reports frame-level
findings: credential-shaped payloads (masked), oversized frames,
and cleartext tokens in text frames.

BOUNDARY: supplied captures/logs or operator-owned endpoints only.
No live third-party stream capture; this module opens no sockets.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, credentialish, mask_secret, text_of

MAX_FRAME = 65536


def _records(text: str) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                recs.append(obj)
    return recs


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if not text:
        return hits
    recs = _records(text)
    oversized = 0
    cred_hits = 0
    total = 0
    if recs:
        for r in recs:
            total += 1
            payload = str(r.get("payload") or r.get("data") or "")
            size = r.get("len") or r.get("length") or len(payload)
            try:
                size = int(size)
            except Exception:
                size = len(payload)
            if size > MAX_FRAME:
                oversized += 1
            c = credentialish(payload)
            if c and cred_hits < 4:
                masked, fp = mask_secret(c[1])
                hits.append({
                    "key": "ws_frame_credential_payload",
                    "severity": "high",
                    "value": f"Credential-shaped payload in a supplied "
                             f"WebSocket frame ({r.get('dir', '?')} "
                             f"opcode {r.get('opcode', '?')}): "
                             f"{c[0]} masked {masked}, fp {fp}",
                    "evidence": {"fingerprint": fp,
                                 "direction": str(r.get("dir", "")),
                                 "remediation": "Never send credentials "
                                 "or tokens as WebSocket frame payloads "
                                 "on unauthenticated channels; bind the "
                                 "session to authenticated identity and "
                                 "rotate anything sent in cleartext."}})
                cred_hits += 1
    else:
        # Plain text log: scan lines for credential-shaped frames.
        for line in text.splitlines():
            total += 1
            c = credentialish(line)
            if c and cred_hits < 4:
                masked, fp = mask_secret(c[1])
                hits.append({
                    "key": "ws_frame_credential_payload",
                    "severity": "high",
                    "value": f"Credential-shaped payload in a supplied "
                             f"WebSocket session log: {c[0]} masked "
                             f"{masked}, fp {fp}",
                    "evidence": {"fingerprint": fp}})
                cred_hits += 1
    if oversized:
        hits.append({
            "key": "ws_frame_oversized", "severity": "medium",
            "value": f"{oversized} oversized WebSocket frame(s) "
                     f"(> {MAX_FRAME} bytes) in supplied capture of "
                     f"{total} frame(s) - no server-side size cap is "
                     "evident",
            "evidence": {"oversized": oversized, "frames": total,
                         "remediation": "Enforce a maximum frame / "
                         "message size on the WebSocket server and "
                         "close connections that exceed it."}})
    return hits[:10]


class WebsocketStreamRecorderPlugin(Plugin):
    id = "websocket_stream_recorder"
    label = "WebSocket Stream Recorder"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "api"
    phase = 2
    description = ("Frame-level analysis of supplied WebSocket "
                   "captures/session logs: opcode/size/direction, "
                   "credential-shaped payloads masked.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "api",
                          ("websocket_captures", "ws_captures"))
            if got is not None:
                return got
            return self._ok([], "no supplied WebSocket capture/log "
                            "in ctx.shared; nothing recorded live")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
