"""CoAP request fuzzer - discovery-weighted adaptation: keyless CoAP
discovery against an operator-owned local target (UDP 5683): GET
/.well-known/core, enumerate resources, flag unauthenticated sensitive
resources (config, OTA, actuator paths) and DTLS-absent posture. A
supplied CoAP response capture is analysed with the same parser. No
payload fuzzing campaign; read requests only.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import (collect, host_of, is_local_or_private,
                           load_artifacts)

_SENSITIVE = ("config", "ota", "update", "firmware", "actuator",
              "admin", "reset", "relay", "door", "lock", "valve")


def parse_core(payload: bytes) -> List[str]:
    text = payload.decode("utf-8", "ignore")
    return re.findall(r"<([^>]+)>", text)


def parse_coap(data: bytes) -> Dict[str, Any]:
    """{ok, code, payload} for one CoAP message. Never raises."""
    out: Dict[str, Any] = {"ok": False, "code": 0, "payload": b""}
    try:
        if len(data) < 4 or (data[0] >> 6) != 1:
            return out
        tkl = data[0] & 0x0F
        out["code"] = data[1]
        pos = 4 + tkl
        while pos < len(data) and data[pos] != 0xFF:
            delta = data[pos] >> 4
            length = data[pos] & 0x0F
            pos += 1
            if delta == 13:
                pos += 1
            elif delta == 14:
                pos += 2
            if length == 13:
                pos += 1
            elif length == 14:
                pos += 2
            pos += length
        if pos < len(data) and data[pos] == 0xFF:
            out["payload"] = data[pos + 1:]
        out["ok"] = True
    except Exception:
        pass
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    msg = parse_coap(data)
    resources: List[str] = []
    if msg["ok"] and msg["payload"]:
        resources = parse_core(msg["payload"])
    if not resources and b"</" in data:
        resources = parse_core(data)
    if not resources:
        return hits
    inventory = {
        "key": "coap_resource_inventory", "severity": "low",
        "value": "CoAP resources discovered via /.well-known/core: "
                 + ", ".join(resources[:10]),
        "evidence": {"resources": resources[:10]}}
    for r in resources:
        low = r.lower()
        if any(s in low for s in _SENSITIVE):
            hits.append({
                "key": "coap_sensitive_resource_unauth", "severity":
                "high",
                "value": f"CoAP sensitive resource {r} is enumerable "
                         "without authentication (plain UDP, no DTLS "
                         "on 5683)",
                "evidence": {"resource": r}})
    if hits:
        hits.insert(0, inventory)
    return hits[:10]


class _CoapClient(asyncio.DatagramProtocol):
    def __init__(self):
        self.data = b""
        self.done = asyncio.Event()

    def datagram_received(self, data, addr):
        self.data = data
        self.done.set()


async def _live_discovery(host: str) -> bytes:
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        _CoapClient, remote_addr=(host, 5683))
    try:
        # CON GET, tid 0x1234, token 0xAB; option 11 (Uri-Path):
        # 0xBB = delta 11 len 11 ".well-known", then 0x04 = delta 0
        # len 4 "core".
        req = bytes([0x41, 0x01, 0x12, 0x34, 0xAB, 0xBB]) + \
            b".well-known" + bytes([0x04]) + b"core"
        transport.sendto(req)
        await asyncio.wait_for(proto.done.wait(), 5)
        return proto.data
    finally:
        transport.close()


class CoapRequestFuzzerPlugin(Plugin):
    id = "coap_request_fuzzer"
    label = "CoAP Discovery Check"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    description = ("Discovery-weighted CoAP posture on operator-owned "
                   "targets only: /.well-known/core enumeration, "
                   "unauthenticated sensitive resources, DTLS-absent. "
                   "Read requests only - no fuzzing campaign.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            if load_artifacts(target, ctx):
                return collect(self, target, ctx, analyze)
            host = host_of(target)
            if ctx.mode == "active" and is_local_or_private(host):
                try:
                    resp = await asyncio.wait_for(
                        _live_discovery(host), 8)
                except Exception:
                    return self._ok(
                        [], f"no CoAP answer from owned target {host}")
                findings: List = []
                for hit in analyze(resp, host):
                    ev = {"severity": hit.get("severity", "low")}
                    ev.update(hit.get("evidence") or {})
                    findings.append(self._f(
                        "infra", hit["key"], hit["value"], source=host,
                        confidence=85, evidence=ev, passive=False))
                return self._ok(findings, "live CoAP discovery")
            return self._ok(
                [], "supply a CoAP response capture, or run active "
                "against an operator-owned local target")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
