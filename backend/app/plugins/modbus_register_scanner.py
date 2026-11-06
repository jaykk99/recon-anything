"""Modbus register scanner (variant of port_audit): port_audit labels
TCP 502 'Modbus' and stops. This speaks Modbus read-only against an
operator-owned target (or parses a supplied Modbus/TCP capture):
device identification (FC43/17) and a bounded holding-register read
(FC3, capped range). Write function codes are NEVER sent - write
posture is inferred from the protocol having no authentication, not
tested by writing.
"""
from __future__ import annotations

import asyncio
import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import (collect, host_of, is_local_or_private,
                           load_artifacts)


def parse_stream(data: bytes) -> Dict[str, Any]:
    """Parse Modbus/TCP ADUs. {functions: [...], device_id, registers}"""
    out: Dict[str, Any] = {"functions": [], "device_id": "",
                           "registers": [], "exceptions": []}
    pos = 0
    while pos + 8 <= len(data):
        try:
            _tid, _pid, length = struct.unpack_from(">HHH", data, pos)
            unit = data[pos + 6]
            pdu = data[pos + 7:pos + 6 + length]
            if length < 2 or len(pdu) < 1:
                break
            pos += 6 + length
            fc = pdu[0]
            if fc & 0x80:
                out["exceptions"].append(fc & 0x7F)
                continue
            out["functions"].append(fc)
            if fc == 0x2B and len(pdu) > 4:
                text = pdu.decode("utf-8", "ignore")
                parts = [p for p in text.split("\x00") if len(p) > 2]
                out["device_id"] = " ".join(parts)[:80]
            if fc in (0x03, 0x04) and len(pdu) >= 2:
                n = pdu[1]
                out["registers"] = list(struct.unpack_from(
                    ">" + "H" * (n // 2), pdu, 2)) if n >= 2 else []
        except Exception:
            break
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    s = parse_stream(data)
    if not s["functions"] and not s["exceptions"]:
        return hits
    if s["exceptions"] and not s["functions"]:
        return hits  # reads refused - clean posture for this delta
    if 0x2B in s["functions"]:
        hits.append({
            "key": "modbus_device_id_disclosed", "severity": "low",
            "value": "Modbus device identification (FC43) answered "
                     "without authentication"
                     + (f": {s['device_id']}" if s["device_id"] else ""),
            "evidence": {"device_id": s["device_id"][:60]}})
    if any(fc in (0x03, 0x04) for fc in s["functions"]):
        hits.append({
            "key": "modbus_registers_readable_noauth",
            "severity": "medium",
            "value": f"Modbus holding/input registers readable without "
                     f"any authentication ({len(s['registers'])} "
                     "values in capture); the protocol has no auth, so "
                     "write function codes are equally unguarded "
                     "(inferred - writes were not tested)",
            "evidence": {"registers": len(s["registers"]),
                         "sample": s["registers"][:8]}})
    return hits[:8]


async def _live_read(host: str) -> bytes:
    reader, writer = await asyncio.open_connection(host, 502)
    try:
        stream = b""
        # FC43/14 device identification (unit 1)
        adu = struct.pack(">HHHB", 1, 0, 5, 1) + bytes([0x2B, 0x0E, 0x01, 0x00])
        writer.write(adu)
        await writer.drain()
        try:
            stream += await asyncio.wait_for(reader.read(1024), 5)
        except Exception:
            pass
        # FC3 read 8 holding registers from 0 (unit 1)
        adu = struct.pack(">HHHB", 2, 0, 6, 1) + bytes(
            [0x03]) + struct.pack(">HH", 0, 8)
        writer.write(adu)
        await writer.drain()
        try:
            stream += await asyncio.wait_for(reader.read(1024), 5)
        except Exception:
            pass
        return stream
    finally:
        writer.close()


class ModbusRegisterScannerPlugin(Plugin):
    id = "modbus_register_scanner"
    label = "Modbus Register Scanner"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of port_audit: Modbus-aware read-only check "
                   "on operator-owned targets (FC43 device ID + bounded "
                   "FC3 register read) or supplied capture analysis. "
                   "Write codes are never sent.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            if load_artifacts(target, ctx):
                return collect(self, target, ctx, analyze)
            host = host_of(target)
            if ctx.mode == "active" and is_local_or_private(host):
                try:
                    stream = await asyncio.wait_for(_live_read(host), 12)
                except Exception:
                    return self._ok(
                        [], f"no Modbus answer from owned target {host}")
                findings: List = []
                for hit in analyze(stream, host):
                    ev = {"severity": hit.get("severity", "low")}
                    ev.update(hit.get("evidence") or {})
                    findings.append(self._f(
                        "infra", hit["key"], hit["value"], source=host,
                        confidence=85, evidence=ev, passive=False))
                return self._ok(findings, "live Modbus read-only probe")
            return self._ok(
                [], "supply a Modbus capture artifact, or run active "
                "against an operator-owned local target")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
