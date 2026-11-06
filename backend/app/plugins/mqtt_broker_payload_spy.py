"""MQTT broker payload spy (variant of port_audit): port_audit flags
1883/8883 open with a static note and never speaks MQTT. This is the
MQTT-aware delta: parse a supplied MQTT session capture (CONNECT /
CONNACK / SUBSCRIBE / SUBACK / PUBLISH bytes) - or run the same
read-only posture flow live against an operator-owned broker -
reporting anonymous-connect posture, wildcard subscription grants and
the topic inventory. Payload values are masked/sampled, never
bulk-collected.
"""
from __future__ import annotations

import asyncio
import struct
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import (collect, host_of, is_local_or_private,
                           load_artifacts, mask_secret)


def _varint(data: bytes, pos: int) -> Tuple[int, int]:
    val, mult = 0, 1
    while pos < len(data):
        b = data[pos]
        pos += 1
        val += (b & 0x7F) * mult
        if not (b & 0x80):
            break
        mult *= 128
    return val, pos


def parse_stream(data: bytes) -> Dict[str, Any]:
    """Parse a stream of MQTT control packets. Never raises."""
    out: Dict[str, Any] = {"connect": None, "connack": None,
                           "subscribes": [], "subacks": [],
                           "publishes": []}
    pos = 0
    while pos + 2 <= len(data):
        ptype = data[pos] >> 4
        rlen, hlen = _varint(data, pos + 1)
        body = data[hlen:hlen + rlen]
        if len(body) < rlen:
            break
        pos = hlen + rlen
        try:
            if ptype == 1 and len(body) >= 10:  # CONNECT
                plen = struct.unpack_from(">H", body, 0)[0]
                proto = body[2:2 + plen]
                if proto != b"MQTT":
                    continue
                off = 2 + plen
                level = body[off]
                flags = body[off + 1]
                off += 4  # level, flags, keepalive(2)
                cid_len = struct.unpack_from(">H", body, off)[0]
                off += 2
                cid = body[off:off + cid_len].decode("utf-8", "ignore")
                off += cid_len
                user = ""
                if flags & 0x80:
                    ulen = struct.unpack_from(">H", body, off)[0]
                    off += 2
                    user = body[off:off + ulen].decode(
                        "utf-8", "ignore")
                out["connect"] = {"client_id": cid, "level": level,
                                  "username": user,
                                  "has_password": bool(flags & 0x40),
                                  "clean": bool(flags & 0x02)}
            elif ptype == 2 and len(body) >= 2:  # CONNACK
                out["connack"] = {"session": bool(body[0] & 1),
                                  "rc": body[1]}
            elif ptype == 8:  # SUBSCRIBE
                topics = []
                off = 2
                while off + 2 < len(body):
                    tlen = struct.unpack_from(">H", body, off)[0]
                    off += 2
                    topics.append(body[off:off + tlen].decode(
                        "utf-8", "ignore"))
                    off += tlen + 1
                out["subscribes"].extend(topics)
            elif ptype == 9:  # SUBACK
                out["subacks"].append(list(body[2:]))
            elif ptype == 3:  # PUBLISH
                tlen = struct.unpack_from(">H", body, 0)[0]
                topic = body[2:2 + tlen].decode("utf-8", "ignore")
                payload = body[2 + tlen:]
                out["publishes"].append(
                    {"topic": topic, "payload": payload})
        except Exception:
            continue
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    s = parse_stream(data)
    conn, ack = s.get("connect"), s.get("connack")
    if conn is not None and ack is not None:
        if not conn["username"] and ack["rc"] == 0:
            hits.append({
                "key": "mqtt_anonymous_accepted", "severity": "high",
                "value": "MQTT broker accepted an anonymous CONNECT "
                         "(no username/password) in the supplied "
                         "session capture",
                "evidence": {"client_id": conn["client_id"][:32]}})
        topics = [t for t in s["subscribes"] if t in ("#", "$SYS/#")
                  or t.startswith("#")]
        granted = any(rc != 0x80 for sub in s["subacks"] for rc in sub)
        if topics and granted:
            hits.append({
                "key": "mqtt_wildcard_subscribe", "severity": "medium",
                "value": "MQTT broker granted a wildcard subscription "
                         f"({topics[0]}) - full topic tree readable",
                "evidence": {"filter": topics[0]}})
    for pub in s["publishes"][:6]:
        payload = pub["payload"][:64].decode("utf-8", "ignore")
        masked, fp = mask_secret(payload) if payload else ("", "")
        hits.append({
            "key": "mqtt_topic_inventory", "severity": "low",
            "value": f"MQTT topic observed: {pub['topic']} "
                     f"(payload masked {masked})",
            "evidence": {"topic": pub["topic"], "fingerprint": fp}})
    return hits[:10]


async def _live_probe(host: str) -> bytes:
    """Anonymous CONNECT + wildcard SUBSCRIBE against an owned broker;
    returns the raw packet stream for analyze(). Read-only posture."""
    reader, writer = await asyncio.open_connection(host, 1883)
    try:
        cid = b"recon-posture"
        var = b"\x00\x04MQTT\x04\x02\x00\x3c" + \
            struct.pack(">H", len(cid)) + cid
        connect_pkt = bytes([0x10, len(var)]) + var
        writer.write(connect_pkt)
        await writer.drain()
        # capture = what we sent interleaved with what came back, in
        # order, so analyze() sees the same stream as a pcap would.
        capture = connect_pkt
        capture += await asyncio.wait_for(reader.read(4096), 5)
        pkt = struct.pack(">H", 1)
        for filt in (b"#", b"$SYS"):
            pkt += struct.pack(">H", len(filt)) + filt + b"\x00"
        sub_pkt = bytes([0x82, len(pkt)]) + pkt
        writer.write(sub_pkt)
        await writer.drain()
        capture += sub_pkt
        try:
            capture += await asyncio.wait_for(reader.read(4096), 5)
        except Exception:
            pass
        writer.write(b"\xe0\x00")
        await writer.drain()
        return capture
    finally:
        writer.close()


class MqttBrokerPayloadSpyPlugin(Plugin):
    id = "mqtt_broker_payload_spy"
    label = "MQTT Broker Posture Spy"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of port_audit: MQTT-aware posture - "
                   "anonymous CONNECT, wildcard subscribe grant and "
                   "topic inventory (payloads masked) from a supplied "
                   "session capture or an operator-owned local broker.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            if load_artifacts(target, ctx):
                return collect(self, target, ctx, analyze)
            host = host_of(target)
            if ctx.mode == "active" and is_local_or_private(host):
                try:
                    stream = await asyncio.wait_for(
                        _live_probe(host), 12)
                except Exception:
                    return self._ok(
                        [], f"no MQTT answer from owned target {host}")
                findings: List = []
                for hit in analyze(stream, host):
                    ev = {"severity": hit.get("severity", "low")}
                    ev.update(hit.get("evidence") or {})
                    findings.append(self._f(
                        "infra", hit["key"], hit["value"], source=host,
                        confidence=85, evidence=ev, passive=False))
                return self._ok(findings, "live MQTT posture probe")
            return self._ok(
                [], "supply an MQTT session capture artifact, or run "
                "active against an operator-owned local broker")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
