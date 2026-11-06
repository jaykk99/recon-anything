"""gRPC / protobuf payload decoder: decodes an operator-supplied
protobuf payload against an operator-supplied .proto schema.

Pure-Python wire-format parser (varint / length-delimited / fixed)
- no protoc, keyless. Field numbers are mapped to schema field
names/types and sensitive fields (password/token/secret/...) are
flagged with values MASKED. A raw payload with no schema is decoded
structurally and string fields that look credential-shaped are
flagged masked the same way.

BOUNDARY: supplied schema + supplied capture/hex payload only.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, mask_secret

_SENSITIVE = re.compile(
    r"(?i)(password|passwd|secret|token|api[-_]?key|auth|credential|"
    r"private|ssn|card)")
_FIELD_RE = re.compile(
    r"^\s*(?:repeated\s+)?([A-Za-z0-9_.]+)\s+([A-Za-z0-9_]+)\s*=\s*(\d+)",
    re.M)
_HEX_RE = re.compile(r"(?im)(?:PAYLOAD_HEX|payload_hex)\s*[:=]\s*"
                     r"([0-9a-fA-F\s]{8,})")
_BARE_HEX_RE = re.compile(r"\b([0-9a-fA-F]{16,})\b")


def parse_schema(text: str) -> Dict[int, Tuple[str, str]]:
    fields: Dict[int, Tuple[str, str]] = {}
    for m in _FIELD_RE.finditer(text or ""):
        try:
            fields[int(m.group(3))] = (m.group(2), m.group(1))
        except Exception:
            continue
    return fields


def _varint(buf: bytes, pos: int) -> Tuple[Optional[int], int]:
    shift = 0
    val = 0
    while pos < len(buf) and shift < 70:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
    return None, pos


def decode_wire(buf: bytes) -> List[Dict[str, Any]]:
    """[(field, wiretype, value)] - value is int or bytes. Defensive."""
    out: List[Dict[str, Any]] = []
    pos = 0
    while pos < len(buf) and len(out) < 512:
        tag, pos2 = _varint(buf, pos)
        if tag is None or tag == 0:
            break
        pos = pos2
        field, wt = tag >> 3, tag & 7
        if field == 0:
            break
        if wt == 0:
            val, pos = _varint(buf, pos)
            if val is None:
                break
            out.append({"field": field, "wt": wt, "value": val})
        elif wt == 2:
            ln, pos = _varint(buf, pos)
            if ln is None or ln > len(buf) - pos:
                break
            out.append({"field": field, "wt": wt,
                        "value": buf[pos:pos + ln]})
            pos += ln
        elif wt == 5 and pos + 4 <= len(buf):
            out.append({"field": field, "wt": wt,
                        "value": buf[pos:pos + 4]})
            pos += 4
        elif wt == 1 and pos + 8 <= len(buf):
            out.append({"field": field, "wt": wt,
                        "value": buf[pos:pos + 8]})
            pos += 8
        else:
            break
    return out


def _payload_bytes(data: bytes, text: str) -> Optional[bytes]:
    m = _HEX_RE.search(text)
    if m:
        try:
            return bytes.fromhex(re.sub(r"\s+", "", m.group(1)))
        except Exception:
            return None
    if b"syntax" not in data[:64] and b"message" not in data[:256]:
        # Raw binary payload artifact.
        if data and all(b < 0x80 or b >= 0x20 for b in data[:1]):
            return data
    m = _BARE_HEX_RE.search(text)
    if m and ("proto" in text or "syntax" in text):
        try:
            return bytes.fromhex(m.group(1))
        except Exception:
            return None
    return None


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = data.decode("utf-8", "ignore")
    schema = parse_schema(text)
    payload = _payload_bytes(data, text)
    if payload is None:
        return hits
    decoded = decode_wire(payload)
    if not decoded:
        return hits
    for item in decoded:
        fname, _ftype = schema.get(item["field"], ("", ""))
        raw = item["value"]
        sval = ""
        if isinstance(raw, (bytes, bytearray)):
            sval = bytes(raw).decode("utf-8", "ignore")
        sensitive = bool(fname and _SENSITIVE.search(fname))
        if not sensitive and sval and len(sval) >= 6:
            low = sval.lower()
            if any(w in low for w in ("password=", "token=", "bearer ")):
                sensitive = True
                fname = fname or f"field{item['field']}"
        if sensitive and sval:
            masked, fp = mask_secret(sval)
            hits.append({
                "key": "grpc_sensitive_field_decoded",
                "severity": "high",
                "value": f"Sensitive protobuf field "
                         f"'{fname or item['field']}' (field "
                         f"{item['field']}) decoded from supplied "
                         f"payload: value masked {masked}, fp {fp}",
                "evidence": {"field_number": item["field"],
                             "field_name": fname,
                             "fingerprint": fp,
                             "remediation": "This sensitive value "
                             "crossed in a decodable protobuf payload. "
                             "Require TLS + per-call authentication on "
                             "the gRPC service and rotate the value."}})
    return hits[:10]


class GrpcProtobufPayloadDecoderPlugin(Plugin):
    id = "grpc_protobuf_payload_decoder"
    label = "gRPC Protobuf Payload Decoder"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "api"
    phase = 2
    description = ("Decodes supplied protobuf payloads against a "
                   "supplied .proto schema (pure-Python wire parser); "
                   "sensitive fields flagged with values masked.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "api",
                          ("proto_schemas", "grpc_captures"))
            if got is not None:
                return got
            return self._ok([], "no supplied .proto schema / payload "
                            "in ctx.shared; nothing decoded")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
