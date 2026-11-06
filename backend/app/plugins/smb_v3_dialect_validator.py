"""SMB v3 dialect validator (variant of port_audit + smb_ldap_enum):
one SMB2 NEGOTIATE probe parsing the returned dialect revision,
SMB1 fallback acceptance, and whether signing is required.

port_audit flags 445 exposure with remediation text only and
smb_ldap_enum enumerates surface; neither negotiates a dialect.
The probe is a crafted NEGOTIATE request (dialects 2.0.2..3.1.1),
handshake bytes only - no authentication, no session setup.
Supplied negotiate-response captures / smb.conf-style configs are
analysed with the same pure parser.
"""
from __future__ import annotations

import asyncio
import re
import socket
import struct
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, host_port_of, text_of

DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0",
            0x0302: "3.0.2", 0x0311: "3.1.1"}


def build_negotiate_request(smb1: bool = False) -> bytes:
    if smb1:
        # Minimal SMB1 negotiate asking only for NT LM 0.12.
        dialects = b"\x02NT LM 0.12\x00"
        hdr = (b"\xffSMB" + b"\x72" + b"\x00" * 27)
        params = b"\x00"
        msg = hdr + struct.pack("<H", len(params)) + params + \
            struct.pack("<H", len(dialects)) + dialects
        return struct.pack(">I", len(msg)) + msg
    body = struct.pack("<HHHHI", 36, 5, 0, 0, 0)  # structsize, count
    body += struct.pack("<HHHHH", 0x0202, 0x0210, 0x0300, 0x0302,
                        0x0311)
    body += b"\x00" * 8  # client guid
    body += struct.pack("<I", 0)  # capabilities
    hdr = (b"\xfeSMB" + struct.pack("<HH", 64, 1) +
           struct.pack("<I", 0) + struct.pack("<I", 0) +
           struct.pack("<H", 0) + struct.pack("<H", 0) +
           struct.pack("<I", 0) + b"\x00" * 8 +
           struct.pack("<Q", 0) + b"\x00" * 12)
    msg = hdr + body
    return struct.pack(">I", len(msg)) + msg


def parse_negotiate_response(data: bytes) -> Dict[str, Any]:
    """{smb1, dialect, signing_required, ok}. Never raises."""
    out: Dict[str, Any] = {"ok": False}
    try:
        blob = data or b""
        if len(blob) >= 4 and struct.unpack_from(">I", blob, 0)[0] == \
                len(blob) - 4:
            blob = blob[4:]
        if blob[:4] == b"\xffSMB":
            out.update({"ok": True, "smb1": True})
            return out
        if blob[:4] != b"\xfeSMB" or len(blob) < 72:
            return out
        security_mode = struct.unpack_from("<H", blob, 66)[0]
        dialect = struct.unpack_from("<H", blob, 68)[0]
        out.update({"ok": True, "smb1": False, "dialect": dialect,
                    "dialect_name": DIALECTS.get(dialect,
                                                 hex(dialect)),
                    "signing_required": bool(security_mode & 0x02),
                    "signing_enabled": bool(security_mode & 0x01)})
    except Exception:
        pass
    return out


def hits_for_parse(parsed: Dict[str, Any], src: str
                   ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not parsed.get("ok"):
        return hits
    if parsed.get("smb1"):
        hits.append({
            "key": "smb1_fallback_accepted", "severity": "high",
            "value": f"SMB1 negotiate accepted ({src}) - the legacy "
                     "SMBv1 dialect is still enabled",
            "evidence": {"remediation": "Disable SMBv1 entirely; "
                         "it is the EternalBlue-era dialect and must "
                         "not be negotiable."}})
        return hits
    dialect = parsed.get("dialect", 0)
    if dialect and dialect < 0x0300:
        hits.append({
            "key": "smb_old_dialect_negotiated", "severity": "medium",
            "value": f"SMB negotiated old dialect "
                     f"{parsed.get('dialect_name')} ({src}) - "
                     "pre-3.0 dialects lack encryption support",
            "evidence": {"dialect": parsed.get("dialect_name"),
                         "remediation": "Require SMB 3.x minimum "
                         "dialect and enable SMB encryption for "
                         "sensitive shares."}})
    if not parsed.get("signing_required"):
        hits.append({
            "key": "smb_signing_not_required", "severity": "medium",
            "value": f"SMB signing is not required ({src}, dialect "
                     f"{parsed.get('dialect_name')}) - relay posture",
            "evidence": {"dialect": parsed.get("dialect_name"),
                         "remediation": "Set server signing to "
                         "REQUIRED so unsigned (relayed) sessions "
                         "are rejected."}})
    return hits


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    if not data:
        return []
    parsed = parse_negotiate_response(data)
    if parsed.get("ok"):
        return hits_for_parse(parsed, "supplied capture")
    text = text_of(data)
    hits: List[Dict[str, Any]] = []
    if re.search(r"(?im)^\s*(min\s+protocol|server\s+min\s+protocol)"
                 r"\s*=\s*(CORE|NT1|LANMAN)", text) or \
            re.search(r"(?i)smb1\s*(enabled|on|true)", text):
        hits.append({
            "key": "smb1_fallback_accepted", "severity": "high",
            "value": "Supplied SMB config enables SMBv1 / a pre-NT1 "
                     "minimum protocol",
            "evidence": {"remediation": "Raise the minimum protocol "
                         "to SMB2/SMB3 and disable SMBv1."}})
    if re.search(r"(?i)server\s+signing\s*=\s*(disabled|optional|auto)",
                 text):
        hits.append({
            "key": "smb_signing_not_required", "severity": "medium",
            "value": "Supplied SMB config does not require signing",
            "evidence": {"remediation": "Set server signing = "
                         "required."}})
    return hits


def _probe(host: str, port: int, smb1: bool,
           timeout: float = 4.0) -> Optional[bytes]:
    try:
        with socket.create_connection((host, port),
                                      timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(build_negotiate_request(smb1))
            data = sock.recv(4096)
            return data or None
    except Exception:
        return None


class SmbV3DialectValidatorPlugin(Plugin):
    id = "smb_v3_dialect_validator"
    label = "SMB v3 Dialect Validator"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("One SMB2 NEGOTIATE probe: dialect revision "
                   "(2.0.2-3.1.1), SMB1 fallback acceptance, signing "
                   "required vs enabled. Handshake bytes only.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("smb_captures", "smb_configs"))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        host, port = host_port_of(target, 445)
        findings = []
        resp = await asyncio.to_thread(_probe, host, port, False)
        if resp:
            for hit in hits_for_parse(
                    parse_negotiate_response(resp), f"{host}:{port}"):
                ev = {"severity": hit["severity"]}
                ev.update(hit.get("evidence") or {})
                findings.append(self._f(
                    "infra", hit["key"], hit["value"],
                    source="SMB2 negotiate probe", confidence=90,
                    evidence=ev, passive=False))
        resp1 = await asyncio.to_thread(_probe, host, port, True)
        if resp1 and parse_negotiate_response(resp1).get("smb1"):
            for hit in hits_for_parse(
                    parse_negotiate_response(resp1), f"{host}:{port}"):
                ev = {"severity": hit["severity"]}
                ev.update(hit.get("evidence") or {})
                findings.append(self._f(
                    "infra", hit["key"], hit["value"],
                    source="SMB1 negotiate probe", confidence=90,
                    evidence=ev, passive=False))
        if not resp and not resp1:
            return self._degraded(f"no SMB response from "
                                  f"{host}:{port}")
        return self._ok(findings, "SMB dialect negotiation parsed")
