"""SMB/LDAP exposure enumeration (Impacket-style, read-only checks).

DETECTION ONLY (Tier-6 rule). Four exposure CHECKS on the target's
own hosts, in the spirit of Impacket's enumeration examples - but no
credential use, no relay, no secrets/hash dumping, no writes:

  1. SMBv1 enabled: an SMB1 negotiate naming only the NT LM 0.12
     dialect; a valid SMB1 negotiate response means the legacy
     dialect is still accepted.
  2. SMB signing posture: an SMB2 negotiate; the response's
     SecurityMode says whether signing is enabled and whether it is
     REQUIRED. Enabled-but-not-required is the relay-friendly
     posture and is the finding.
  3. LDAP anonymous bind: one BindRequest with an empty DN and an
     empty simple password. resultCode 0 = the directory accepts
     unauthenticated binds. The bind is the check; nothing is
     searched or read afterwards.
  4. SMB null session: after a successful SMB1 negotiate, one
     SessionSetupAndX with an empty account; a success status means
     unauthenticated sessions are accepted. No share is listed and
     nothing is read - acceptance alone is the exposure.

Distinct remainder vs existing plugins (checked against master 847):
smb_tech.py fingerprints small-business WEBSITE platforms (its name
is a false friend - no SMB protocol), ldapi.py is LDAP *injection*
over HTTP parameters, and port_audit.py flags ports 445/389 by
number with advice text ("verify anonymous bind is disabled") but
never performs any of these protocol checks.
"""
from __future__ import annotations

import asyncio
import struct
import time
from typing import Dict, List, Optional

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION_SMBV1 = ("Disable SMBv1 everywhere (it is the EternalBlue "
                     "attack surface) and require SMB2/3.")
REMEDIATION_SIGNING = ("Require SMB signing (not merely enable it) on "
                       "servers and clients to close the relay path.")
REMEDIATION_LDAP = ("Disable anonymous LDAP binds; require "
                    "authenticated binds and LDAP signing/channel "
                    "binding.")
REMEDIATION_NULL = ("Disable null sessions / anonymous SMB logons "
                    "(RestrictAnonymous) and require authentication "
                    "for any session setup.")


# ---------------------------------------------------------------------------
# Wire builders (minimal, standards-shaped)
# ---------------------------------------------------------------------------

def _netbios(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def build_smb1_negotiate() -> bytes:
    dialects = b"\x02NT LM 0.12\x00"
    params = bytes([0])  # WordCount = 0
    data = struct.pack("<H", len(dialects)) + dialects
    # 32-byte SMB1 header: magic, cmd, status, flags, flags2, rest 0.
    header = b"\xffSMB" + bytes([0x72]) + b"\x00" * 27
    msg = header + params + data
    return _netbios(msg)


def build_smb2_negotiate() -> bytes:
    # SMB2 header (64 bytes) + negotiate request naming dialect 0x0202.
    header = struct.pack("<4sHHIHHIIQIIQ16s",
                         b"\xfeSMB", 64, 0, 0, 0x0000, 1, 0, 0, 0, 0,
                         0, 0, b"\x00" * 16)
    body = struct.pack("<HHHHI16sBBI", 36, 1, 0, 1, 0,
                       b"\x00" * 16, 0, 0, 0) + struct.pack("<H", 0x0202)
    return _netbios(header + body)


def build_smb1_session_setup_null() -> bytes:
    """SessionSetupAndX (0x73) with empty account/native fields."""
    # 13 words (26 bytes): AndX cmd/offset, max buffer, max mpx, VC,
    # session key, ANSI pw len = 0, unicode pw len = 0, reserved,
    # capabilities. Data: empty password bytes + empty account,
    # domain, native OS and native LAN manager strings (NUL each).
    words = struct.pack("<BHHHIHHIII", 0xFF, 0, 1024, 2, 0, 0, 0, 0,
                        0, 0)
    words = words[:26].ljust(26, b"\x00")
    data = b"\x00\x00\x00\x00"
    header = b"\xffSMB" + bytes([0x73]) + b"\x00" * 27
    msg = (header + bytes([13]) + words
           + struct.pack("<H", len(data)) + data)
    return _netbios(msg)


def build_ldap_anon_bind() -> bytes:
    # LDAPMessage { messageID 1, BindRequest(0x60) { version 3,
    # name "" , simple(0x80) "" } } - BER encoded.
    bind = bytes([0x60, 0x0C, 0x02, 0x01, 0x03, 0x04, 0x00,
                  0x80, 0x00])
    return bytes([0x30, 0x0E, 0x02, 0x01, 0x01]) + bind


# ---------------------------------------------------------------------------
# Pure response parsers (fixture-tested on canned bytes)
# ---------------------------------------------------------------------------

def parse_smb1_negotiate(resp: bytes) -> Optional[Dict]:
    """Parse an SMB1 negotiate response; None if not one."""
    if not resp:
        return None
    idx = resp.find(b"\xffSMB")
    if idx < 0 or len(resp) < idx + 37:
        return None
    status = struct.unpack("<I", resp[idx + 5:idx + 9])[0]
    wc = resp[idx + 32]
    out: Dict = {"status": status, "word_count": wc}
    if wc >= 17 and len(resp) >= idx + 37 + 33:
        p = resp[idx + 33:idx + 33 + 34]
        out["dialect_index"] = struct.unpack("<H", p[0:2])[0]
        out["security_mode"] = p[2]
        out["signing_enabled"] = bool(p[2] & 0x04)
        out["signing_required"] = bool(p[2] & 0x08)
    return out


def parse_smb2_negotiate(resp: bytes) -> Optional[Dict]:
    """Parse an SMB2 negotiate response; None if not one."""
    if not resp:
        return None
    idx = resp.find(b"\xfeSMB")
    if idx < 0 or len(resp) < idx + 64 + 6:
        return None
    status = struct.unpack("<I", resp[idx + 8:idx + 12])[0]
    body = resp[idx + 64:]
    out: Dict = {"status": status}
    if len(body) >= 6:
        sec = struct.unpack("<H", body[2:4])[0]
        out["dialect"] = struct.unpack("<H", body[4:6])[0]
        out["security_mode"] = sec
        out["signing_enabled"] = bool(sec & 0x01)
        out["signing_required"] = bool(sec & 0x02)
    return out


def parse_smb1_session_setup(resp: bytes) -> Optional[Dict]:
    """Status of an SMB1 SessionSetupAndX response."""
    if not resp:
        return None
    idx = resp.find(b"\xffSMB")
    if idx < 0 or len(resp) < idx + 9:
        return None
    return {"status": struct.unpack("<I", resp[idx + 5:idx + 9])[0]}


def parse_ldap_bind_response(resp: bytes) -> Optional[int]:
    """resultCode of an LDAP BindResponse, or None if unparseable."""
    if not resp or len(resp) < 8 or resp[0] != 0x30:
        return None
    # Skip LDAPMessage header + messageID, find protocolOp 0x61.
    i = 2
    if resp[1] & 0x80:
        i = 2 + (resp[1] & 0x7F)
    if i >= len(resp):
        return None
    # messageID INTEGER
    if resp[i] != 0x02:
        return None
    i += 2 + resp[i + 1]
    if i + 2 >= len(resp) or resp[i] != 0x61:
        return None
    # BindResponse body starts with resultCode ENUMERATED.
    j = i + 2
    if resp[i + 1] & 0x80:
        j = i + 2 + (resp[i + 1] & 0x7F)
    if j + 2 >= len(resp) or resp[j] != 0x0A:
        return None
    return resp[j + 2]


# ---------------------------------------------------------------------------
# Transport (module-level so fixtures can substitute canned responses)
# ---------------------------------------------------------------------------

async def _tcp_exchange(host: str, port: int, payload: bytes,
                        timeout: float = 4.0) -> bytes:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return b""
    try:
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.read(4096),
                                      timeout=timeout)
    except Exception:
        return b""
    finally:
        try:
            writer.close()
        except Exception:
            pass


class SmbLdapEnumPlugin(Plugin):
    id = "smb_ldap_enum"
    label = "SMB/LDAP Exposure Enumeration"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    description = ("Read-only SMB/LDAP exposure checks: SMBv1, SMB "
                   "signing posture, LDAP anonymous bind, SMB null "
                   "session. No credentials, no dumping.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = domain_from_target(target.type, target.normalized)
        if not host:
            return self._skipped("no host for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode (protocol probes)")
        findings: List[Finding] = []

        # --- SMB on 445 (fallback 139) ---
        smb_port = 445
        resp1 = await _tcp_exchange(host, 445, build_smb1_negotiate())
        neg1 = parse_smb1_negotiate(resp1)
        if neg1 is None:
            resp1b = await _tcp_exchange(host, 139,
                                         build_smb1_negotiate())
            neg1 = parse_smb1_negotiate(resp1b)
            if neg1 is not None:
                smb_port = 139
        if neg1 is not None and neg1.get("status", 1) == 0:
            findings.append(self._f(
                "infra", "smbv1_enabled",
                f"HIGH: SMBv1 (NT LM 0.12) negotiate accepted on "
                f"{host}:{smb_port} - the legacy dialect is enabled.",
                source="smb negotiate probe",
                source_url=f"smb://{host}:{smb_port}", confidence=90,
                evidence={"severity": "high",
                          "remediation": REMEDIATION_SMBV1,
                          "security_mode": neg1.get("security_mode")},
                passive=False, bounty_value="high"))
            # Null-session check on the dialect that just answered.
            ss = await _tcp_exchange(
                host, smb_port, build_smb1_session_setup_null())
            parsed_ss = parse_smb1_session_setup(ss)
            if parsed_ss is not None and parsed_ss["status"] == 0:
                findings.append(self._f(
                    "infra", "smb_null_session",
                    f"HIGH: SMB null session accepted on "
                    f"{host}:{smb_port} - unauthenticated session "
                    f"setup succeeded with empty credentials.",
                    source="smb session-setup probe",
                    source_url=f"smb://{host}:{smb_port}",
                    confidence=85,
                    evidence={"severity": "high",
                              "remediation": REMEDIATION_NULL},
                    passive=False, bounty_value="high"))

        resp2 = await _tcp_exchange(host, smb_port,
                                    build_smb2_negotiate())
        neg2 = parse_smb2_negotiate(resp2)
        if neg2 is not None and neg2.get("signing_enabled") \
                and not neg2.get("signing_required"):
            findings.append(self._f(
                "infra", "smb_signing_not_required",
                f"SMB signing is enabled but NOT required on "
                f"{host}:{smb_port} (SMB2 SecurityMode "
                f"{neg2.get('security_mode')}) - the relay-friendly "
                f"posture.",
                source="smb2 negotiate probe",
                source_url=f"smb://{host}:{smb_port}", confidence=90,
                evidence={"severity": "medium",
                          "remediation": REMEDIATION_SIGNING,
                          "dialect": neg2.get("dialect")},
                passive=False, bounty_value="medium"))

        # --- LDAP anonymous bind on 389 ---
        bind_resp = await _tcp_exchange(host, 389,
                                        build_ldap_anon_bind())
        rc = parse_ldap_bind_response(bind_resp)
        if rc == 0:
            findings.append(self._f(
                "infra", "ldap_anonymous_bind",
                f"HIGH: LDAP anonymous bind accepted on {host}:389 "
                f"(BindResponse resultCode 0 with empty DN/password).",
                source="ldap bind probe",
                source_url=f"ldap://{host}:389", confidence=95,
                evidence={"severity": "high",
                          "remediation": REMEDIATION_LDAP,
                          "result_code": 0},
                passive=False, bounty_value="high"))

        res = self._ok(findings, "SMB/LDAP exposure checks complete")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
