"""Multi-protocol exposure rollup (NetExec-style, enumeration only).

DETECTION ONLY (Tier-6 rule). In the spirit of CrackMapExec/NetExec
host enumeration - which protocols answer and what their handshake
says about authentication posture - with the credential half of the
tool removed entirely: NO password spraying, NO login attempts with
credential lists, NO authentication with any real credential.

Checks (all are protocol-standard enumeration handshakes):
  - SSH (22): banner + the auth-method list the server returns to a
    "none" auth query (an RFC 4252 mechanism that lists methods; it
    authenticates nobody). Finding: password auth offered.
  - RDP (3389): one X.224 connection request offering all security
    protocols; the server's selection shows whether NLA (CredSSP)
    is required. Finding: NLA not required / plain RDP selected.
  - WinRM (5985): GET /wsman; the 401 challenge's WWW-Authenticate
    schemes are the fact. Finding: Basic auth offered over plain
    HTTP (credentials would cross the wire base64-only).
  - MSSQL (1433): one PRELOGIN packet; the response's ENCRYPTION
    option is the fact. Finding: encryption not supported / not
    required. The version option is recorded as evidence.

Distinct remainder vs existing plugins (checked against master 847):
port_audit.py reports these ports open by number with generic
advice; it never performs the SSH auth-method query, the RDP
security negotiation, the WinRM challenge read, or the MSSQL
prelogin parse. smb_ldap_enum (this tier) owns SMB/LDAP, so SMB is
deliberately not repeated here.
"""
from __future__ import annotations

import asyncio
import struct
import time
from typing import Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION_SSH = ("Disable SSH password authentication; require "
                   "public-key auth and restrict port 22 by source.")
REMEDIATION_RDP = ("Require Network Level Authentication (CredSSP) "
                   "on RDP and put 3389 behind a VPN/gateway.")
REMEDIATION_WINRM = ("Disable Basic auth on WinRM over HTTP, or serve "
                     "WinRM only over HTTPS (5986) with Kerberos/"
                     "Negotiate.")
REMEDIATION_MSSQL = ("Force/require TLS encryption for MSSQL "
                     "connections (ForceEncryption) so logins and "
                     "data are not sent in cleartext.")


# ---------------------------------------------------------------------------
# SSH: banner + "none" auth method query (RFC 4252 section 5.2)
# ---------------------------------------------------------------------------

def _ssh_packet(payload: bytes) -> bytes:
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8
    packet_len = len(payload) + pad_len + 1
    return (struct.pack(">I", packet_len) + bytes([pad_len]) + payload
            + b"\x00" * pad_len)


def build_ssh_none_auth() -> bytes:
    """SSH_MSG_USERAUTH_REQUEST with method "none" for user "recon"."""
    def s(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b
    payload = (bytes([50]) + s(b"recon") + s(b"ssh-connection")
               + s(b"none"))
    return _ssh_packet(payload)


def parse_ssh_auth_methods(data: bytes) -> Optional[List[str]]:
    """Auth methods from an SSH_MSG_USERAUTH_FAILURE (51) packet."""
    if not data or len(data) < 6:
        return None
    try:
        packet_len = struct.unpack(">I", data[0:4])[0]
        pad_len = data[4]
        payload = data[5:5 + packet_len - pad_len - 1]
        if not payload or payload[0] != 51:
            return None
        ln = struct.unpack(">I", payload[1:5])[0]
        names = payload[5:5 + ln].decode("utf-8", "replace")
        return [m for m in names.split(",") if m]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# RDP: X.224 + RDP_NEG_REQ / RDP_NEG_RSP
# ---------------------------------------------------------------------------

def build_rdp_request() -> bytes:
    # TPKT + X.224 CR + RDP_NEG_REQ offering RDP|SSL|HYBRID protocols.
    neg = bytes([0x01, 0x00, 0x08, 0x00]) + struct.pack("<I", 0x07)
    x224 = bytes([0xE0]) + b"\x00\x00\x00\x00\x00" + b"Cookie: mstshash=recon\r\n"
    body = bytes([len(x224) + len(neg)]) + x224 + neg
    tpkt = bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(body))
    return tpkt + body


def parse_rdp_response(data: bytes) -> Optional[Dict]:
    """Selected protocol from an RDP_NEG_RSP, or failure type."""
    if not data:
        return None
    idx = data.find(b"\x02\x00\x08\x00")  # RDP_NEG_RSP type/len
    if idx >= 0 and len(data) >= idx + 8:
        proto = struct.unpack("<I", data[idx + 4:idx + 8])[0]
        return {"selected_protocol": proto,
                "nla_required": proto in (0x02, 0x08, 0x0A)}
    fidx = data.find(b"\x03\x00\x08\x00")  # RDP_NEG_FAILURE
    if fidx >= 0 and len(data) >= fidx + 8:
        return {"failure_code": struct.unpack(
            "<I", data[fidx + 4:fidx + 8])[0]}
    if len(data) > 11 and data[11] == 0xD0:
        return {"selected_protocol": 0, "nla_required": False,
                "note": "connection confirm without negotiation data"}
    return None


# ---------------------------------------------------------------------------
# MSSQL PRELOGIN
# ---------------------------------------------------------------------------

def build_mssql_prelogin() -> bytes:
    # PRELOGIN (0x12) with a VERSION option and ENCRYPTION option.
    version_off = 21
    encrypt_off = 27
    payload = (bytes([0x00]) + struct.pack(">H", version_off)
               + bytes([0x06, 0x01]) + struct.pack(">H", encrypt_off)
               + bytes([0x01, 0xFF]) + b"\x00" * 5
               + bytes([0x01, 0x00]))
    header = bytes([0x12, 0x01]) + struct.pack(">H", 8 + len(payload)) \
        + b"\x00\x00\x01\x00"
    return header + payload


def parse_mssql_prelogin(resp: bytes) -> Optional[Dict]:
    """Options from a MSSQL PRELOGIN response (packet type 0x04)."""
    if not resp or len(resp) < 8 or resp[0] != 0x04:
        return None
    body = resp[8:]
    out: Dict = {}
    i = 0
    while i + 4 < len(body):
        token = body[i]
        if token == 0xFF:
            break
        off = struct.unpack(">H", body[i + 1:i + 3])[0]
        ln = body[i + 3]
        if token == 0x00 and off + 6 <= len(body):
            v = body[off:off + 4]
            out["version"] = ".".join(str(b) for b in v[:3])
        if token == 0x01 and off < len(body):
            enc = body[off]
            out["encryption"] = enc
            out["encryption_label"] = {
                0x00: "off", 0x01: "on", 0x02: "not supported",
                0x03: "required"}.get(enc, f"unknown({enc})")
        i += 4
    return out or None


# ---------------------------------------------------------------------------
# Transport (module-level so fixtures can substitute canned responses)
# ---------------------------------------------------------------------------

async def _tcp_exchange(host: str, port: int, payloads: List[bytes],
                        timeout: float = 4.0) -> bytes:
    """Send payloads in order, return everything read (banner+reply)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return b""
    out = b""
    try:
        for payload in payloads:
            if payload:
                writer.write(payload)
                await writer.drain()
            chunk = await asyncio.wait_for(reader.read(4096),
                                           timeout=timeout)
            out += chunk
            if not chunk:
                break
        return out
    except Exception:
        return out
    finally:
        try:
            writer.close()
        except Exception:
            pass


class NetexecEnumPlugin(Plugin):
    id = "netexec_enum"
    label = "Multi-Protocol Exposure Rollup"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("NetExec-style enumeration without credentials: SSH "
                   "auth methods, RDP NLA posture, WinRM auth schemes, "
                   "MSSQL prelogin encryption. No logins, no spraying.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = domain_from_target(target.type, target.normalized)
        if not host:
            return self._skipped("no host for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode (protocol probes)")
        findings: List[Finding] = []

        # --- SSH ---
        raw = await _tcp_exchange(host, 22, [b"", build_ssh_none_auth()])
        banner = raw.split(b"\r\n")[0].decode("utf-8", "replace")[:120] \
            if raw else ""
        # The auth-failure packet follows the banner line; search the
        # whole buffer for a parseable packet start after the banner.
        methods: Optional[List[str]] = None
        nl = raw.find(b"\n")
        if nl >= 0:
            methods = parse_ssh_auth_methods(raw[nl + 1:])
        if methods is None:
            methods = parse_ssh_auth_methods(raw)
        if methods and "password" in methods:
            findings.append(self._f(
                "infra", "ssh_password_auth",
                f"SSH on {host}:22 offers PASSWORD authentication "
                f"(methods: {', '.join(methods)}; banner: {banner}).",
                source="ssh auth-method query",
                source_url=f"ssh://{host}:22", confidence=90,
                evidence={"severity": "medium",
                          "remediation": REMEDIATION_SSH,
                          "methods": methods, "banner": banner},
                passive=False, bounty_value="medium"))

        # --- RDP ---
        rdp_raw = await _tcp_exchange(host, 3389, [build_rdp_request()])
        rdp = parse_rdp_response(rdp_raw)
        if rdp is not None and rdp.get("selected_protocol") == 0:
            findings.append(self._f(
                "infra", "rdp_nla_not_required",
                f"HIGH: RDP on {host}:3389 negotiated plain RDP "
                f"security (protocol 0) - NLA/CredSSP is not required "
                f"before session setup.",
                source="rdp negotiation probe",
                source_url=f"rdp://{host}:3389", confidence=90,
                evidence={"severity": "high",
                          "remediation": REMEDIATION_RDP,
                          "negotiation": rdp},
                passive=False, bounty_value="high"))

        # --- WinRM over HTTP ---
        try:
            wr = await fetch(ctx.http, ctx.limiter, "GET",
                             f"http://{host}:5985/wsman", timeout=6,
                             max_retries=0, follow_redirects=False)
            schemes = (wr.headers.get("www-authenticate") or "")
            if wr.status_code == 401 and "basic" in schemes.lower():
                findings.append(self._f(
                    "infra", "winrm_basic_auth_http",
                    f"WinRM on {host}:5985 offers BASIC authentication "
                    f"over plain HTTP (WWW-Authenticate: "
                    f"{schemes[:120]}).",
                    source="winrm challenge read",
                    source_url=f"http://{host}:5985/wsman",
                    confidence=90,
                    evidence={"severity": "medium",
                              "remediation": REMEDIATION_WINRM,
                              "www_authenticate": schemes[:200]},
                    passive=False, bounty_value="medium"))
        except Exception:
            pass

        # --- MSSQL ---
        ms_raw = await _tcp_exchange(host, 1433,
                                     [build_mssql_prelogin()])
        ms = parse_mssql_prelogin(ms_raw)
        if ms is not None and ms.get("encryption") in (0x00, 0x02):
            findings.append(self._f(
                "infra", "mssql_encryption_not_required",
                f"MSSQL on {host}:1433 prelogin reports encryption "
                f"'{ms.get('encryption_label')}' (server version "
                f"{ms.get('version', 'unknown')}) - connections are "
                f"not forced to TLS.",
                source="mssql prelogin probe",
                source_url=f"sqlserver://{host}:1433", confidence=90,
                evidence={"severity": "medium",
                          "remediation": REMEDIATION_MSSQL,
                          "prelogin": ms},
                passive=False, bounty_value="medium"))

        res = self._ok(findings,
                       "SSH/RDP/WinRM/MSSQL enumeration complete")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
