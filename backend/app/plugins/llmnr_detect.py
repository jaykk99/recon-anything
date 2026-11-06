"""LLMNR / NBT-NS / mDNS exposure detection (Responder surface).

DETECTION ONLY (Tier-6 rule) - and for this tool the detection-only
line is the whole point: Responder works by ANSWERING other hosts'
name-resolution broadcasts and poisoning their resolution. This
plugin never answers anything, never poisons, and sends exactly one
benign query per protocol, addressed to the target host itself:

  - LLMNR (UDP 5355): one unicast DNS-format query for the target's
    own hostname. A host with LLMNR enabled answers unicast queries
    for its own name; a matching response = protocol enabled.
  - NBT-NS (UDP 137): one NBSTAT node-status query for the wildcard
    name - the standard status request every NetBIOS stack answers
    when NBT-NS is enabled.
  - mDNS (UDP 5353): one unicast query (QU bit set, the normal
    unicast-response form) for the target's hostname .local form.

A response proves the legacy resolution protocol is live on that
host, which is exactly the surface Responder-class poisoning needs.
Silence = no finding. No response is ever sent to any query, and no
name but the target's own is ever asked about.

Distinct remainder: no plugin on master (847) touches LLMNR, NBT-NS
or mDNS - grep for llmnr/nbt/mdns across app/plugins returns zero
protocol implementations (port_audit lists port numbers only).
"""
from __future__ import annotations

import asyncio
import socket
import struct
import time
from typing import List, Optional

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Disable LLMNR and NetBIOS name resolution via Group "
               "Policy (\"Turn off multicast name resolution\" + "
               "disable NetBIOS over TCP/IP) and block UDP "
               "5355/137/5353 between workstation segments; use DNS "
               "only. These protocols are the entry point for "
               "Responder-style credential poisoning on LANs.")

QID = 0x7A11


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode("utf-8", "replace")
    return out + b"\x00"


def build_llmnr_query(hostname: str) -> bytes:
    """One A-record query for the target's own (single-label) name."""
    label = hostname.split(".")[0]
    return (struct.pack(">HHHHHH", QID, 0x0000, 1, 0, 0, 0)
            + _dns_name(label) + struct.pack(">HH", 1, 1))


def build_mdns_query(hostname: str) -> bytes:
    """One unicast-response (QU bit) A query for <name>.local."""
    label = hostname.split(".")[0]
    return (struct.pack(">HHHHHH", QID + 1, 0x0000, 1, 0, 0, 0)
            + _dns_name(f"{label}.local")
            + struct.pack(">HH", 1, 0x8001))  # class IN + QU bit


def build_nbstat_query() -> bytes:
    """NBSTAT node-status request for the wildcard NetBIOS name."""
    # First-level encoding of "*               " (CKAAAAAAAAAAAAAAAA...)
    encoded = b"CK" + b"AA" * 15
    return (struct.pack(">HHHHHH", QID, 0x0000, 1, 0, 0, 0)
            + bytes([32]) + encoded + b"\x00"
            + struct.pack(">HH", 0x0021, 0x0001))


def is_dns_response_for(resp: bytes, qid: int) -> bool:
    """True if resp is a DNS-format response carrying our query id."""
    if not resp or len(resp) < 12:
        return False
    rid, flags = struct.unpack(">HH", resp[0:4])
    return rid == qid and bool(flags & 0x8000) \
        and struct.unpack(">H", resp[6:8])[0] >= 0


def is_nbstat_response(resp: bytes) -> bool:
    if not resp or len(resp) < 12:
        return False
    rid, flags = struct.unpack(">HH", resp[0:4])
    answers = struct.unpack(">H", resp[6:8])[0]
    return rid == QID and bool(flags & 0x8000) and answers >= 1


async def _udp_query(ip: str, port: int, payload: bytes,
                     timeout: float = 2.5) -> bytes:
    """Send one UDP datagram, return the first reply (or b"").

    Module-level so fixture tests can substitute canned replies
    without real sockets.
    """
    loop = asyncio.get_running_loop()

    class _Proto(asyncio.DatagramProtocol):
        def __init__(self):
            self.future = loop.create_future()

        def datagram_received(self, data, addr):
            if not self.future.done():
                self.future.set_result(data)

        def error_received(self, exc):
            if not self.future.done():
                self.future.set_result(b"")

    try:
        transport, proto = await loop.create_datagram_endpoint(
            _Proto, remote_addr=(ip, port))
    except Exception:
        return b""
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(proto.future, timeout=timeout)
    except Exception:
        return b""
    finally:
        transport.close()


async def _resolve(host: str) -> Optional[str]:
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        return infos[0][4][0] if infos else None
    except Exception:
        return None


class LlmnrDetectPlugin(Plugin):
    id = "llmnr_detect"
    label = "LLMNR/NBT-NS/mDNS Exposure"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("Exposure detection only: one benign query each "
                   "for LLMNR, NBT-NS and mDNS to the target host "
                   "itself. Never answers or poisons anything.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = domain_from_target(target.type, target.normalized)
        if not host:
            return self._skipped("no host for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode (sends one query "
                                 "per protocol)")
        ip = host
        try:
            socket.inet_aton(host)
        except Exception:
            ip = await _resolve(host) or host
        findings: List[Finding] = []

        resp = await _udp_query(ip, 5355, build_llmnr_query(host))
        if is_dns_response_for(resp, QID):
            findings.append(self._f(
                "infra", "llmnr_enabled",
                f"LLMNR is ENABLED on {host} ({ip}:5355 answered a "
                f"unicast query for its own name) - poisonable name "
                f"resolution surface.",
                source="llmnr unicast query",
                source_url=f"udp://{ip}:5355", confidence=90,
                evidence={"severity": "medium",
                          "remediation": REMEDIATION,
                          "protocol": "LLMNR"},
                passive=False, bounty_value="medium"))

        resp = await _udp_query(ip, 137, build_nbstat_query())
        if is_nbstat_response(resp):
            findings.append(self._f(
                "infra", "nbt_ns_enabled",
                f"NBT-NS is ENABLED on {host} ({ip}:137 answered an "
                f"NBSTAT node-status query) - poisonable name "
                f"resolution surface.",
                source="nbt-ns nbstat query",
                source_url=f"udp://{ip}:137", confidence=90,
                evidence={"severity": "medium",
                          "remediation": REMEDIATION,
                          "protocol": "NBT-NS"},
                passive=False, bounty_value="medium"))

        resp = await _udp_query(ip, 5353, build_mdns_query(host))
        if is_dns_response_for(resp, QID + 1):
            findings.append(self._f(
                "infra", "mdns_enabled",
                f"mDNS is answering on {host} ({ip}:5353 replied to a "
                f"unicast query for its .local name).",
                source="mdns unicast query",
                source_url=f"udp://{ip}:5353", confidence=85,
                evidence={"severity": "low",
                          "remediation": REMEDIATION,
                          "protocol": "mDNS"},
                passive=False, bounty_value="low"))

        res = self._ok(findings, "LLMNR/NBT-NS/mDNS checks complete")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
