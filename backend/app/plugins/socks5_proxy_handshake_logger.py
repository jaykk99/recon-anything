"""SOCKS5 proxy handshake logger: sends ONE SOCKS5 greeting to the
target's own proxy port, records the server's chosen auth method,
and flags NO-AUTH selection as an open-proxy posture finding.

Detection only: the greeting offers no-auth + user/pass; if the
server picks no-auth (0x00) that is the finding. NO traffic is ever
relayed through the proxy - the connection closes after method
selection. Also analyses supplied handshake logs with the same
pure parser. Keyless stdlib socket.
"""
from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, host_port_of, text_of

GREETING = b"\x05\x02\x00\x02"  # VER, 2 methods: no-auth, user/pass


def analyze_handshake(resp: bytes) -> List[Dict[str, Any]]:
    """Pure: findings from a SOCKS5 method-selection response."""
    hits: List[Dict[str, Any]] = []
    if not resp or len(resp) < 2:
        return hits
    if resp[0] != 0x05:
        return hits
    method = resp[1]
    if method == 0x00:
        hits.append({
            "key": "socks5_no_auth_open_proxy", "severity": "high",
            "value": "SOCKS5 server selected NO-AUTH (0x00) - an "
                     "open proxy posture: any client can relay "
                     "through it without credentials",
            "evidence": {"method": "0x00",
                         "remediation": "Require username/password "
                         "or GSSAPI auth on the SOCKS5 proxy, bind "
                         "it to trusted interfaces only, and firewall "
                         "port 1080 from untrusted networks."}})
    elif method == 0xFF:
        hits.append({
            "key": "socks5_no_acceptable_methods", "severity": "low",
            "value": "SOCKS5 server rejected all offered methods "
                     "(0xFF) - authentication is enforced",
            "evidence": {"method": "0xff"}})
        hits.pop()  # enforced auth is the clean posture
    return hits


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    if not data:
        return []
    if len(data) >= 2 and data[0] == 0x05:
        return analyze_handshake(data)
    text = text_of(data).lower()
    hits: List[Dict[str, Any]] = []
    if "method 0x00" in text or "no-auth" in text or \
            "no authentication" in text:
        hits.append({
            "key": "socks5_no_auth_open_proxy", "severity": "high",
            "value": "Supplied SOCKS5 handshake log shows NO-AUTH "
                     "method selection - open proxy posture",
            "evidence": {"method": "0x00",
                         "remediation": "Require authentication on "
                         "the SOCKS5 proxy and restrict it to "
                         "trusted networks."}})
    return hits


def _probe(host: str, port: int, timeout: float = 4.0
           ) -> Optional[bytes]:
    try:
        with socket.create_connection((host, port),
                                      timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(GREETING)
            return sock.recv(2)
    except Exception:
        return None


class Socks5ProxyHandshakeLoggerPlugin(Plugin):
    id = "socks5_proxy_handshake_logger"
    label = "SOCKS5 Proxy Handshake Logger"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("One SOCKS5 greeting to the target's own proxy "
                   "port; flags NO-AUTH method selection (open-proxy "
                   "posture). No traffic is relayed.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("socks5_logs",))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        host, port = host_port_of(target, 1080)
        try:
            resp = await asyncio.to_thread(_probe, host, port)
        except Exception:
            resp = None
        if resp is None:
            return self._degraded(
                f"no SOCKS5 response from {host}:{port}")
        findings = []
        for hit in analyze_handshake(resp):
            ev = {"severity": hit["severity"],
                  "remediation": (hit.get("evidence") or {}).get(
                      "remediation", "")}
            ev.update(hit.get("evidence") or {})
            findings.append(self._f(
                "infra", hit["key"], hit["value"], source="SOCKS5 "
                "greeting", confidence=90, evidence=ev, passive=False))
        return self._ok(findings,
                        f"SOCKS5 method selected: "
                        f"{resp[1]:#04x}" if len(resp) > 1 else
                        "SOCKS5 probe complete")
