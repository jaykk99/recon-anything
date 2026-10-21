"""HTTP/2 and HTTP/3 support detection plugin.

Checks the ALPN-negotiated protocol of the target's TLS connection:
sites still on HTTP/1.1 only miss out on multiplexing and header
compression, and HTTP/1.1-only on an https site is a (minor) hardening
smell. Also notes HTTP/3 (QUIC) support.

Detection only: a TLS handshake with ALPN offer, no application data
beyond the handshake. Runs in a thread (blocking socket).
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import List, Optional

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target


def _alpn_probe(host: str, port: int = 443,
                timeout: float = 8.0) -> Optional[str]:
    """Return the ALPN-negotiated protocol, or None on failure."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h3", "h2", "http/1.1"])
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.selected_alpn_protocol()
    except Exception:
        return None


class Http2CheckPlugin(Plugin):
    id = "http2_check"
    label = "HTTP/2 / HTTP/3 Support"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Detect negotiated HTTP version via ALPN: HTTP/1.1-only, "
                   "HTTP/2, or HTTP/3 (QUIC).")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        proto = await asyncio.to_thread(_alpn_probe, domain)
        findings: List = []
        if proto is None:
            return self._degraded("TLS handshake failed, no ALPN result")
        if proto == "http/1.1":
            findings.append(self._f(
                "web", "http1_only",
                f"{domain} negotiates only HTTP/1.1 over TLS - no HTTP/2 "
                "multiplexing or header compression",
                source="ALPN probe", confidence=85, passive=True,
                evidence={"severity": "low", "alpn": proto,
                          "remediation": ("Enable HTTP/2 (and HTTP/3/QUIC) on "
                                          "the web server / CDN for "
                                          "performance and modern hardening.")}))
        else:
            findings.append(self._f(
                "web", "http_version",
                f"{domain} negotiates {proto} over TLS",
                source="ALPN probe", confidence=95, passive=True,
                evidence={"severity": "low", "alpn": proto,
                          "remediation": ("No action - informational. Keep "
                                          "the server patched.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"ALPN negotiated: {proto}")
