"""WebSocket endpoint tester: find and probe ws/wss endpoints.

Discovers WebSocket URLs (ws://, wss://) in page source and JavaScript,
then performs a connect-only handshake test: a raw TCP/TLS socket sends
an HTTP Upgrade request and reads the response. A "101 Switching
Protocols" means the endpoint is live.

Detection only: it never sends application frames, never authenticates,
never subscribes to channels. Endpoints that accept the handshake with
no token in the URL are flagged for manual authorization review.

Phase 2: consumes JS/endpoints from the discovery bus.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
import socket
import ssl
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, Target

WS_RE = re.compile(
    r"""(?i)\b(wss?://[a-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)""")
# also catch "new WebSocket('/path')" relative forms
WS_CTOR_RE = re.compile(
    r"""(?i)new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""")

MAX_ENDPOINTS = 10
HANDSHAKE_TIMEOUT = 8


def _parse_ws(url: str) -> Optional[Tuple[str, int, str, bool]]:
    try:
        p = urlparse(url)
        if p.scheme not in ("ws", "wss"):
            return None
        host = p.hostname
        if not host:
            return None
        secure = p.scheme == "wss"
        port = p.port or (443 if secure else 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        return host, port, path, secure
    except Exception:
        return None


def _handshake(host: str, port: int, path: str,
               secure: bool) -> Tuple[bool, str]:
    """Blocking connect-only handshake. Returns (accepted, detail)."""
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: https://{host}\r\n"
        "\r\n"
    )
    sock = None
    try:
        sock = socket.create_connection((host, port),
                                        timeout=HANDSHAKE_TIMEOUT)
        if secure:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(HANDSHAKE_TIMEOUT)
        sock.sendall(req.encode())
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        head = data.decode("latin1", "replace")
        first = head.split("\r\n", 1)[0] if head else ""
        if "101" in first:
            return True, first.strip()
        return False, first.strip() or "no response"
    except Exception as e:
        return False, f"connect failed: {type(e).__name__}"
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


class WebsocketTesterPlugin(Plugin):
    id = "websocket_tester"
    label = "WebSocket Tester"
    accepts = ["domain", "url"]
    passive = False  # performs handshake connections
    cost = Cost.FREE
    group = "api"
    phase = 2
    description = ("Finds ws/wss endpoints in JS and page source, tests the "
                   "upgrade handshake connect-only.")
    timeout_s = 30

    def _collect(self, target: Target, ctx: Ctx) -> List[str]:
        found: List[str] = []
        seen = set()

        def add(u: str) -> None:
            # strip trailing JS/HTML junk the regex can over-capture
            u = u.strip().rstrip(".,;)]}>'\"")
            if not u or u in seen or len(u) > 500:
                return
            # must still parse as a websocket URL after cleanup
            if _parse_ws(u) is None:
                return
            seen.add(u)
            found.append(u)

        texts: List[str] = []
        # homepage via shared cache
        page = ctx.cache.get("http", f"page:{target.normalized.rstrip('/')}")
        if isinstance(page, dict) and page.get("text"):
            texts.append(page["text"])
        # JS files from discovery bus
        for js in ctx.consume("js_files"):
            if isinstance(js, str) and js.startswith("http"):
                texts.append(js)
        for ep in ctx.consume("endpoints"):
            if isinstance(ep, str):
                texts.append(ep)

        for t in texts:
            for m in WS_RE.finditer(t):
                add(m.group(1))
            for m in WS_CTOR_RE.finditer(t):
                raw = m.group(1).strip()
                if raw.startswith(("ws://", "wss://")):
                    add(raw)
                elif raw.startswith("/"):
                    dom = domain_from_target(target.type,
                                             target.normalized)
                    if dom:
                        add(f"wss://{dom}{raw}")
        return found[:MAX_ENDPOINTS]

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        endpoints = self._collect(target, ctx)
        if not endpoints:
            return self._ok([], reason="no websocket endpoints discovered")

        findings = []
        live = 0
        loop = asyncio.get_running_loop()
        for ws_url in endpoints:
            if (time.monotonic() - t0) > 26:
                break
            parsed = _parse_ws(ws_url)
            if not parsed:
                continue
            host, port, path, secure = parsed
            try:
                accepted, detail = await loop.run_in_executor(
                    None, _handshake, host, port, path, secure)
            except Exception:
                accepted, detail = False, "handshake error"
            if accepted:
                live += 1
                has_token = bool(re.search(
                    r"(?i)(token|auth|key|session|jwt)=|/token/|bearer",
                    ws_url))
                findings.append(self._f(
                    "api", "websocket_open",
                    f"live websocket: {ws_url}",
                    source="handshake",
                    source_url=ws_url,
                    confidence=90,
                    evidence={
                        "severity": "medium" if not has_token else "low",
                        "handshake": detail,
                        "auth_token_in_url": has_token,
                        "remediation": (
                            "Verify this WebSocket enforces authentication "
                            "and per-connection authorization. Test with two "
                            "accounts: an unauthenticated handshake that "
                            "receives private data is a real finding."),
                    },
                    passive=False,
                    bounty_value="medium" if not has_token else "low",
                ))
                ctx.publish("endpoints", ws_url)

        reason = (f"{live}/{len(endpoints)} websocket endpoints accepted "
                  f"the handshake")
        return self._ok(findings, reason=reason)
