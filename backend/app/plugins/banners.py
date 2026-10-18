"""Banner grabber plugin (Shodan-style).

Grabs service banners from HTTP headers and common ports.
Identifies server software versions that may have known CVEs.
Custom-built, no API keys needed.
"""
from __future__ import annotations

import asyncio
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Known-vulnerable version hints (not exhaustive, flags for manual review)
VULN_HINTS = [
    ("apache/2.2", "Apache 2.2 is EOL - multiple known CVEs", 85),
    ("apache/2.4.49", "CVE-2021-41773 path traversal", 95),
    ("apache/2.4.50", "CVE-2021-42013 path traversal", 95),
    ("nginx/1.18.0", "Check for CVE-2021-23017", 70),
    ("php/5.", "PHP 5 is EOL - critically outdated", 90),
    ("php/7.0", "PHP 7.0 is EOL", 80),
    ("php/7.1", "PHP 7.1 is EOL", 80),
    ("openssh_7.", "Old OpenSSH - check for CVEs", 70),
    ("microsoft-iis/6.0", "IIS 6.0 is EOL", 90),
    ("microsoft-iis/7.5", "IIS 7.5 is EOL", 80),
]


class BannersPlugin(Plugin):
    id = "banners"
    label = "Banner Grabber"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "Grab service banners, flag outdated software."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        host = domain or target.normalized
        if not host:
            return self._skipped("no host for this target type")
        url = f"https://{host}" if target.type in ("domain", "ip") else target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        # HTTP banner
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
            server = r.headers.get("server", "")
            if server:
                findings.append(self._f(
                    "infra", "http_banner",
                    f"Server: {server}",
                    source="banner grabber", source_url=url,
                    confidence=90, passive=True))
                for vuln_sig, desc, conf in VULN_HINTS:
                    if vuln_sig.lower() in server.lower():
                        findings.append(self._f(
                            "infra", "outdated_software",
                            f"{desc} (found: {server})",
                            source="banner grabber", source_url=url,
                            confidence=conf, passive=True))
            powered = r.headers.get("x-powered-by", "")
            if powered:
                findings.append(self._f(
                    "infra", "http_banner",
                    f"X-Powered-By: {powered}",
                    source="banner grabber", source_url=url,
                    confidence=90, passive=True))
        except Exception as e:
            findings.append(self._f(
                "infra", "banner_note",
                f"Could not fetch HTTP banner: {str(e)[:100]}",
                source="banner grabber", confidence=40, passive=True))

        # Active: TCP banner grab on common ports
        if mode == "active":
            async def grab(host: str, port: int) -> str:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=4)
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=3)
                        return data.decode("utf-8", errors="ignore")[:200]
                    finally:
                        writer.close()
                except Exception:
                    return ""

            for port, svc in [(22, "SSH"), (21, "FTP"), (25, "SMTP"), (110, "POP3")]:
                banner = await grab(host, port)
                if banner.strip():
                    findings.append(self._f(
                        "infra", "tcp_banner",
                        f"{svc} ({port}): {banner.strip()[:150]}",
                        source="banner grabber", confidence=85, passive=False))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, "grabbed service banners")
        res.duration_ms = dur
        return res
