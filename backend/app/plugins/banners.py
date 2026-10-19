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
    ("apache/2.4.1", "Apache 2.4.1x - check for CVE-2024-3847x", 70),
    ("nginx/1.18.0", "Check for CVE-2021-23017", 70),
    ("nginx/1.14", "nginx 1.14 is old - check for CVEs", 65),
    ("nginx/1.16", "nginx 1.16 is old - check for CVEs", 65),
    ("php/5.", "PHP 5 is EOL - critically outdated", 90),
    ("php/7.0", "PHP 7.0 is EOL", 80),
    ("php/7.1", "PHP 7.1 is EOL", 80),
    ("php/7.2", "PHP 7.2 is EOL", 80),
    ("php/7.3", "PHP 7.3 is EOL", 80),
    ("php/7.4", "PHP 7.4 is EOL (Nov 2022)", 75),
    ("php/8.0", "PHP 8.0 is EOL (Nov 2023)", 70),
    ("openssh_7.", "Old OpenSSH - check for CVEs", 70),
    ("openssh_6.", "OpenSSH 6.x is EOL", 80),
    ("openssh_5.", "OpenSSH 5.x is EOL", 85),
    ("microsoft-iis/6.0", "IIS 6.0 is EOL", 90),
    ("microsoft-iis/7.5", "IIS 7.5 is EOL", 80),
    ("microsoft-iis/8.0", "IIS 8.0 is EOL", 75),
    ("microsoft-iis/8.5", "IIS 8.5 is EOL", 70),
    ("tomcat/7.", "Tomcat 7 is EOL", 80),
    ("tomcat/8.0", "Tomcat 8.0 is EOL", 75),
    ("tomcat/8.5.0", "Check Tomcat CVEs", 65),
    ("jetty/9.2", "Jetty 9.2 is EOL", 75),
    ("jetty/9.3", "Jetty 9.3 is EOL", 70),
    ("jboss", "JBoss detected - check for deserialization CVEs", 70),
    ("weblogic", "WebLogic detected - check for T3 CVEs", 70),
    ("websphere", "WebSphere detected - check for CVEs", 65),
    ("lighttpd/1.4.4", "Old lighttpd - check CVEs", 65),
    ("squid/3.", "Squid 3.x is EOL", 70),
    ("varnish/4.", "Varnish 4 is EOL", 65),
    ("haproxy/1.", "HAProxy 1.x is old", 60),
    ("cowboy", "Cowboy/Erlang detected", 55),
    ("gunicorn/19.", "Old gunicorn", 60),
    ("werkzeug/0.", "Old Werkzeug - check CVEs", 65),
    ("werkzeug/1.0", "Check Werkzeug CVEs", 60),
    ("django/1.", "Django 1.x is EOL", 80),
    ("django/2.0", "Django 2.0 is EOL", 75),
    ("django/2.1", "Django 2.1 is EOL", 75),
    ("django/2.2", "Django 2.2 is EOL", 70),
    ("rails", "Rails detected - check version CVEs", 60),
    ("express", "Express.js detected", 55),
    ("asp.net/2.0", "ASP.NET 2.0 is EOL", 85),
    ("asp.net/4.0", "ASP.NET 4.0 is old", 65),
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

            for port, svc in [(21, "FTP"), (22, "SSH"), (23, "Telnet"),
                              (25, "SMTP"), (110, "POP3"), (143, "IMAP"),
                              (389, "LDAP"), (3306, "MySQL"),
                              (3389, "RDP"), (5900, "VNC"),
                              (6379, "Redis"), (27017, "MongoDB")]:
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
