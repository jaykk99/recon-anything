"""Deep web-port scanner: TCP connect + banner grab, no exploitation.

Probes common AND non-standard web ports (80, 443, 8080, 8443, 3000,
5000, 8000, 9000, 3001, 4200, 5173, 8001, 8888, 9090, 10000, ...).
For HTTP(S)-looking ports it grabs the Server header and page title;
for others it grabs whatever banner the service volunteers. TLS is
attempted on 443/8443-style ports to read the certificate CN/SANs.

Read-only. Short timeouts, bounded concurrency, paced.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from typing import List, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (port, service label, try_tls)
WEB_PORTS: List[Tuple[int, str, bool]] = [
    (80, "http", False), (443, "https", True),
    (8000, "http-alt", False), (8080, "http-proxy-alt", False),
    (8443, "https-alt", True), (8001, "http-alt", False),
    (8081, "http-alt", False), (8888, "http-alt", False),
    (9000, "http-alt/php-fpm", False), (9080, "http-alt", False),
    (9090, "http-alt", False), (10000, "webmin", False),
    (3000, "node/react dev", False), (3001, "node dev", False),
    (4200, "angular dev", False), (5173, "vite dev", False),
    (5000, "flask/dev", False), (5001, "dev", False),
    (7000, "dev", False), (7001, "dev", False),
    (8008, "http-alt", False), (8088, "http-alt", False),
    (8880, "http-alt", False), (9999, "http-alt", False),
    (4000, "dev", False), (4100, "dev", False),
    (4567, "dev", False), (5002, "dev", False),
    (6006, "tensorboard", False), (8002, "http-alt", False),
    (8010, "http-alt", False), (8043, "https-alt", True),
    (8228, "http-alt", False), (8280, "http-alt", False),
    (8403, "https-alt", True), (8500, "consul", False),
    (8600, "http-alt", False), (8800, "http-alt", False),
    (8900, "http-alt", False), (8983, "solr", False),
    (9200, "elasticsearch", False), (9300, "elasticsearch", False),
    (5601, "kibana", False), (3002, "dev", False),
    (1313, "hugo dev", False), (4001, "dev", False),
    (2368, "ghost", False), (8082, "http-alt", False),
    (18080, "http-alt", False), (10443, "https-alt", True),
    (4443, "https-alt", True), (9443, "https-alt", True),
]


class PortScanPlugin(Plugin):
    id = "port_scan"
    label = "Web Port Scan"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "network"
    timeout_s = 300
    description = ("Deep scan of 50 web/dev ports with banner grab and "
                   "TLS cert inspection. Read-only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        host = domain or (target.normalized if target.type == "ip"
                          else None)
        if not host:
            return self._skipped("no host for this target type")
        host = host.split(":")[0]
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            res = self._degraded(f"could not resolve {host}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        if passive:
            for port, service, _ in WEB_PORTS:
                findings.append(self._f(
                    "infra", "port_suggestion",
                    f"Port {port} ({service}) - commonly hosts web UIs; "
                    f"verify manually",
                    source="web port list", confidence=30, passive=True))
            res = self._ok(findings, f"{len(WEB_PORTS)} web ports suggested")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        sem = asyncio.Semaphore(20)

        async def check(port: int, service: str, try_tls: bool):
            async with sem:
                banner = ""
                tls_info = ""
                is_open = False
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=3)
                    is_open = True
                    try:
                        if try_tls:
                            ctx_ssl = ssl.create_default_context()
                            ctx_ssl.check_hostname = False
                            ctx_ssl.verify_mode = ssl.CERT_NONE
                            reader, writer = await asyncio.wait_for(
                                asyncio.open_connection(
                                    ip, port, ssl=ctx_ssl,
                                    server_hostname=host), timeout=4)
                            try:
                                cert = writer.get_extra_info("peercert") or {}
                                sans = [v for t, v in
                                        cert.get("subjectAltName", [])]
                                subj = cert.get("subject", ())
                                cn = next((v for rdn in subj for k, v in rdn
                                           if k == "commonName"), "")
                                tls_info = f"TLS CN={cn}" + (
                                    f" SANs={','.join(sans[:4])}" if sans else "")
                            except Exception:
                                pass
                        req = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                               f"User-Agent: ReconAnything/1.0\r\n\r\n")
                        writer.write(req.encode())
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(2048),
                                                      timeout=4)
                        text = data.decode("utf-8", "replace")
                        server = ""
                        for line in text.split("\r\n"):
                            if line.lower().startswith("server:"):
                                server = line.split(":", 1)[1].strip()[:80]
                                break
                        m = re.search(r"<title[^>]*>(.*?)</title>", text,
                                      re.I | re.S)
                        title = (re.sub(r"\s+", " ", m.group(1)).strip()[:80]
                                 if m else "")
                        banner = f"HTTP {server}".strip()
                        if title:
                            banner += f" - {title}"
                        if not banner:
                            banner = text[:80].replace("\r\n", " ").strip()
                    except Exception:
                        pass
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                except Exception:
                    return None
                if not is_open:
                    return None
                return port, service, banner, tls_info

        def _record(res_item) -> None:
            port, service, banner, tls_info = res_item
            val = f"HIGH: Port {port} ({service}) is OPEN on {host}"
            if banner:
                val += f" - {banner}"
            if tls_info:
                val += f" [{tls_info}]"
            findings.append(self._f(
                "infra", "web_port_open", val,
                source="web port scan", confidence=95, passive=False,
                evidence={"severity": "high", "port": port,
                          "service": service, "banner": banner[:200],
                          "tls": tls_info[:200],
                          "remediation": ("Confirm this port must be public. "
                                          "Dev ports (3000/5000/8000/9000) "
                                          "exposed to the internet are a "
                                          "common breach path - firewall them "
                                          "or require auth.")}))

        # Batched (instead of one all-at-once gather over all 50 ports) so
        # a kill at the 300s timeout_s (clamped to MAX_PLUGIN_TIMEOUT_S=120,
        # and further by the scan's remaining budget - a firewall that
        # drops instead of resetting can make every connect() run its
        # full 3s timeout) checkpoints the open ports already found
        # instead of discarding them all.
        CHUNK = 15
        for i in range(0, len(WEB_PORTS), CHUNK):
            batch_results = await asyncio.gather(
                *[check(p, s, t) for p, s, t in WEB_PORTS[i:i + CHUNK]])
            for res_item in batch_results:
                if res_item:
                    _record(res_item)
            self._checkpoint(findings)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"scanned {len(WEB_PORTS)} web ports, "
                       f"{len(findings)} open")
        res.duration_ms = dur
        return res
