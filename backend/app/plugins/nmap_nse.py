"""nmap-style service/version detection + safe NSE equivalents (native).

No external nmap binary is required (and none is shelled out to):
service/version detection is banner-based, and three read-only NSE
script equivalents are implemented natively -
  http-title : GET / on web ports, report <title> + Server header
  ssl-cert  : TLS handshake on TLS ports, report cert subject/issuer
  ssh banner: the SSH protocol/software banner a hostkey script reads
              first (banner only; no key exchange is attempted)
Read-only handshakes only, target's own IPs only.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Optional

from ._tier2_common import (SERVICE_LABELS, extract_title, host_of,
                            resolve_ips, tcp_banner, tls_probe)
from .base import Cost, Ctx, Plugin, PluginResult, Target

PROBE_PORTS = [21, 22, 25, 80, 110, 143, 443, 993, 995, 3389, 5900,
               8080, 8443]
TLS_PORTS = {443, 8443, 993, 995}
WEB_PORTS = {80, 8080, 443, 8443}
_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9._-]*/[0-9][A-Za-z0-9._-]*)")


def parse_banner_service(port: int, banner: str) -> Dict[str, str]:
    """Classify a raw banner into {service, product} - pure helper."""
    b = (banner or "").strip()
    out = {"service": SERVICE_LABELS.get(port, "unknown"), "product": ""}
    if not b:
        return out
    first = b.splitlines()[0][:200]
    if first.startswith("SSH-"):
        out["service"] = "ssh"
        out["product"] = first
        return out
    if "HTTP/" in first:
        out["service"] = "https" if port in TLS_PORTS else "http"
        out["product"] = first
        return out
    m = _VERSION_RE.search(b)
    if m:
        out["product"] = m.group(1)
    elif first:
        out["product"] = first[:80]
    if "ftp" in b.lower()[:60]:
        out["service"] = "ftp"
    if "smtp" in b.lower()[:80] or "mail" in b.lower()[:80]:
        out["service"] = "smtp"
    return out


class NmapNsePlugin(Plugin):
    id = "nmap_nse"
    label = "nmap NSE (native)"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    timeout_s = 120
    description = ("Service/version detection via banner grabbing plus "
                   "native http-title, ssl-cert and ssh-banner NSE "
                   "equivalents. Read-only handshakes only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = host_of(target)
        if not host:
            return self._skipped("no host for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("service detection needs active mode")
        ips = await resolve_ips(host, cap=2)
        if not ips:
            res = self._degraded(f"could not resolve {host}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        ip = ips[0]
        findings = []
        for port in PROBE_PORTS:
            payload = None
            if port in WEB_PORTS and port not in TLS_PORTS:
                payload = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                           f"User-Agent: ReconAnything\r\n\r\n").encode()
            state, banner = await tcp_banner(
                ip, port, timeout=2.0, payload=payload,
                read_len=4096 if port in WEB_PORTS else 512)
            if state != "open":
                continue
            info = parse_banner_service(port, banner)
            findings.append(self._f(
                "infra", "nmap_service_version",
                f"{ip}:{port} {info['service']}"
                + (f" - {info['product']}" if info["product"] else ""),
                source="nmap_nse banner grab", confidence=88,
                passive=False,
                evidence={"severity": "low", "ip": ip, "port": port,
                          "service": info["service"],
                          "product": info["product"],
                          "remediation": "Keep the service patched; "
                                         "version banners help attackers "
                                         "pick exploits, so suppress them "
                                         "where the software allows."}))
            # http-title equivalent
            if port in WEB_PORTS and banner:
                title = extract_title(banner)
                server = ""
                m = re.search(r"(?im)^server:\s*(.+)$", banner)
                if m:
                    server = m.group(1).strip()[:80]
                if title or server:
                    findings.append(self._f(
                        "web", "nmap_http_title",
                        f"http-title on {host}:{port}: "
                        f"{title or '(no title)'}"
                        + (f" [Server: {server}]" if server else ""),
                        source="nmap_nse http-title", confidence=85,
                        passive=False,
                        evidence={"severity": "low", "title": title,
                                  "server": server, "port": port,
                                  "remediation": "Informational: confirm "
                                                 "this web service is "
                                                 "intended to be public."}))
            # ssl-cert equivalent
            if port in TLS_PORTS:
                cert = await asyncio.to_thread(tls_probe, host, port)
                if cert:
                    findings.append(self._f(
                        "infra", "nmap_ssl_cert",
                        f"ssl-cert on {host}:{port}: "
                        f"{cert.get('subject', '')[:100]} issued by "
                        f"{cert.get('issuer', '')[:80]}, expires "
                        f"{cert.get('not_after', '')}",
                        source="nmap_nse ssl-cert", confidence=90,
                        passive=False,
                        evidence={"severity": "low", "port": port,
                                  "subject": cert.get("subject", ""),
                                  "issuer": cert.get("issuer", ""),
                                  "not_after": cert.get("not_after", ""),
                                  "san": cert.get("san", [])[:10],
                                  "remediation": "Keep certificates "
                                                 "valid and issued by a "
                                                 "trusted CA."}))
                    for san in cert.get("san", [])[:10]:
                        ctx.publish("cert_sans", san)
            # ssh banner (hostkey-script first read; no KEX attempted)
            if port == 22 and banner.startswith("SSH-"):
                findings.append(self._f(
                    "infra", "nmap_ssh_banner",
                    f"ssh banner on {ip}:22: {banner.splitlines()[0][:100]}",
                    source="nmap_nse ssh banner", confidence=90,
                    passive=False,
                    evidence={"severity": "low",
                              "banner": banner.splitlines()[0][:100],
                              "remediation": "Informational: keep SSH "
                                             "patched and key-only."}))
        res = self._ok(findings, f"{len(findings)} service findings on {ip}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
