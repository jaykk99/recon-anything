"""Command-based detectors: real system tools, not just HTTP fetches.

Jay's 2026-10-26 order: ReconAnything "cant find shit" - give it more
access via commands, show everything, run faster. These five plugins run
the tools a human recon operator would run, and report what the tools
actually saw:

  cmd_dns   dig / host / nslookup enumeration (records + PTR)
  cmd_tls   openssl s_client: cert chain, protocol, cipher, expiry
  cmd_http  curl: redirect chain, raw banner headers, timing, HTTP version
  cmd_ports TCP connect to service ports + banner grabs (nc, socket fallback)
  cmd_smtp  MX-driven SMTP banner + STARTTLS capability (QUIT, never mails)

DETECTION ONLY. No payloads, no auth attempts, no brute force, no mail
sent, no private data. Every tool runs via subprocess exec (never a
shell), with the target host validated against a strict allowlist
pattern first, so a crafted target can never inject command arguments.
Every plugin skips gracefully with a clean note when its tool is missing
or the network path is blocked (e.g. a sandbox proxy that answers HTTP
but not direct TLS) - never a crash, never a fake finding.
"""
from __future__ import annotations

import asyncio
import re
import socket
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")
_DIG_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
# Service ports only: the existing port_scan plugin already covers web
# ports (80/443/8080/...). These are the non-web services operators check.
_SERVICE_PORTS: List[Tuple[int, str]] = [
    (21, "ftp"), (22, "ssh"), (25, "smtp"), (110, "pop3"), (143, "imap"),
    (389, "ldap"), (636, "ldaps"), (993, "imaps"), (995, "pop3s"),
    (1433, "mssql"), (1521, "oracle"), (2049, "nfs"), (3306, "mysql"),
    (5432, "postgres"), (5900, "vnc"), (6379, "redis"),
    (8086, "influxdb"), (11211, "memcached"), (27017, "mongodb"),
]


def _valid_host(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if not _HOST_RE.match(host) or ".." in host or host.startswith("-"):
        return None
    return host


async def _exec(argv: List[str], timeout_s: float) -> Optional[Tuple[int, str, str]]:
    """Run a command without a shell. None = tool missing / spawn failed."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
    except (FileNotFoundError, PermissionError, OSError):
        return None
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return -1, "", "timeout"


def _clean_lines(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.strip().strip('"')
        if line:
            out.append(line)
    return out


class _CmdPlugin(Plugin):
    """Shared host extraction + tool-missing skip for command plugins."""

    # No id: the registry only collects classes with a truthy id, so this
    # abstract helper is never instantiated as a plugin of its own.
    id = None  # type: ignore[assignment]

    def _host(self, target: Target) -> Optional[str]:
        host = domain_from_target(target.type, target.normalized)
        if host:
            return _valid_host(host)
        if target.type == "ip":
            return _valid_host(target.normalized)
        return None

    def _url(self, target: Target, host: str) -> str:
        if target.type == "url" and target.normalized.startswith("http"):
            return target.normalized
        return f"https://{host}"


class CmdDnsPlugin(_CmdPlugin):
    id = "cmd_dns"
    label = "Command DNS (dig/host)"
    accepts = ["domain", "url", "email"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "dig/host/nslookup record enumeration: A, AAAA, MX, NS, TXT, SOA, CAA + PTR."
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        host = self._host(target)
        if not host:
            return self._skipped("no domain to enumerate for this target type")
        findings: List[Finding] = []
        tool = None
        for cand in ("dig", "host", "nslookup"):
            probe = await _exec([cand, "-v"] if cand == "dig" else [cand], 5)
            if probe is not None:
                tool = cand
                break
        if tool is None:
            return self._skipped("no DNS command tool available (dig/host/nslookup missing)")

        async def dig_query(rtype: str, name: str) -> List[str]:
            if tool == "dig":
                res = await _exec(["dig", "+short", "+time=5", "+tries=1",
                                   name, rtype], 8)
                if res is None or res[0] == -1:
                    return []
                return _clean_lines(res[1])
            if tool == "host":
                res = await _exec(["host", "-t", rtype, name], 8)
                if res is None or res[0] == -1:
                    return []
                vals = []
                for line in res[1].splitlines():
                    if " has address " in line or " mail is handled " in line \
                            or " name server " in line or " text " in line:
                        vals.append(line.split(" ", 3)[-1].strip())
                return vals
            res = await _exec(["nslookup", f"-type={rtype}", name], 8)
            if res is None or res[0] == -1:
                return []
            return [l.split("=", 1)[-1].strip() for l in res[1].splitlines()
                    if "=" in l and "Server" not in l and "Address" not in l]

        sem = asyncio.Semaphore(6)

        async def one(rtype: str):
            async with sem:
                vals = await dig_query(rtype, host)
                for v in vals:
                    findings.append(self._f("dns", rtype.lower(), v,
                                            source=f"{tool} {rtype}",
                                            confidence=95, passive=True))
                self._checkpoint(findings)

        await asyncio.gather(*[one(rt) for rt in _DIG_TYPES],
                             return_exceptions=True)
        # PTR for each A record found.
        a_vals = [f.value for f in findings if f.key == "a"]

        async def one_ptr(ip: str):
            async with sem:
                if tool == "dig":
                    res = await _exec(["dig", "+short", "+time=5", "+tries=1",
                                       "-x", ip], 8)
                    vals = _clean_lines(res[1]) if res and res[0] != -1 else []
                else:
                    vals = []
                for v in vals:
                    findings.append(self._f("dns", "ptr", v,
                                            source=f"{tool} -x {ip}",
                                            confidence=90, passive=True))

        await asyncio.gather(*[one_ptr(ip) for ip in a_vals[:8]],
                             return_exceptions=True)
        if not findings:
            return self._skipped(f"{tool} returned no records for {host}")
        return self._ok(findings, f"{tool}: {len(findings)} DNS records for {host}")


class CmdTlsPlugin(_CmdPlugin):
    id = "cmd_tls"
    label = "Command TLS (openssl)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "openssl s_client cert inspection: subject, issuer, SANs, protocol, cipher, expiry."
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        host = self._host(target)
        if not host:
            return self._skipped("no domain for TLS inspection")
        port = 443
        if target.type == "url":
            try:
                from urllib.parse import urlparse
                port = urlparse(target.normalized).port or 443
            except Exception:
                port = 443
        # NOTE: no -brief here on purpose: -brief suppresses the PEM
        # chain, and this plugin parses the leaf cert out of it.
        res = await _exec(["openssl", "s_client", "-connect",
                           f"{host}:{port}", "-servername", host], 12)
        if res is None:
            return self._skipped("openssl not available on this host")
        rc, out, err = res
        if "BEGIN CERTIFICATE" not in out and "BEGIN CERTIFICATE" not in err:
            return self._skipped(f"openssl could not complete a TLS handshake with {host}:{port} (direct TLS may be blocked here)")
        text = out + "\n" + err
        findings: List[Finding] = []
        # Modern s_client prints "New, TLSv1.3, Cipher is X" (the
        # "Protocol : / Cipher :" session block only appears in some
        # invocations); accept both shapes.
        proto = cipher = None
        m_new = re.search(r"New,\s*(TLSv\S+),\s*Cipher is (\S+)", text)
        if m_new:
            proto, cipher = m_new.group(1), m_new.group(2)
        else:
            mp = re.search(r"Protocol\s*:\s*(\S+)", text)
            mc = re.search(r"Cipher\s*:\s*(\S+)", text)
            proto = mp.group(1) if mp else None
            cipher = mc.group(1) if mc else None
        if proto:
            findings.append(self._f("infra", "tls_protocol", proto,
                                    source=f"openssl s_client {host}:{port}",
                                    confidence=95, passive=True))
        if cipher:
            findings.append(self._f("infra", "tls_cipher", cipher,
                                    source=f"openssl s_client {host}:{port}",
                                    confidence=95, passive=True))
        # Cert details via openssl x509 on the leaf PEM block.
        pem = re.search(r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
                        text, re.S)
        if pem:
            proc = await asyncio.create_subprocess_exec(
                "openssl", "x509", "-noout", "-subject", "-issuer", "-dates",
                "-ext", "subjectAltName",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            try:
                xout, _ = await asyncio.wait_for(
                    proc.communicate(pem.group(1).encode()), timeout=8)
                xtext = xout.decode(errors="replace")
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                xtext = ""
            for key, pat in (("tls_subject", r"subject=(.*)"),
                             ("tls_issuer", r"issuer=(.*)"),
                             ("tls_not_before", r"notBefore=(.*)"),
                             ("tls_not_after", r"notAfter=(.*)")):
                m = re.search(pat, xtext)
                if m:
                    findings.append(self._f("infra", key, m.group(1).strip(),
                                            source=f"openssl x509 {host}",
                                            confidence=95, passive=True))
            san = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.*)", xtext)
            if san:
                for name in san.group(1).split(","):
                    name = name.strip().removeprefix("DNS:")
                    if name:
                        findings.append(self._f("infra", "cert_san", name,
                                                source=f"openssl x509 {host}",
                                                confidence=95, passive=True))
            m = re.search(r"notAfter=(.*)", xtext)
            if m:
                try:
                    exp = datetime.strptime(m.group(1).strip(),
                                            "%b %d %H:%M:%S %Y %Z")
                    exp = exp.replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    if days < 0:
                        findings.append(self._f(
                            "infra", "tls_cert_expired",
                            f"certificate expired {abs(days)} days ago",
                            source=f"openssl x509 {host}", confidence=95,
                            passive=True,
                            evidence={"severity": "high"}))
                    elif days < 30:
                        findings.append(self._f(
                            "infra", "tls_cert_expiring_soon",
                            f"certificate expires in {days} days",
                            source=f"openssl x509 {host}", confidence=95,
                            passive=True,
                            evidence={"severity": "medium"}))
                except Exception:
                    pass
        # Old-protocol acceptance probes (handshake only, no exploit).
        for ver, flag in (("tls1_0", "-tls1"), ("tls1_1", "-tls1_1")):
            r2 = await _exec(["openssl", "s_client", "-connect",
                              f"{host}:{port}", "-servername", host,
                              flag], 8)
            if r2 and "BEGIN CERTIFICATE" in (r2[1] + r2[2]):
                findings.append(self._f(
                    "infra", "weak_tls_version",
                    f"server accepts {ver} (outdated protocol)",
                    source=f"openssl s_client {flag} {host}",
                    confidence=90, passive=True,
                    evidence={"severity": "medium"}))
        if not findings:
            return self._skipped(f"openssl connected to {host} but parsed no cert details")
        return self._ok(findings, f"openssl: {len(findings)} TLS observations for {host}")


class CmdHttpPlugin(_CmdPlugin):
    id = "cmd_http"
    label = "Command HTTP (curl)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "curl redirect chain, raw banner headers, HTTP version and timing."
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        host = self._host(target)
        if not host:
            return self._skipped("no host for curl probe")
        url = self._url(target, host)
        res = await _exec(["curl", "-sS", "-D", "-", "-o", "/dev/null", "-L",
                           "--max-time", "15", "-w",
                           "\nCURL_META %{http_code} %{time_total} %{url_effective}",
                           url], 20)
        if res is None:
            return self._skipped("curl not available on this host")
        rc, out, err = res
        if rc != 0 and not out.strip():
            return self._skipped(f"curl failed for {url}: {err.strip()[:200]}")
        findings: List[Finding] = []
        # Proxy CONNECT responses ("HTTP/1.1 200 Connection established")
        # are not hops: drop them so a proxied fetch is not misread.
        hops = []
        for line in re.findall(r"^HTTP/\S+ \d+.*$", out, re.M):
            if "established" in line.lower():
                continue
            m2 = re.match(r"HTTP/(\S+) (\d+)", line)
            if m2:
                hops.append((m2.group(1), m2.group(2)))
        meta = re.search(r"CURL_META (\d+) ([\d.]+) (\S+)", out)
        if meta and meta.group(1) == "000":
            # curl never completed (timeout / no route): report the miss
            # honestly instead of dressing a 000 up as a result.
            return self._skipped(
                f"curl could not complete {url} within 15s "
                f"(code 000; direct fetches may be blocked here)")
        for i, (ver, code) in enumerate(hops):
            findings.append(self._f("web", "http_hop",
                                    f"hop {i}: HTTP/{ver} {code}",
                                    source=f"curl -L {url}",
                                    confidence=95, passive=True))
        m = re.search(r"^Server:\s*(.*)$", out, re.M | re.I)
        if m:
            findings.append(self._f("web", "server_banner", m.group(1).strip(),
                                    source=f"curl {url}",
                                    confidence=90, passive=True))
        if meta:
            findings.append(self._f(
                "web", "http_final",
                f"HTTP {meta.group(1)} in {meta.group(2)}s",
                source=f"curl {url}", confidence=95, passive=True,
                evidence={"final_url": meta.group(3)}))
        if not findings:
            return self._skipped(f"curl returned no parseable output for {url}")
        return self._ok(findings, f"curl: {len(findings)} observations for {url}")


class CmdPortsPlugin(_CmdPlugin):
    id = "cmd_ports"
    label = "Command Service Ports"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "TCP connect to common service ports + banner grabs (nc, socket fallback). Detection only."
    timeout_s = 45

    async def _banner(self, host: str, port: int) -> str:
        res = await _exec(["nc", "-w", "3", host, str(port)], 5)
        if res is not None and res[1].strip():
            return res[1].strip().splitlines()[0][:500]
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3)
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=3)
                return data.decode(errors="replace").strip().splitlines()[0][:500] if data.strip() else ""
            finally:
                writer.close()
        except Exception:
            return ""

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        host = self._host(target)
        if not host:
            return self._skipped("no host for port connect checks")
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
            ip = infos[0][4][0] if infos else host
        except Exception:
            ip = host
        findings: List[Finding] = []
        sem = asyncio.Semaphore(20)

        async def one(port: int, label: str):
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=2)
                    writer.close()
                except Exception:
                    return
                findings.append(self._f("infra", "open_port",
                                        f"{host}:{port} ({label}) open",
                                        source=f"tcp connect {ip}:{port}",
                                        confidence=95, passive=True))
                banner = await self._banner(host, port)
                if banner:
                    findings.append(self._f(
                        "infra", "service_banner",
                        f"{host}:{port} banner: {banner}",
                        source=f"banner grab {host}:{port}",
                        confidence=90, passive=True))
                self._checkpoint(findings)

        await asyncio.gather(*[one(p, l) for p, l in _SERVICE_PORTS],
                             return_exceptions=True)
        if not findings:
            return self._ok([], f"no service ports open on {host} (probed {len(_SERVICE_PORTS)})")
        return self._ok(findings, f"{len(findings)} service-port observations on {host}")


class CmdSmtpPlugin(_CmdPlugin):
    id = "cmd_smtp"
    label = "Command SMTP Check"
    accepts = ["domain", "url", "email"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "MX-driven SMTP banner + STARTTLS capability. QUIT immediately, never sends mail."
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        host = self._host(target)
        if not host:
            return self._skipped("no domain for SMTP check")
        res = await _exec(["dig", "+short", "+time=5", "+tries=1",
                           host, "MX"], 8)
        if res is None:
            return self._skipped("dig not available for MX lookup")
        mx_hosts = []
        for line in _clean_lines(res[1]):
            parts = line.split()
            if len(parts) >= 2:
                mx_hosts.append(parts[-1].rstrip("."))
            elif parts:
                mx_hosts.append(parts[0].rstrip("."))
        if not mx_hosts:
            return self._skipped(f"no MX records for {host}")
        findings: List[Finding] = []
        for mx in mx_hosts[:3]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(mx, 25), timeout=4)
            except Exception:
                continue
            try:
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=4)
                    banner = data.decode(errors="replace").strip().splitlines()
                    if banner:
                        findings.append(self._f(
                            "infra", "smtp_banner",
                            f"{mx}: {banner[0][:300]}",
                            source=f"smtp banner {mx}:25",
                            confidence=90, passive=True))
                except Exception:
                    pass
                try:
                    writer.write(b"QUIT\r\n")
                    await writer.drain()
                except Exception:
                    pass
            finally:
                writer.close()
            starttls = await _exec(["openssl", "s_client", "-connect",
                                    f"{mx}:25", "-starttls", "smtp"], 10)
            if starttls and "BEGIN CERTIFICATE" in (starttls[1] + starttls[2]):
                findings.append(self._f("infra", "smtp_starttls",
                                        f"{mx} supports STARTTLS",
                                        source=f"openssl -starttls smtp {mx}",
                                        confidence=95, passive=True))
            self._checkpoint(findings)
        if not findings:
            return self._ok([], f"MX hosts for {host} did not answer SMTP (tried {len(mx_hosts[:3])})")
        return self._ok(findings, f"{len(findings)} SMTP observations for {host}")
