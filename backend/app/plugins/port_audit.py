"""Port auditor: top-100 port scan + banner grab + dangerous-exposure flags.

Connect-only, never exploits. Resolves the target's own IPs and scans
only those (never ranges). Each open port gets a banner grab; dangerous
exposures are flagged with risk + remediation:

  HIGH:   database ports on the open internet (3306 MySQL, 1433 MSSQL,
          1521 Oracle, 5432 Postgres, 27017/27018 MongoDB, 6379 Redis,
          11211 Memcached, 9200/9300 Elasticsearch), plaintext remote
          access (23 Telnet), RDP (3389), VNC (5900/5901)
  MEDIUM: FTP (21) with anonymous login allowed, TFTP (69), SMB (445/139),
          NFS (111/2049), unauthenticated-looking Elasticsearch/Kibana
  LOW:    everything else open, informational

Passive mode: no packets, reports resolved IPs + note. Active mode does
the real scan. Bounded concurrency, short timeouts, hard 30s ceiling
(runner-enforced anyway).
"""
from __future__ import annotations

import asyncio
import re
import socket
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (port, service label)
TOP_PORTS: List[Tuple[int, str]] = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (69, "TFTP"), (80, "HTTP"), (88, "Kerberos"),
    (110, "POP3"), (111, "RPCbind"), (119, "NNTP"), (123, "NTP"),
    (135, "MSRPC"), (137, "NetBIOS-NS"), (138, "NetBIOS-DGM"),
    (139, "NetBIOS-SSN"), (143, "IMAP"), (161, "SNMP"),
    (162, "SNMP-trap"), (179, "BGP"), (194, "IRC"), (389, "LDAP"),
    (443, "HTTPS"), (445, "SMB"), (465, "SMTPS"), (514, "Syslog"),
    (515, "LPD"), (520, "RIP"), (587, "SMTP-submission"), (631, "IPP"),
    (636, "LDAPS"), (873, "rsync"), (989, "FTPS-data"), (990, "FTPS"),
    (993, "IMAPS"), (995, "POP3S"), (1080, "SOCKS"), (1194, "OpenVPN"),
    (1433, "MSSQL"), (1434, "MSSQL-monitor"), (1521, "Oracle-DB"),
    (1723, "PPTP"), (2049, "NFS"), (2082, "cPanel"), (2083, "cPanel-SSL"),
    (2086, "WHM"), (2087, "WHM-SSL"), (2095, "webmail"), (2096, "webmail-SSL"),
    (2181, "Zookeeper"), (2195, "APNS"), (2196, "APNS-feedback"),
    (3306, "MySQL"), (3389, "RDP"), (3690, "SVN"), (4369, "EPMD"),
    (4444, "metasploit-default"), (4567, "dev"), (5000, "UPnP/Flask"),
    (5001, "dev"), (5060, "SIP"), (5061, "SIP-TLS"), (5432, "PostgreSQL"),
    (5631, "pcAnywhere"), (5632, "pcAnywhere-data"), (5672, "RabbitMQ"),
    (5900, "VNC"), (5901, "VNC-1"), (5985, "WinRM"), (5986, "WinRM-SSL"),
    (6000, "X11"), (6001, "X11-1"), (6379, "Redis"), (6443, "Kubernetes-API"),
    (6660, "IRC"), (6667, "IRC"), (7000, "dev"), (7001, "Cassandra"),
    (8000, "HTTP-alt"), (8008, "HTTP-alt"), (8009, "AJP13"),
    (8010, "HTTP-alt"), (8080, "HTTP-proxy-alt"), (8081, "HTTP-alt"),
    (8088, "HTTP-alt"), (8090, "HTTP-alt"), (8181, "HTTP-alt"),
    (8200, "HTTP-alt"), (8300, "Consul"), (8443, "HTTPS-alt"),
    (8500, "Consul-HTTP"), (8888, "HTTP-alt"), (9000, "dev/PHP-FPM"),
    (9001, "dev"), (9042, "Cassandra-CQL"), (9080, "HTTP-alt"),
    (9090, "HTTP-alt"), (9100, "JetDirect"), (9200, "Elasticsearch"),
    (9300, "Elasticsearch-cluster"), (9418, "git"), (9999, "dev"),
    (10000, "Webmin"), (11211, "Memcached"), (27017, "MongoDB"),
    (27018, "MongoDB-shard"), (50070, "Hadoop-NameNode"),
]

# port -> (risk, title, remediation, bounty_key)
DANGEROUS: Dict[int, Tuple[str, str, str, str]] = {
    3306: ("high", "MySQL exposed to the internet",
           "Bind MySQL to 127.0.0.1 or a private network, firewall port 3306, "
           "enforce strong credentials and TLS.", "db_exposed"),
    1433: ("high", "MSSQL exposed to the internet",
           "Firewall port 1433, restrict to app servers only, disable sa "
           "account, enforce strong passwords.", "db_exposed"),
    1521: ("high", "Oracle DB exposed to the internet",
           "Firewall port 1521, restrict to private network, review listener "
           "configuration.", "db_exposed"),
    5432: ("high", "PostgreSQL exposed to the internet",
           "Bind to localhost/private net, firewall port 5432, use strong "
           "passwords and scram-sha-256 auth.", "db_exposed"),
    27017: ("high", "MongoDB exposed to the internet",
            "Bind to 127.0.0.1, enable authentication, firewall port 27017. "
            "Open MongoDB instances are routinely ransomed.", "db_exposed"),
    27018: ("high", "MongoDB shard exposed to the internet",
            "Same as MongoDB: bind localhost, enable auth, firewall it.",
            "db_exposed"),
    6379: ("high", "Redis exposed to the internet",
           "Bind to 127.0.0.1, set requirepass, firewall port 6379. Open "
           "Redis is a classic RCE vector.", "db_exposed"),
    11211: ("high", "Memcached exposed to the internet",
            "Bind to localhost, firewall port 11211. Open Memcached is "
            "abused for DDoS amplification.", "db_exposed"),
    9200: ("high", "Elasticsearch exposed (often unauthenticated)",
           "Put behind authentication/reverse proxy, firewall port 9200, "
           "enable X-Pack security.", "db_exposed"),
    9300: ("high", "Elasticsearch cluster port exposed",
           "Firewall port 9300 - cluster join should never be internet "
           "reachable.", "db_exposed"),
    23: ("high", "Telnet open (plaintext remote access)",
         "Disable Telnet entirely. Use SSH with key auth instead.",
         "telnet_open"),
    3389: ("high", "RDP exposed to the internet",
           "Put RDP behind VPN, enable NLA + MFA, firewall port 3389. "
           "Exposed RDP is brute-forced constantly.", "rdp_exposed"),
    5900: ("high", "VNC exposed to the internet",
           "Put VNC behind VPN/SSH tunnel, enforce strong passwords. "
           "VNC auth is weak and brute-forced.", "vnc_exposed"),
    5901: ("high", "VNC (display :1) exposed to the internet",
           "Put VNC behind VPN/SSH tunnel, enforce strong passwords.",
           "vnc_exposed"),
    21: ("medium", "FTP open - check for anonymous login",
         "Disable anonymous FTP, use SFTP instead, enforce strong "
         "credentials.", "ftp_open"),
    69: ("medium", "TFTP open (unauthenticated file transfer)",
         "Disable TFTP if unneeded; it has no authentication. Firewall "
         "port 69.", "tftp_open"),
    445: ("medium", "SMB exposed to the internet",
          "Firewall ports 445/139. SMB must never be internet-reachable "
          "(WannaCry/EternalBlue class risk).", "smb_exposed"),
    139: ("medium", "NetBIOS/SMB exposed to the internet",
          "Firewall ports 445/139. SMB must never be internet-reachable.",
          "smb_exposed"),
    111: ("medium", "RPCbind exposed (NFS indicator)",
          "Firewall port 111. NFS/RPC services must not be internet "
          "reachable.", "nfs_exposed"),
    2049: ("medium", "NFS exposed to the internet",
           "Firewall port 2049. NFS must never be internet-reachable; "
           "restrict to trusted hosts with proper exports.", "nfs_exposed"),
    161: ("medium", "SNMP open - check community strings",
          "Use SNMPv3 with auth, disable public/private community strings, "
          "firewall port 161.", "snmp_open"),
    6443: ("medium", "Kubernetes API exposed",
           "Restrict K8s API to trusted networks, enforce RBAC + strong "
           "auth. Internet-facing K8s APIs are attacked.", "k8s_api_exposed"),
    2375: ("high", "Docker daemon exposed (unauthenticated root)",
           "Firewall port 2375 immediately. An open Docker socket is "
           "instant root. Use TLS-protected 2376 only.", "docker_exposed"),
    2376: ("medium", "Docker TLS port exposed",
           "Restrict to trusted hosts, verify TLS client certs are enforced.",
           "docker_exposed"),
}

HTTP_PORTS = {80, 443, 8000, 8008, 8010, 8080, 8081, 8088, 8090, 8181,
              8200, 8443, 8888, 9000, 9080, 9090, 9200}
TLS_PORTS = {443, 8443}

DEFAULT_REMEDIATION = ("Close this port at the firewall/security group if the "
                       "service is not needed publicly. If it must be public, "
                       "keep it patched and restrict management access to "
                       "trusted IPs.")


async def _grab_banner(host: str, port: int, service: str,
                       timeout: float = 4.0) -> Tuple[bool, str]:
    """Connect-only banner grab. Returns (open, banner)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return False, ""
    banner = ""
    try:
        if port in HTTP_PORTS:
            scheme = "https" if port in TLS_PORTS else "http"
            _ = scheme  # plain HTTP probe; TLS handled by port_scan plugin
            req = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                   f"User-Agent: ReconAnything/1.0\r\n\r\n")
            writer.write(req.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            text = data.decode("utf-8", "replace")
            server = ""
            for line in text.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()[:80]
                    break
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:60] if m else ""
            banner = f"HTTP {server}".strip()
            if title:
                banner += f" | {title}"
        else:
            # services that volunteer a banner (FTP, SSH, SMTP, etc.)
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=2.5)
                banner = data.decode("utf-8", "replace").strip()[:160]
                banner = re.sub(r"\s+", " ", banner)
            except asyncio.TimeoutError:
                banner = ""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
    return True, banner


async def _ftp_anonymous_ok(host: str, timeout: float = 5.0) -> Optional[bool]:
    """Check if FTP allows anonymous login. Connect-only, no file access."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 21), timeout=timeout)

        async def _readline() -> str:
            line = await asyncio.wait_for(reader.readline(), timeout=3)
            return line.decode("utf-8", "replace").strip()

        await _readline()  # banner
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        resp = await _readline()
        if resp.startswith("331"):
            writer.write(b"PASS recon@anythi.ng\r\n")
            await writer.drain()
            resp2 = await _readline()
            writer.close()
            return resp2.startswith("230")
        writer.close()
        return False
    except Exception:
        return None


class PortAuditPlugin(Plugin):
    id = "port_audit"
    label = "Port Auditor"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("Top-100 port audit with banner grabs and dangerous-"
                   "exposure flags (databases, RDP/VNC/Telnet, anon FTP).")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain and target.type != "ip":
            return self._skipped("no host for this target type")
        host = domain or target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        # -- resolve target's own IPs (scan these only, never ranges) -------
        ips: List[str] = []
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(
                host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            seen = set()
            for info in infos:
                ip = info[4][0]
                # skip link-local / loopback weirdness from odd resolvers
                if ip.startswith(("127.", "::1", "fe80:")):
                    continue
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
            ips = ips[:4]
        except Exception:
            pass
        if not ips:
            # fall back to hostname connect (resolver may block getaddrinfo)
            ips = [host]

        if mode == "passive":
            if ips != [host]:
                findings.append(self._f(
                    "infra", "target_ips",
                    f"Target resolves to: {', '.join(ips)} - run in active "
                    f"mode for the full port audit",
                    source="DNS", confidence=95, passive=True))
            dur = int((time.monotonic() - t0) * 1000)
            res = self._ok(findings, "passive: port audit needs active mode")
            res.duration_ms = dur
            return res

        # -- active: scan top ports on each IP, bounded concurrency ---------
        sem = asyncio.Semaphore(40)
        deadline = t0 + 26  # leave headroom under the 30s runner cap

        async def _scan(ip: str, port: int, service: str):
            if time.monotonic() > deadline:
                return None
            async with sem:
                if time.monotonic() > deadline:
                    return None
                is_open, banner = await _grab_banner(ip, port, service)
                if is_open:
                    return (ip, port, service, banner)
                return None

        results = await asyncio.gather(*[
            _scan(ip, port, service)
            for ip in ips for port, service in TOP_PORTS
        ])
        open_ports = [r for r in results if r]

        for ip, port, service, banner in open_ports:
            danger = DANGEROUS.get(port)
            if danger:
                risk, title, remediation, bkey = danger
                extra = ""
                if port == 21:
                    # verify anonymous login before flagging
                    anon = await _ftp_anonymous_ok(ip)
                    if anon is True:
                        title = "FTP allows ANONYMOUS login"
                        risk = "medium"
                        extra = " - anonymous login CONFIRMED"
                        remediation = ("Disable anonymous FTP immediately, "
                                       "use SFTP instead.")
                    elif anon is False:
                        title = "FTP open (anonymous login refused)"
                        risk = "low"
                        extra = " - anonymous refused"
                    else:
                        extra = " - anonymous check inconclusive"
                val = (f"{title} on {ip}:{port} ({service}){extra}"
                       + (f" - banner: {banner}" if banner else ""))
                findings.append(self._f(
                    "infra", bkey, val,
                    source="port audit", confidence=95, passive=False,
                    bounty_value=("high" if risk == "high"
                                  else "medium" if risk == "medium" else "low"),
                    evidence={"port": port, "service": service, "ip": ip,
                              "banner": banner, "severity": risk,
                              "exploitability": ("weaponized" if port in
                                                 (2375, 6379, 27017)
                                                 else "public_poc" if risk == "high"
                                                 else "theoretical"),
                              "remediation": remediation}))
            else:
                val = (f"Port {port} ({service}) OPEN on {ip}"
                       + (f" - {banner}" if banner else ""))
                findings.append(self._f(
                    "infra", "port_open", val,
                    source="port audit", confidence=90, passive=False,
                    bounty_value="low",
                    evidence={"port": port, "service": service, "ip": ip,
                              "banner": banner, "severity": "low",
                              "exploitability": "unknown",
                              "remediation": DEFAULT_REMEDIATION}))

        n_open = len(open_ports)
        n_danger = sum(1 for f in findings
                       if f.evidence and f.evidence.get("severity") in ("high", "medium"))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"audited {len(TOP_PORTS)} ports on {len(ips)} IP(s): "
            f"{n_open} open, {n_danger} dangerous")
        res.duration_ms = dur
        return res
