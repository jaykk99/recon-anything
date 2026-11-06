"""Shared helpers for the Tier-2 (100-plugin expansion) enumeration plugins.

Native, keyless, stdlib-only building blocks: target-host resolution
(the target's OWN IPs only - never a range, never third parties), TCP
connect probes with short timeouts, banner grabs, and a TLS handshake
probe. Every scanner built on these helpers is scoped to the IPs the
target itself resolves to, with curated port lists and bounded
concurrency - the same safety shape as asn_scan / port_scan.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target

# port -> service label (curated, well-known assignments)
SERVICE_LABELS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 587: "submission", 631: "ipp",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql-s",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "grafana/http-dev",
    3128: "squid-proxy", 3306: "mysql", 3389: "ms-wbt-server",
    4369: "epmd", 5000: "http-dev", 5060: "sip", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6006: "tensorboard",
    6379: "redis", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8088: "http-alt", 8443: "https-alt",
    8500: "consul", 8888: "http-alt", 9000: "http-alt", 9042: "cassandra",
    9090: "http-alt", 9092: "kafka", 9100: "node-exporter",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb-shard", 51820: "wireguard",
}

# Ports whose exposure is worth a medium (not low) severity.
RISKY_PORTS = {
    21, 23, 111, 135, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389,
    5432, 5900, 5984, 6379, 9200, 9300, 11211, 27017, 27018,
}


def host_of(target) -> Optional[str]:
    """Hostname or IP literal for a target, or None."""
    domain = domain_from_target(target.type, target.normalized)
    if domain:
        return domain.split(":")[0]
    if target.type == "ip":
        return (target.normalized or "").split(":")[0].strip() or None
    if target.type == "url":
        from urllib.parse import urlparse
        try:
            return urlparse(target.normalized).hostname
        except Exception:
            return None
    return None


async def resolve_ips(host: str, cap: int = 4) -> List[str]:
    """Resolve a host to its own IPs (IP literals pass through)."""
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        return [host]
    except Exception:
        pass
    try:
        infos = await asyncio.wait_for(
            asyncio.get_event_loop().getaddrinfo(
                host, None, family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM),
            timeout=6)
    except Exception:
        return []
    out: List[str] = []
    seen = set()
    for info in infos or []:
        try:
            ip = info[4][0]
        except Exception:
            continue
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
        if len(out) >= cap:
            break
    return out


async def tcp_state(ip: str, port: int, timeout: float = 1.5) -> str:
    """One TCP connect probe: 'open' | 'closed' | 'timeout' | 'error'."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return "open"
    except asyncio.TimeoutError:
        return "timeout"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "error"
    except Exception:
        return "error"


async def tcp_banner(ip: str, port: int, timeout: float = 2.0,
                     payload: Optional[bytes] = None,
                     read_len: int = 512) -> Tuple[str, str]:
    """Connect, optionally send a read-only probe payload, read a banner.

    Returns (state, banner_text). The banner is whatever the service
    volunteers (plus, when a payload is sent, its direct response
    headers/head) - read-only handshakes only.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
    except asyncio.TimeoutError:
        return "timeout", ""
    except ConnectionRefusedError:
        return "closed", ""
    except Exception:
        return "error", ""
    banner = ""
    try:
        if payload:
            try:
                writer.write(payload)
                await writer.drain()
            except Exception:
                pass
        try:
            data = await asyncio.wait_for(reader.read(read_len),
                                          timeout=timeout)
            banner = data.decode("utf-8", "ignore") if data else ""
        except Exception:
            banner = ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return "open", banner


async def scan_ports(ips: List[str], ports: List[int], probe,
                     concurrency: int = 40) -> List[Tuple[str, int, str]]:
    """Run probe(ip, port) -> state over ips x ports, bounded.

    Returns [(ip, port, state)] for every probed pair.
    """
    sem = asyncio.Semaphore(max(1, concurrency))
    results: List[Tuple[str, int, str]] = []

    async def one(ip: str, port: int):
        async with sem:
            try:
                state = await probe(ip, port)
            except Exception:
                state = "error"
            results.append((ip, port, state))

    await asyncio.gather(*[one(ip, p) for ip in ips for p in ports])
    return results


def tls_probe(host: str, port: int = 443, timeout: float = 6.0) -> Optional[Dict]:
    """Blocking TLS handshake probe (run via asyncio.to_thread).

    Returns {subject, issuer, san, not_before, not_after, protocol,
    cipher, self_signed} or None when no TLS service answers.
    Read-only: a normal ClientHello handshake, no renegotiation tricks.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.version() or ""
                cipher = (ssock.cipher() or ("",))[0]
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return None
                # NOTE: getpeercert() returns {} under CERT_NONE, so
                # the certificate is decoded from its DER form.
                # cryptography is a declared backend dependency
                # (requirements.txt); the stdlib _test_decode_cert is
                # the fallback when it is unavailable.
                parsed = _decode_cert_der(der)
                if parsed is None:
                    return {"subject": "(unparsed certificate)",
                            "issuer": "", "san": [], "not_before": "",
                            "not_after": "", "protocol": protocol,
                            "cipher": cipher, "self_signed": False}
                parsed["protocol"] = protocol
                parsed["cipher"] = cipher
                return parsed
    except Exception:
        return None


def _fmt_cert_date(d) -> str:
    """Format a datetime like an OpenSSL cert date string."""
    try:
        return d.strftime("%b %d %H:%M:%S %Y GMT")
    except Exception:
        return str(d or "")


def _decode_cert_der(der: bytes):
    """Decode a DER certificate into the tls_probe dict, or None."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID

        cert = x509.load_der_x509_certificate(der)

        def _name(name) -> str:
            parts = []
            for attr in name:
                oid_name = {
                    NameOID.COMMON_NAME: "CN",
                    NameOID.ORGANIZATION_NAME: "O",
                    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
                    NameOID.COUNTRY_NAME: "C",
                    NameOID.STATE_OR_PROVINCE_NAME: "ST",
                    NameOID.LOCALITY_NAME: "L",
                }.get(attr.oid, attr.oid.dotted_string)
                parts.append(f"{oid_name}={attr.value}")
            return ", ".join(parts)

        san = []
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = [str(n) for n in ext.value.get_values_for_type(
                x509.DNSName)]
            san += [str(n) for n in ext.value.get_values_for_type(
                x509.IPAddress)]
        except Exception:
            pass
        subject = _name(cert.subject)
        issuer = _name(cert.issuer)
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except Exception:
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
        return {"subject": subject, "issuer": issuer, "san": san,
                "not_before": _fmt_cert_date(not_before),
                "not_after": _fmt_cert_date(not_after),
                "self_signed": bool(subject and issuer
                                    and subject == issuer)}
    except Exception:
        pass
    try:
        import ssl as _ssl
        import tempfile
        with tempfile.NamedTemporaryFile(
                suffix=".der", delete=True) as fh:
            fh.write(der)
            fh.flush()
            cert = _ssl._ssl._test_decode_cert(fh.name)
        san = [str(v) for _k, v in cert.get("subjectAltName", []) or []]

        def _name2(rdns) -> str:
            return ", ".join(f"{k}={v}" for rdn in rdns or []
                             for k, v in rdn)

        subject = _name2(cert.get("subject"))
        issuer = _name2(cert.get("issuer"))
        return {"subject": subject, "issuer": issuer, "san": san,
                "not_before": str(cert.get("notBefore", "")),
                "not_after": str(cert.get("notAfter", "")),
                "self_signed": bool(subject and issuer
                                    and subject == issuer)}
    except Exception:
        return None


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def extract_title(html: str) -> str:
    if not html:
        return ""
    m = _TITLE_RE.search(html[:20000])
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:160]


def tech_hints(headers: Dict[str, str], body: str) -> List[str]:
    """Cheap technology fingerprints from headers / markup."""
    hints: List[str] = []
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if h.get("server"):
        hints.append(f"server: {h['server'][:80]}")
    if h.get("x-powered-by"):
        hints.append(f"x-powered-by: {h['x-powered-by'][:80]}")
    low = (body or "")[:20000].lower()
    for needle, label in (
            ("wp-content", "wordpress"), ("wp-includes", "wordpress"),
            ("generator\" content=\"wordpress", "wordpress"),
            ("drupal", "drupal"), ("joomla", "joomla"),
            ("__next_data__", "next.js"), ("_next/static", "next.js"),
            ("ng-version", "angular"), ("react", "react (hint)"),
            ("shopify", "shopify"), ("ghost/", "ghost")):
        if needle in low and label not in hints:
            hints.append(label)
    if "set-cookie" in h:
        hints.append("sets cookies")
    return hints[:8]
