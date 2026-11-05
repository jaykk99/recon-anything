"""SSRF guard for the agent's browser route.

Every outbound fetch (browser route, terminal curl URLs, crt.sh lookups)
passes through here: only http/https, hostname must resolve to a public IP.
Private, loopback, link-local, reserved, multicast and cloud-metadata
ranges are refused before any packet leaves.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse


class SSRFBlocked(ValueError):
    pass


def _ip_is_public(ip: str) -> bool:
    """True unless the IP is in a range that must never be fetched.

    Deliberately NOT Python's ipaddress.is_private: that also flags
    198.18.0.0/15 (benchmarking space), which real public services behind
    CDNs/proxies resolve to. The cloud-metadata endpoint 169.254.169.254
    stays blocked via the link-local range.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    blocked = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/29", "192.0.2.0/24",
        "192.168.0.0/16", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10",
    ]
    return not any(addr in ipaddress.ip_network(n) for n in blocked)


def check_host(host: str, resolve=socket.getaddrinfo) -> str:
    """Validate a hostname. Returns the hostname on success, raises SSRFBlocked."""
    host = (host or "").strip().strip(".")
    if not host:
        raise SSRFBlocked("empty host")
    if host.lower() == "localhost":
        raise SSRFBlocked("localhost is not a public target")
    try:
        infos = resolve(host, None)
    except Exception as e:
        raise SSRFBlocked(f"cannot resolve {host}: {e}")
    ips = {info[4][0] for info in infos if info[4]}
    if not ips:
        raise SSRFBlocked(f"no addresses for {host}")
    for ip in ips:
        if not _ip_is_public(ip):
            raise SSRFBlocked(f"{host} resolves to non-public address {ip}")
    return host


def check_url(url: str, resolve=socket.getaddrinfo) -> urllib.parse.ParseResult:
    """Validate a full URL. Returns the parsed URL on success."""
    parsed = urllib.parse.urlparse((url or "").strip())
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlocked("only http and https URLs are allowed")
    if not parsed.hostname:
        raise SSRFBlocked("URL has no host")
    check_host(parsed.hostname, resolve=resolve)
    return parsed
