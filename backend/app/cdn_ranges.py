"""Classify an IP as a CDN edge / shared-PaaS address.

Why this exists: reverse-IP ("what else is hosted on this address?") is
how one scanned IP turns into the rest of an operator's footprint - BUT
only when the IP is dedicated. On a CDN edge (Cloudflare, Fastly,
CloudFront, Akamai) or a shared PaaS (Render, Vercel, Netlify, Heroku,
Fly.io) a single anycast/shared address fronts thousands of unrelated
tenants, so reverse-IP there returns hundreds of strangers' domains.
Expanding those into scan targets is pure dilution - a real scan of one
site ballooned to 600+ findings, almost all co-tenant noise, because
reverse-IP fired on a shared Render/Cloudflare address.

A human operator never reverse-IPs a Cloudflare address. This module
lets the reverse-IP plugin make the same call: `classify_ip(ip)` names
the provider when the address sits in a known CDN/PaaS range, and the
plugin skips reverse expansion there (emitting one explanatory note
instead of a flood of unrelated neighbours).

Pure stdlib (`ipaddress`), no network, deterministic. The ranges are a
curated, deliberately conservative set: only providers whose addresses
are ALWAYS shared edge/tenant space, never a customer's dedicated box.
General IaaS (EC2/GCE/Azure VMs) is intentionally NOT listed - those can
be dedicated, so the caller's result-count heuristic handles them.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

# provider -> list of CIDR strings. Shared edge / shared PaaS only.
_RANGES: Dict[str, List[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    ],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/32"],
    "Amazon CloudFront": [
        "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.182.0.0/16",
        "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18",
        "99.84.0.0/16", "143.204.0.0/16", "204.246.164.0/22",
        "205.251.192.0/19", "216.137.32.0/19", "130.176.0.0/16",
    ],
    "Akamai": [
        "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
        "2.16.0.0/13", "95.100.0.0/15", "96.16.0.0/15", "96.6.0.0/15",
    ],
    "Render": ["216.24.56.0/22"],
    "Vercel": ["76.76.21.0/24", "76.223.126.0/24", "66.33.60.0/24"],
    "Netlify": ["99.86.0.0/16", "3.33.152.0/24", "75.2.60.0/24",
                "13.52.0.0/16"],
    "Fly.io": ["66.241.124.0/24", "168.220.80.0/23", "149.248.192.0/19"],
    "GitHub Pages": ["185.199.108.0/22"],
    "Heroku": ["3.218.0.0/16"],
}


def _build() -> List[Tuple[object, str]]:
    nets: List[Tuple[object, str]] = []
    for provider, cidrs in _RANGES.items():
        for cidr in cidrs:
            try:
                nets.append((ipaddress.ip_network(cidr, strict=False),
                             provider))
            except ValueError:
                continue
    return nets


_NETS = _build()


def classify_ip(ip: str) -> Optional[str]:
    """Return the CDN/PaaS provider name if `ip` is in a known shared
    edge/tenant range, else None. Never raises on bad input."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    for net, provider in _NETS:
        if addr.version == net.version and addr in net:
            return provider
    return None


def is_shared_edge_ip(ip: str) -> bool:
    """True if reverse-IP on this address is not worth doing (its
    co-tenants are unrelated)."""
    return classify_ip(ip) is not None
