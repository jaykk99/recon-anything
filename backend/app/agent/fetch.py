"""Browser route: SSRF-guarded server-side fetch.

This is the agent's primary investigation route. Every fetch re-validates
the host (including each redirect hop) before connecting. Returns status,
headers, a text snippet, and cert info for https hosts.
"""

from __future__ import annotations

import socket
import ssl
import urllib.parse

import httpx

from .http_client import client as http_client
from .ssrf import SSRFBlocked, check_url

MAX_BYTES = 512 * 1024
TIMEOUT = 25


def fetch_url(url: str, max_redirects: int = 3, snippet_chars: int = 2000) -> dict:
    """Fetch a URL through the browser route. Raises SSRFBlocked."""
    current = url
    hops = 0
    while True:
        parsed = check_url(current)
        try:
            with http_client(TIMEOUT) as c:
                r = c.get(current, headers={"User-Agent": "recon-anything-agent/1.0"},
                          follow_redirects=False)
        except httpx.HTTPError as e:
            return {"url": current, "error": str(e)[:300], "status": None}
        except Exception as e:
            return {"url": current, "error": str(e)[:300], "status": None}
        if r.is_redirect and hops < max_redirects:
            nxt = r.headers.get("location", "")
            nxt = urllib.parse.urljoin(current, nxt)
            try:
                check_url(nxt)
            except SSRFBlocked:
                return {"url": current, "status": r.status_code,
                        "redirect_blocked": nxt[:200]}
            current = nxt
            hops += 1
            continue
        body = r.content[:MAX_BYTES]
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        out = {
            "url": str(r.url),
            "status": r.status_code,
            "headers": {k.lower(): v for k, v in r.headers.items()},
            "text_snippet": text[:snippet_chars],
            "bytes": len(body),
        }
        if parsed.scheme == "https" and parsed.hostname and parsed.port not in (None, 443):
            out["cert"] = cert_info(parsed.hostname, parsed.port)
        elif parsed.scheme == "https" and parsed.hostname:
            out["cert"] = cert_info(parsed.hostname, 443)
        return out


def cert_info(host: str, port: int) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", "") or issuer.get("commonName", ""),
            "not_after": cert.get("notAfter", ""),
            "san": [v for _, v in cert.get("subjectAltName", [])][:20],
        }
    except Exception as e:
        return {"error": str(e)[:200]}
