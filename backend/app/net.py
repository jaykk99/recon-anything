"""Unrestricted internet egress for ReconAnything.

Jay's rule: the app can reach anything on the internet. No artificial
restrictions. This module centralizes egress configuration so every HTTP
client in the app behaves the same:

- Proxy: honors HTTP_PROXY / HTTPS_PROXY (and lowercase) from the
  environment, unless it points at localhost (which would loop).
- TLS: uses the system CA bundle when present (the sandbox egress proxy
  re-signs TLS and certifi lacks its CA); otherwise default verification.
- trust_env=False is deliberate: proxy handling is explicit through
  egress_proxy(), not implicit. Direct connections work everywhere;
  Render has no egress allowlist.

There are no host, port, or scheme blocklists here. The only fetch
restriction in the app is the SSRF guard on the /fetch file-viewer
endpoint (main.py), which is a deliberate security boundary, not an
egress limitation.
"""
from __future__ import annotations

import os
from typing import Optional
from urllib.parse import urlparse

import httpx


def egress_proxy() -> Optional[str]:
    """Proxy URL from the environment, or None for direct egress."""
    p = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
         or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
         or None)
    if p:
        try:
            if (urlparse(p).hostname or "") in ("localhost", "127.0.0.1", "::1"):
                return None
        except Exception:
            return None
    return p


def ca_bundle():
    """System CA bundle path when present, else True (default verification)."""
    p = "/etc/ssl/certs/ca-certificates.crt"
    return p if os.path.isfile(p) else True


def async_client(**kwargs) -> httpx.AsyncClient:
    """httpx.AsyncClient with full, unrestricted egress configured."""
    kwargs.setdefault("proxy", egress_proxy())
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault("verify", ca_bundle())
    return httpx.AsyncClient(**kwargs)


def sync_client(**kwargs) -> httpx.Client:
    """httpx.Client with full, unrestricted egress configured."""
    kwargs.setdefault("proxy", egress_proxy())
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault("verify", ca_bundle())
    return httpx.Client(**kwargs)
