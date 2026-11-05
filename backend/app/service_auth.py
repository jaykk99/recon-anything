"""Service-to-service auth for the narrow /api/service/* API.

This is the ONLY server-to-server path into ReconAnything, built for
Error Inbox's black team agents. It deliberately does NOT touch the
human gate (`gate()` in main.py: the legacy access code / frontend
sign-in flow). Human auth is unchanged; this is a second, smaller door
with its own key, and it stays shut unless RECON_SERVICE_KEY is set:

  RECON_SERVICE_KEY       shared secret; the caller sends it as the
                          X-Recon-Service-Key header. Never in the repo,
                          never in logs, never in a URL (headers only —
                          query params would leak it to access logs).

Authorization model (Jay's call, 2026-10-25): the key is NOT a
per-target gate. When Jay explicitly asks for a scan, ANY target is
pre-approved — there is deliberately no allowlist and no per-target
approval table, because making him approve each target separately is
exactly what he vetoed. The trigger rule lives on the Error Inbox
side (scans run only on Jay's explicit ask, never autonomously);
this side enforces the two standing exclusions that Jay's blanket
approval does NOT override:

  - crypto.com is NEVER a scan target (its policy bans scanners).
    Apex and every subdomain are rejected before any work starts,
    so a blocked scan makes zero contact with the site.
  - Detection only: the service API starts scans and reads back runs
    it created. It cannot retest, change settings, touch keys or
    schedules, or read human-created runs. The plugins are detectors;
    the service key adds no capability the human UI does not already
    have.

The key is read per call (not at import) so tests can set and unset
it, and so a rotated key takes effect without a restart.
"""

from __future__ import annotations

import hmac
import os
from typing import Optional
from urllib.parse import urlparse

from fastapi import Header, HTTPException


def _service_key() -> str:
    return os.environ.get("RECON_SERVICE_KEY", "")


def service_gate(
    x_recon_service_key: Optional[str] = Header(default=None),
) -> bool:
    """Accept only the configured service key. Fail closed everywhere:
    no key configured, no header, or a mismatch all get 401, and the
    configured key is never echoed back in an error."""
    expected = _service_key()
    if not expected or not x_recon_service_key:
        raise HTTPException(
            status_code=401, detail="service API not configured or key missing")
    if not hmac.compare_digest(x_recon_service_key, expected):
        raise HTTPException(status_code=401, detail="bad service key")
    return True


def target_host(target: str) -> Optional[str]:
    """Extract the hostname from a scan target (full URL or bare host).
    Returns None for anything unparseable, multi-target input, or an
    empty host. Userinfo tricks ("decoy@real.com") are safe by
    construction: urlparse's hostname excludes userinfo, so the real
    host is what gets scanned, not the decoy."""
    if not target or not isinstance(target, str):
        return None
    raw = target.strip()
    if not raw or any(c.isspace() for c in raw):
        return None
    candidate = raw if "://" in raw else "https://" + raw
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.lower()


def is_blocked_target(host: str) -> bool:
    """Standing exclusion, NOT overridden by Jay's blanket approval:
    crypto.com is never a scan target. Apex and all subdomains match;
    lookalikes (evil-crypto.com, crypto.com.evil.com) do NOT match —
    the dot boundary matters, so a suffix check without it would
    over-block and a substring check would too."""
    return host == "crypto.com" or host.endswith(".crypto.com")
