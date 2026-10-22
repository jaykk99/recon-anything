"""Scan environment modes: SANDBOX vs LIVE.

The mode is an app-level SETTING (not a per-scan choice):

- SANDBOX (default, incl. fresh installs): scans may only target Jay's own
  assets (the owned-assets allowlist) and local/lab targets (localhost,
  private/loopback IPs, *.local / *.test / *.lab / *.internal names).
  Sandbox runs are stamped env_mode="sandbox", badged in the UI, and never
  counted as production findings.
- LIVE: the long-standing production behavior - authorized targets,
  detection plus gated read-only assessment, full audit logging.

Switching modes is an explicit settings action and every switch is
written to the audit log. The mode changes target scope and data handling
ONLY: it does not enable, unlock, or add any capability in either mode -
the existing authorization gates (bank/ATM source types, plugin safety
boundaries, detection-only rules) apply identically in both modes.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .models import AppSetting, AuditLog

SANDBOX = "sandbox"
LIVE = "live"
MODES = (SANDBOX, LIVE)

# Jay's own assets (seeded default allowlist; editable in settings).
DEFAULT_OWNED_ASSETS: List[str] = [
    "guttergenie.pages.dev",
    "gutter-genie-master.pages.dev",
    "move-and-metal-site.pages.dev",
    "error-inbox.onrender.com",
    "bro-agent.onrender.com",
    "recon-anything.onrender.com",
    "uncensored-harness-production.up.railway.app",
    "jaykk99.github.io",
]

# Hostname suffixes that always count as local/lab space.
LAB_SUFFIXES = (".local", ".test", ".lab", ".internal", ".home", ".lan")

_MODE_KEY = "scan_mode"
_OWNED_KEY = "owned_assets"


def get_mode(session) -> str:
    """Current app mode; SANDBOX when nothing was ever set."""
    row = session.query(AppSetting).filter_by(key=_MODE_KEY).first()
    mode = ((row.value or {}).get("mode") if row else None) or SANDBOX
    return mode if mode in MODES else SANDBOX


def set_mode(session, mode: str, actor: str = "ui") -> Dict:
    """Persist a mode switch and audit it. Returns the audit detail."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    previous = get_mode(session)
    row = session.query(AppSetting).filter_by(key=_MODE_KEY).first()
    if row is None:
        row = AppSetting(key=_MODE_KEY, value={})
        session.add(row)
    row.value = {"mode": mode}
    detail = {"from": previous, "to": mode}
    session.add(AuditLog(action="mode_switch", actor=actor, detail=detail))
    session.commit()
    return detail


def get_owned_assets(session) -> List[str]:
    row = session.query(AppSetting).filter_by(key=_OWNED_KEY).first()
    assets = (row.value or {}).get("assets") if row else None
    if not assets:
        return list(DEFAULT_OWNED_ASSETS)
    return [str(a).strip().lower() for a in assets if str(a).strip()]


def set_owned_assets(session, assets: List[str], actor: str = "ui") -> List[str]:
    clean = sorted({str(a).strip().lower().lstrip("*.") for a in assets
                    if str(a).strip()})
    row = session.query(AppSetting).filter_by(key=_OWNED_KEY).first()
    if row is None:
        row = AppSetting(key=_OWNED_KEY, value={})
        session.add(row)
    row.value = {"assets": clean}
    session.add(AuditLog(action="owned_assets_update", actor=actor,
                         detail={"assets": clean}))
    session.commit()
    return clean


def audit_tail(session, limit: int = 20) -> List[Dict]:
    rows = (session.query(AuditLog).order_by(AuditLog.id.desc())
            .limit(limit).all())
    return [{"id": r.id,
             "ts": r.ts.isoformat() if r.ts else None,
             "action": r.action, "actor": r.actor,
             "detail": r.detail or {}} for r in rows]


def host_of(target_type: str, normalized: str) -> Optional[str]:
    """Best-effort host extraction from a classified target."""
    n = (normalized or "").strip()
    if not n:
        return None
    if target_type == "ip":
        return n.split("/")[0]
    if target_type == "email":
        return n.rsplit("@", 1)[-1].lower() if "@" in n else None
    if target_type in ("domain", "asn"):
        return n.lower()
    if target_type == "url" or "://" in n:
        host = urlparse(n if "://" in n else f"https://{n}").hostname
        return host.lower() if host else None
    return None


def sandbox_host_allowed(host: Optional[str], owned: List[str]) -> Tuple[bool, str]:
    """Sandbox scope rule for one host. Returns (allowed, reason)."""
    if not host:
        return False, "target has no host (not an own/lab asset)"
    h = host.strip().lower().rstrip(".")
    if h == "localhost" or h.endswith(LAB_SUFFIXES):
        return True, "lab/local name"
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True, "private/loopback IP"
        return False, "public IP is not an owned asset"
    except ValueError:
        pass
    for asset in owned:
        a = asset.lower().rstrip(".")
        if h == a or h.endswith("." + a):
            return True, f"owned asset ({a})"
    return False, "not an owned asset or lab target"


def check_sandbox_targets(classified: List[Dict],
                          owned: List[str]) -> List[Dict]:
    """Validate classified targets for sandbox mode.

    Returns the list of REJECTED targets as {raw, reason} dicts (empty list
    = everything allowed). Username targets resolve accounts on third-party
    platforms, so they are never sandbox-legal; POI targets are locations,
    allowed only when they carry an owned/lab website.
    """
    rejected: List[Dict] = []
    for c in classified:
        t = c.get("type") or ""
        raw = c.get("raw", c.get("normalized", ""))
        if t == "username":
            rejected.append({"raw": raw,
                             "reason": "username lookups hit third-party "
                                       "platforms; not sandbox scope"})
            continue
        if t == "poi":
            site = (c.get("poi") or {}).get("website") or ""
            host = host_of("url", site) if site else None
            ok, reason = sandbox_host_allowed(host, owned)
            if not ok:
                rejected.append({"raw": raw,
                                 "reason": f"POI website: {reason}"})
            continue
        host = host_of(t, c.get("normalized", ""))
        if host is None and t not in ("domain", "url", "ip", "email", "asn"):
            # Non-network target types (play_store, npm_package, unknown,
            # ...): the classifier sometimes labels plain hostnames as app
            # packages ("victim.test" -> play_store). A target is sandbox
            # legal only when its normalized form IS a lab/owned hostname;
            # anything else (a real third-party app/package id) fails
            # closed.
            n = (c.get("normalized") or "").strip().lower()
            if n and all(ch.isalnum() or ch in ".-_" for ch in n) \
                    and ("." in n or n == "localhost"):
                ok, _ = sandbox_host_allowed(n, owned)
                if ok:
                    continue
            rejected.append({"raw": raw,
                             "reason": f"target type '{t}' is not sandbox "
                                       "scope (own assets + lab only)"})
            continue
        ok, reason = sandbox_host_allowed(host, owned)
        if not ok:
            rejected.append({"raw": raw, "reason": reason})
    return rejected
