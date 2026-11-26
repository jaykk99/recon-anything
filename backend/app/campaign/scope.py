"""Campaign scope: who may be touched, how, and under which approval.

ARTEX-style autonomy without a scope file is just an out-of-control
scanner. This module is the scope file:

* a campaign only ever touches hosts under its declared roots (exact,
  ``*.example.com`` wildcard, or ``*`` globs); anything else is blocked
  before a request is built, not after,
* every intent is classified (recon, probe, impact, auth replay) and the
  stricter classes are off unless the operator enabled them,
* the never-target list is enforced here as well as in the agent
  allowlist: it is a hard floor, not a default.

Nothing in this module performs I/O.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

# Mirrors app.agent.allowlist.NEVER_TARGETS (kept local so the campaign
# core imports nothing but stdlib and cannot fail on a missing data dir).
NEVER_TARGETS = {"crypto.com"}

# Intents that may touch the target. ``verify`` is included because one
# of its actions (bucket-list) sends a GET; the offline token check is
# harmless behind the same switch.
ACTIVE_KINDS = {"recon", "probe", "impact", "verify"}
# Intents that read an exposed console / enumerate what it exposes. These
# need both allow_active and the explicit data-enumeration opt-in.
IMPACT_KINDS = {"impact"}
# Actions that replay an identity (a forged JWT, a captured cookie).
AUTH_REPLAY_ACTIONS = {"auth-replay"}


def host_of(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        try:
            return (urlparse(t).hostname or "").lower()
        except ValueError:
            return ""
    return t.split("/")[0].split(":")[0].lower().strip("[]")


def _pattern_matches(pattern: str, host: str) -> bool:
    p = (pattern or "").strip().lower()
    if not p:
        return False
    if "://" in p:
        p = host_of(p)
    p = p.rstrip(".")
    if p == host:
        return True
    if p.startswith("*."):
        base = p[2:]
        return host == base or host.endswith("." + base)
    if "*" in p:
        return fnmatch.fnmatch(host, p)
    # A declared root authorizes its own subtree: example.com covers
    # api.example.com, which is how every scan scope is written.
    return host.endswith("." + p)


@dataclass
class Scope:
    """The declared authorized surface for one campaign."""
    roots: Tuple[str, ...] = ()
    exclude: Tuple[str, ...] = ()
    allow_active: bool = False
    allow_exploit_confirm: bool = False
    allow_auth_replay: bool = False
    max_requests: int = 80
    max_intents: int = 30
    max_rounds: int = 4
    max_seconds: float = 90.0
    per_host_rps: float = 1.0

    def __post_init__(self) -> None:
        self.roots = tuple(dict.fromkeys(
            r.strip() for r in self.roots if r and r.strip()))
        self.exclude = tuple(dict.fromkeys(
            r.strip() for r in self.exclude if r and r.strip()))

    # -- target authorization -------------------------------------------
    def allows(self, target: str) -> Tuple[bool, str]:
        host = host_of(target)
        if not host:
            return False, "target has no host"
        if host in NEVER_TARGETS or host.endswith(".crypto.com"):
            return False, "crypto.com is never a campaign target"
        for pattern in self.exclude:
            if _pattern_matches(pattern, host):
                return False, f"{host} is explicitly excluded by scope"
        if not self.roots:
            return False, "campaign has no authorized roots"
        for pattern in self.roots:
            if _pattern_matches(pattern, host):
                return True, f"in scope ({pattern})"
        return False, (f"{host} is outside the campaign scope; "
                       "add its root to the campaign to authorize it")

    # -- intent authorization -------------------------------------------
    def allows_intent(self, intent) -> Tuple[bool, str]:
        ok, reason = self.allows(intent.target)
        if not ok:
            return False, reason
        if intent.kind in IMPACT_KINDS:
            if not self.allow_active:
                return False, "impact enumeration needs active mode"
            if not self.allow_exploit_confirm:
                return False, ("impact enumeration needs "
                               "allow_exploit_confirm=true")
        elif intent.kind in ACTIVE_KINDS and not self.allow_active:
            return False, "active probing is disabled for this campaign"
        if intent.action in AUTH_REPLAY_ACTIONS \
                and not self.allow_auth_replay:
            return False, "credential/token replay is disabled for this campaign"
        return True, "in scope"

    def needs_approval(self, intent) -> bool:
        """Impact enumeration always needs a human yes, even when the
        operator enabled the capability for the campaign."""
        return bool(intent.requires_approval) or intent.kind in IMPACT_KINDS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "roots": list(self.roots),
            "exclude": list(self.exclude),
            "allow_active": self.allow_active,
            "allow_exploit_confirm": self.allow_exploit_confirm,
            "allow_auth_replay": self.allow_auth_replay,
            "max_requests": self.max_requests,
            "max_intents": self.max_intents,
            "max_rounds": self.max_rounds,
            "max_seconds": self.max_seconds,
            "per_host_rps": self.per_host_rps,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Scope":
        return cls(
            roots=tuple(d.get("roots") or ()),
            exclude=tuple(d.get("exclude") or ()),
            allow_active=bool(d.get("allow_active")),
            allow_exploit_confirm=bool(d.get("allow_exploit_confirm")),
            allow_auth_replay=bool(d.get("allow_auth_replay")),
            max_requests=int(d.get("max_requests") or 80),
            max_intents=int(d.get("max_intents") or 30),
            max_rounds=int(d.get("max_rounds") or 4),
            max_seconds=float(d.get("max_seconds") or 90),
            per_host_rps=float(d.get("per_host_rps") or 1.0),
        )
