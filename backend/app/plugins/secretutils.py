"""Shared helpers for secret/exposure finding plugins.

Redaction: findings never carry a full secret in `value`. The full match
goes into evidence["match"] so the owner can verify and rotate it, and
`value` carries a redacted form plus severity tag.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple


def redact(secret: str, show: int = 4) -> str:
    s = (secret or "").strip()
    if len(s) <= show:
        return "***"
    if len(s) <= show * 2 + 3:
        return s[:show] + "..." + s[-show:]
    return s[:show] + "..." + s[-show:]


REMEDIATION: Dict[str, str] = {
    "api_key": "Rotate this key immediately in the provider dashboard, then remove it from client-side code. Move it server-side behind your own API.",
    "wallet_key": "Funds are at risk. Sweep funds to a new wallet generated offline, then treat this key as burned. Never commit keys to repos.",
    "credential": "Force-rotate this credential now, audit access logs for misuse, and move secrets to a vault or env config that is never served.",
    "default_cred": "Change this default credential immediately. Defaults are the first thing attackers try.",
}

SEVERITY_TAG = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
}


def finding_value(severity: str, kind_label: str, redacted: str,
                  where: str) -> str:
    tag = SEVERITY_TAG.get(severity, severity.upper())
    return f"{tag}: {kind_label} {redacted} ({where})"


def evidence_block(match: str, pattern_name: str, remediation_key: str,
                   severity: str, extra: Optional[Dict] = None) -> Dict:
    ev: Dict = {
        "severity": severity,
        "match": match,
        "pattern": pattern_name,
        "redacted": True,
        "remediation": REMEDIATION.get(remediation_key, ""),
        "scope_note": "Authorized testing only: verify you own this asset or it is in an approved bounty scope before acting on this finding.",
    }
    if extra:
        ev.update(extra)
    return ev


# Words that mean "this is just an example / placeholder", used to cut noise.
PLACEHOLDERS = {
    "example", "sample", "test", "testing", "demo", "placeholder", "changeme",
    "xxx", "xxxx", "todo", "yourkey", "your_key", "mykey", "fakekey",
    "123456", "password", "abcdef", "null", "none", "undefined",
}


def is_placeholder(s: str) -> bool:
    low = (s or "").strip().lower().strip("\"' ")
    return low in PLACEHOLDERS or "example" in low or "sample" in low
