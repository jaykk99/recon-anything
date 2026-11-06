"""Firmware password/shadow posture (variant of credential_strength):
locates /etc/passwd and /etc/shadow content inside an operator-supplied
firmware artifact and reports STORAGE POSTURE per account - empty
password, locked, legacy DES/MD5 vs modern hashes, known vendor-default
account names. Hashes are masked + fingerprinted only.

ADAPTATION: posture DETECTION only. NO password cracking, NO dictionary
attempts of any kind are performed.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, fingerprint

# user:hash:lastchg:min:max:warn:inactive:expire (7+ colon fields)
_SHADOW_RE = re.compile(
    r"(?m)^([A-Za-z_][\w.-]{0,31}):([^:\n]{0,200}):(\d{0,6}):(\d{0,5}):"
    r"(\d{0,6}):")
_DEFAULT_ACCOUNTS = {"root", "admin", "administrator", "user", "support",
                     "ubnt", "cisco", "default", "service", "tech"}


def hash_posture(h: str) -> str:
    if h == "":
        return "empty"
    if h in ("!", "*", "x", "!!"):
        return "locked"
    if h.startswith("$1$"):
        return "md5crypt"
    if h.startswith("$5$"):
        return "sha256crypt"
    if h.startswith("$6$"):
        return "sha512crypt"
    if h.startswith(("$2a$", "$2b$", "$2y$", "$7$")):
        return "modern"
    if len(h) == 13 and "$" not in h:
        return "des"
    return "other"


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = data.decode("utf-8", "ignore")
    seen = set()
    for m in _SHADOW_RE.finditer(text):
        user, h = m.group(1), m.group(2)
        if (user, h) in seen:
            continue
        seen.add((user, h))
        posture = hash_posture(h)
        fp = fingerprint(h) if h else ""
        if posture == "empty":
            hits.append({
                "key": "fw_shadow_empty_password", "severity": "high",
                "value": f"Firmware shadow: account '{user}' has an "
                         "EMPTY password",
                "evidence": {"account": user, "posture": posture}})
        elif posture == "des":
            hits.append({
                "key": "fw_shadow_legacy_des", "severity": "high",
                "value": f"Firmware shadow: account '{user}' uses a "
                         "legacy DES password hash (masked, fp "
                         f"{fp}) - posture only, no cracking performed",
                "evidence": {"account": user, "posture": posture,
                             "fingerprint": fp}})
        elif posture == "md5crypt":
            hits.append({
                "key": "fw_shadow_weak_md5", "severity": "medium",
                "value": f"Firmware shadow: account '{user}' uses a "
                         f"weak MD5-crypt hash (masked, fp {fp}) - "
                         "posture only, no cracking performed",
                "evidence": {"account": user, "posture": posture,
                             "fingerprint": fp}})
        if user.lower() in _DEFAULT_ACCOUNTS and posture not in (
                "locked", "empty"):
            hits.append({
                "key": "fw_shadow_default_account", "severity": "medium",
                "value": f"Firmware shadow: vendor-default account "
                         f"'{user}' is enabled with a password set "
                         f"(masked, fp {fp})",
                "evidence": {"account": user, "posture": posture,
                             "fingerprint": fp}})
    return hits[:12]


class FirmwarePasswordShadowCrackPlugin(Plugin):
    id = "firmware_password_shadow_crack"
    label = "Firmware Shadow Posture"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of credential_strength: /etc/shadow storage "
                   "posture inside supplied firmware (empty/legacy/weak "
                   "hash formats, default accounts). Posture only - no "
                   "cracking or dictionary attempts; hashes masked.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
