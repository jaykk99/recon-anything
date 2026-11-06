"""Secure boot key status check: review launch-path signature
parameters in an operator-supplied firmware/bootloader image set -
U-Boot FIT image signatures + required-key markers, UEFI Secure Boot
variable presence (PK/KEK/db) in firmware volumes, bootloader
verified-boot flags - and flag unsigned images, dev/test keys, or
verification disabled. Offline parsing, keyless.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, strings_only, text_of

_TEST_KEYS = ("dev-key", "dev_key", "test-key", "test_key", "snakeoil",
              "demo-key", "example-key", "insecure-key")
_DISABLED = [
    (re.compile(r"CONFIG_(FIT_)?SIGNATURE is not set|"
                r"CONFIG_SECURE_BOOT\s*[:=]\s*(n|0|off|disabled)", re.I),
     "Verified-boot/signature support compiled OUT of the bootloader"),
    (re.compile(r"\bverified[_\- ]?boot\s*[:=]\s*(off|disabled|0|no)",
                re.I),
     "Verified boot explicitly disabled in bootloader config"),
    (re.compile(r"\bsecure[_\- ]?boot\s*[:=]\s*(off|disabled|0|no)",
                re.I),
     "Secure boot explicitly disabled in boot configuration"),
    (re.compile(r"avb[_\- ]?(hashtree|verify)[^\n]{0,24}"
                r"(disabled|off)", re.I),
     "Android VBMeta verification disabled in the boot chain"),
]


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = text_of(data)
    strs = strings_only(data, 4)
    joined = "\n".join(strs)
    is_fit = data[:4] == b"\xd0\x0d\xfe\xed" and (
        "images" in joined or "configurations" in joined
        or "signature" in joined)
    if is_fit:
        has_sig = "signature" in joined
        has_required = "required" in joined
        if not has_sig:
            hits.append({
                "key": "fit_image_unsigned", "severity": "high",
                "value": "U-Boot FIT image carries NO signature node "
                         "- the boot chain accepts it unsigned",
                "evidence": {"format": "fit"}})
        elif not has_required:
            hits.append({
                "key": "fit_signature_not_required", "severity":
                "medium",
                "value": "FIT image has signatures but no "
                         "'required' key marker - verification is "
                         "optional in the control DTB",
                "evidence": {"format": "fit"}})
    for s in strs:
        ls = s.lower()
        if any(k in ls for k in _TEST_KEYS):
            hits.append({
                "key": "secure_boot_test_key", "severity": "high",
                "value": f"Dev/test signing key material referenced "
                         f"in the boot chain: '{s[:48]}' - test keys "
                         "must never ship in production firmware",
                "evidence": {"marker": s[:48]}})
            break
    seen = set()
    for rx, label in _DISABLED:
        if rx.search(text) and label not in seen:
            seen.add(label)
            hits.append({
                "key": "secure_boot_verification_disabled",
                "severity": "high", "value": label,
                "evidence": {"detection": "config-string"}})
    uefi = [v for v in ("PK", "KEK", "db", "dbx")
            if re.search(rf"\b{v}\b", joined)]
    if "SecureBoot" in joined and len(uefi) < 3:
        hits.append({
            "key": "uefi_sb_vars_incomplete", "severity": "medium",
            "value": "Firmware volume references SecureBoot but the "
                     "PK/KEK/db variable set is incomplete in the "
                     f"image (found: {', '.join(uefi) or 'none'})",
            "evidence": {"variables": uefi}})
    return hits[:10]


class SecureBootKeyStatusCheckPlugin(Plugin):
    id = "secure_boot_key_status_check"
    label = "Secure Boot Key Status Check"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Launch-path trust audit of supplied firmware: "
                   "FIT signatures/required markers, UEFI PK/KEK/db "
                   "presence, dev/test keys and verification-disabled "
                   "flags.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
