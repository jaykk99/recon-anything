"""Firmware signature-override finder (variant of da_ota_manifest):
da_ota_manifest parses OTA manifests for versions + URLs and never
examines signature posture. This audits the update path: signature-
required flags, signing keys/certs embedded in the update path,
unsigned-image acceptance indicators and downgrade/rollback fields,
over the manifest + a supplied update package header. Key material is
masked + fingerprinted only.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, fingerprint

_BOOLISH = re.compile(
    r'"?(signature_required|verify_signature|require_signature|'
    r'signed|allow_downgrade|allow_rollback|anti_rollback|'
    r'rollback_protection)"?\s*[:=]\s*"?(true|false|yes|no|1|0)"?',
    re.I)


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = data.decode("utf-8", "ignore")
    parsed: Dict[str, Any] = {}
    try:
        parsed = json.loads(text[text.index("{"):text.rindex("}") + 1])
    except Exception:
        parsed = {}
    flat: Dict[str, Any] = {}

    def _walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                flat[(prefix + k).lower()] = v
                _walk(v, prefix + k + ".")
    _walk(parsed)

    def _flag(key_names, want_truthy):
        for k, v in flat.items():
            if any(n in k for n in key_names):
                if isinstance(v, bool):
                    return v
                if isinstance(v, str):
                    return v.lower() in ("true", "yes", "1", "on")
                if isinstance(v, (int, float)):
                    return bool(v)
        return None

    sig_req = _flag(["signature_required", "verify_signature",
                     "require_signature"], True)
    if sig_req is False:
        hits.append({
            "key": "fw_update_signature_not_required", "severity": "high",
            "value": "OTA/update manifest explicitly disables the "
                     "update signature requirement - unsigned images "
                     "are accepted",
            "evidence": {"field": "signature_required=false"}})
    elif sig_req is None and (parsed or "version" in text.lower()):
        if not re.search(r'"signature"\s*:\s*"[^"]{16,}"', text) and \
                "-----BEGIN" not in text:
            hits.append({
                "key": "fw_update_no_signature_field", "severity":
                "medium",
                "value": "Update manifest carries no signature field "
                         "and no signature-required flag - update "
                         "authenticity is not evidenced",
                "evidence": {"field": "signature absent"}})
    downgrade = _flag(["allow_downgrade"], True)
    rollback_off = _flag(["anti_rollback", "rollback_protection"], True)
    if downgrade is True or rollback_off is False:
        hits.append({
            "key": "fw_update_downgrade_allowed", "severity": "medium",
            "value": "Update path allows downgrade / has rollback "
                     "protection off - old vulnerable firmware can be "
                     "reinstalled",
            "evidence": {"field": "allow_downgrade/anti_rollback"}})
    m = re.search(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", text)
    if m:
        hits.append({
            "key": "fw_update_signing_key_embedded", "severity": "high",
            "value": "A PRIVATE signing key is embedded in the update "
                     f"path material (masked, fp "
                     f"{fingerprint(text[m.start():m.start() + 200])}) "
                     "- anyone with the package can sign updates",
            "evidence": {"fingerprint": fingerprint(
                text[m.start():m.start() + 200])}})
    for km in _BOOLISH.finditer(text):
        if km.group(1).lower() in ("signed",) and \
                km.group(2).lower() in ("false", "no", "0"):
            hits.append({
                "key": "fw_update_marked_unsigned", "severity": "high",
                "value": "Update material is explicitly marked "
                         "signed=false",
                "evidence": {"field": "signed=false"}})
            break
    return hits[:10]


class FirmwareSigOverrideFinderPlugin(Plugin):
    id = "firmware_sig_override_finder"
    label = "Firmware Signature Override Finder"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of da_ota_manifest: update-signature audit "
                   "of supplied OTA manifests/packages - signature not "
                   "required, downgrade allowed, signing keys embedded "
                   "(masked).")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
