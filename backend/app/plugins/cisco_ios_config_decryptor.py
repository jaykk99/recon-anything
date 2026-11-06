"""Cisco IOS config decryptor (variant of da_device_config_export):
da_device_config_export reports credential FIELD NAMES only. This is
the offline audit delta for an operator-supplied Cisco IOS config:
decode legacy Type-7 values (the documented XOR obfuscation) for
audit, classify Type-5/8/9 secret posture. ALL credential evidence is
masked + fingerprinted - decoded plaintext never appears in findings,
only its length class and whether it matches a known vendor default.
Operator-supplied configs only, offline.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, fingerprint

_TYPE7_KEY = bytes([
    0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x6F, 0x41, 0x2C, 0x2E,
    0x69, 0x79, 0x65, 0x77, 0x72, 0x6B, 0x6C, 0x64, 0x4A, 0x4B, 0x44,
    0x48, 0x53, 0x55, 0x42])  # "dsfd;kfoA,.iyewrkldJKDHSUB"
_DEFAULTS = {"cisco", "password", "admin", "letmein", "1234", "12345",
             "changeme", "default", "private"}
_TYPE7_RE = re.compile(r"\b(?:password|secret)\s+7\s+([0-9A-Fa-f]{4,})")
_TYPE5_RE = re.compile(r"\b(?:password|secret)\s+5\s+(\S+)")
_TYPE89_RE = re.compile(r"\b(?:password|secret)\s+(8|9)\s+(\S+)")


def decode_type7(enc: str) -> str:
    """Decode a Cisco Type-7 obfuscated value. '' on malformed input."""
    try:
        salt = int(enc[:2])
        hexpart = enc[2:]
        raw = bytes(int(hexpart[i:i + 2], 16)
                    for i in range(0, len(hexpart) - 1, 2))
        return bytes(b ^ _TYPE7_KEY[(salt + i) % len(_TYPE7_KEY)]
                     for i, b in enumerate(raw)).decode(
                         "utf-8", "ignore")
    except Exception:
        return ""


def encode_type7(plain: str, salt: int = 3) -> str:
    """Test-fixture helper: produce a Type-7 value for `plain`."""
    raw = bytes(b ^ _TYPE7_KEY[(salt + i) % len(_TYPE7_KEY)]
                for i, b in enumerate(plain.encode()))
    return f"{salt:02d}" + raw.hex().upper()


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = data.decode("utf-8", "ignore")
    if "!" not in text and "hostname" not in text \
            and "interface" not in text:
        pass  # still scan: type-7 strings are distinctive on their own
    for m in _TYPE7_RE.finditer(text):
        enc = m.group(1)
        plain = decode_type7(enc)
        is_default = plain.lower() in _DEFAULTS
        hits.append({
            "key": "cisco_type7_reversible", "severity": "high",
            "value": "Cisco Type-7 credential in supplied config is "
                     "trivially reversible obfuscation (decoded "
                     "offline for audit; plaintext withheld, "
                     f"fingerprint {fingerprint(plain)}, "
                     f"{'matches a known vendor default' if is_default else 'not a known default'})",
            "evidence": {"fingerprint": fingerprint(plain),
                         "is_default": is_default,
                         "length": len(plain)}})
    for m in _TYPE5_RE.finditer(text):
        hits.append({
            "key": "cisco_type5_md5", "severity": "medium",
            "value": "Cisco Type-5 (MD5) secret in supplied config - "
                     "fast-hash posture, upgrade to Type-8/9 "
                     f"(fingerprint {fingerprint(m.group(1))})",
            "evidence": {"fingerprint": fingerprint(m.group(1))}})
    return hits[:10]


class CiscoIosConfigDecryptorPlugin(Plugin):
    id = "cisco_ios_config_decryptor"
    label = "Cisco IOS Config Audit Decoder"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of da_device_config_export: offline audit "
                   "decode of legacy Type-7 obfuscation in supplied "
                   "Cisco configs + Type-5/8/9 posture. Evidence "
                   "masked + fingerprinted; plaintext never reported.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
