"""NVRAM parameter dumper: parse key=value stores in OPERATOR-SUPPLIED
artifacts only - an extracted firmware rootfs or a raw NVRAM partition
file the operator provides. Flags factory credentials, Wi-Fi PSKs and
maintenance parameters; values are masked + fingerprinted, never
reported in full. Never reads a live device's NVRAM. Offline, keyless.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, mask_secret

_PAIR_RE = re.compile(
    r"(?m)([A-Za-z0-9_.-]{2,48})\s*=\s*([^\s\x00\"']{2,80})")
_SENSITIVE = ("pass", "passwd", "password", "psk", "wpa", "secret",
              "token", "pin", "credential", "auth_key", "wep")
_FACTORY = ("admin", "password", "1234", "12345", "123456", "default",
            "changeme", "root", "ubnt", "cisco")


def parse_store(data: bytes) -> Dict[str, str]:
    text = data.decode("utf-8", "ignore")
    out: Dict[str, str] = {}
    for m in _PAIR_RE.finditer(text):
        key = m.group(1)
        if key not in out:
            out[key] = m.group(2)
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    store = parse_store(data)
    if len(store) < 2:
        return hits
    for key, val in store.items():
        lk = key.lower()
        if any(s in lk for s in _SENSITIVE) and val:
            masked, fp = mask_secret(val)
            is_factory = val.lower() in _FACTORY
            hits.append({
                "key": "nvram_factory_credential" if is_factory
                else "nvram_sensitive_parameter",
                "severity": "high" if is_factory else "medium",
                "value": f"NVRAM parameter {key} holds "
                         f"{'a factory-default credential value' if is_factory else 'a sensitive value'} "
                         f"(masked {masked}, fp {fp}) in the supplied "
                         "artifact",
                "evidence": {"parameter": key, "fingerprint": fp}})
    if any(k.lower() in ("wl0_ssid", "wl_ssid", "ssid") for k in store) \
            and not any("psk" in k.lower() or "wpa" in k.lower()
                        for k in store):
        hits.append({
            "key": "nvram_open_wifi", "severity": "medium",
            "value": "NVRAM defines a Wi-Fi SSID with no PSK/WPA "
                     "parameter - open wireless network posture",
            "evidence": {"parameter": "ssid"}})
    return hits[:12]


class NvramParameterDumperPlugin(Plugin):
    id = "nvram_parameter_dumper"
    label = "NVRAM Parameter Dumper"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Parses key=value NVRAM stores in supplied artifacts "
                   "only; flags factory credentials and Wi-Fi PSKs "
                   "(masked + fingerprinted). Never touches a live "
                   "device.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
