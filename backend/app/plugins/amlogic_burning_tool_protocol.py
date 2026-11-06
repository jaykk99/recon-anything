"""Amlogic Burning Tool protocol - offline adaptation: parse an
operator-supplied Amlogic firmware package manifest (image.cfg,
partition list, DDR/USB boot files) and/or a supplied Burning Tool
capture/log; flag secure-boot-disabled package posture and exposed
download-mode configuration. No emulation against, or reading of
protected boot space from, any device. Offline, keyless.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, text_of


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    text = text_of(data)
    low = text.lower()
    is_aml = ("image.cfg" in low or "aml" in low or "burning" in low
              or "[list_" in low or "meson" in low
              or "u-boot.bin" in low)
    if not is_aml:
        return hits
    if re.search(r"secure[_\- ]?boot\s*[:=]\s*(0|disable|off|no)", low):
        hits.append({
            "key": "aml_secure_boot_disabled", "severity": "high",
            "value": "Amlogic package is configured with secure boot "
                     "DISABLED - unsigned boot chain accepted in "
                     "download mode",
            "evidence": {"detection": "image.cfg"}})
    if "[list_normal]" in low and "[list_verify]" not in low \
            and "[list_secure]" not in low:
        hits.append({
            "key": "aml_unverified_package_list", "severity": "medium",
            "value": "Amlogic image.cfg uses the plain [LIST_NORMAL] "
                     "partition set with no verify/secure list - "
                     "package contents are not signature-checked",
            "evidence": {"detection": "image.cfg"}})
    for fname in ("u-boot.bin.usb.bl2", "u-boot.bin.sd.bin",
                  "ddr.bin", "usb_boot.bin"):
        if fname in low:
            hits.append({
                "key": "aml_download_mode_files", "severity": "low",
                "value": f"Download-mode boot file shipped in the "
                         f"package: {fname} (USB burning path "
                         "material)",
                "evidence": {"file": fname}})
            break
    parts = re.findall(r"(?m)^\s*(system|vendor|boot|recovery|dtb|"
                       r"vbmeta|bootloader)\s*[:=]", low)
    if parts:
        hits.append({
            "key": "aml_partition_inventory", "severity": "low",
            "value": "Amlogic package partition list: "
                     + ", ".join(sorted(set(parts))[:10]),
            "evidence": {"partitions": sorted(set(parts))[:10]}})
    if len(hits) == 1 and hits[0]["key"] == "aml_partition_inventory":
        return []
    return hits[:10]


class AmlogicBurningToolProtocolPlugin(Plugin):
    id = "amlogic_burning_tool_protocol"
    label = "Amlogic Burning Tool Protocol (offline)"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Offline analysis of supplied Amlogic packages/"
                   "captures: image.cfg posture, secure-boot-disabled "
                   "and unverified partition lists flagged.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
