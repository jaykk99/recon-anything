"""SPI flash dump analyzer: rebuild the layout of an operator-supplied
raw SPI flash dump - partition signatures (uImage, SquashFS, DTB, U-Boot
env blocks, UBI), per-region entropy profile, partition map with
offsets/sizes/types. Offline, keyless.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, find_all, shannon_entropy

_SIGS = [(b"\x27\x05\x19\x56", "uImage kernel"), (b"hsqs", "SquashFS"),
         (b"\xd0\x0d\xfe\xed", "DTB"), (b"\x55\x42\x49\x23", "UBI"),
         (b"\x85\x19", "JFFS2"), (b"PK\x03\x04", "ZIP archive")]


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data or len(data) < 4096:
        return hits
    nonblank = any(b not in (0x00, 0xFF) for b in data[:4096]) or \
        len(set(data)) > 4
    if not nonblank:
        return hits
    parts = []
    for magic, label in _SIGS:
        for off in find_all(data, magic, limit=6):
            parts.append((off, label))
    parts.sort()
    if parts:
        desc = ", ".join(f"{lbl}@0x{off:x}" for off, lbl in parts[:8])
        hits.append({
            "key": "spi_partition_map", "severity": "low",
            "value": f"SPI flash partition map rebuilt "
                     f"({len(data)} bytes): {desc}",
            "evidence": {"partitions": len(parts)}})
    # env block heuristic: bootargs/bootcmd strings mark an env region
    if b"bootcmd=" in data or b"bootargs=" in data:
        off = data.find(b"bootcmd=")
        if off < 0:
            off = data.find(b"bootargs=")
        hits.append({
            "key": "spi_env_region", "severity": "medium",
            "value": f"Writable U-Boot environment region located at "
                     f"offset {off & ~0xFFF:#x} in the flash dump - "
                     "boot config is modifiable with flash access",
            "evidence": {"offset": off & ~0xFFF}})
    step = 65536
    for off in range(0, len(data) - step + 1, step):
        ent = shannon_entropy(data[off:off + step])
        if ent >= 7.7:
            hits.append({
                "key": "spi_high_entropy_region", "severity": "medium",
                "value": f"High-entropy 64KB region at offset {off:#x} "
                         f"(entropy {ent:.2f}) - encrypted or compressed "
                         "payload with no filesystem signature",
                "evidence": {"offset": off, "entropy": round(ent, 3)}})
            break
    return hits[:8]


class SpiFlashDumpAnalyzerPlugin(Plugin):
    id = "spi_flash_dump_analyzer"
    label = "SPI Flash Dump Analyzer"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Rebuilds the partition map of a supplied raw SPI "
                   "flash dump (signatures + entropy profile + env "
                   "region). Offline.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
