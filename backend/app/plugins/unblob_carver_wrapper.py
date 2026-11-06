"""Unblob-carver-wrapper: keyless native carver over an operator-supplied
firmware image. Magic-signature scan for nested filesystems/archives plus
an entropy map. No external unblob dependency; offline only.
da_firmware_image verifies only the outer format from a 4 KB head window
and never carves - this is the carving delta.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, find_all, window_entropies

MAGICS = [
    (b"hsqs", "SquashFS"), (b"sqsh", "SquashFS (BE)"),
    (b"\x55\x42\x49\x23", "UBI"), (b"\x85\x19", "JFFS2"),
    (b"PK\x03\x04", "ZIP"), (b"\xd0\x0d\xfe\xed", "FDT/DTB"),
    (b"\x27\x05\x19\x56", "uImage"), (b"\xfd7zXZ\x00", "XZ"),
    (b"\x1f\x8b\x08", "gzip"), (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"\x7fELF", "ELF"), (b"ustar", "tar"),
]


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data or len(data) < 64:
        return hits
    seen = set()
    for magic, label in MAGICS:
        for off in find_all(data, magic, limit=8):
            if off == 0:
                continue  # outer container itself, not a nested carve
            if (label, off) in seen:
                continue
            seen.add((label, off))
            hits.append({
                "key": "unblob_nested_filesystem", "severity": "low",
                "value": f"Nested {label} signature carved at offset "
                         f"{off:#x} inside supplied firmware image",
                "evidence": {"offset": off, "kind": label}})
            break
    for off, ent in window_entropies(data, 1024, 512):
        if ent >= 7.6:
            hits.append({
                "key": "unblob_high_entropy_region", "severity": "medium",
                "value": f"High-entropy region at offset {off:#x} "
                         f"(entropy {ent:.2f}) - encrypted/compressed "
                         "payload not accounted for by any signature",
                "evidence": {"offset": off, "entropy": round(ent, 3)}})
            break
    return hits[:12]


class UnblobCarverWrapperPlugin(Plugin):
    id = "unblob_carver_wrapper"
    label = "Unblob Carver (native)"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Keyless native carver: nested filesystem/archive "
                   "signatures + entropy map of a supplied firmware image.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
