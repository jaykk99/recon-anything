"""SquashFS image mounter (variant of da_firmware_image): da_firmware_image
recognizes the 'hsqs' magic and stops. This actually opens an operator-
supplied SquashFS image with a pure-Python reader: parses the 4.0
superblock and decompresses metadata blocks (gzip/xz/lzma via stdlib)
to inventory the rootfs tree - binaries, init scripts, config paths.
Offline, keyless.
"""
from __future__ import annotations

import lzma
import struct
import zlib
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect, extract_strings

_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
_SENSITIVE = ("shadow", "passwd", "telnetd", "dropbear", "sshd_config",
              "authorized_keys", "uhttpd", "boa.conf", "httpd.conf",
              "wpa_supplicant", "hostapd", "init.d", "rcS", "inittab")


def parse_superblock(data: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {"ok": False}
    try:
        if len(data) < 96 or data[:4] not in (b"hsqs", b"sqsh"):
            return info
        en = "<" if data[:4] == b"hsqs" else ">"
        (_magic, inodes, _mkfs, block_size, fragments, comp, _blog,
         _flags, _ids, _maj, _min, _rootref, bytes_used, _idt, _xattr,
         inode_start, dir_start, _frag_start,
         _exp) = struct.unpack_from(en + "IIIIIHHHHHHQQQQQQQQ", data, 0)
        info.update(ok=True, inodes=inodes, block_size=block_size,
                    fragments=fragments, compression=_COMP.get(comp, comp),
                    bytes_used=bytes_used, inode_start=inode_start,
                    dir_start=dir_start, comp_id=comp)
    except Exception:
        pass
    return info


def _decompress_block(raw: bytes, comp_id: int) -> bytes:
    try:
        if comp_id == 1:
            return zlib.decompress(raw, -15)
        if comp_id == 4:
            return lzma.decompress(raw, format=lzma.FORMAT_ALONE) \
                if raw else b""
        if comp_id == 2:
            return lzma.decompress(raw, format=lzma.FORMAT_ALONE)
    except Exception:
        return b""
    return b""


def metadata_strings(data: bytes, sb: Dict[str, Any]) -> List[str]:
    """Decompress metadata blocks between the inode/dir tables and
    bytes_used; pull printable strings (directory entry names live
    there as plain bytes)."""
    out: List[str] = []
    try:
        pos = min(sb.get("inode_start", 96), sb.get("dir_start", 96))
        end = min(sb.get("bytes_used", len(data)), len(data))
        guard = 0
        while pos + 2 <= end and guard < 512:
            guard += 1
            (mlen,) = struct.unpack_from("<H", data, pos)
            pos += 2
            size = mlen & 0x7FFF
            if size == 0 or pos + size > len(data):
                break
            raw = data[pos:pos + size]
            pos += size
            blob = raw if (mlen & 0x8000) else _decompress_block(
                raw, sb.get("comp_id", 1))
            for _off, s in extract_strings(blob, 3):
                if "/" not in s and len(s) <= 64:
                    out.append(s)
    except Exception:
        pass
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    sb = parse_superblock(data)
    if not sb.get("ok"):
        return hits
    hits.append({
        "key": "squashfs_rootfs_opened", "severity": "low",
        "value": f"SquashFS rootfs opened: {sb['inodes']} inodes, "
                 f"{sb['fragments']} fragments, compression "
                 f"{sb['compression']}, image {sb['bytes_used']} bytes",
        "evidence": {"inodes": sb["inodes"],
                     "compression": str(sb["compression"])}})
    names = metadata_strings(data, sb)
    sensitive = sorted({n for n in names
                        if any(s in n for s in _SENSITIVE)})
    if sensitive:
        hits.append({
            "key": "squashfs_sensitive_files", "severity": "medium",
            "value": "Sensitive rootfs entries extracted from SquashFS "
                     "metadata: " + ", ".join(sensitive[:12]),
            "evidence": {"files": sensitive[:12]}})
    binish = sorted({n for n in names if n.endswith(
        (".sh", ".ko", ".cgi")) or n in ("busybox", "init")})
    if binish:
        hits.append({
            "key": "squashfs_rootfs_inventory", "severity": "low",
            "value": "Rootfs executables/scripts inventoried: "
                     + ", ".join(binish[:12]),
            "evidence": {"files": binish[:12]}})
    return hits[:8]


class SquashfsImageMounterPlugin(Plugin):
    id = "squashfs_image_mounter"
    label = "SquashFS Image Mounter"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of da_firmware_image: actually opens a "
                   "supplied SquashFS image (pure-Python metadata "
                   "decompression) and inventories the rootfs tree.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
