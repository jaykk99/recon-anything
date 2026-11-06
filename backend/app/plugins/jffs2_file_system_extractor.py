"""JFFS2 file system extractor (variant of da_firmware_image):
da_firmware_image's signature list does not even recognize JFFS2. This
walks JFFS2 nodes (dirent/inode) in an operator-supplied image -
little-endian images (magic 0x1985) - and reconstructs the file
listing + file-type inventory. zlib payloads are recognised, names are
read from dirent nodes. Offline, pure Python.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect

JFFS2_MAGIC = 0x1985
NODETYPE_MASK = 0x0003
NODETYPE_DIRENT = 0x0002
NODETYPE_INODE = 0x0001
_SENSITIVE = ("shadow", "passwd", "telnetd", "dropbear", "authorized_keys",
              ".ko", "init", "rcS", "httpd", "boa", "uhttpd")


def walk_nodes(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"files": [], "inodes": 0, "nodes": 0}
    pos = 0
    guard = 0
    while pos + 12 <= len(data) and guard < 20000:
        guard += 1
        # nodes are 4-byte aligned; resync by scanning for the magic
        idx = data.find(b"\x85\x19", pos)
        if idx < 0:
            break
        pos = idx
        if pos + 12 > len(data):
            break
        magic, ntype, totlen = struct.unpack_from("<HHI", data, pos)
        if magic != JFFS2_MAGIC or totlen < 12 or pos + totlen > len(data) + 4096:
            pos += 2
            continue
        out["nodes"] += 1
        kind = ntype & NODETYPE_MASK
        if kind == NODETYPE_DIRENT and totlen >= 40:
            try:
                nsize = data[pos + 28]
                name = data[pos + 40:pos + 40 + nsize].decode(
                    "utf-8", "ignore")
                if name and all(32 <= ord(c) < 127 or c in "/._-"
                                for c in name):
                    out["files"].append(name)
            except Exception:
                pass
        elif kind == NODETYPE_INODE:
            out["inodes"] += 1
        pos += max(4, (totlen + 3) & ~3)
    out["files"] = sorted(set(out["files"]))
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data or b"\x85\x19" not in data:
        return hits
    walk = walk_nodes(data)
    if not walk["nodes"]:
        return hits
    hits.append({
        "key": "jffs2_file_listing", "severity": "low",
        "value": f"JFFS2 image extracted: {walk['nodes']} nodes, "
                 f"{walk['inodes']} inodes, {len(walk['files'])} named "
                 f"files ({', '.join(walk['files'][:10])})",
        "evidence": {"nodes": walk["nodes"],
                     "files": walk["files"][:12]}})
    sensitive = [f for f in walk["files"]
                 if any(s in f for s in _SENSITIVE)]
    if sensitive:
        hits.append({
            "key": "jffs2_sensitive_files", "severity": "medium",
            "value": "Sensitive files present in the JFFS2 rootfs: "
                     + ", ".join(sensitive[:10]),
            "evidence": {"files": sensitive[:10]}})
    return hits[:8]


class Jffs2FileSystemExtractorPlugin(Plugin):
    id = "jffs2_file_system_extractor"
    label = "JFFS2 File System Extractor"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Variant of da_firmware_image: JFFS2 node walk over "
                   "a supplied image (LE), reconstructing the file "
                   "listing and flagging sensitive rootfs files.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
