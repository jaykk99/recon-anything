"""Native library (.so) deep pass (Cat-7 #196, VARIANT of binex).

binex inventories .so names/arches only; contents are never opened.
Delta: per-.so pass - ELF header/exports (JNI_OnLoad, Java_*
symbols), strings (URLs, key-shaped material), and hardening flags
(NX / PIE / RELRO) per library. Pure-python ELF parsing, keyless.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional

from ._cat7_common import Cat7Plugin, extract_strings, finding

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1
PF_W = 0x2


def parse_elf(data: bytes) -> Optional[Dict]:
    """ELF64/32 header + program-header hardening summary."""
    if not data or len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    try:
        is64 = data[4] == 2
        endian = "<" if data[5] != 2 else ">"
        e_type = struct.unpack(endian + "H", data[16:18])[0]
        if is64:
            phoff = struct.unpack(endian + "Q", data[32:40])[0]
            phentsize = struct.unpack(endian + "H", data[54:56])[0]
            phnum = struct.unpack(endian + "H", data[56:58])[0]
        else:
            phoff = struct.unpack(endian + "I", data[28:32])[0]
            phentsize = struct.unpack(endian + "H", data[42:44])[0]
            phnum = struct.unpack(endian + "H", data[44:46])[0]
        nx = True
        relro = False
        for i in range(min(phnum, 64)):
            off = phoff + i * phentsize
            if off + 8 > len(data):
                break
            p_type = struct.unpack(endian + "I", data[off:off + 4])[0]
            if is64:
                p_flags = struct.unpack(endian + "I",
                                        data[off + 4:off + 8])[0]
            else:
                p_flags = struct.unpack(endian + "I",
                                        data[off + 24:off + 28])[0]
            if p_type == PT_GNU_STACK and (p_flags & PF_X):
                nx = False
            if p_type == PT_GNU_RELRO:
                relro = True
        return {"is64": is64, "pie": e_type == 3, "nx": nx,
                "relro": relro, "e_type": e_type}
    except Exception:
        return None


def analyze_so(name: str, data: bytes) -> List[Dict]:
    info = parse_elf(data)
    if info is None:
        return []
    out: List[Dict] = []
    strings = extract_strings(data)
    exports = sorted({s for s in strings
                      if s.startswith("Java_") or s == "JNI_OnLoad"})
    weak = []
    if not info["nx"]:
        weak.append("executable stack (NX off)")
    if not info["pie"]:
        weak.append("not PIE (ET_REL/ET_EXEC)")
    if not info["relro"]:
        weak.append("no GNU_RELRO")
    if weak:
        out.append(finding(
            "so_weak_hardening",
            f"Native library {name}: weak hardening - "
            f"{', '.join(weak)}",
            "medium", source=name, confidence=85,
            hardening=info, exports=exports[:15]))
    if exports:
        out.append(finding(
            "so_jni_exports",
            f"Native library {name} exports {len(exports)} JNI "
            f"symbols: {', '.join(exports[:5])}",
            "low", source=name, confidence=80, exports=exports[:20]))
    return out


class NativeLibrarySoBridgePlugin(Cat7Plugin):
    id = "native_library_so_bridge"
    label = "Native Library .so Bridge"
    description = ("Per-.so deep pass over an operator-supplied APK: "
                   "ELF hardening (NX/PIE/RELRO) and JNI exports.")

    def analyze(self, art: Dict) -> List[Dict]:
        out: List[Dict] = []
        for name, blob in (art.get("files") or {}).items():
            if name.endswith(".so"):
                out.extend(analyze_so(name, blob))
        return out[:40]
