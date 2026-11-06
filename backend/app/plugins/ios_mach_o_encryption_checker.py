"""Mach-O encryption checker (Cat-7 #197, SHIP).

Parses Mach-O load commands of an operator-supplied IPA/Mach-O for
LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 and reports cryptid:
0 = decrypted/dumped binary, 1 = FairPlay-encrypted. Pure-python
struct parsing, keyless.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional

from ._cat7_common import Cat7Plugin, finding

MH_MAGICS = {b"\xcf\xfa\xed\xfe": ("<", True), b"\xce\xfa\xed\xfe": ("<", False),
             b"\xfe\xed\xfa\xcf": (">", True), b"\xfe\xed\xfa\xce": (">", False)}
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C


def parse_macho_encryption(data: bytes) -> Optional[Dict]:
    """Return {cryptid, cryptoff, cryptsize, is64} or None."""
    if not data or len(data) < 32:
        return None
    magic = data[:4]
    if magic not in MH_MAGICS:
        # Fat binary: take the first slice offset.
        if magic == b"\xca\xfe\xba\xbe" and len(data) >= 16:
            off = struct.unpack(">I", data[12:16])[0]
            return parse_macho_encryption(data[off:])
        return None
    endian, is64 = MH_MAGICS[magic]
    try:
        if is64:
            ncmds = struct.unpack(endian + "I", data[16:20])[0]
            off = 32
        else:
            ncmds = struct.unpack(endian + "I", data[16:20])[0]
            off = 28
        for _ in range(min(ncmds, 200)):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack(endian + "II", data[off:off + 8])
            if cmdsize < 8:
                break
            if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                cryptoff, cryptsize, cryptid = struct.unpack(
                    endian + "III", data[off + 8:off + 20])
                return {"cryptid": cryptid, "cryptoff": cryptoff,
                        "cryptsize": cryptsize, "is64": is64}
            off += cmdsize
    except Exception:
        return None
    return {"cryptid": None, "cryptoff": 0, "cryptsize": 0, "is64": is64}


def analyze_macho(data: bytes) -> List[Dict]:
    info = parse_macho_encryption(data or b"")
    if info is None:
        return []
    if info["cryptid"] == 0:
        return [finding(
            "macho_decrypted_binary",
            "Mach-O cryptid=0: binary is NOT FairPlay-encrypted "
            "(decrypted/dumped redistribution)",
            "high", source="Mach-O LC_ENCRYPTION_INFO", confidence=90,
            cryptoff=info["cryptoff"], cryptsize=info["cryptsize"])]
    if info["cryptid"] is None:
        return [finding(
            "macho_no_encryption_info",
            "Mach-O carries no LC_ENCRYPTION_INFO load command "
            "(never FairPlay-encrypted)",
            "medium", source="Mach-O header", confidence=75)]
    return []  # cryptid=1: properly encrypted, silent


def analyze_ipa_bins(art: Dict) -> List[Dict]:
    out: List[Dict] = []
    if art.get("kind") == "file" and art.get("data"):
        out.extend(analyze_macho(art["data"]))
    for name, blob in (art.get("files") or {}).items():
        low = name.lower()
        if "/payload/" in low or low.endswith(".app/app") or \
                ("." not in name.rsplit("/", 1)[-1] and blob[:4]
                 in MH_MAGICS):
            out.extend(analyze_macho(blob))
    return out


class IosMachOEncryptionCheckerPlugin(Cat7Plugin):
    id = "ios_mach_o_encryption_checker"
    label = "iOS Mach-O Encryption Checker"
    description = ("Parses LC_ENCRYPTION_INFO(_64) in an operator-"
                   "supplied IPA/Mach-O; flags cryptid=0 decrypted "
                   "binaries.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_ipa_bins(art)
