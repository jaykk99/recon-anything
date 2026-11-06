"""Shared pure-Python native-binary parsing for the Cat-5 (300-expansion)
native binaries & decompiler bridges family.

Everything here is pure analysis: bytes in, structured data out. No I/O,
no network, no external tools. Parsers are defensive: malformed input
degrades to partial/empty structures instead of raising.

Formats covered: ELF (32/64, LE/BE), PE/COFF, Mach-O (thin, 32/64 LE).
Plus: printable-string extraction, Shannon entropy (whole + sliding
window), a tiny x86/x64 length-decoder + block splitter used by the
CFG/disassembly-flavoured plugins (capstone is used when importable,
with this decoder as the always-available fallback), string-xref
search, and an operator-supplied artifact loader for plugin wrappers.

BOUNDARY: analysis only. Nothing here executes, patches, bypasses or
builds payloads of any kind.
"""
from __future__ import annotations

import hashlib
import math
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

MAX_ARTIFACT = 32 * 1024 * 1024  # 32 MB cap per supplied artifact

# ---------------------------------------------------------------------------
# Basics
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def window_entropies(data: bytes, window: int = 256,
                     step: int = 128) -> List[Tuple[int, float]]:
    out: List[Tuple[int, float]] = []
    if len(data) < 16:
        return [(0, shannon_entropy(data))] if data else []
    pos = 0
    while pos < len(data):
        out.append((pos, shannon_entropy(data[pos:pos + window])))
        pos += step
    return out


def extract_strings(data: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    """(offset, string) for printable ASCII runs."""
    out: List[Tuple[int, str]] = []
    start = None
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_len:
                out.append((start, data[start:i].decode("ascii", "ignore")))
            start = None
    if start is not None and len(data) - start >= min_len:
        out.append((start, data[start:].decode("ascii", "ignore")))
    return out


def strings_only(data: bytes, min_len: int = 4) -> List[str]:
    return [s for _, s in extract_strings(data, min_len)]


def detect_format(data: bytes) -> str:
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "elf"
    if len(data) >= 2 and data[:2] == b"MZ":
        return "pe"
    if len(data) >= 4 and data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                                       b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                                       b"\xca\xfe\xba\xbe"):
        return "macho"
    if len(data) >= 4 and data[:4] == b"MDMP":
        return "minidump"
    return "raw"


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_RELRO = 0x6474E552
PT_GNU_STACK = 0x6474E551
PF_X, PF_W, PF_R = 1, 2, 4
SHT_SYMTAB = 2
SHT_DYNAMIC = 6


def parse_elf(data: bytes) -> Dict[str, Any]:
    """Best-effort ELF parse. Never raises; missing pieces stay empty."""
    info: Dict[str, Any] = {
        "format": "elf", "bits": 0, "endian": "<", "etype": None,
        "machine": None, "entry": 0, "phdrs": [], "sections": [],
        "dynstrs": [], "symbols": [], "dynamic": {}, "ok": False,
    }
    try:
        if len(data) < 52 or data[:4] != b"\x7fELF":
            return info
        info["bits"] = {1: 32, 2: 64}.get(data[4], 0)
        en = ">" if data[5] == 2 else "<"
        info["endian"] = en
        if info["bits"] == 64:
            (etype, machine, _ver, entry, phoff, shoff, _flags, _eh,
             phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
                en + "HHIQQQIHHHHHH", data, 16)
        elif info["bits"] == 32:
            (etype, machine, _ver, entry, phoff, shoff, _flags, _eh,
             phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
                en + "HHIIIIIHHHHHH", data, 16)
        else:
            return info
        info.update(etype=etype, machine=machine, entry=entry, ok=True)
        # Program headers
        for i in range(min(phnum, 128)):
            off = phoff + i * phentsize
            try:
                if info["bits"] == 64:
                    (ptype, pflags, poff, pvaddr, _pa, pfilesz, pmemsz,
                     _al) = struct.unpack_from(en + "IIQQQQQQ", data, off)
                else:
                    (ptype, poff, pvaddr, _pa, pfilesz, pmemsz, pflags,
                     _al) = struct.unpack_from(en + "IIIIIIII", data, off)
            except Exception:
                break
            info["phdrs"].append({
                "type": ptype, "flags": pflags, "offset": poff,
                "vaddr": pvaddr, "filesz": pfilesz, "memsz": pmemsz})
        # Section headers (names resolved via shstrtab when present)
        raw_secs = []
        for i in range(min(shnum, 512)):
            off = shoff + i * shentsize
            try:
                if info["bits"] == 64:
                    (name, stype, sflags, saddr, soff, ssize, slink, _si,
                     _sa, _se) = struct.unpack_from(en + "IIQQQQIIQQ", data, off)
                else:
                    (name, stype, sflags, saddr, soff, ssize, slink, _si,
                     _sa, _se) = struct.unpack_from(en + "IIIIIIIIII", data, off)
            except Exception:
                break
            raw_secs.append({"name_off": name, "type": stype, "flags": sflags,
                             "addr": saddr, "offset": soff, "size": ssize,
                             "link": slink})
        shstr = b""
        if 0 <= shstrndx < len(raw_secs):
            s = raw_secs[shstrndx]
            shstr = data[s["offset"]:s["offset"] + s["size"]]
        def _nm(off: int) -> str:
            if off >= len(shstr):
                return ""
            end = shstr.find(b"\x00", off)
            return shstr[off:end if end >= 0 else len(shstr)].decode(
                "utf-8", "ignore")
        for s in raw_secs:
            s["name"] = _nm(s.pop("name_off"))
            info["sections"].append(s)
        # String tables + symbols
        for s in info["sections"]:
            blob = data[s["offset"]:s["offset"] + s["size"]]
            if s["name"] in (".dynstr", ".strtab") and blob:
                parts = [p.decode("utf-8", "ignore")
                         for p in blob.split(b"\x00") if p]
                if s["name"] == ".dynstr":
                    info["dynstrs"].extend(parts)
                else:
                    info["symbols"].extend(parts)
            if s["name"] == ".dynamic":
                step = 16 if info["bits"] == 64 else 8
                fmt = en + "qQ" if info["bits"] == 64 else en + "iI"
                for j in range(0, len(blob) - step + 1, step):
                    try:
                        tag, val = struct.unpack_from(fmt, blob, j)
                    except Exception:
                        break
                    if tag == 0:
                        break
                    info["dynamic"][tag] = val
    except Exception:
        pass
    return info


def elf_section(info: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    for s in info.get("sections", []):
        if s.get("name") == name:
            return s
    return None


def elf_imports(info: Dict[str, Any]) -> List[str]:
    return list(info.get("dynstrs", []))


def offset_to_vaddr(info: Dict[str, Any], offset: int) -> Optional[int]:
    for ph in info.get("phdrs", []):
        if ph["type"] == PT_LOAD and ph["offset"] <= offset < ph["offset"] + ph["filesz"]:
            return ph["vaddr"] + (offset - ph["offset"])
    return None


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------

def parse_pe(data: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "format": "pe", "ok": False, "timestamp": 0, "machine": 0,
        "characteristics": 0, "dll_characteristics": 0, "entry_rva": 0,
        "image_base": 0, "checksum": 0, "sections": [], "dirs": [],
        "imports": [],  # list of (dll, [funcs])
        "num_sections": 0,
    }
    try:
        if len(data) < 64 or data[:2] != b"MZ":
            return info
        (peoff,) = struct.unpack_from("<I", data, 0x3C)
        if peoff + 24 > len(data) or data[peoff:peoff + 4] != b"PE\x00\x00":
            return info
        coff = peoff + 4
        (machine, nsec, tstamp, _psym, _nsym, optsize,
         chars) = struct.unpack_from("<HHIIIHH", data, coff)
        info.update(machine=machine, timestamp=tstamp,
                    characteristics=chars, num_sections=nsec)
        opt = coff + 20
        if opt + 2 > len(data):
            return info
        (magic,) = struct.unpack_from("<H", data, opt)
        is64 = magic == 0x20B
        if magic not in (0x10B, 0x20B):
            return info
        if is64:
            (entry, _code, image_base) = struct.unpack_from("<IIQ", data, opt + 16)
            (dllchars,) = struct.unpack_from("<H", data, opt + 70)
            (checksum,) = struct.unpack_from("<I", data, opt + 64)
            ndirs_off = opt + 108
            dirs_off = opt + 112
        else:
            (entry,) = struct.unpack_from("<I", data, opt + 16)
            (image_base,) = struct.unpack_from("<I", data, opt + 28)
            (dllchars,) = struct.unpack_from("<H", data, opt + 70)
            (checksum,) = struct.unpack_from("<I", data, opt + 64)
            ndirs_off = opt + 92
            dirs_off = opt + 96
        info.update(entry_rva=entry, image_base=image_base,
                    dll_characteristics=dllchars, checksum=checksum, ok=True)
        (ndirs,) = struct.unpack_from("<I", data, ndirs_off) if ndirs_off + 4 <= len(data) else (0,)
        dirs = []
        for i in range(min(ndirs, 16)):
            if dirs_off + i * 8 + 8 <= len(data):
                rva, size = struct.unpack_from("<II", data, dirs_off + i * 8)
                dirs.append((rva, size))
            else:
                dirs.append((0, 0))
        info["dirs"] = dirs
        sec_off = opt + optsize
        for i in range(nsec):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].split(b"\x00")[0].decode("utf-8", "ignore")
            vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, o + 8)
            (schar,) = struct.unpack_from("<I", data, o + 36)
            info["sections"].append({
                "name": name, "vsize": vsize, "vaddr": vaddr,
                "raw_size": rawsize, "raw_off": rawoff, "chars": schar})
        info["imports"] = _pe_imports(data, info)
    except Exception:
        pass
    return info


def _rva_to_off(info: Dict[str, Any], rva: int) -> Optional[int]:
    for s in info.get("sections", []):
        span = max(s["vsize"], s["raw_size"])
        if s["vaddr"] <= rva < s["vaddr"] + span:
            return s["raw_off"] + (rva - s["vaddr"])
    return None


def _pe_imports(data: bytes, info: Dict[str, Any]) -> List[Tuple[str, List[str]]]:
    out: List[Tuple[str, List[str]]] = []
    try:
        if len(info.get("dirs", [])) < 2:
            return out
        rva, _size = info["dirs"][1]
        if not rva:
            return out
        off = _rva_to_off(info, rva)
        if off is None:
            return out
        is64 = len(data) > 0 and info.get("image_base", 0) > 0xFFFFFFFF or True
        # Determine thunk width from optional magic via entry heuristics:
        # try 64-bit thunks when the PE is PE32+ (image base large or
        # machine AMD64).
        wide = info.get("machine") == 0x8664
        for d in range(64):
            doff = off + d * 20
            if doff + 20 > len(data):
                break
            oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, doff)
            if not any((oft, name_rva, ft)):
                break
            noff = _rva_to_off(info, name_rva)
            dll = ""
            if noff is not None:
                end = data.find(b"\x00", noff)
                dll = data[noff:end if end >= 0 else noff + 64].decode(
                    "utf-8", "ignore")
            funcs: List[str] = []
            thunk_rva = oft or ft
            toff = _rva_to_off(info, thunk_rva) if thunk_rva else None
            if toff is not None:
                step = 8 if wide else 4
                for t in range(256):
                    eoff = toff + t * step
                    if eoff + step > len(data):
                        break
                    (val,) = struct.unpack_from("<Q" if wide else "<I", data, eoff)
                    if val == 0:
                        break
                    if wide and (val >> 63):
                        funcs.append(f"ord{val & 0xFFFF}")
                        continue
                    if not wide and (val >> 31):
                        funcs.append(f"ord{val & 0xFFFF}")
                        continue
                    hnoff = _rva_to_off(info, int(val))
                    if hnoff is None:
                        continue
                    end = data.find(b"\x00", hnoff + 2)
                    funcs.append(data[hnoff + 2:end if end >= 0 else hnoff + 66].decode(
                        "utf-8", "ignore"))
            out.append((dll, funcs))
    except Exception:
        pass
    return out


def pe_all_import_names(info: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for dll, funcs in info.get("imports", []):
        if dll:
            names.append(dll)
        names.extend(funcs)
    return names


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO_64 = 0x2C


def parse_macho(data: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {"format": "macho", "ok": False, "bits": 0,
                            "segments": [], "commands": [],
                            "codesig_off": 0, "codesig_size": 0}
    try:
        if len(data) < 28:
            return info
        magic = data[:4]
        if magic == b"\xcf\xfa\xed\xfe":
            en, bits = "<", 64
        elif magic == b"\xfe\xed\xfa\xcf":
            en, bits = ">", 64
        elif magic == b"\xce\xfa\xed\xfe":
            en, bits = "<", 32
        elif magic == b"\xfe\xed\xfa\xce":
            en, bits = ">", 32
        else:
            return info
        info["bits"] = bits
        hdr = 32 if bits == 64 else 28
        (_mg, _cpu, _sub, _ft, ncmds, sizeofcmds, _fl) = struct.unpack_from(
            en + "IIIIIII", data, 0)[:7] if bits == 64 else (
            *struct.unpack_from(en + "IIIIII", data, 0), 0)
        if bits == 32:
            (_mg, _cpu, _sub, _ft, ncmds, sizeofcmds, _fl) = struct.unpack_from(
                en + "IIIIIII", data, 0) if False else (0, 0, 0, 0, 0, 0, 0)
            vals = struct.unpack_from(en + "IIIIII", data, 0)
            ncmds, sizeofcmds = vals[4], vals[5]
        info["ok"] = True
        off = hdr
        for _ in range(min(ncmds, 256)):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(en + "II", data, off)
            if cmdsize < 8:
                break
            info["commands"].append(cmd)
            if cmd in (LC_SEGMENT, LC_SEGMENT_64):
                name = data[off + 8:off + 24].split(b"\x00")[0].decode(
                    "utf-8", "ignore")
                if bits == 64:
                    (_c, _cs, _n, vmaddr, vmsize, fileoff, filesize,
                     maxprot, initprot, nsects, sflags) = struct.unpack_from(
                        en + "II16sQQQQIIII", data, off)
                else:
                    (_c, _cs, _n, vmaddr, vmsize, fileoff, filesize,
                     maxprot, initprot, nsects, sflags) = struct.unpack_from(
                        en + "II16sIIIIIIII", data, off)
                info["segments"].append({
                    "name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                    "fileoff": fileoff, "filesize": filesize,
                    "maxprot": maxprot, "initprot": initprot,
                    "nsects": nsects, "flags": sflags})
            elif cmd == LC_CODE_SIGNATURE and off + 16 <= len(data):
                _c, _cs, doff, dsize = struct.unpack_from(en + "IIII", data, off)
                info["codesig_off"], info["codesig_size"] = doff, dsize
            off += cmdsize
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# Tiny x86/x64 decoder + block model (capstone fallback)
# ---------------------------------------------------------------------------

def try_capstone_disasm(code: bytes, base: int = 0) -> Optional[List[Dict[str, Any]]]:
    """Use capstone when importable; None otherwise (caller falls back)."""
    try:
        import capstone  # type: ignore
    except Exception:
        return None
    try:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        return [{"address": i.address, "mnemonic": i.mnemonic,
                 "op_str": i.op_str, "size": i.size}
                for i in md.disasm(code, base)]
    except Exception:
        return None


# opcode -> (length, kind) for the fixture/real-world subset we model.
# kind: seq | jmp | jcc | call | ret | syscall | div | other
def decode_one(code: bytes, i: int) -> Tuple[int, str, Optional[int]]:
    """(length, kind, rel_target_offset_within_code or None)."""
    if i >= len(code):
        return 0, "other", None
    b = code[i]
    if b == 0x90 or b == 0xCC or b == 0x55:
        return 1, "seq", None
    if b == 0xC3:
        return 1, "ret", None
    if b == 0xC2:
        return 3, "ret", None
    if b == 0xEB and i + 1 < len(code):
        rel = struct.unpack_from("<b", code, i + 1)[0]
        return 2, "jmp", i + 2 + rel
    if b == 0xE9 and i + 4 < len(code):
        rel = struct.unpack_from("<i", code, i + 1)[0]
        return 5, "jmp", i + 5 + rel
    if 0x70 <= b <= 0x7F and i + 1 < len(code):
        rel = struct.unpack_from("<b", code, i + 1)[0]
        return 2, "jcc", i + 2 + rel
    if b == 0xE8 and i + 4 < len(code):
        rel = struct.unpack_from("<i", code, i + 1)[0]
        return 5, "call", i + 5 + rel
    if b == 0x0F and i + 1 < len(code):
        b2 = code[i + 1]
        if b2 == 0x05:
            return 2, "syscall", None
        if b2 == 0x31:
            return 2, "rdtsc", None
        if 0x80 <= b2 <= 0x8F and i + 5 < len(code):
            rel = struct.unpack_from("<i", code, i + 2)[0]
            return 6, "jcc", i + 6 + rel
        return 2, "seq", None
    if b == 0xCD and i + 1 < len(code):
        return 2, "int", None
    if b == 0xF4:
        return 1, "hlt", None
    if b in (0xF7, 0xF6) and i + 1 < len(code):
        modrm = code[i + 1]
        reg = (modrm >> 3) & 7
        if reg in (6, 7):  # DIV / IDIV
            return 2, "div", None
        return 2, "seq", None
    if 0xB8 <= b <= 0xBF:
        return 5, "seq", None
    if b == 0x48 and i + 2 < len(code):
        if code[i + 1] == 0x89 and code[i + 2] == 0xE5:
            return 3, "seq", None
        if code[i + 1] in (0xB8, 0xBB, 0xB9, 0xBA, 0xBE, 0xBF):
            return 10, "seq", None
        if code[i + 1] == 0x83:
            return 4, "seq", None
        if code[i + 1] == 0x31:
            return 3, "seq", None
        return 3, "seq", None
    if b == 0x31 and i + 1 < len(code):
        return 2, "seq", None
    if b == 0x83 and i + 2 < len(code):
        return 3, "seq", None
    if b == 0xFF and i + 1 < len(code):
        modrm = code[i + 1]
        reg = (modrm >> 3) & 7
        if reg == 2:
            return 2, "call", None
        if reg == 4:
            return 2, "jmp", None
        return 2, "seq", None
    if b == 0x94:  # xchg eax, esp - classic stack pivot
        return 1, "pivot", None
    return 1, "seq", None


def split_blocks(code: bytes) -> List[Dict[str, Any]]:
    """Split code into basic blocks using the tiny decoder.

    Returns blocks: {start, end, kind(terminator), target, fallthrough}.
    Leaders: entry, branch targets, instructions after terminators.
    """
    n = len(code)
    if n == 0:
        return []
    leaders = {0}
    instrs: Dict[int, Tuple[int, str, Optional[int]]] = {}
    i = 0
    # Linear sweep collecting leaders (bounded, tolerant of bad bytes).
    guard = 0
    while i < n and guard < 200000:
        guard += 1
        ln, kind, tgt = decode_one(code, i)
        if ln <= 0:
            ln = 1
        instrs[i] = (ln, kind, tgt)
        if kind in ("jmp", "jcc", "call") and tgt is not None and 0 <= tgt < n:
            leaders.add(tgt)
        if kind in ("jmp", "jcc", "call", "ret", "hlt"):
            if i + ln < n:
                leaders.add(i + ln)
        i += ln
    starts = sorted(leaders)
    blocks: List[Dict[str, Any]] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else n
        # terminator = last decoded instruction fully inside the block
        term_kind, term_tgt = "seq", None
        j = start
        while j < end:
            ln, kind, tgt = instrs.get(j, (1, "seq", None))
            if j + ln >= end or kind in ("jmp", "jcc", "call", "ret", "hlt",
                                          "syscall", "div", "int", "pivot"):
                term_kind, term_tgt = kind, tgt
                end = min(end, j + ln)
                break
            j += ln
        blocks.append({"start": start, "end": end, "term": term_kind,
                       "target": term_tgt})
    return blocks


def block_edges(blocks: List[Dict[str, Any]]) -> Dict[int, List[int]]:
    by_start = {b["start"]: b for b in blocks}
    edges: Dict[int, List[int]] = {}
    starts = [b["start"] for b in blocks]
    for idx, b in enumerate(blocks):
        outs: List[int] = []
        nxt = starts[idx + 1] if idx + 1 < len(starts) else None
        if b["term"] == "jmp":
            if b["target"] in by_start:
                outs.append(b["target"])
        elif b["term"] in ("jcc", "call"):
            if b["target"] in by_start:
                outs.append(b["target"])
            if nxt is not None:
                outs.append(nxt)
        elif b["term"] in ("ret", "hlt"):
            pass
        else:
            if nxt is not None:
                outs.append(nxt)
        edges[b["start"]] = outs
    return edges


def code_section_bytes(data: bytes, fmt: str,
                       info: Dict[str, Any]) -> Tuple[bytes, int]:
    """(code_bytes, code_file_offset) for the primary executable region."""
    try:
        if fmt == "elf":
            for s in info.get("sections", []):
                if s.get("flags", 0) & 0x4 and s.get("size", 0) > 0:  # SHF_EXECINSTR
                    return data[s["offset"]:s["offset"] + s["size"]], s["offset"]
            for ph in info.get("phdrs", []):
                if ph["type"] == PT_LOAD and ph["flags"] & PF_X:
                    return data[ph["offset"]:ph["offset"] + ph["filesz"]], ph["offset"]
        elif fmt == "pe":
            for s in info.get("sections", []):
                if s["chars"] & 0x20000000 and s["raw_size"] > 0:  # EXECUTE
                    return data[s["raw_off"]:s["raw_off"] + s["raw_size"]], s["raw_off"]
        elif fmt == "macho":
            for seg in info.get("segments", []):
                if seg["initprot"] & 4 and seg["filesize"] > 0:
                    return (data[seg["fileoff"]:seg["fileoff"] + seg["filesize"]],
                            seg["fileoff"])
    except Exception:
        pass
    return b"", 0


def find_string_xrefs(data: bytes, code: bytes, code_off: int,
                      info: Dict[str, Any], fmt: str) -> List[Dict[str, Any]]:
    """Map strings to code locations referencing them by absolute VA.

    Searches the code region for little-endian 32/64-bit encodings of
    each string's virtual address (ELF/PE) or file offset (fallback).
    """
    xrefs: List[Dict[str, Any]] = []
    strs = extract_strings(data, 4)
    for soff, s in strs:
        vas: List[int] = []
        if fmt == "elf":
            va = offset_to_vaddr(info, soff)
            if va:
                vas.append(va)
        elif fmt == "pe":
            va = info.get("image_base", 0)
            # offset -> RVA via sections
            for sec in info.get("sections", []):
                if sec["raw_off"] <= soff < sec["raw_off"] + max(sec["raw_size"], 1):
                    vas.append(info.get("image_base", 0) + sec["vaddr"]
                               + (soff - sec["raw_off"]))
                    break
        vas.append(soff)
        hit_at = None
        for va in vas:
            for width in (8, 4):
                needle = int(va).to_bytes(width, "little")
                pos = code.find(needle)
                if pos >= 0:
                    hit_at = pos
                    break
            if hit_at is not None:
                break
        if hit_at is not None:
            xrefs.append({"string": s, "string_off": soff,
                          "code_off": code_off + hit_at, "code_idx": hit_at})
    return xrefs


DANGEROUS_IMPORTS = {
    "strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf", "sscanf",
    "memcpy", "strncpy", "system", "popen", "execve", "execl", "alloca",
    "realpath", "getwd", "recv", "read", "mprotect", "VirtualAlloc",
    "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA",
    "URLDownloadToFileW",
}
BUFFER_IMPORTS = {
    "strcpy", "strcat", "gets", "sprintf", "vsprintf", "memcpy",
    "strncpy", "strncat", "scanf", "sscanf", "alloca", "realpath",
}
SECRET_RE = None  # compiled lazily in memory-dump plugin to keep this lean


def mask_secret(value: str) -> Tuple[str, str]:
    """(masked, sha256 fingerprint) - full secrets never leave analysis."""
    fp = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]
    if len(value) <= 4:
        return "****", fp
    return value[:2] + "***" + value[-2:], fp


# ---------------------------------------------------------------------------
# Artifact loading for plugin wrappers (operator-supplied only)
# ---------------------------------------------------------------------------

_SHARED_KEYS = ("binary_artifacts", "artifacts", "binary_data",
                "binary_files", "supplied_binaries")


def _coerce_artifact(item: Any, idx: int) -> Optional[Tuple[str, bytes]]:
    try:
        if isinstance(item, (bytes, bytearray)):
            return (f"artifact{idx}", bytes(item))
        if isinstance(item, (list, tuple)) and len(item) == 2:
            name, payload = item
            if isinstance(payload, (bytes, bytearray)):
                return (str(name), bytes(payload))
            if isinstance(payload, str) and os.path.isfile(payload):
                with open(payload, "rb") as fh:
                    return (str(name), fh.read(MAX_ARTIFACT))
        if isinstance(item, dict):
            payload = item.get("data") or item.get("bytes") or item.get("content")
            name = str(item.get("name") or item.get("filename")
                       or f"artifact{idx}")
            if isinstance(payload, (bytes, bytearray)):
                return (name, bytes(payload))
            path = item.get("path") or item.get("file")
            if isinstance(path, str) and os.path.isfile(path):
                with open(path, "rb") as fh:
                    return (name, fh.read(MAX_ARTIFACT))
        if isinstance(item, str) and os.path.isfile(item):
            with open(item, "rb") as fh:
                return (item, fh.read(MAX_ARTIFACT))
    except Exception:
        return None
    return None


def load_artifacts(target: Any, ctx: Any) -> List[Tuple[str, bytes]]:
    """All operator-supplied binary artifacts for this run.

    Sources, in order: ctx.shared artifact buckets, then the target
    itself when it names a local file. Never fetches anything.
    """
    out: List[Tuple[str, bytes]] = []
    seen = set()
    shared = getattr(ctx, "shared", None) or {}
    idx = 0
    for key in _SHARED_KEYS:
        try:
            items = shared.get(key) if isinstance(shared, dict) else None
        except Exception:
            items = None
        if items is None:
            continue
        if isinstance(items, (bytes, bytearray, str, dict)):
            items = [items]
        for item in items or []:
            got = _coerce_artifact(item, idx)
            idx += 1
            if got and got[1]:
                h = hashlib.sha256(got[1]).hexdigest()
                if h not in seen:
                    seen.add(h)
                    out.append(got)
    for cand in (getattr(target, "normalized", ""), getattr(target, "raw", "")):
        if isinstance(cand, str) and cand and os.path.isfile(cand):
            try:
                with open(cand, "rb") as fh:
                    blob = fh.read(MAX_ARTIFACT)
                if blob:
                    h = hashlib.sha256(blob).hexdigest()
                    if h not in seen:
                        seen.add(h)
                        out.append((cand, blob))
            except Exception:
                pass
    return out[:8]


def parse_any(data: bytes) -> Tuple[str, Dict[str, Any]]:
    fmt = detect_format(data)
    if fmt == "elf":
        return fmt, parse_elf(data)
    if fmt == "pe":
        return fmt, parse_pe(data)
    if fmt == "macho":
        return fmt, parse_macho(data)
    return fmt, {}


REMEDIATION = ("Review this native-binary finding on the operator-supplied "
               "artifact. Rebuild with modern exploit mitigations "
               "(PIE, NX/DEP, stack canaries, full RELRO, CFG where "
               "available), strip debug info from release builds, and "
               "remove dangerous functions and embedded secrets.")
