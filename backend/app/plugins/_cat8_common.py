"""Shared pure-Python helpers for the Cat-8 (300-expansion) Firmware &
Hardware IoT Protocols family.

Everything here is pure analysis: bytes in, structured data out. No I/O
beyond reading operator-supplied artifact files named by the target or
placed in ctx.shared. Parsers are defensive: malformed input degrades
to partial/empty structures instead of raising.

BOUNDARY: supplied artifacts and operator-owned local targets only.
Credential evidence is always masked + SHA-256 fingerprinted; full
secret values never reach a Finding.
"""
from __future__ import annotations

import hashlib
import math
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

MAX_ARTIFACT = 32 * 1024 * 1024

REMEDIATION = ("Review this firmware/IoT finding on the operator-supplied "
               "artifact or operator-owned device. Rebuild/reflash with "
               "debug interfaces disabled, strong unique credentials, "
               "signed updates and verified boot enabled, and rotate any "
               "credential the artifact contains.")


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


def window_entropies(data: bytes, window: int = 512,
                     step: int = 256) -> List[Tuple[int, float]]:
    out: List[Tuple[int, float]] = []
    if not data:
        return out
    pos = 0
    while pos < len(data):
        out.append((pos, shannon_entropy(data[pos:pos + window])))
        pos += step
    return out


def extract_strings(data: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
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


def mask_secret(value: str) -> Tuple[str, str]:
    """(masked, sha256 fingerprint) - full secrets never leave analysis."""
    fp = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]
    if len(value) <= 4:
        return "****", fp
    return value[:2] + "***" + value[-2:], fp


def fingerprint(value: str) -> str:
    return hashlib.sha256(
        (value or "").encode("utf-8", "ignore")).hexdigest()[:16]


def find_all(data: bytes, needle: bytes, limit: int = 64) -> List[int]:
    out: List[int] = []
    if not needle:
        return out
    pos = data.find(needle)
    while pos >= 0 and len(out) < limit:
        out.append(pos)
        pos = data.find(needle, pos + 1)
    return out


def text_of(data: bytes) -> str:
    return data.decode("utf-8", "ignore")


# ---------------------------------------------------------------------------
# Flattened Device Tree (DTB) parser
# ---------------------------------------------------------------------------

FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def parse_dtb(data: bytes) -> Dict[str, Any]:
    """Walk an FDT blob. Returns {ok, nodes: [{path, props{name: bytes}}]}.

    Never raises; a bad magic or truncated block yields ok=False/partial.
    """
    info: Dict[str, Any] = {"ok": False, "nodes": []}
    try:
        if len(data) < 40 or struct.unpack_from(">I", data, 0)[0] != FDT_MAGIC:
            return info
        (_magic, totalsize, off_struct, off_strings, _off_rsv, _ver,
         _last, _boot_cpu, size_strings,
         size_struct) = struct.unpack_from(">10I", data, 0)
        totalsize = min(totalsize or len(data), len(data))
        strs = data[off_strings:off_strings + size_strings]
        pos = off_struct
        end = min(off_struct + size_struct, totalsize, len(data))
        stack: List[str] = []
        current: Optional[Dict[str, Any]] = None

        def _str_at(off: int) -> str:
            if off < 0 or off >= len(strs):
                return ""
            e = strs.find(b"\x00", off)
            return strs[off:e if e >= 0 else len(strs)].decode(
                "utf-8", "ignore")

        guard = 0
        while pos + 4 <= end and guard < 100000:
            guard += 1
            (token,) = struct.unpack_from(">I", data, pos)
            pos += 4
            if token == FDT_BEGIN_NODE:
                e = data.find(b"\x00", pos, end)
                if e < 0:
                    break
                name = data[pos:e].decode("utf-8", "ignore")
                pos = (e + 4) & ~3
                stack.append(name)
                current = {"path": "/" + "/".join(
                    s for s in stack if s), "name": name, "props": {}}
                info["nodes"].append(current)
            elif token == FDT_END_NODE:
                if stack:
                    stack.pop()
                current = info["nodes"][-1] if info["nodes"] else None
            elif token == FDT_PROP:
                if pos + 8 > end:
                    break
                plen, noff = struct.unpack_from(">II", data, pos)
                pos += 8
                value = data[pos:pos + plen]
                pos += (plen + 3) & ~3
                if current is not None:
                    current["props"][_str_at(noff)] = value
            elif token == FDT_NOP:
                continue
            elif token == FDT_END:
                break
            else:
                break
        info["ok"] = bool(info["nodes"])
    except Exception:
        pass
    return info


def prop_str(value: bytes) -> str:
    return value.split(b"\x00")[0].decode("utf-8", "ignore")


# ---------------------------------------------------------------------------
# libpcap reader (classic pcap, LE/BE, us/ns)
# ---------------------------------------------------------------------------

def parse_pcap(data: bytes) -> Dict[str, Any]:
    """{ok, linktype, packets: [bytes]}. Never raises."""
    out: Dict[str, Any] = {"ok": False, "linktype": 0, "packets": []}
    try:
        if len(data) < 24:
            return out
        magic = data[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            en = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            en = ">"
        else:
            return out
        (_maj, _min, _tz, _sig, _snap, linktype) = struct.unpack_from(
            en + "HHIIII", data, 4)
        out["linktype"] = linktype
        pos = 24
        while pos + 16 <= len(data) and len(out["packets"]) < 4096:
            _ts, _us, caplen, _wirelen = struct.unpack_from(
                en + "IIII", data, pos)
            pos += 16
            if caplen > 16 * 1024 * 1024 or pos + caplen > len(data):
                break
            out["packets"].append(data[pos:pos + caplen])
            pos += caplen
        out["ok"] = True
    except Exception:
        pass
    return out


def udp_payloads(pcap: Dict[str, Any]) -> List[Tuple[int, int, bytes]]:
    """(src_port, dst_port, payload) for UDP packets in a parsed pcap.

    Handles Ethernet (linktype 1), Linux cooked (113) and raw IP (101).
    """
    out: List[Tuple[int, int, bytes]] = []
    lt = pcap.get("linktype", 0)
    for pkt in pcap.get("packets", []):
        try:
            ip = None
            if lt == 1 and len(pkt) > 14 and pkt[12:14] == b"\x08\x00":
                ip = pkt[14:]
            elif lt == 113 and len(pkt) > 16:
                ip = pkt[16:]
            elif lt in (101, 12) and pkt:
                ip = pkt
            if not ip or len(ip) < 20 or (ip[0] >> 4) != 4:
                continue
            ihl = (ip[0] & 0x0F) * 4
            if ip[9] != 17 or len(ip) < ihl + 8:
                continue
            sport, dport, ulen = struct.unpack_from(">HHH", ip, ihl)
            out.append((sport, dport, ip[ihl + 8:ihl + max(ulen, 8)]))
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------------
# Artifact loading for plugin wrappers (operator-supplied only)
# ---------------------------------------------------------------------------

_SHARED_KEYS = ("firmware_artifacts", "artifacts", "binary_artifacts",
                "firmware_data", "supplied_files", "captures",
                "binary_data", "binary_files", "supplied_binaries")


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
            payload = (item.get("data") or item.get("bytes")
                       or item.get("content"))
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
    """All operator-supplied artifacts for this run. Never fetches."""
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
    for cand in (getattr(target, "normalized", ""),
                 getattr(target, "raw", "")):
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


def collect(plugin: Any, target: Any, ctx: Any, analyze,
            category: str = "infra"):
    """Standard wrapper body: run analyze(name, data) over artifacts."""
    findings: List = []
    arts = load_artifacts(target, ctx)
    if not arts:
        return plugin._ok(
            [], "no operator-supplied artifact in ctx.shared or target "
            "file path; nothing to analyse")
    for name, data in arts:
        for hit in analyze(data, name):
            ev = {"severity": hit.get("severity", "low"),
                  "remediation": hit.get("remediation", REMEDIATION)}
            ev.update(hit.get("evidence") or {})
            findings.append(plugin._f(
                category, hit["key"], hit["value"],
                source=name or "supplied artifact", confidence=85,
                evidence=ev))
    return plugin._ok(findings,
                      f"{len(findings)} finding(s) from supplied "
                      "artifact(s)")


def host_of(target: Any) -> str:
    """Bare host for live operator-owned probes (no scheme/port)."""
    raw = (getattr(target, "normalized", "") or "").strip()
    for pref in ("http://", "https://", "udp://", "tcp://"):
        if raw.lower().startswith(pref):
            raw = raw[len(pref):]
            break
    raw = raw.split("/")[0].split(":")[0]
    return raw.strip("[]") or "127.0.0.1"


def is_local_or_private(host: str) -> bool:
    import ipaddress
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_private or \
            ipaddress.ip_address(host).is_loopback
    except Exception:
        return host.endswith((".local", ".lan"))
