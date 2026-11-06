"""Shared helpers for the Cat-9 (300-expansion) Network & Protocol
Traffic Analysis family.

Pure analysis first: operator-supplied captures / logs / configs /
records in, structured hits out. Live lanes are read-only posture
probes against operator-owned targets in the port_audit family style
(single handshake / single standard query, no relay, no spoofing).

BOUNDARY: supplied captures only for traffic analysis - nothing here
captures live third-party traffic. Credential evidence is always
MASKED (first/last chars) + SHA-256 fingerprinted; full secrets never
reach a Finding. SNMP/RADIUS/Kerberos/FTP-PASV lanes are DETECTION
ONLY (posture from banners/configs/captures) - no guessing, no
secret testing, no ticket harvesting, no interception.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

MAX_ARTIFACT = 32 * 1024 * 1024

REMEDIATION = ("Review this network/protocol finding on the "
               "operator-owned target or supplied capture. Restrict "
               "the service to trusted networks, disable cleartext "
               "and legacy protocol options, require strong "
               "authentication, and re-scan to verify.")

SHARED_KEYS = ("captures", "supplied_captures", "capture_data",
               "supplied_files", "artifacts", "session_logs",
               "configs", "supplied_configs", "flow_records",
               "pcap_data", "binary_data", "supplied_binaries")


def mask_secret(value: str) -> Tuple[str, str]:
    """(masked, sha256 fingerprint) - full secrets never leave here."""
    fp = hashlib.sha256(
        (value or "").encode("utf-8", "ignore")).hexdigest()[:16]
    if not value or len(value) <= 4:
        return "****", fp
    return value[:2] + "***" + value[-2:], fp


def fingerprint(value: str) -> str:
    return hashlib.sha256(
        (value or "").encode("utf-8", "ignore")).hexdigest()[:16]


def text_of(data: bytes) -> str:
    return (data or b"").decode("utf-8", "ignore")


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


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def is_external_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_multicast
                    or a.is_reserved or a.is_link_local)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# pcap / pcapng reader (classic LE/BE + pcapng SHB/EPB/SPB)
# ---------------------------------------------------------------------------

def parse_pcap(data: bytes) -> Dict[str, Any]:
    """{ok, linktype, packets: [bytes]}. Never raises."""
    out: Dict[str, Any] = {"ok": False, "linktype": 1, "packets": []}
    try:
        if not data or len(data) < 8:
            return out
        if data[:4] == b"\x0a\x0d\x0d\x0a":  # pcapng
            return _parse_pcapng(data)
        magic = data[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            en = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            en = ">"
        else:
            return out
        if len(data) < 24:
            return out
        (_maj, _min, _tz, _sig, _snap, linktype) = struct.unpack_from(
            en + "HHIIII", data, 4)
        out["linktype"] = linktype
        pos = 24
        while pos + 16 <= len(data) and len(out["packets"]) < 8192:
            _ts, _us, caplen, _wl = struct.unpack_from(
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


def _parse_pcapng(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False, "linktype": 1, "packets": []}
    try:
        en = "<"
        pos = 0
        linktype = 1
        while pos + 12 <= len(data) and len(out["packets"]) < 8192:
            btype, blen = struct.unpack_from(en + "II", data, pos)
            if btype == 0x0A0D0D0A and blen >= 28:
                bom = struct.unpack_from("<I", data, pos + 8)[0]
                en = "<" if bom == 0x1A2B3C4D else ">"
                btype, blen = struct.unpack_from(en + "II", data, pos)
            if blen < 12 or pos + blen > len(data):
                break
            body = data[pos + 8:pos + blen - 4]
            if btype == 1 and len(body) >= 8:  # IDB
                linktype = struct.unpack_from(en + "H", body, 0)[0]
                out["linktype"] = linktype
            elif btype == 6 and len(body) >= 20:  # EPB
                caplen = struct.unpack_from(en + "I", body, 12)[0]
                pkt = body[20:20 + caplen]
                if len(pkt) == caplen:
                    out["packets"].append(pkt)
            elif btype == 3 and len(body) >= 4:  # SPB
                out["packets"].append(body[4:])
            pos += blen
        out["ok"] = True
    except Exception:
        pass
    return out


def packet_payloads(pcap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Per-packet L4 payloads: {proto, src, sport, dst, dport, data}.

    Handles Ethernet (1), Linux cooked (113), raw IP (101/12). IPv4
    only, no fragment reassembly. Never raises per packet.
    """
    out: List[Dict[str, Any]] = []
    lt = pcap.get("linktype", 1)
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
            proto = ip[9]
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
            if proto == 6 and len(ip) >= ihl + 20:
                sport, dport = struct.unpack_from(">HH", ip, ihl)
                doff = (ip[ihl + 12] >> 4) * 4
                payload = ip[ihl + doff:]
                out.append({"proto": "tcp", "src": src, "sport": sport,
                            "dst": dst, "dport": dport, "data": payload})
            elif proto == 17 and len(ip) >= ihl + 8:
                sport, dport, ulen = struct.unpack_from(">HHH", ip, ihl)
                out.append({"proto": "udp", "src": src, "sport": sport,
                            "dst": dst, "dport": dport,
                            "data": ip[ihl + 8:ihl + max(ulen, 8)]})
        except Exception:
            continue
    return out


def tcp_stream_text(pcap: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(flow_label, concatenated_payload_text) per TCP direction."""
    streams: Dict[Tuple, bytearray] = {}
    order: List[Tuple] = []
    for p in packet_payloads(pcap):
        if p["proto"] != "tcp" or not p["data"]:
            continue
        key = (p["src"], p["sport"], p["dst"], p["dport"])
        if key not in streams:
            streams[key] = bytearray()
            order.append(key)
        streams[key] += p["data"]
    return [(f"{k[0]}:{k[1]}->{k[2]}:{k[3]}",
             bytes(streams[k]).decode("latin1", "ignore"))
            for k in order]


# ---------------------------------------------------------------------------
# Artifact loading (operator-supplied only; never fetches)
# ---------------------------------------------------------------------------

def _coerce(item: Any, idx: int) -> Optional[Tuple[str, bytes]]:
    try:
        if isinstance(item, (bytes, bytearray)):
            return (f"artifact{idx}", bytes(item))
        if isinstance(item, str):
            if os.path.isfile(item):
                with open(item, "rb") as fh:
                    return (item, fh.read(MAX_ARTIFACT))
            return (f"artifact{idx}", item.encode("utf-8", "ignore"))
        if isinstance(item, (list, tuple)) and len(item) == 2:
            name, payload = item
            got = _coerce(payload, idx)
            if got:
                return (str(name), got[1])
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("filename")
                       or f"artifact{idx}")
            payload = (item.get("data") or item.get("bytes")
                       or item.get("content") or item.get("text"))
            if payload is not None:
                got = _coerce(payload, idx)
                if got:
                    return (name, got[1])
            path = item.get("path") or item.get("file")
            if isinstance(path, str) and os.path.isfile(path):
                with open(path, "rb") as fh:
                    return (name, fh.read(MAX_ARTIFACT))
    except Exception:
        return None
    return None


def load_artifacts(target: Any, ctx: Any,
                   extra_keys: Tuple[str, ...] = ()
                   ) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    seen = set()
    shared = getattr(ctx, "shared", None) or {}
    idx = 0
    for key in tuple(extra_keys) + SHARED_KEYS:
        try:
            items = shared.get(key) if isinstance(shared, dict) else None
        except Exception:
            items = None
        if items is None:
            continue
        if isinstance(items, (bytes, bytearray, str, dict)):
            items = [items]
        for item in items or []:
            got = _coerce(item, idx)
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
            category: str = "infra",
            extra_keys: Tuple[str, ...] = ()):
    """Run analyze(data, name) over every supplied artifact."""
    findings: List = []
    arts = load_artifacts(target, ctx, extra_keys)
    if not arts:
        return None
    for name, data in arts:
        for hit in analyze(data, name):
            ev = {"severity": hit.get("severity", "low"),
                  "remediation": hit.get("remediation", REMEDIATION)}
            ev.update(hit.get("evidence") or {})
            findings.append(plugin._f(
                category, hit["key"], hit["value"],
                source=name or "supplied artifact", confidence=85,
                evidence=ev, passive=True))
    return plugin._ok(findings,
                      f"{len(findings)} finding(s) from supplied "
                      "artifact(s)")


def host_port_of(target: Any, default_port: int) -> Tuple[str, int]:
    raw = (getattr(target, "normalized", "") or "").strip()
    for pref in ("http://", "https://", "udp://", "tcp://", "ftp://"):
        if raw.lower().startswith(pref):
            raw = raw[len(pref):]
            break
    raw = raw.split("/")[0].strip("[]")
    host, port = raw, default_port
    if ":" in raw:
        h, _, p = raw.rpartition(":")
        if p.isdigit():
            host, port = h, int(p)
    return (host or "127.0.0.1"), port


def host_of(target: Any) -> str:
    return host_port_of(target, 0)[0]


_CRED_WORD = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[-_]?key|auth)")


def credentialish(text: str) -> Optional[Tuple[str, str]]:
    """First (label, value) credential-shaped pair in text, or None."""
    m = re.search(r"(?i)(password|passwd|pwd|secret|token|api[-_]?key)"
                  r"\s*[:=]\s*[\"']?([^\s\"',;]{4,})", text or "")
    if m:
        return m.group(1), m.group(2)
    return None
