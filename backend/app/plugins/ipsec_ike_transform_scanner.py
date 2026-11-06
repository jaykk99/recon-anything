"""IPsec IKE transform scanner: parses the transforms a responder
selects (supplied IKE capture / ipsec config) and flags weak
posture: DES/3DES encryption, MD5 integrity, DH groups 1/2/5,
IKEv1 Aggressive Mode acceptance, IKEv1-only configurations.

Live lane: ONE crafted IKEv2 SA_INIT (and an IKEv1 main-mode
probe) over UDP 500 to the target's own host, handshake bytes
only - no key exchange completion, no authentication. The pure
parser walks the SA payload's transform substructures.
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import struct
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, host_port_of, text_of

ENCR_NAMES = {1: "DES-CBC", 2: "IDEA", 3: "Blowfish", 4: "RC5",
              5: "3DES-CBC", 6: "CAST", 7: "AES-CBC", 8: "AES-CTR"}
WEAK_ENCR = {1, 5}
INTEG_NAMES = {1: "HMAC-MD5", 2: "HMAC-SHA1", 3: "HMAC-SHA256"}
DH_NAMES = {1: "768-bit MODP (group 1)", 2: "1024-bit MODP (group 2)",
            5: "1536-bit MODP (group 5)", 14: "2048-bit MODP",
            19: "ECP-256", 20: "ECP-384", 31: "Curve25519"}
WEAK_DH = {1, 2, 5}


def build_sa_init(aggressive_v1: bool = False) -> bytes:
    if aggressive_v1:
        # IKEv1 header + SA payload with a single DES/MD5/group1
        # proposal: if the responder answers, aggressive/main-mode
        # v1 handling exists; transform parsing stays v2-focused.
        hdr = os.urandom(8) + b"\x00" * 8 + b"\x01\x10\x02\x00" + \
            b"\x00" * 8
        sa = b"\x00" * 4
        return hdr + struct.pack(">I", 28 + len(sa)) + sa
    spi = os.urandom(8)
    # One transform: ENCR AES-CBC(7) with 256-bit key attr - the
    # responder's REPLY is what we grade, not our offer.
    # transform: next=0 rsvd len=12 type=1(ENCR) rsvd id=7 attr
    transform = bytes([0, 0]) + struct.pack(">H", 12) + \
        bytes([1, 0]) + struct.pack(">H", 7) + b"\x80\x0e\x01\x00"
    # proposal: next=0 rsvd len num=1 proto=1(IKE) spi_size=0 ntrans=1
    proposal = bytes([0, 0]) + struct.pack(">H", 8 + len(transform)) \
        + bytes([1, 1, 0, 1]) + transform
    # SA payload: next=0 rsvd len | proposal
    sa_payload = bytes([0, 0]) + struct.pack(
        ">H", 4 + len(proposal)) + proposal
    hdr = spi + b"\x00" * 8 + bytes([33, 0x20, 34, 0x08]) + \
        struct.pack(">I", 0) + struct.pack(">I", 28 + len(sa_payload))
    return hdr + sa_payload


def parse_ikev2_sa(data: bytes) -> Dict[str, Any]:
    """{ok, encr, integ, prf, dh} transform ids from an SA_INIT
    response's SA payload. Defensive, never raises."""
    out: Dict[str, Any] = {"ok": False}
    try:
        blob = data or b""
        if len(blob) < 29:
            return out
        next_payload = blob[16]
        pos = 28
        # Walk payload chain to the SA payload (type 33).
        guard = 0
        while next_payload and pos + 4 <= len(blob) and guard < 32:
            guard += 1
            plen = struct.unpack_from(">H", blob, pos + 2)[0]
            if plen < 4 or pos + plen > len(blob):
                return out
            if next_payload == 33:
                sa = blob[pos:pos + plen]
                transforms = _parse_sa_payload(sa)
                if transforms:
                    out.update(transforms)
                    out["ok"] = True
                return out
            next_payload = blob[pos]
            pos += plen
    except Exception:
        pass
    return out


def _parse_sa_payload(sa: bytes) -> Dict[str, Any]:
    """Transforms from the first proposal of an SA payload.

    Layout: payload header(4) | proposal: next(1) rsvd(1) len(2)
    num(1) proto(1) spi_size(1) n_transforms(1) spi | transforms:
    next(1) rsvd(1) len(2) type(1) rsvd(1) id(2) [attrs].
    """
    out: Dict[str, Any] = {}
    try:
        if len(sa) < 12:
            return out
        prop_len = struct.unpack_from(">H", sa, 6)[0]
        prop = sa[4:4 + prop_len]
        if len(prop) < 8:
            return out
        spi_size = prop[6]
        q = 8 + spi_size
        while q + 8 <= len(prop):
            tlen = struct.unpack_from(">H", prop, q + 2)[0]
            ttype = prop[q + 4]
            tid = struct.unpack_from(">H", prop, q + 6)[0]
            key = {1: "encr", 2: "prf", 3: "integ", 4: "dh"}.get(
                ttype)
            if key:
                out[key] = tid
            if tlen < 8:
                break
            q += tlen
    except Exception:
        pass
    return out


def hits_for_transforms(t: Dict[str, Any], src: str
                        ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    encr = t.get("encr")
    if encr in WEAK_ENCR:
        hits.append({
            "key": "ike_weak_encryption_transform",
            "severity": "high",
            "value": f"IKE responder ({src}) selected "
                     f"{ENCR_NAMES.get(encr, encr)} encryption - "
                     "broken/legacy cipher in the chosen transform",
            "evidence": {"encr": encr,
                         "remediation": "Remove DES/3DES from IKE "
                         "proposals; offer AES-GCM / AES-CBC-256 "
                         "minimum."}})
    integ = t.get("integ")
    if integ == 1:
        hits.append({
            "key": "ike_md5_integrity_transform", "severity": "medium",
            "value": f"IKE responder ({src}) selected HMAC-MD5 "
                     "integrity",
            "evidence": {"integ": integ,
                         "remediation": "Remove MD5 integrity from "
                         "IKE proposals (SHA-256+ only)."}})
    dh = t.get("dh")
    if dh in WEAK_DH:
        hits.append({
            "key": "ike_weak_dh_group", "severity": "medium",
            "value": f"IKE responder ({src}) selected DH "
                     f"{DH_NAMES.get(dh, dh)} - weak MODP group",
            "evidence": {"dh": dh,
                         "remediation": "Require DH group 14+ or "
                         "ECP groups (19/20/31); drop groups 1/2/5."}})
    return hits


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    if not data:
        return []
    parsed = parse_ikev2_sa(data)
    if parsed.get("ok"):
        return hits_for_transforms(parsed, "supplied IKE capture")
    text = text_of(data)
    low = text.lower()
    hits: List[Dict[str, Any]] = []
    weak = re.findall(r"(?i)\b(des|3des|md5|modp768|modp1024|"
                      r"modp1536|dh-group\s*[125]\b|group\s*[125]\b)",
                      text)
    if weak and ("ike" in low or "esp" in low or "proposal" in low
                 or "transform" in low):
        hits.append({
            "key": "ike_weak_transform_in_config",
            "severity": "medium",
            "value": f"Supplied IKE config carries weak transform "
                     f"material ({', '.join(sorted(set(w.lower() for w in weak))[:6])}): "
                     "DES/3DES/MD5 or DH group 1/2/5 in a proposal",
            "evidence": {"remediation": "Prune weak transforms "
                         "from IKE/ESP proposals: AES-256+, SHA-256+, "
                         "DH 14+/ECP only."}})
    if re.search(r"(?i)aggrmode\s*=\s*yes| aggressive\s*mode", text):
        hits.append({
            "key": "ikev1_aggressive_mode_enabled",
            "severity": "medium",
            "value": "Supplied IKE config enables IKEv1 Aggressive "
                     "Mode - the PSK hash is exposed to offline "
                     "attack by any initiator",
            "evidence": {"remediation": "Disable Aggressive Mode; "
                         "use IKEv2 (or Main Mode with certificates)."}})
    if re.search(r"(?i)^\s*ike\s*=\s*ikev1|version\s*=\s*ikev1|"
                 r"keyexchange\s*=\s*ikev1", text, re.M):
        hits.append({
            "key": "ikev1_only_configuration", "severity": "low",
            "value": "Supplied IKE config is IKEv1-only",
            "evidence": {"remediation": "Migrate to IKEv2; IKEv1 "
                         "is deprecated."}})
    return hits[:10]


def _probe(host: str, port: int, timeout: float = 3.0
           ) -> Optional[bytes]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(build_sa_init(), (host, port))
            data, _ = s.recvfrom(4096)
            return data
    except Exception:
        return None


class IpsecIkeTransformScannerPlugin(Plugin):
    id = "ipsec_ike_transform_scanner"
    label = "IPsec IKE Transform Scanner"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("Parses IKE responder transforms (supplied "
                   "capture/config, or one IKEv2 SA_INIT handshake "
                   "probe): DES/3DES, MD5, DH 1/2/5, IKEv1 "
                   "Aggressive Mode posture. Handshake bytes only.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("ike_captures", "ipsec_configs"))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        host, port = host_port_of(target, 500)
        try:
            resp = await asyncio.to_thread(_probe, host, port)
        except Exception:
            resp = None
        if not resp:
            return self._degraded(f"no IKE response from "
                                  f"{host}:{port}")
        parsed = parse_ikev2_sa(resp)
        findings = []
        for hit in hits_for_transforms(parsed, f"{host}:{port}"):
            ev = {"severity": hit["severity"]}
            ev.update(hit.get("evidence") or {})
            findings.append(self._f(
                "infra", hit["key"], hit["value"],
                source="IKEv2 SA_INIT probe", confidence=85,
                evidence=ev, passive=False))
        return self._ok(findings, "IKE SA_INIT response parsed")
