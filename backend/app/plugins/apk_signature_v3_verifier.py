"""APK Signing Block v2/v3 verifier (Cat-7 #199, VARIANT of binex).

binex fingerprints the v1 META-INF cert only; signing-block IDs are
never read. Delta: parse the APK Signing Block for v2/v3/v3.1 scheme
presence and consistency, signer-rotation lineage markers, and flag
v1-only signing. Pure-python parsing of operator-supplied APK bytes.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional

from ._cat7_common import Cat7Plugin, finding

SIG_MAGIC = b"APK Sig Block 42"
SCHEMES = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1",
           0x42726577: "v1-jar-in-block"}
ROTATION_ID = 0x3BA06F8C  # proof-of-rotation attribute (v3 lineage)


def parse_signing_block(data: bytes) -> Optional[Dict]:
    """Locate the signing block and return {schemes, rotation}."""
    if not data:
        return None
    idx = data.rfind(SIG_MAGIC)
    if idx < 24:
        return None
    try:
        size_footer = struct.unpack("<Q", data[idx - 8:idx])[0]
        block_start = idx - 8 - size_footer + 8
        if block_start < 0:
            return None
        size_header = struct.unpack(
            "<Q", data[block_start:block_start + 8])[0]
        if size_header != size_footer:
            return None
        pos = block_start + 8
        end = idx - 8
        schemes: List[str] = []
        rotation = False
        while pos + 8 <= end:
            pair_len = struct.unpack("<Q", data[pos:pos + 8])[0]
            if pair_len < 4 or pos + 8 + pair_len > end + 8:
                break
            pair_id = struct.unpack(
                "<I", data[pos + 8:pos + 12])[0]
            if pair_id in SCHEMES:
                schemes.append(SCHEMES[pair_id])
            if pair_id == ROTATION_ID:
                rotation = True
            pos += 8 + pair_len
        return {"schemes": schemes, "rotation": rotation}
    except Exception:
        return None


def analyze_signature(art: Dict) -> List[Dict]:
    data = art.get("data") or b""
    names = list((art.get("files") or {}).keys())
    v1_jar = any(n.startswith("META-INF/") and
                 n.endswith((".RSA", ".DSA", ".EC")) for n in names)
    block = parse_signing_block(data)
    out: List[Dict] = []
    if block is None:
        if v1_jar:
            out.append(finding(
                "apk_v1_only_signing",
                "APK is signed with the v1 (JAR) scheme ONLY - no "
                "APK Signing Block (v2/v3) present; v1 is bypassable "
                "via Janus-style DEX injection on old Android",
                "high", source="APK signing block", confidence=85,
                schemes=["v1"]))
        return out
    schemes = block["schemes"]
    if "v3" not in schemes and "v3.1" not in schemes and "v2" in schemes:
        out.append(finding(
            "apk_no_v3_signing",
            "APK Signing Block has v2 but no v3/v3.1 - no signer "
            "rotation support; a leaked key can never be rotated out",
            "medium", source="APK signing block", confidence=82,
            schemes=schemes, rotation=block["rotation"]))
    if not schemes and v1_jar:
        out.append(finding(
            "apk_v1_only_signing",
            "APK Signing Block carries no v2/v3 scheme; effective "
            "signing is v1-only",
            "high", source="APK signing block", confidence=82,
            schemes=["v1"]))
    return out


class ApkSignatureV3VerifierPlugin(Cat7Plugin):
    id = "apk_signature_v3_verifier"
    label = "APK Signature v3 Verifier"
    description = ("Parses the APK Signing Block of an operator-"
                   "supplied APK for v2/v3/v3.1 presence and rotation "
                   "lineage; flags v1-only signing.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_signature(art)
