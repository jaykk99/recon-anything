"""Binwalk-entropy-scanner: sliding-window entropy + magic-byte carving over an operator-supplied firmware/binary blob. Locates high-entropy (packed/encrypted) regions and embedded filesystem/archive signatures.
"""
from __future__ import annotations
import re, struct, time
from typing import Any, Dict, List, Tuple
from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat5_common import (
    DANGEROUS_IMPORTS, BUFFER_IMPORTS, REMEDIATION, block_edges,
    code_section_bytes, decode_one, detect_format, elf_imports,
    elf_section, extract_strings, find_string_xrefs, load_artifacts,
    mask_secret, offset_to_vaddr, parse_any, parse_elf, parse_macho,
    parse_pe, pe_all_import_names, shannon_entropy, split_blocks,
    strings_only, try_capstone_disasm, window_entropies, PT_GNU_STACK,
    PT_GNU_RELRO, PF_W, PF_X)


MAGICS = [(b"\x1f\x8b\x08", "gzip"), (b"PK\x03\x04", "zip"), (b"7z\xbc\xaf\x27\x1c", "7zip"),
          (b"hsqs", "squashfs"), (b"\xfd7zXZ\x00", "xz"), (b"\x28\xb5\x2f\xfd", "zstd"),
          (b"ustar", "tar"), (b"\x7fELF", "elf"), (b"\x27\x05\x19\x56", "uImage")]
def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    if not data or len(data) < 64:
        return hits
    for off, ent in window_entropies(data, 512, 256):
        if ent >= 7.4:
            hits.append({"key": "binwalk_high_entropy_region", "severity": "medium",
                "value": f"High-entropy region at offset {off:#x} (entropy {ent:.2f}) - packed or encrypted payload candidate",
                "evidence": {"offset": off, "entropy": round(ent, 3)}})
            break
    seen = set()
    for magic, label in MAGICS:
        start = 1  # offset 0 is the outer container itself
        idx = data.find(magic, start)
        if idx > 0 and label not in seen:
            seen.add(label)
            hits.append({"key": "binwalk_embedded_signature", "severity": "low",
                "value": f"Embedded {label} signature at offset {idx:#x} inside supplied blob",
                "evidence": {"offset": idx, "kind": label}})
    return hits[:10]

class BinwalkEntropyScannerPlugin(Plugin):
    id = "binwalk_entropy_scanner"
    label = "Binwalk Entropy Scanner"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Entropy + embedded-signature carving scan of supplied firmware/binary blobs.'
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings: List = []
        try:
            arts = load_artifacts(target, ctx)
            if not arts:
                return self._ok([], "no operator-supplied binary artifact in ctx.shared or target file path; nothing to analyse")
            for name, data in arts:
                for hit in analyze(data, name):
                    ev = {"severity": hit.get("severity", "low"),
                          "remediation": REMEDIATION}
                    ev.update(hit.get("evidence") or {})
                    findings.append(self._f(
                        "infra", hit["key"], hit["value"],
                        source=name or "supplied binary", confidence=85,
                        evidence=ev))
        except Exception as exc:  # never raise fatally
            return self._ok(findings, f"analysis degraded: {exc}"[:200])
        return self._ok(findings, f"{len(findings)} finding(s) from supplied artifact(s)")
