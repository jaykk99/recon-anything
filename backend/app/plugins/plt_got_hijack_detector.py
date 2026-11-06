"""PLT-GOT-hijack-detector: looks for evidence of actual runtime GOT patching in an operator-supplied ELF (and/or its dump) - GOT entries pre-filled with values pointing into the binary's own text or outside legitimate library mappings, and tampered PLT stubs. Distinct from the static PLT configuration audit.
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


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    if detect_format(data) != "elf":
        return hits
    info = parse_elf(data)
    if not info.get("ok"):
        return hits
    got = elf_section(info, ".got.plt") or elf_section(info, ".got")
    text = elf_section(info, ".text")
    if got and text:
        blob = data[got["offset"]:got["offset"] + got["size"]]
        step = 8 if info.get("bits") == 64 else 4
        text_lo, text_hi = text["addr"], text["addr"] + text["size"]
        for i in range(0, len(blob) - step + 1, step):
            (val,) = struct.unpack_from("<Q" if step == 8 else "<I", blob, i)
            if val == 0:
                continue
            # first 3 GOT.PLT slots are resolver bookkeeping; real entries
            # in an unexecuted on-disk file should be 0 (lazy) - a value
            # pointing into .text is a patch indicator.
            if i >= step * 3 and text_lo <= val < text_hi:
                hits.append({"key": "got_entry_points_to_text", "severity": "high",
                    "value": f"GOT entry #{i//step} in on-disk ELF is pre-filled with .text address {val:#x} - runtime GOT patch indicator (unexecuted files keep these zero)",
                    "evidence": {"entry": i // step, "value": val}})
                break
    plt = elf_section(info, ".plt")
    if plt:
        blob = data[plt["offset"]:plt["offset"] + plt["size"]]
        # canonical PLT stub starts ff 25 (jmp *GOT) - a stub rewritten to
        # an absolute call/jmp elsewhere is a tamper indicator
        if len(blob) >= 16 and blob[:2] not in (b"\xff\x25", b"\xf3\x0f") and blob[0] not in (0xFF, 0xF3):
            hits.append({"key": "plt_stub_tampered", "severity": "medium",
                "value": "First PLT stub does not start with the canonical ff 25 / endbr pattern - PLT tampering indicator",
                "evidence": {"first_bytes": blob[:4].hex()}})
    return hits[:8]

class PltGotHijackDetectorPlugin(Plugin):
    id = "plt_got_hijack_detector"
    label = "PLT/GOT Hijack Detector"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'Runtime GOT-patch evidence detection for supplied ELFs: pre-filled GOT entries, tampered PLT stubs.'
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
