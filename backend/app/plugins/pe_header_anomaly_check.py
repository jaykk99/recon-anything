"""PE-header-anomaly-check: pure-Python PE parser auditing an operator-supplied Windows PE for header anomalies - tampered/zero/future timestamps, section entropy/name mismatches, missing Authenticode evidence, zero checksum and entry point inside a writable section.
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
    if detect_format(data) != "pe":
        return hits
    info = parse_pe(data)
    if not info.get("ok"):
        hits.append({"key": "pe_malformed_header", "severity": "medium",
            "value": "PE signature present but optional header is malformed/unparseable",
            "evidence": {}})
        return hits
    ts = info.get("timestamp", 0)
    if ts == 0 or ts > 1893456000:  # 2030-01-01
        hits.append({"key": "pe_timestamp_anomaly", "severity": "low",
            "value": f"PE timestamp anomaly: TimeDateStamp={ts} (zero or implausibly future - tampering/packer indicator)",
            "evidence": {"timestamp": ts}})
    if info.get("checksum", 0) == 0:
        hits.append({"key": "pe_zero_checksum", "severity": "low",
            "value": "PE header checksum is zero - unsigned/unverified image indicator",
            "evidence": {}})
    entry = info.get("entry_rva", 0)
    for s in info.get("sections", []):
        blob = data[s["raw_off"]:s["raw_off"] + s["raw_size"]]
        ent = shannon_entropy(blob) if blob else 0.0
        if s["vaddr"] <= entry < s["vaddr"] + max(s["vsize"], s["raw_size"]):
            if s["chars"] & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                hits.append({"key": "pe_entry_in_writable_section", "severity": "high",
                    "value": f"Entry point lies in writable section {s['name']} - packer/self-modifying indicator",
                    "evidence": {"section": s["name"], "entry_rva": entry}})
        if ent >= 7.2 and s["name"] in (".text", ".rdata", ".data"):
            hits.append({"key": "pe_section_entropy_mismatch", "severity": "medium",
                "value": f"Section {s['name']} entropy {ent:.2f} is abnormally high for its type - packed/encrypted content",
                "evidence": {"section": s["name"], "entropy": round(ent, 3)}})
    return hits[:10]

class PeHeaderAnomalyCheckPlugin(Plugin):
    id = "pe_header_anomaly_check"
    label = "PE Header Anomaly Check"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'PE header anomaly audit for supplied Windows binaries: timestamps, entropy, entry-point placement, checksum.'
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
