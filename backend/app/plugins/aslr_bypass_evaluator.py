"""ASLR-bypass-evaluator (posture form): grades randomization effectiveness of an operator-supplied binary - PIE vs non-PIE, PE DYNAMIC_BASE, fixed load addresses, and info-leak-prone format-string/pointer-disclosure patterns. This is a posture assessment, not a bypass tool.
"""
from __future__ import annotations
from typing import Any, Dict, List
from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat5_common import (
    REMEDIATION, elf_imports,
    load_artifacts,
    parse_any, pe_all_import_names, strings_only)


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    fmt, info = parse_any(data)
    if fmt == "elf":
        if info.get("etype") == 2:  # ET_EXEC
            hits.append({"key": "aslr_non_pie_binary", "severity": "medium",
                "value": "ELF is ET_EXEC (non-PIE): code loads at a fixed address, defeating ASLR for the main executable",
                "evidence": {"etype": 2, "entry": info.get("entry")}})
        elif info.get("etype") == 3 and info.get("entry", 0) not in (0,) and False:
            pass
    elif fmt == "pe":
        if not (info.get("dll_characteristics", 0) & 0x0040):
            hits.append({"key": "aslr_no_dynamic_base", "severity": "medium",
                "value": "PE lacks DYNAMIC_BASE - image is not randomized by ASLR",
                "evidence": {"dll_characteristics": info.get("dll_characteristics")}})
    if fmt in ("elf", "pe", "macho"):
        strs = strings_only(data, 3)
        fmt_strs = [s for s in strs if "%p" in s or "%x" in s or "%s%p" in s]
        imps = []
        if fmt == "elf":
            imps = elf_imports(info)
        elif fmt == "pe":
            imps = pe_all_import_names(info)
        if fmt_strs and any(i in imps for i in ("printf", "fprintf", "sprintf", "syslog")):
            hits.append({"key": "aslr_infoleak_format_string", "severity": "low",
                "value": f"Format-string pointer-disclosure pattern present ({fmt_strs[0]!r} with printf-family import) - undermines randomization",
                "evidence": {"pattern": fmt_strs[0]}})
    return hits

class AslrBypassEvaluatorPlugin(Plugin):
    id = "aslr_bypass_evaluator"
    label = "ASLR Posture Evaluator"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'ASLR/PIE posture evaluation for supplied binaries. Posture assessment only, not a bypass tool.'
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
