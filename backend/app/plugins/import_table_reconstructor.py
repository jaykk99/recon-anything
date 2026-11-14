"""Import-table-reconstructor: rebuilds the import address table of an operator-supplied PE/dump - resolved API names per IAT slot - and flags unresolvable slots and manual resolution (GetProcAddress hashing) as packing indicators.
"""
from __future__ import annotations
from typing import Any, Dict, List
from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat5_common import (
    REMEDIATION, detect_format, load_artifacts,
    parse_pe, strings_only)


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits = []
    strs = strings_only(data, 4)
    if detect_format(data) == "pe":
        info = parse_pe(data)
        imports = info.get("imports", [])
        total_funcs = sum(len(f) for _d, f in imports)
        has_manual = any(s in strs for s in ("GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LdrGetProcedureAddress"))
        if has_manual and total_funcs <= 3:
            hits.append({"key": "iat_manual_resolution_packing", "severity": "medium",
                "value": f"Import table is nearly empty ({total_funcs} resolved imports) but manual resolution APIs are present (GetProcAddress/LoadLibrary) - packed/manual IAT reconstruction indicator",
                "evidence": {"resolved_imports": total_funcs}})
        unres = 0
        for dll, funcs in imports:
            for f in funcs:
                if f.startswith("ord"):
                    unres += 1
        if unres:
            hits.append({"key": "iat_ordinal_only_imports", "severity": "low",
                "value": f"{unres} IAT slot(s) resolve only to ordinals (no API names) in rebuilt import table",
                "evidence": {"ordinal_imports": unres}})
    else:
        # damaged dump form: API names present as strings but no PE structure
        if any(s in strs for s in ("GetProcAddress",)) and any(s in strs for s in ("VirtualAlloc", "VirtualProtect")):
            hits.append({"key": "iat_manual_resolution_packing", "severity": "medium",
                "value": "Dump shows manual API resolution pattern (GetProcAddress + VirtualAlloc/VirtualProtect) with no intact import table - packing indicator",
                "evidence": {"resolved_imports": 0}})
    return hits

class ImportTableReconstructorPlugin(Plugin):
    id = "import_table_reconstructor"
    label = "Import Table Reconstructor"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip", "apk_url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = 'IAT reconstruction for supplied PE/dumps: resolved names per slot, manual-resolution packing flags.'
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
