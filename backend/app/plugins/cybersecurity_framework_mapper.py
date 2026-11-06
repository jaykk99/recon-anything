"""Cybersecurity framework mapper.

Maps each supplied finding's vuln class to MITRE ATT&CK technique ids,
CWE ids and D3FEND countermeasures via a bundled static table, emitting
framework-tagged findings; high-severity findings whose class has no
mapping are coverage gaps. Pure table lookup, keyless, no external API.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# pattern -> (attack_id, tactic, cwe, d3fend)
MAPPING: List[Tuple[str, str, str, str, str]] = [
    (r"sql.?injection|sqli", "T1190", "initial-access", "CWE-89", "D3-DAA"),
    (r"xss|cross.site.script", "T1059.007", "execution", "CWE-79", "D3-DAA"),
    (r"ssrf|server.side.request", "T1190", "initial-access", "CWE-918", "D3-NTA"),
    (r"default.cred|weak.cred|brute", "T1110", "credential-access", "CWE-798", "D3-CRO"),
    (r"valid.account|exposed.*(key|token|secret|password)|credential.*leak",
     "T1078", "defense-evasion", "CWE-200", "D3-CRO"),
    (r"open.*port|exposed.*service|management.*expos", "T1133", "initial-access", "CWE-200", "D3-NTA"),
    (r"rce|remote.code|command.injection", "T1190", "initial-access", "CWE-78", "D3-DAA"),
    (r"path.traversal|directory.traversal|lfi", "T1083", "discovery", "CWE-22", "D3-DAA"),
    (r"subdomain.takeover|dangling", "T1584.001", "resource-development", "CWE-404", "D3-DNSDL"),
    (r"tls|certificate|weak.cipher", "T1557", "credential-access", "CWE-327", "D3-ET"),
    (r"idor|bola|broken.access", "T1190", "initial-access", "CWE-639", "D3-DAA"),
    (r"upload", "T1105", "command-and-control", "CWE-434", "D3-DAA"),
]


def map_finding(f: Dict[str, Any]) -> Dict[str, str] | None:
    hay = " ".join(str(f.get(k, "")) for k in ("key", "category", "value")).lower()
    for pat, atk, tactic, cwe, d3 in MAPPING:
        if re.search(pat, hay):
            return {"attack": atk, "tactic": tactic, "cwe": cwe, "d3fend": d3}
    return None


def analyze_framework(findings: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(findings, list):
        return rows
    for f in findings:
        if not isinstance(f, dict):
            continue
        m = map_finding(f)
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        sev = str(f.get("severity") or ev.get("severity") or "low").lower()
        label = str(f.get("key") or f.get("value") or "finding")[:60]
        if m:
            rows.append({"key": "framework_tagged",
                         "value": f"'{label}' maps to MITRE ATT&CK {m['attack']} "
                                  f"({m['tactic']}), {m['cwe']}, D3FEND {m['d3fend']}",
                         "severity": "low",
                         "evidence": {"attack": m["attack"], "tactic": m["tactic"],
                                      "cwe": m["cwe"], "d3fend": m["d3fend"],
                                      "finding_key": str(f.get("key", ""))}})
        elif sev in ("high", "critical"):
            rows.append({"key": "framework_unmapped_high",
                         "value": f"High-severity finding '{label}' has no "
                                  f"ATT&CK/CWE mapping in the table: framework "
                                  f"coverage gap",
                         "severity": "medium",
                         "evidence": {"finding_key": str(f.get("key", ""))}})
    return rows


class CybersecurityFrameworkMapperPlugin(Plugin):
    id = "cybersecurity_framework_mapper"
    label = "Cybersecurity Framework Mapper"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Map findings to MITRE ATT&CK, CWE and D3FEND via a "
                   "static table; flag unmapped high-severity classes.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            rows = analyze_framework(ctx.consume("findings"))
        except Exception as exc:
            return self._degraded(f"framework mapping failed: {exc}")
        findings: List[Finding] = [
            self._f("web", r["key"], r["value"], source="Framework mapper",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Use the ATT&CK/CWE/D3FEND tags "
                                             "to prioritize the mapped "
                                             "countermeasure.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"framework rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
