"""Bounty pack: the report generator, finally called.

audit_report.build_report / triage_corpus had zero callers. The loop
calls them: a pack is auto-generated when the investigation ends in
VERIFIED_REAL, or when the target clears the $100k realizable-value
floor with high/critical findings (a high-value triage pack, honestly
labelled with its verdict - UNVERIFIED included). A pack never claims
a verdict the validator did not give: the verdict is printed in the
report header and in the pack manifest.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ..audit_report import build_report, render_markdown
from .state import BOUNTY_FLOOR_USD


def pack_should_generate(verdict: Optional[str], value_usd: Optional[float],
                         findings: List[Dict[str, Any]]) -> bool:
    """The pack rule: VERIFIED_REAL, or high-value + high findings."""
    if verdict == "VERIFIED_REAL":
        return True
    if value_usd is not None and value_usd >= BOUNTY_FLOOR_USD:
        return any(str(f.get("severity") or "").lower() in ("high", "critical")
                   for f in findings)
    return False


def write_pack(investigation: Any, out_dir: str,
               findings: Optional[List[Dict[str, Any]]] = None,
               verdicts: Optional[List[Dict[str, Any]]] = None,
               source: Optional[str] = None,
               force: bool = False) -> Optional[Dict[str, Any]]:
    """Write the bounty pack for one investigation. Returns manifest or None.

    Pack contents: report.md (audit_report, verdict in header), plus
    findings.json and verdicts.json (machine-readable), plus a manifest
    dict describing what was written and why. With force=False the pack
    rule decides; force=True writes regardless (the MCP bounty_pack
    tool, which states the reason explicitly).
    """
    findings = list(findings if findings is not None
                    else investigation.findings)
    verdicts = list(verdicts if verdicts is not None
                    else investigation.verdicts)
    verdict = investigation.verdict
    if not force and not pack_should_generate(
            verdict, investigation.value_usd, findings):
        return None
    os.makedirs(out_dir, exist_ok=True)
    probes = [{"finding": v.get("kind", ""),
               "verdict": v.get("verdict", ""),
               "transcript": v.get("reason", "")} for v in verdicts]
    report = build_report(
        investigation.address, investigation.chain, findings,
        source=source,
        probes=probes,
        meta={"investigation_id": investigation.id,
              "verdict": verdict or "UNVERIFIED",
              "value_usd": investigation.value_usd,
              "value_band": investigation.value_band,
              "hypothesis": investigation.hypothesis or {}},
        checks_run=None)
    md = render_markdown(report)
    # Verdict banner: the report must never be read as verified when
    # it is not. render_markdown states counts; we state the verdict.
    banner = (f"\n> **Investigator verdict: {verdict or 'UNVERIFIED'}** "
              f"(investigation {investigation.id}). Fork/simulation "
              f"evidence is analysis signal only and never proves a "
              f"live payout.\n")
    md = md + banner
    report_path = os.path.join(out_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    findings_path = os.path.join(out_dir, "findings.json")
    with open(findings_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, sort_keys=True, default=str)
    verdicts_path = os.path.join(out_dir, "verdicts.json")
    with open(verdicts_path, "w", encoding="utf-8") as fh:
        json.dump(verdicts, fh, indent=2, sort_keys=True, default=str)
    manifest = {
        "investigation_id": investigation.id,
        "address": investigation.address,
        "chain": investigation.chain,
        "verdict": verdict,
        "value_usd": investigation.value_usd,
        "reason": ("VERIFIED_REAL" if verdict == "VERIFIED_REAL"
                   else "high-value triage pack"),
        "files": {"report": report_path,
                  "findings": findings_path,
                  "verdicts": verdicts_path},
    }
    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True, default=str)
    manifest["files"]["manifest"] = manifest_path
    return manifest
