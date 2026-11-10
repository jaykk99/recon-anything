"""Audit-style report output for ReconAnything.

Turns a contract's scan findings (from contract_audit / contract_chain,
plus any live-probe transcripts) into a professional, shareable audit
report - the deliverable for the product's real use cases: pre-deploy
audit, bounty triage, continuous monitoring. Not a drain-hunt tracker: a
findings report with severity, confidence, location, evidence, remediation
and probe verdicts, the thing an auditor or protocol team actually reads.

Detection only. The report states what was observed statically and what the
read-only probe found; it never asserts a contract is exploitable for
profit, and it carries the probe verdict (including "could not verify")
verbatim.

    from app.audit_report import build_report, render_markdown
    report = build_report(address, chain, findings, source=src, probes=pr)
    md = render_markdown(report)
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
              "low": "Low", "info": "Informational"}

# Plain-language remediation per finding class. Keyed by the kind/check the
# analyzers emit. A finding with no mapping still renders; it just omits the
# remediation block.
_REMEDIATION = {
    "reentrancy":
        "Apply checks-effects-interactions: update all state before the "
        "external call, or wrap the function in a reentrancy guard "
        "(e.g. OpenZeppelin ReentrancyGuard).",
    "selfdestruct":
        "Gate any selfdestruct behind strict access control, or remove it. "
        "An ungated selfdestruct lets anyone destroy the contract.",
    "unprotected_initializer":
        "Guard the initializer with OpenZeppelin's initializer modifier (or "
        "an initialized flag) so it can be called exactly once, by the "
        "deployer, and cannot be front-run to seize ownership.",
    "ownership_takeover_path":
        "Remove or access-gate the path that reassigns owner/admin. "
        "Ownership transfer must be restricted to the current owner.",
    "full_balance_withdraw":
        "Restrict any function that moves the contract's full balance to an "
        "authorized role, and prefer pull-over-push withdrawal patterns.",
    "delegatecall_untrusted":
        "Never delegatecall to an address an attacker can supply. Pin the "
        "implementation to an immutable/admin-set address and validate it.",
    "tx_origin":
        "Use msg.sender, not tx.origin, for authorization. tx.origin checks "
        "are bypassable by a malicious intermediary contract.",
    "missing_access_control":
        "Add an access-control modifier (onlyOwner / role check) to any "
        "state-changing public or external function that should be "
        "privileged.",
    "flashloan_callback":
        "Verify the caller of a flash-loan callback is the expected lending "
        "pool, and that the operation was initiated by this contract.",
    "privileged_function":
        "Confirm the privileged function is access-gated and that the owner "
        "key is held securely (ideally a multisig or timelock).",
}


def _norm(f: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a finding from either analyzer into one shape."""
    kind = f.get("kind") or f.get("check") or "finding"
    return {
        "kind": kind,
        "title": f.get("title") or f.get("detail", "")[:80] or kind,
        "severity": (f.get("severity") or "info").lower(),
        "confidence": f.get("confidence"),
        "function": f.get("function") or "",
        "detail": f.get("detail") or f.get("title") or "",
        "code": f.get("code") or "",
        "remediation": f.get("remediation") or _REMEDIATION.get(kind, ""),
    }


def build_report(address: str, chain: str, findings: List[Dict[str, Any]],
                 source: Optional[str] = None,
                 probes: Optional[List[Dict[str, Any]]] = None,
                 meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Assemble a structured audit report from scan findings.

    probes: optional list of {finding, verdict, transcript} from the live
    read-only probe. Verdicts are carried verbatim - including
    "unverified"/"could not confirm", which is the honest and common case.
    """
    norm = [_norm(f) for f in findings]
    norm.sort(key=lambda x: (_SEV_ORDER.get(x["severity"], 9),
                             -(x["confidence"] or 0)))
    counts: Dict[str, int] = {}
    for f in norm:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for i, f in enumerate(norm, 1):
        f["id"] = f"RA-{i:03d}"
    return {
        "address": address,
        "chain": chain or "",
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "severity_counts": counts,
        "findings": norm,
        "probes": probes or [],
        "meta": meta or {},
        "source_lines": len((source or "").splitlines()) if source else None,
    }


def _risk_headline(counts: Dict[str, int]) -> str:
    if counts.get("critical"):
        return ("**Critical issues present.** At least one finding is a "
                "direct fund-loss or takeover path and must be resolved "
                "before deployment.")
    if counts.get("high"):
        return ("**High-severity issues present.** Address before deploying "
                "to mainnet with real value.")
    if counts.get("medium"):
        return ("Medium-severity issues present; review and remediate as "
                "appropriate for the contract's risk profile.")
    if counts:
        return "Only low/informational findings. No fund-loss path observed."
    return "No findings. Nothing flagged by static analysis."


def render_markdown(report: Dict[str, Any]) -> str:
    c = report["severity_counts"]
    lines: List[str] = []
    lines.append(f"# Security Review — `{report['address']}`")
    lines.append("")
    meta_bits = [f"**Chain:** {report['chain'] or 'n/a'}",
                 f"**Generated:** {report['generated_at']}",
                 "**Tool:** ReconAnything (static analysis + read-only probe)"]
    if report.get("source_lines"):
        meta_bits.append(f"**Source:** {report['source_lines']} lines")
    lines.append("  \n".join(meta_bits))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(_risk_headline(c))
    lines.append("")
    if c:
        order = sorted(c.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        for sev, n in order:
            lines.append(f"| {_SEV_LABEL.get(sev, sev)} | {n} |")
        lines.append("")
    lines.append("> Detection is static plus a read-only probe. Findings are "
                 "observed code shapes and probe results, not an assertion "
                 "that the contract is exploitable for profit. A probe "
                 "verdict of *unverified* means the issue could not be "
                 "confirmed live — the honest and common outcome.")
    lines.append("")

    probe_by_kind: Dict[str, Dict[str, Any]] = {}
    for p in report.get("probes", []):
        probe_by_kind[p.get("finding", "")] = p

    if report["findings"]:
        lines.append("## Findings")
        lines.append("")
        for f in report["findings"]:
            conf = f" · confidence {f['confidence']}" if f["confidence"] \
                else ""
            loc = f" · `{f['function']}()`" if f["function"] else ""
            lines.append(f"### {f['id']} — {f['title']}")
            lines.append("")
            lines.append(f"**{_SEV_LABEL.get(f['severity'], f['severity'])}**"
                         f"{loc}{conf}")
            lines.append("")
            lines.append(f["detail"])
            lines.append("")
            if f["code"]:
                snippet = f["code"].strip()
                if len(snippet) > 600:
                    snippet = snippet[:600] + " …"
                lines.append("```solidity")
                lines.append(snippet)
                lines.append("```")
                lines.append("")
            probe = probe_by_kind.get(f["kind"])
            if probe:
                lines.append(f"**Live probe:** {probe.get('verdict', 'n/a')}")
                if probe.get("transcript"):
                    lines.append("")
                    lines.append("```")
                    lines.append(str(probe["transcript"]).strip()[:800])
                    lines.append("```")
                lines.append("")
            if f["remediation"]:
                lines.append(f"**Remediation:** {f['remediation']}")
                lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No findings.")
        lines.append("")

    lines.append("## Methodology")
    lines.append("")
    lines.append("Static analysis of the verified source (function-level "
                 "control-flow and access-control checks, drain/takeover "
                 "pattern detection) followed by a read-only on-chain probe "
                 "to corroborate exploitable shapes. No state-changing "
                 "transactions are sent; the contract is never drained or "
                 "modified.")
    lines.append("")
    return "\n".join(lines)
