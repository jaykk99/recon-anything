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

    # --- Token / memecoin market risk (Solana/pump.fun + any SPL/ERC20) ---
    "rugcheck_mint_authority":
        "Mint authority is still active — supply can be inflated at will. "
        "Revoke mint authority (set to null) before trusting the supply.",
    "mint_authority_active":
        "Mint authority is still active — the supply can be increased, "
        "diluting holders. Revoke it (set to null).",
    "rugcheck_freeze_authority":
        "Freeze authority is still active — balances can be frozen to block "
        "sells. Revoke freeze authority.",
    "freeze_authority_active":
        "Freeze authority is still active — holders can be frozen and "
        "prevented from selling. Revoke it.",
    "rugcheck_liquidity_unlocked":
        "Liquidity is neither locked nor burned — it can be pulled in a "
        "single transaction (a classic rug). Require locked or burned LP.",
    "rugcheck_liquidity_thin":
        "Liquidity is thin — price is easily manipulated and exit is costly. "
        "Verify real depth before trusting the market price.",
    "rugcheck_holder_concentration":
        "A few wallets hold most of the supply — a coordinated sell can "
        "collapse the price. Check the holder distribution.",
    "holder_aggregation":
        "Supply is concentrated in a few related wallets. Treat the circulating "
        "supply and price as fragile.",
    "rugcheck_high_tax":
        "Buy/sell tax is high — returns are eroded and the tax may be "
        "adjustable. Confirm the tax is fixed and reasonable.",
    "rugcheck_extreme_tax":
        "Extreme buy/sell tax — effectively unsellable. Strong honeypot "
        "signal; do not treat as tradeable.",
    "rugcheck_honeypot":
        "Honeypot: buys succeed but sells are blocked or taxed to ~100%. "
        "Do not buy.",
    "honeypot":
        "Honeypot pattern — the contract blocks or punishes selling. Do not "
        "buy; funds entered cannot be withdrawn.",
    "rugcheck_owner_control":
        "The owner retains control that can rug (mint, freeze, tax, or "
        "blacklist). Verify ownership is renounced or timelocked.",
    "creator_share":
        "The creator/dev holds a large share of supply — a dev dump can "
        "crash the price. Size the position against this risk.",
    "mutable_metadata":
        "Token metadata (name, symbol, image, URI) is mutable and can be "
        "changed after launch. Make metadata immutable for trust.",
    "rugcheck_unverified_contract":
        "Source is not verified, so behavior cannot be audited. Treat with "
        "caution until verified source is available.",
    "bytecode_selfdestruct":
        "Bytecode can self-destruct. Obtain verified source and confirm the "
        "SELFDESTRUCT path is access-gated (or removed) before trusting the "
        "contract with value.",
    "bytecode_delegatecall":
        "Bytecode delegatecalls another address. Verify the target is fixed "
        "and trusted (not attacker-settable); get verified source to confirm "
        "the upgrade/library path is guarded.",
    "bytecode_minimal_proxy":
        "This is a minimal proxy; audit the implementation contract it points "
        "to, where the real logic and risk live.",
    "bytecode_unverified":
        "No verified source available. Request/verify source (e.g. via "
        "Sourcify or the explorer) so the contract can be fully audited; "
        "bytecode-only findings are capability facts, not guarantees.",
}


def _norm(f: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a finding from either analyzer into one shape."""
    kind = f.get("kind") or f.get("check") or "finding"
    detector = (f.get("plugin") or f.get("detector") or f.get("source")
                or f.get("rule") or "")
    return {
        "kind": kind,
        "title": f.get("title") or f.get("detail", "")[:80] or kind,
        "severity": (f.get("severity") or "info").lower(),
        "confidence": f.get("confidence"),
        "function": f.get("function") or "",
        "detail": f.get("detail") or f.get("title") or "",
        "code": f.get("code") or "",
        "remediation": f.get("remediation") or _REMEDIATION.get(kind, ""),
        "detectors": [detector] if detector else [],
        "corroboration": 1,
    }


# Corroboration never, on its own, pushes a finding into the confirmed tier -
# that tier is reserved for the live read-only probe. Independent detectors
# agreeing is a real priority signal, so it raises confidence, but the bump is
# capped just below CONFIRMED_MIN (75) unless the base was already there.
_CORROBORATION_BUMP = 5      # per extra detector
_CORROBORATION_CAP = 74      # ceiling reachable by corroboration alone


def _dedupe(norm: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge findings that describe the same issue (same kind + location).

    Multiple plugins flagging one vulnerability collapse into a single
    finding that records how many independent detectors agreed. Keeps the
    worst severity and the highest confidence seen, and the richest
    evidence (longest detail / any code). Order is preserved by first
    appearance; build_report re-sorts afterwards.
    """
    merged: Dict[tuple, Dict[str, Any]] = {}
    order: List[tuple] = []
    for f in norm:
        # Same kind + same function is the same issue. When neither names a
        # function, fall back to the detail text so genuinely distinct
        # findings of the same kind aren't over-merged.
        loc = f["function"] or (f["detail"][:80])
        key = (f["kind"], loc)
        cur = merged.get(key)
        if cur is None:
            merged[key] = dict(f)
            order.append(key)
            continue
        # merge into the existing finding
        if _SEV_ORDER.get(f["severity"], 9) < _SEV_ORDER.get(cur["severity"], 9):
            cur["severity"] = f["severity"]
        if (f["confidence"] or 0) > (cur["confidence"] or 0):
            cur["confidence"] = f["confidence"]
        if len(f["detail"]) > len(cur["detail"]):
            cur["detail"] = f["detail"]
        if f["code"] and not cur["code"]:
            cur["code"] = f["code"]
        if f["remediation"] and not cur["remediation"]:
            cur["remediation"] = f["remediation"]
        for d in f["detectors"]:
            if d not in cur["detectors"]:
                cur["detectors"].append(d)
        cur["corroboration"] += 1

    out: List[Dict[str, Any]] = []
    for key in order:
        f = merged[key]
        extra = f["corroboration"] - 1
        if extra > 0 and f["confidence"] is not None:
            bumped = f["confidence"] + extra * _CORROBORATION_BUMP
            if f["confidence"] < _CORROBORATION_CAP:
                bumped = min(bumped, _CORROBORATION_CAP)
            f["confidence"] = min(bumped, max(f["confidence"], 100))
        out.append(f)
    return out


def build_report(address: str, chain: str, findings: List[Dict[str, Any]],
                 source: Optional[str] = None,
                 probes: Optional[List[Dict[str, Any]]] = None,
                 meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Assemble a structured audit report from scan findings.

    probes: optional list of {finding, verdict, transcript} from the live
    read-only probe. Verdicts are carried verbatim - including
    "unverified"/"could not confirm", which is the honest and common case.
    """
    norm = _dedupe([_norm(f) for f in findings])
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
            corr = ""
            if f.get("corroboration", 1) > 1:
                corr = f" · corroborated by {f['corroboration']} detectors"
            lines.append(f"### {f['id']} — {f['title']}")
            lines.append("")
            lines.append(f"**{_SEV_LABEL.get(f['severity'], f['severity'])}**"
                         f"{loc}{conf}{corr}")
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
    lines.append("For contract source (EVM Solidity, Move, Cairo and "
                 "others): function-level control-flow and access-control "
                 "analysis with drain/takeover pattern detection. For tokens "
                 "and markets (SPL / pump.fun, ERC-20 and equivalents): "
                 "on-chain authority checks (mint/freeze), liquidity "
                 "lock/burn status, holder concentration, creator/dev share "
                 "and honeypot/tax signals, derived from chain RPC and market "
                 "data. All findings are corroborated by a read-only probe "
                 "where possible. No state-changing transactions are sent; "
                 "nothing is drained or modified — detection only.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Batch triage: turn a batch_scan findings file into per-contract audit
# reports plus a ranked triage index - the "run it over a program's scope,
# kill the false positives, hand a human the reports" workflow.
# ---------------------------------------------------------------------------
def _worst_severity(findings: List[Dict[str, Any]]) -> str:
    best = "info"
    for f in findings:
        s = (f.get("severity") or "info").lower()
        if _SEV_ORDER.get(s, 9) < _SEV_ORDER.get(best, 9):
            best = s
    return best


def triage_corpus(findings_path: str, out_dir: str,
                  min_severity: str = "low",
                  min_value_usd: float = 0.0,
                  only_kinds: Optional[set] = None) -> Dict[str, Any]:
    """Read a batch_scan --out JSONL ({address, chain, findings, value_usd?})
    and write one markdown audit report per contract that has a finding at or
    above min_severity, plus an INDEX.md triage summary ranked by risk.

    min_value_usd skips contracts whose realizable value is below the
    threshold - the "nominally has 100k but holds dust" case. A row with no
    value_usd is never skipped on value grounds (we can't assess it). The
    scanner supplies value_usd via valuation.realizable_value_usd().

    only_kinds, when set, keeps only contracts that have at least one finding
    of one of those kinds - e.g. {"guard_convention_break"} to pull just the
    contracts where the zero-day guard detector fired, or
    {"reentrancy", "full_balance_withdraw"} for a specific vuln hunt. The
    report still shows all of that contract's findings for context.
    """
    import json
    import os
    from .valuation import is_dust, value_band

    floor = _SEV_ORDER.get(min_severity.lower(), 3)
    want = {str(k).lower() for k in only_kinds} if only_kinds else None
    skipped_dust = 0
    skipped_kind = 0
    os.makedirs(out_dir, exist_ok=True)
    index: List[Dict[str, Any]] = []
    written = 0
    with open(findings_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings = rec.get("findings") or []
            if not findings:
                continue
            if want is not None:
                kinds = {str(f.get("kind") or f.get("check")
                             or "").lower() for f in findings}
                if not (kinds & want):
                    skipped_kind += 1
                    continue  # doesn't have the vuln class we're hunting
            worst = _worst_severity(findings)
            if _SEV_ORDER.get(worst, 9) > floor:
                continue  # nothing at or above the floor
            value_usd = rec.get("value_usd")
            if min_value_usd > 0 and is_dust(value_usd, min_value_usd):
                skipped_dust += 1
                continue  # real value below threshold - skip the dust
            addr = str(rec.get("address", "unknown"))
            report = build_report(addr, rec.get("chain", ""), findings)
            safe = "".join(c if c.isalnum() or c in "-_" else "_"
                           for c in addr)[:64] or "contract"
            fname = f"{worst}_{safe}.md"
            with open(os.path.join(out_dir, fname), "w",
                      encoding="utf-8") as out:
                out.write(render_markdown(report))
            written += 1
            index.append({"address": addr, "chain": rec.get("chain", ""),
                          "worst": worst, "count": len(findings),
                          "file": fname, "value_usd": value_usd,
                          "band": value_band(value_usd)})

    # Rank by severity first, then by realizable value (so the high-value
    # contracts rise to the top within a severity), then finding count.
    index.sort(key=lambda r: (_SEV_ORDER.get(r["worst"], 9),
                              -(r["value_usd"] or 0.0), -r["count"]))

    def _fmt_val(r: Dict[str, Any]) -> str:
        v = r["value_usd"]
        if v is None:
            return "unknown"
        return f"${float(v):,.0f}"

    idx_lines = ["# Triage Index", "",
                 f"{written} contract(s) with findings at or above "
                 f"`{min_severity}`, ranked by risk.", ""]
    if want is not None:
        idx_lines += [f"_Hunting kinds: {', '.join(sorted(want))} "
                      f"({skipped_kind} contract(s) without them skipped)._",
                      ""]
    if skipped_dust:
        idx_lines += [f"_{skipped_dust} contract(s) skipped as dust "
                      f"(realizable value under ${min_value_usd:,.0f})._", ""]
    idx_lines += [
        "| # | Severity | Value | Findings | Chain | Contract | Report |",
        "| --- | --- | --- | --- | --- | --- | --- |"]
    for i, r in enumerate(index, 1):
        idx_lines.append(
            f"| {i} | {_SEV_LABEL.get(r['worst'], r['worst'])} | {_fmt_val(r)} "
            f"| {r['count']} | {r['chain'] or 'n/a'} | `{r['address'][:20]}` "
            f"| [{r['file']}]({r['file']}) |")
    with open(os.path.join(out_dir, "INDEX.md"), "w",
              encoding="utf-8") as out:
        out.write("\n".join(idx_lines) + "\n")
    return {"reports_written": written, "out_dir": out_dir,
            "skipped_dust": skipped_dust, "skipped_kind": skipped_kind,
            "index": [r["address"] for r in index[:20]]}


def _main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json
    ap = argparse.ArgumentParser(
        description="Turn batch_scan findings into audit reports + triage "
                    "index.")
    ap.add_argument("--findings", required=True,
                    help="JSONL from `batch_scan --out` "
                         "({address, chain, findings})")
    ap.add_argument("--out-dir", required=True,
                    help="directory to write per-contract reports + INDEX.md")
    ap.add_argument("--min-severity", default="low",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="only report contracts with a finding at or above "
                         "this severity (default low)")
    ap.add_argument("--min-value", type=float, default=0.0,
                    help="skip contracts whose realizable value_usd is below "
                         "this (strips 'nominally 100k but dust' contracts; "
                         "rows without value_usd are never skipped)")
    ap.add_argument("--only-kind", default="",
                    help="comma-separated finding kinds to hunt; keep only "
                         "contracts that have one (e.g. guard_convention_break "
                         "for the zero-day, or reentrancy)")
    args = ap.parse_args(argv)
    only = {k.strip() for k in args.only_kind.split(",") if k.strip()} or None
    summary = triage_corpus(args.findings, args.out_dir, args.min_severity,
                            min_value_usd=args.min_value, only_kinds=only)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
