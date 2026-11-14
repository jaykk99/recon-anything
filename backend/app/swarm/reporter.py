"""Reporter: write up the evidence.

The Reporter turns one target's blackboard state into two artifacts:
a human-readable markdown write-up and a machine-readable JSON
record. Both contain the actual probe outputs (return data, revert
messages, balances, bytecode length), not summaries of them: a 200
or a log line is not proof, and neither is a paragraph that says
"probed OK".

The Reporter never upgrades a verdict. The verdict in the write-up
is the LiveProber's verdict, copied verbatim.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional


def _fmt_probe(p: Dict[str, Any]) -> str:
    sig = p.get("signature", "?")
    if p.get("ok"):
        return f"- `{sig}` from stranger: OK, returned `{p.get('result')}`"
    return f"- `{sig}` from stranger: FAILED, `{p.get('error')}`"


def render_report(target: Dict[str, Any], scout: Dict[str, Any],
                  hypothesis: Dict[str, Any], fork: Dict[str, Any],
                  probe: Dict[str, Any]) -> str:
    """Markdown evidence write-up for one target."""
    address = str(target.get("address") or "")
    chain = str(target.get("chain") or "")
    name = scout.get("contract_name") or target.get("name") or "(unnamed)"
    verdict = probe.get("verdict", "UNVERIFIED")
    lines = [
        f"# Swarm evidence: {name}",
        "",
        f"- **Chain:** {chain}",
        f"- **Address:** `{address}`",
        f"- **Verdict:** {verdict}",
        f"- **Generated:** {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"- **Fresh 7d:** {bool(target.get('fresh_7d'))}",
        "",
        "## Scout (what the contract is)",
        "",
        f"- Has bytecode: {scout.get('has_code')} "
        f"({scout.get('bytecode_len', 0)} bytes)",
        f"- Native balance: {scout.get('native_balance_wei', 0)} wei "
        f"({scout.get('native_balance_eth', 0)} ETH)",
        f"- Verified source: {scout.get('has_source')} "
        f"(length {scout.get('source_len', 0)} chars via "
        f"{scout.get('source_via') or 'n/a'})",
        f"- Scan engine: {scout.get('scan_engine')}",
        f"- Findings: {scout.get('findings_count', 0)} "
        f"(worst severity: {scout.get('worst_severity')})",
        f"- Related addresses: {', '.join(scout.get('related_addresses') or []) or 'none'}",
        f"- Related dropped (no code / not contracts): "
        f"{len(scout.get('related_dropped') or [])}",
        "",
        "### View calls (stranger sender, live RPC)",
        "",
    ]
    for label, view in (scout.get("views") or {}).items():
        if view.get("ok"):
            lines.append(
                f"- `{label}`: OK, raw `{view.get('raw')}`, "
                f"uint256={view.get('uint256')}, address={view.get('address')}")
        else:
            lines.append(f"- `{label}`: FAILED, `{view.get('error')}`")
    if scout.get("errors"):
        lines += ["", "### Scout errors", ""] + [
            f"- {e}" for e in scout["errors"]]
    lines += [
        "",
        "## Hypothesizer (the attack story)",
        "",
        f"- Kind: {hypothesis.get('kind')}",
        f"- Story: {hypothesis.get('story')}",
        f"- Function: `{hypothesis.get('function') or 'n/a'}`",
        f"- Recipient: {hypothesis.get('recipient')}",
        f"- Next test: {hypothesis.get('next_test')}",
        f"- Engine: {hypothesis.get('engine')}",
        "",
        "## ForkTester (fork test)",
        "",
        f"- Engine: {fork.get('engine')}",
        f"- Planned sequences: {fork.get('planned_count', 0)}",
        f"- Executed: {fork.get('executed')} "
        f"({fork.get('executed_count', 0)} step outcomes)",
        f"- State carried between steps: {fork.get('state_carried_between_steps')}",
        f"- Note: {fork.get('note')}",
        "",
    ]
    for outcome in fork.get("outcomes") or []:
        fn = outcome.get("function")
        if outcome.get("called"):
            if outcome.get("error"):
                lines.append(
                    f"- `{fn}` ({outcome.get('role')}): called, "
                    f"REVERTED `{outcome.get('error')}`")
            else:
                lines.append(
                    f"- `{fn}` ({outcome.get('role')}): called, "
                    f"returned `{outcome.get('result')}`")
        else:
            lines.append(
                f"- `{fn}` ({outcome.get('role')}): NOT called, "
                f"{outcome.get('reason')}")
    lines += [
        "",
        "## LiveProber (live read-only probes, stranger sender)",
        "",
        f"- Sender: `{probe.get('sender')}` (unfunded stranger, no keys)",
        f"- Candidates built: {len(probe.get('candidates') or [])}",
        f"- Verdicts: {json.dumps(probe.get('verdicts') or [])}",
        "",
    ]
    for p in probe.get("probes") or []:
        lines.append(_fmt_probe(p))
    if probe.get("validator_error"):
        lines += ["", f"- Validator: {probe['validator_error']}"]
    if probe.get("trigger_only_reason"):
        lines += ["", f"- Trigger-only: {probe['trigger_only_reason']}"]
    lines += [
        "",
        "## Rules compliance",
        "",
        "- Detection only; no transaction sent, no funds moved.",
        "- Live probes are read-only eth_call from the unfunded stranger.",
        "- Fork outcomes are analysis signal only, never proof; "
        "VERIFIED_REAL can only arrive via the validator path.",
        "- crypto.com was never a target.",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_record(target: Dict[str, Any], scout: Dict[str, Any],
                  hypothesis: Dict[str, Any], fork: Dict[str, Any],
                  probe: Dict[str, Any],
                  metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Machine-readable evidence record for one target."""
    return {
        "target": {k: target.get(k) for k in
                   ("chain", "address", "name", "fresh_7d", "block",
                    "first_seen_utc", "creator", "tx_hash")},
        "verdict": probe.get("verdict", "UNVERIFIED"),
        "scout": scout,
        "hypothesis": hypothesis,
        "fork": fork,
        "probe": probe,
        "metrics": metrics or {},
    }


class ReporterAgent:
    """Role agent: write the evidence files for one target."""

    name = "reporter"

    def run(self, target: Dict[str, Any], board: Any,
            out_dir: Optional[str] = None,
            metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        key = (f"{str(target.get('chain') or '').lower()}:"
               f"{str(target.get('address') or '').lower()}")
        scout = board.get(key, "scout") or {}
        hypothesis = board.get(key, "hypothesis") or {}
        fork = board.get(key, "fork") or {}
        probe = board.get(key, "probe") or {}
        md = render_report(target, scout, hypothesis, fork, probe)
        record = render_record(target, scout, hypothesis, fork, probe, metrics)
        result: Dict[str, Any] = {
            "agent": self.name, "key": key,
            "verdict": probe.get("verdict", "UNVERIFIED"),
            "markdown": md, "record": record,
            "files": [], "write_errors": [],
        }
        if out_dir:
            slug = f"{str(target.get('chain') or 'chain')}-" \
                   f"{str(target.get('address') or 'addr')[:10]}"
            md_path = os.path.join(out_dir, f"swarm-evidence-{slug}.md")
            json_path = os.path.join(out_dir, f"swarm-evidence-{slug}.json")
            try:
                os.makedirs(out_dir, exist_ok=True)
                with open(md_path, "w", encoding="utf-8") as f:
                    f.write(md)
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(record, f, indent=2, default=str)
                result["files"] = [md_path, json_path]
            except Exception as e:  # noqa: BLE001 - report, don't crash
                result["write_errors"].append(
                    f"{type(e).__name__}: {e}")
        board.post(self.name, key, "report", {
            "verdict": result["verdict"], "files": result["files"],
            "write_errors": result["write_errors"]})
        return result
