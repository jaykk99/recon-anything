"""Agent evidence ledger: hash-chain integrity audit of a supplied log.

Verifies a tamper-evident evidence ledger (entries carrying timestamp,
plugin id, target, finding key, SHA-256 of evidence, and the hash of the
previous entry). This is an integrity AUDIT only: it recomputes hashes
and checks linkage; it never writes a ledger to disk. Broken links,
tampered evidence and missing hash fields are findings. Pure local
computation over supplied data, keyless.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def entry_hash(entry: Dict[str, Any]) -> str:
    """Canonical SHA-256 of an entry's assertion fields."""
    canon = {k: entry.get(k) for k in
             ("timestamp", "plugin_id", "target", "key", "evidence")}
    blob = json.dumps(canon, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def build_ledger(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build a hash-chained ledger from finding dicts (pure)."""
    out: List[Dict[str, Any]] = []
    prev = "GENESIS"
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        e = {"timestamp": str(f.get("timestamp", "")),
             "plugin_id": str(f.get("plugin_id", "")),
             "target": str(f.get("target", "")),
             "key": str(f.get("key", "")),
             "evidence": f.get("evidence", {})}
        e["prev_hash"] = prev
        e["hash"] = entry_hash(e)
        prev = e["hash"]
        out.append(e)
    return out


def analyze_ledger(entries: Any) -> List[Dict[str, Any]]:
    """Audit ledger entries; one row per integrity defect."""
    rows: List[Dict[str, Any]] = []
    if not isinstance(entries, list):
        return rows
    prev_hash = None
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            rows.append({"key": "ledger_malformed_entry",
                         "value": f"Ledger entry #{i} is not an object",
                         "severity": "medium",
                         "evidence": {"index": i}})
            continue
        h = e.get("hash")
        ph = e.get("prev_hash")
        if not h or not ph:
            rows.append({"key": "ledger_missing_hash",
                         "value": f"Ledger entry #{i} ({e.get('plugin_id', '?')}/"
                                  f"{e.get('key', '?')}) is missing hash linkage fields",
                         "severity": "high",
                         "evidence": {"index": i,
                                      "plugin_id": e.get("plugin_id", "")}})
            prev_hash = h
            continue
        try:
            actual = entry_hash(e)
        except Exception:
            actual = None
        if actual != h:
            rows.append({"key": "ledger_tampered_entry",
                         "value": f"Ledger entry #{i} ({e.get('plugin_id', '?')}/"
                                  f"{e.get('key', '?')}) hash does not match its "
                                  f"contents: evidence was altered after chaining",
                         "severity": "high",
                         "evidence": {"index": i, "stored_hash": str(h)[:16],
                                      "plugin_id": e.get("plugin_id", "")}})
        if prev_hash is not None and ph != prev_hash:
            rows.append({"key": "ledger_broken_chain",
                         "value": f"Ledger entry #{i} prev_hash does not match "
                                  f"entry #{i - 1} hash: chain is broken "
                                  f"(entries removed, reordered or inserted)",
                         "severity": "high",
                         "evidence": {"index": i,
                                      "plugin_id": e.get("plugin_id", "")}})
        prev_hash = h
    return rows


class AgentEvidenceLedgerPlugin(Plugin):
    id = "agent_evidence_ledger"
    label = "Agent Evidence Ledger"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Verify hash-chain/timeline integrity of a supplied "
                   "evidence ledger; flag tampered or unlinked entries.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            entries: Any = []
            for kind in ("evidence_ledger", "ledger"):
                got = ctx.consume(kind)
                if got:
                    entries = got[0] if len(got) == 1 and isinstance(got[0], list) else got
                    break
            rows = analyze_ledger(entries)
        except Exception as exc:  # never raise fatally
            return self._degraded(f"ledger audit failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Evidence ledger audit",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Rebuild the ledger from the "
                                             "original findings, re-chain it, "
                                             "and investigate the gap before "
                                             "relying on this evidence.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"ledger defects: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
