"""Delta detection engine: what CHANGED between two runs.

app/diff.py already diffs one run's findings against another's.
This module is the asset-level half, built on the knowledge store
(app/knowledge_store.py): it compares the previous completed run
for a target scope against the latest one and emits structured
delta records in the monitoring format:

    + NEW_SUBDOMAIN        api.example.com
    - REMOVED_ENDPOINT     https://example.com/old-admin
    ~ CHANGED_TLS_CERTIFICATE  example.com: <old> -> <new>

Entry points (diff-style, per Jay's brief):
    diff(store, scope, run_old=None, run_new=None) -> dict
    diff_scope(store, scope)  -> same, latest two runs
    format_delta(result)      -> the + / - / ~ lines as text

Changed fields tracked, from per-run observation snapshots:
tech_stack, tls_certificate, tls_issuer, tls_expires, http_status,
ports, resolved_ip. An asset present in the newer run but not the
older is NEW; present in the older but not the newer is REMOVED.
Assets are only compared within one scope, and a scope with fewer
than two completed runs yields an explicit empty delta with a
reason - never a fabricated "everything is new" firehose (that
case is reported as baseline_only so callers can decide).
"""
from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

from .knowledge_store import KnowledgeStore

# observation kind -> (label field name) for CHANGED records
_CHANGED_FIELDS = {
    "tech": "TECH_STACK",
    "tls_certificate": "TLS_CERTIFICATE",
    "tls_issuer": "TLS_ISSUER",
    "tls_expires": "TLS_EXPIRES",
    "http_status": "HTTP_STATUS",
    "port": "PORTS",
    "resolved_ip": "RESOLVED_IP",
}
_SYMBOLS = {"new": "+", "removed": "-", "changed": "~"}


def _record(change: str, label: str, asset: Dict, **extra) -> Dict[str, Any]:
    rec = {
        "change": change,
        "symbol": _SYMBOLS[change],
        "label": label,
        "asset_kind": asset.get("kind"),
        "asset": asset.get("value"),
        "scope": asset.get("scope"),
    }
    rec.update(extra)
    return rec


def diff(store: KnowledgeStore, scope: str,
         run_old: Optional[str] = None,
         run_new: Optional[str] = None) -> Dict[str, Any]:
    """Asset-level delta for one scope between two completed runs.

    With no run ids, uses the latest two completed runs for the
    scope (previous -> latest)."""
    runs = store.runs_for_scope(scope)
    run_ids = [r["run_id"] for r in runs]
    if run_new is None and run_ids:
        run_new = run_ids[-1]
    if run_old is None:
        older = [r for r in run_ids if r != run_new]
        run_old = older[-1] if older else None
    base = {"scope": scope, "from_run": run_old, "to_run": run_new,
            "records": [], "counts": {"new": 0, "removed": 0, "changed": 0}}
    if run_new is None:
        base["reason"] = "no completed runs for scope"
        return base
    if run_old is None:
        base["reason"] = "baseline_only: no previous completed run"
        return base

    old_assets = store.asset_presence(scope, run_old)
    new_assets = store.asset_presence(scope, run_new)
    records: List[Dict[str, Any]] = []

    for aid, asset in new_assets.items():
        if aid not in old_assets:
            records.append(_record(
                "new", f"NEW_{str(asset.get('kind') or 'asset').upper()}",
                asset))
    for aid, asset in old_assets.items():
        if aid not in new_assets:
            records.append(_record(
                "removed",
                f"REMOVED_{str(asset.get('kind') or 'asset').upper()}",
                asset))
    for aid in old_assets.keys() & new_assets.keys():
        asset = new_assets[aid]
        old_snap = store.observation_snapshot(aid, run_old)
        new_snap = store.observation_snapshot(aid, run_new)
        for kind, field in _CHANGED_FIELDS.items():
            old_vals = old_snap.get(kind, [])
            new_vals = new_snap.get(kind, [])
            if old_vals != new_vals and (old_vals or new_vals):
                records.append(_record(
                    "changed", f"CHANGED_{field}", asset,
                    field=field.lower(),
                    old=old_vals, new=new_vals))

    order = {"new": 0, "changed": 1, "removed": 2}
    records.sort(key=lambda r: (order[r["change"]], r["label"],
                                str(r["asset"])))
    counts = {"new": 0, "removed": 0, "changed": 0}
    for r in records:
        counts[r["change"]] += 1
    base["records"] = records
    base["counts"] = counts
    return base


def diff_scope(store: KnowledgeStore, scope: str) -> Dict[str, Any]:
    """diff(previous_db) style entry: latest two completed runs."""
    return diff(store, scope)


def format_delta(result: Dict[str, Any]) -> str:
    lines = []
    for r in result.get("records", []):
        line = f"{r['symbol']} {r['label']} {r['asset']}"
        if r["change"] == "changed":
            line += f": {r.get('old')} -> {r.get('new')}"
        lines.append(line)
    if not lines and result.get("reason"):
        return f"(no delta: {result['reason']})"
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m app.delta <scope> [--db PATH]")
        return 2
    scope = argv[0]
    path = None
    if "--db" in argv:
        path = argv[argv.index("--db") + 1]
    store = KnowledgeStore(path)
    result = diff_scope(store, scope)
    print(f"delta for {scope}: {result['counts']} "
          f"({result['from_run']} -> {result['to_run']})")
    print(format_delta(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
