"""OWASP Amass-style asset change tracking (Tier-5 orchestration).

One-shot enumeration answers "what exists now". TRACKING answers
the monitoring question: "what CHANGED since last time" - the new
subdomain nobody reviewed, the IP that disappeared, the asset that
appeared outside any change window. That diff is the Amass tracker
function, and it is genuinely distinct from enumeration itself.

This plugin takes a previous enumeration snapshot
(ctx.shared["amass_previous_snapshot"]: {"subdomains": [...],
"ips": [...]}, as a prior run or a fixture would store it), runs a
fresh enumeration (downstream plugins, default passive_subdomains,
plus whatever the discovery bus already holds), and reports the
diff: asset_added and asset_removed findings per asset, and one
change summary. Additions are graded medium - new attack surface
that arrived unreviewed is exactly what monitoring exists to catch.

No previous snapshot means no diff is possible: the plugin stays
silent and says so in its reason (baseline establishment is the
caller's job - BBRF store in this tier can hold it). A snapshot that
matches the fresh run exactly is a clean result: silent.
Malformed snapshots degrade to ok(0), never a crash.
"""
from __future__ import annotations

import time
from typing import Dict, List, Set

from ..classifier import domain_from_target
from ._orchestration import collect_findings, consume, override_for, \
    run_downstream, shared_get
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _string_set(raw) -> Set[str]:
    out: Set[str] = set()
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            if isinstance(item, str) and item.strip():
                out.add(item.strip().lower())
    return out


class AmassAssetTrackerPlugin(Plugin):
    id = "amass_asset_tracker"
    label = "Amass Asset Change Tracker"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 2
    timeout_s = 90
    description = ("Compares a stored previous enumeration snapshot "
                   "against a fresh enum run and reports added/removed "
                   "subdomains and IPs (monitoring, not one-shot enum).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        snapshot = shared_get(ctx, "amass_previous_snapshot")
        if snapshot is None:
            return self._ok([], "no previous snapshot provided; "
                                "change tracking needs a baseline")
        if not isinstance(snapshot, dict):
            return self._ok([], "previous snapshot malformed: "
                                "expected a mapping")
        prev_subs = _string_set(snapshot.get("subdomains"))
        prev_ips = _string_set(snapshot.get("ips"))
        if not prev_subs and not prev_ips and snapshot:
            # A snapshot with unrecognised shape only: treat as empty
            # baseline only when the caller explicitly emptied it.
            if not snapshot.get("subdomains") and not snapshot.get("ips"):
                return self._ok([], "previous snapshot has no "
                                    "subdomains/ips lists")

        modules = override_for(ctx, "amass_tracker_modules")
        if not (isinstance(modules, (list, tuple)) and modules):
            modules = ["passive_subdomains"]
        records = await run_downstream(
            ctx, target, [str(m) for m in modules], cap=4)
        fresh_subs = _string_set(consume(ctx, "subdomains"))
        fresh_ips = _string_set(consume(ctx, "ips"))
        for f in collect_findings(records):
            if getattr(f, "key", "") == "subdomain":
                fresh_subs.add(str(f.value).strip().lower())
            val = str(getattr(f, "value", "") or "")
            if val and all(c.isdigit() or c == "." for c in val):
                fresh_ips.add(val)

        added_subs = sorted(fresh_subs - prev_subs)
        removed_subs = sorted(prev_subs - fresh_subs)
        added_ips = sorted(fresh_ips - prev_ips)
        removed_ips = sorted(prev_ips - fresh_ips)
        if not (added_subs or removed_subs or added_ips or removed_ips):
            res = self._ok([], "amass tracker: no changes vs snapshot "
                               f"({len(fresh_subs)} subdomains, "
                               f"{len(fresh_ips)} IPs)")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        for sub in added_subs[:40]:
            findings.append(self._f(
                "graph", "asset_added",
                f"New subdomain since last snapshot: {sub}",
                source="amass_asset_tracker", confidence=85,
                evidence={"severity": "medium", "asset": sub,
                          "kind": "subdomain",
                          "remediation": "Review new subdomains the "
                                         "moment they appear: confirm "
                                         "ownership, intended exposure "
                                         "and patch level before they "
                                         "become shadow IT."}))
        for ip in added_ips[:40]:
            findings.append(self._f(
                "graph", "asset_added",
                f"New IP since last snapshot: {ip}",
                source="amass_asset_tracker", confidence=85,
                evidence={"severity": "medium", "asset": ip,
                          "kind": "ip",
                          "remediation": "Confirm this IP is an "
                                         "intended part of the surface "
                                         "and is inventoried."}))
        for sub in removed_subs[:40]:
            findings.append(self._f(
                "graph", "asset_removed",
                f"Subdomain gone since last snapshot: {sub}",
                source="amass_asset_tracker", confidence=80,
                evidence={"severity": "low", "asset": sub,
                          "kind": "subdomain",
                          "remediation": "Confirm the removal was "
                                         "intended; dangling DNS for "
                                         "removed assets is a takeover "
                                         "risk - clean the records."}))
        for ip in removed_ips[:40]:
            findings.append(self._f(
                "graph", "asset_removed",
                f"IP gone since last snapshot: {ip}",
                source="amass_asset_tracker", confidence=80,
                evidence={"severity": "low", "asset": ip, "kind": "ip",
                          "remediation": "Confirm the removal was "
                                         "intended and no DNS still "
                                         "points at the released IP."}))
        findings.append(self._f(
            "graph", "asset_change_summary",
            f"Asset changes for {domain}: +{len(added_subs)} "
            f"subdomains, -{len(removed_subs)} subdomains, "
            f"+{len(added_ips)} IPs, -{len(removed_ips)} IPs",
            source="amass_asset_tracker", confidence=90,
            evidence={"severity": "medium" if added_subs or added_ips
                                  else "low",
                      "added_subdomains": added_subs,
                      "removed_subdomains": removed_subs,
                      "added_ips": added_ips, "removed_ips": removed_ips,
                      "remediation": "Diff every scan against the last "
                                     "snapshot; unexplained additions "
                                     "are the highest-value monitoring "
                                     "signal there is."}))
        res = self._ok(findings, f"tracker diff: +{len(added_subs) + len(added_ips)} "
                                 f"-{len(removed_subs) + len(removed_ips)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
