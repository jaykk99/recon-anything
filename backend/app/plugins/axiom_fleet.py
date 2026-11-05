"""Axiom-style fleet dispatch planner (Tier-5 orchestration).

Axiom's idea: one operator, many workers - a target list and a port
space are SHARDED into per-worker job specs, workers scan in
parallel, and shard outputs are merged and deduped into one result
set. The hard parts are the plan (balanced, deterministic, no target
scanned twice, no target dropped) and the merge.

This plugin produces and validates that shard plan as JSON job specs
and merges shard outputs - no real fleet is needed or claimed:

  * targets come from ctx.shared["axiom_targets"] when provided,
    else the target itself plus subdomains already on the discovery
    bus; ports from ctx.shared["axiom_ports"] (list, or "1-1024"
    range string) else [80, 443]; workers from
    ctx.shared["axiom_workers"] (default 4, clamped 1-64).
  * sharding is deterministic round-robin over the sorted target
    list, so the same inputs always produce the same plan and a
    re-run is diffable; the plan self-validates (every target in
    exactly one shard, no empty shards) and the validation result is
    part of the evidence.
  * shard outputs supplied as ctx.shared["axiom_shard_results"]
    (finding-shaped dicts, as a returning worker would report them)
    are merged and deduped on (key, value) into fleet findings.

A plan is only emitted when there is something to shard - at least
two targets, or shard results to merge. A lone target with no bus
assets stays silent.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List

from ..classifier import domain_from_target
from ._orchestration import consume, shared_get
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _parse_ports(raw: Any) -> List[int]:
    ports: List[int] = []
    if isinstance(raw, str) and "-" in raw:
        try:
            lo, hi = raw.split("-", 1)
            ports = list(range(int(lo), int(hi) + 1))
        except Exception:
            ports = []
    elif isinstance(raw, (list, tuple)):
        for item in raw:
            try:
                ports.append(int(item))
            except Exception:
                continue
    ports = sorted({p for p in ports if 1 <= p <= 65535})
    return ports[:4096] or [80, 443]


def build_shards(targets: List[str], ports: List[int],
                 workers: int) -> List[Dict[str, Any]]:
    """Deterministic round-robin shard plan over sorted targets."""
    ordered = sorted(set(targets))
    n = max(1, min(workers, len(ordered) or 1))
    buckets: List[List[str]] = [[] for _ in range(n)]
    for idx, host in enumerate(ordered):
        buckets[idx % n].append(host)
    shards: List[Dict[str, Any]] = []
    for idx, bucket in enumerate(buckets):
        if not bucket:
            continue
        job_id = hashlib.sha256(
            f"{idx}:{'|'.join(bucket)}:{','.join(map(str, ports))}"
            .encode()).hexdigest()[:12]
        shards.append({"worker": idx, "job_id": job_id,
                       "targets": bucket, "ports": ports,
                       "target_count": len(bucket)})
    return shards


def validate_shards(shards: List[Dict[str, Any]],
                    targets: List[str]) -> Dict[str, Any]:
    assigned: List[str] = []
    for shard in shards:
        assigned.extend(shard.get("targets") or [])
    return {
        "targets_expected": len(set(targets)),
        "targets_assigned": len(assigned),
        "targets_unique": len(set(assigned)),
        "complete": sorted(set(assigned)) == sorted(set(targets)),
        "no_duplicates": len(assigned) == len(set(assigned)),
        "no_empty_shards": all(shard.get("targets") for shard in shards),
    }


class AxiomFleetDispatchPlugin(Plugin):
    id = "axiom_fleet_dispatch"
    label = "Axiom Fleet Dispatch Planner"
    accepts = ["domain", "url", "ip", "cidr"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    phase = 1
    timeout_s = 30
    description = ("Shards a target list / port space into validated "
                   "per-worker job specs (JSON) and merges/dedupes "
                   "shard results. Plan + merge only; no real fleet.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        targets: List[str] = []
        raw_targets = shared_get(ctx, "axiom_targets")
        if isinstance(raw_targets, (list, tuple)):
            targets.extend(str(t) for t in raw_targets if str(t).strip())
        domain = domain_from_target(target.type, target.normalized)
        primary = domain or (target.normalized or "").strip()
        if primary and primary not in targets:
            targets.insert(0, primary)
        for sub in consume(ctx, "subdomains"):
            if isinstance(sub, str) and sub not in targets:
                targets.append(sub)
        targets = [t for t in targets if t]
        ports = _parse_ports(shared_get(ctx, "axiom_ports"))
        try:
            workers = int(shared_get(ctx, "axiom_workers", 4) or 4)
        except Exception:
            workers = 4
        workers = max(1, min(64, workers))

        shard_results = shared_get(ctx, "axiom_shard_results")
        if not isinstance(shard_results, list):
            shard_results = []

        if len(targets) < 2 and not shard_results:
            return self._ok([], "nothing to shard: single target and "
                                "no shard results to merge")
        findings: List[Finding] = []
        if len(targets) >= 2:
            shards = build_shards(targets, ports, workers)
            validation = validate_shards(shards, targets)
            for shard in shards:
                findings.append(self._f(
                    "infra", "fleet_shard_plan",
                    f"Fleet shard {shard['worker']}: "
                    f"{shard['target_count']} targets x "
                    f"{len(ports)} ports (job {shard['job_id']})",
                    source="axiom_fleet_dispatch", confidence=95,
                    evidence={"severity": "low", "shard": shard,
                              "validation": validation,
                              "remediation": "Dispatch each shard job "
                                             "spec to one worker; merge "
                                             "outputs with the fleet "
                                             "merge (dedupe on key + "
                                             "value) before reporting."}))
        if shard_results:
            seen = set()
            merged: List[Dict[str, Any]] = []
            for item in shard_results:
                if not isinstance(item, dict):
                    continue
                key = (str(item.get("key", "")), str(item.get("value", "")))
                if key in seen or not key[1]:
                    continue
                seen.add(key)
                merged.append(item)
            for item in merged[:50]:
                findings.append(self._f(
                    "infra", "fleet_merged_finding",
                    f"Merged shard finding: {item.get('key', 'finding')} "
                    f"= {str(item.get('value', ''))[:160]}",
                    source="axiom_fleet_dispatch", confidence=85,
                    evidence={"severity": str(item.get("severity")
                                              or "low"),
                              "merged": item,
                              "remediation": "Review this merged fleet "
                                             "finding; it survived "
                                             "cross-shard dedupe."}))
            if merged:
                findings.append(self._f(
                    "infra", "fleet_merge_summary",
                    f"Fleet merge: {len(shard_results)} shard results "
                    f"-> {len(merged)} unique findings after dedupe",
                    source="axiom_fleet_dispatch", confidence=95,
                    evidence={"severity": "low",
                              "raw_results": len(shard_results),
                              "unique_results": len(merged),
                              "remediation": "Report the merged set, "
                                             "not per-shard dumps; "
                                             "duplicates across shards "
                                             "are expected overlap."}))
        res = self._ok(findings, f"fleet plan/merge: "
                                 f"{len(targets)} targets, "
                                 f"{len(findings)} findings")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
