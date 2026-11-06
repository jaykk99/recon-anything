"""Gnosis Safe multisig audit (Cat-4 variant).

Live Safe state audit: for a discovered Safe address, read owners,
threshold, nonce, enabled modules and guard keylessly (Safe client
API, or operator-supplied state artifacts) and flag risky
configurations - threshold 1 (any single owner can drain), enabled
modules (which bypass the threshold entirely), unknown guards, and
backlogs of pending unexecuted transactions.

Keyless read-only API reads. Detection only.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import artifact_dicts, fetch_json
from .base import Cost, Ctx, Plugin, PluginResult, Target

SAFE_API = ("https://safe-transaction-mainnet.safe.global/api/v1"
            "/safes/{addr}/")
PENDING_BACKLOG = 3


def audit_safe_state(state: Any) -> List[Dict[str, Any]]:
    """Pure: Safe state dict -> risky-configuration hits.

    Shape: {"address","owners":[],"threshold":int,"nonce":int,
            "modules":[],"guard":str|None,"pending_txs":int}
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(state, dict):
        return hits
    owners = state.get("owners") or []
    try:
        threshold = int(state.get("threshold") or 0)
    except (TypeError, ValueError):
        threshold = 0
    base = {"address": state.get("address"),
            "owners_count": len(owners), "threshold": threshold}
    if threshold == 1 and len(owners) > 1:
        hits.append({**base, "kind": "threshold_one_multisig"})
    if threshold == 1 and len(owners) == 1:
        hits.append({**base, "kind": "single_owner_safe"})
    if threshold > len(owners) and owners:
        hits.append({**base, "kind": "threshold_exceeds_owners"})
    modules = state.get("modules") or []
    for mod in modules[:6]:
        hits.append({**base, "kind": "module_enabled",
                     "module": mod if isinstance(mod, str)
                     else str(mod)})
    if state.get("guard"):
        hits.append({**base, "kind": "guard_set",
                     "guard": state.get("guard")})
    try:
        pending = int(state.get("pending_txs") or 0)
    except (TypeError, ValueError):
        pending = 0
    if pending >= PENDING_BACKLOG:
        hits.append({**base, "kind": "pending_tx_backlog",
                     "pending_txs": pending})
    return hits


class GnosisSafeMultisigAuditPlugin(Plugin):
    id = "gnosis_safe_multisig_audit"
    label = "Gnosis Safe Multisig Audit"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Audit a live Safe's owners, threshold, modules "
                   "and guard keylessly; flag threshold-1, enabled "
                   "modules, unknown guards, pending backlogs.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            states: List[Dict[str, Any]] = []
            for d in artifact_dicts(ctx):
                for s in d.get("safe_states") or []:
                    if isinstance(s, dict):
                        states.append(s)
                if d.get("owners") and d.get("threshold") is not None:
                    states.append(d)
            if not states:
                addrs: List[str] = []
                norm = (target.normalized or "").strip()
                if norm.startswith("0x") and len(norm) == 42:
                    addrs.append(norm)
                for kind in ("contract_addresses", "crypto_addresses"):
                    for item in ctx.consume(kind):
                        if isinstance(item, str) and \
                                item.startswith("0x") and \
                                len(item) == 42 and item not in addrs:
                            addrs.append(item)
                for addr in addrs[:3]:
                    data = await fetch_json(
                        ctx, SAFE_API.format(addr=addr))
                    if isinstance(data, dict) and data.get("owners"):
                        data.setdefault("address", addr)
                        states.append(data)
            sev_map = {"threshold_one_multisig": "high",
                       "single_owner_safe": "high",
                       "module_enabled": "medium",
                       "threshold_exceeds_owners": "medium",
                       "guard_set": "low",
                       "pending_tx_backlog": "low"}
            for state in states[:5]:
                for hit in audit_safe_state(state):
                    findings.append(self._f(
                        "web3", f"safe_{hit['kind']}",
                        f"Safe {hit.get('address')}: "
                        f"{hit['kind'].replace('_', ' ')} "
                        f"(threshold {hit['threshold']} of "
                        f"{hit['owners_count']} owners"
                        f"{', module ' + str(hit['module']) if hit.get('module') else ''}"
                        f"{', guard ' + str(hit['guard']) if hit.get('guard') else ''})",
                        source="gnosis safe multisig audit",
                        confidence=90,
                        evidence={
                            "severity": sev_map.get(hit["kind"], "low"),
                            "hit": hit,
                            "remediation": "Raise the threshold, "
                            "remove modules you cannot name, and clear "
                            "the pending queue; a module or a 1-of-n "
                            "threshold defeats the multisig."}))
            res = self._ok(findings,
                           f"{len(states)} Safes audited"
                           if not findings else
                           f"{len(findings)} Safe config risks")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
