"""Tally proposal decoder (Cat-4 SHIP).

Decodes live DAO proposal execution payloads (Governor proposals,
as surfaced by Tally or supplied as artifacts): targets, ETH values,
declared signatures and calldata selectors are decoded into readable
actions, and the payload is checked against what it CLAIMS to do -
hidden treasury transfers, approval grants, and proxy-upgrade
payloads riding inside innocuously-titled proposals are flagged.

Keyless: local selector decoding of supplied/on-chain-read proposal
data. Read-only. Detection only.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import (APPROVAL_SELECTORS, VALUE_MOVING_SELECTORS,
                           artifact_dicts, selector_name)
from .base import Cost, Ctx, Plugin, PluginResult, Target

UPGRADE_SELECTORS = {"3659cfe6", "4f1ef286", "99a88ec4", "9623609d"}
TREASURY_VALUE_WEI = 10 ** 18  # 1 ETH


def _fn_name(signature: str) -> str:
    return (signature or "").split("(")[0].strip().lower()


def decode_proposal(proposal: Any) -> List[Dict[str, Any]]:
    """Pure: Governor proposal dict -> decoded-action risk hits.

    Shape: {"id","title","targets":[],"values":[],"signatures":[],
            "calldatas":[]}
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(proposal, dict):
        return hits
    targets = proposal.get("targets") or []
    values = proposal.get("values") or []
    sigs = proposal.get("signatures") or []
    datas = proposal.get("calldatas") or []
    n = max(len(targets), len(datas))
    for i in range(min(n, 50)):
        target = targets[i] if i < len(targets) else ""
        data = str(datas[i] if i < len(datas) else "")
        sig = str(sigs[i] if i < len(sigs) else "")
        try:
            value = int(str(values[i]), 0) if i < len(values) else 0
        except (TypeError, ValueError):
            value = 0
        sel = data.replace("0x", "")[:8].lower()
        known = selector_name(sel)
        base = {"index": i, "target": target, "signature": sig,
                "selector": "0x" + sel, "decoded": known,
                "value_wei": value,
                "proposal": proposal.get("id"),
                "title": str(proposal.get("title") or "")[:80]}
        if sel in UPGRADE_SELECTORS:
            hits.append({**base, "kind": "upgrade_payload"})
        elif sel in APPROVAL_SELECTORS:
            hits.append({**base, "kind": "approval_payload"})
        elif sel in VALUE_MOVING_SELECTORS:
            hits.append({**base, "kind": "value_transfer_payload"})
        elif value >= TREASURY_VALUE_WEI:
            hits.append({**base, "kind": "large_treasury_value"})
        if sig and known and _fn_name(sig) and \
                _fn_name(known) != _fn_name(sig):
            hits.append({**base, "kind": "signature_calldata_mismatch"})
    return hits


class TallyProposalDecoderPlugin(Plugin):
    id = "tally_proposal_decoder"
    label = "Tally / Governor Proposal Decoder"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Decode Governor/Tally proposal calldata into "
                   "readable actions; flag hidden treasury, approval "
                   "and upgrade payloads and signature mismatches.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            proposals: List[Any] = []
            for d in artifact_dicts(ctx):
                if d.get("targets") or d.get("calldatas"):
                    proposals.append(d)
                for p in d.get("proposals") or []:
                    if isinstance(p, dict):
                        proposals.append(p)
            for proposal in proposals[:5]:
                for hit in decode_proposal(proposal):
                    sev = ("high" if hit["kind"] in
                           ("upgrade_payload", "approval_payload",
                            "signature_calldata_mismatch") else "medium")
                    findings.append(self._f(
                        "web3", f"proposal_{hit['kind']}",
                        f"Proposal {hit.get('proposal')} action "
                        f"#{hit['index']} on {hit['target']}: "
                        f"{hit['kind'].replace('_', ' ')} - declared "
                        f"'{hit['signature']}' decodes as "
                        f"{hit['decoded'] or hit['selector']}"
                        f" (value {hit['value_wei']} wei)",
                        source="tally proposal decoder", confidence=90,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Vote only on proposals whose "
                            "every action you have decoded yourself; "
                            "a mismatch between title/signature and "
                            "calldata is a governance attack pattern."}))
            res = self._ok(findings,
                           f"{len(proposals)} proposals decoded"
                           if not findings else
                           f"{len(findings)} hidden proposal payloads")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
