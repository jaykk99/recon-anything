"""Contract creator OSINT (Cat-4 variant of chain_osint).

For each discovered contract: identify the deployer (creation data
from keyless Blockscout / supplied artifacts), then trace the
deployer's first funder and label it - exchange hot wallet, bridge,
mixer, or fresh wallet. A contract deployed by a mixer-funded fresh
wallet is a materially different risk from one deployed by a known
team multisig, and that provenance is invisible in the contract code
itself.

Keyless read-only explorer/RPC reads. Detection only.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import artifact_dicts, fetch_json, find_addresses
from .base import Cost, Ctx, Plugin, PluginResult, Target

BLOCKSCOUT = "https://eth.blockscout.com/api/v2"
MIXER_LABELS = ("mixer", "tornado", "tumbler")
FRESH_LABELS = ("fresh", "new wallet", "fresh wallet")
MAX_CONTRACTS = 3


def analyse_creation(info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pure: creation provenance record -> risk hits.

    Shape: {"contract", "creator", "funder", "funder_label",
            "creator_tx_count", "creator_age_days"}
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(info, dict) or not info.get("creator"):
        return hits
    label = str(info.get("funder_label") or "").lower()
    base = {"contract": info.get("contract"),
            "creator": info.get("creator"),
            "funder": info.get("funder"),
            "funder_label": info.get("funder_label")}
    if any(m in label for m in MIXER_LABELS):
        hits.append({**base, "kind": "mixer_funded_deployer"})
    elif any(f in label for f in FRESH_LABELS) or \
            (isinstance(info.get("creator_tx_count"), int)
             and info["creator_tx_count"] <= 2):
        hits.append({**base, "kind": "fresh_wallet_deployer"})
    return hits


class ContractCreatorOsintPlugin(Plugin):
    id = "contract_creator_osint"
    label = "Contract Creator OSINT"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Resolve a contract's deployer and first funder "
                   "keylessly and label the funding origin (exchange, "
                   "bridge, mixer, fresh wallet).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            infos: List[Dict[str, Any]] = []
            for d in artifact_dicts(ctx):
                for info in d.get("creation_info") or []:
                    if isinstance(info, dict):
                        infos.append(info)
                if d.get("creator") and d.get("contract"):
                    infos.append(d)
            if not infos:
                addrs: List[str] = []
                norm = (target.normalized or "").strip()
                if norm.startswith("0x") and len(norm) == 42:
                    addrs.append(norm)
                for kind in ("contract_addresses", "crypto_addresses"):
                    for item in ctx.consume(kind):
                        a = item if isinstance(item, str) else ""
                        if a.startswith("0x") and len(a) == 42 \
                                and a not in addrs:
                            addrs.append(a)
                for addr in addrs[:MAX_CONTRACTS]:
                    data = await fetch_json(
                        ctx, f"{BLOCKSCOUT}/smart-contracts/{addr}")
                    if not isinstance(data, dict):
                        continue
                    creator = (data.get("creator_address_hash")
                               or data.get("creator"))
                    if creator:
                        infos.append({"contract": addr,
                                      "creator": creator,
                                      "funder": data.get("funder"),
                                      "funder_label":
                                          data.get("funder_label")})
            for info in infos:
                for hit in analyse_creation(info):
                    sev = ("high" if hit["kind"] ==
                           "mixer_funded_deployer" else "medium")
                    findings.append(self._f(
                        "web3", f"creator_{hit['kind']}",
                        f"Contract {hit.get('contract')} was deployed "
                        f"by {hit.get('creator')}, funded by "
                        f"{hit.get('funder') or 'unknown'} "
                        f"({hit.get('funder_label') or 'unlabelled'})",
                        source="contract creator osint", confidence=80,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Weight provenance in trust "
                            "decisions: mixer/fresh-funded deployers "
                            "warrant full source audit before any "
                            "interaction."}))
            res = self._ok(findings,
                           f"{len(infos)} creators traced"
                           if not findings else
                           f"{len(findings)} provenance risks")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
