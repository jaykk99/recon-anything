"""ENS reverse lookup (Cat-4 variant of cp_ens_name).

Reverse direction: for each discovered 0x address, resolve its
primary ENS name keylessly (ENS Ideas public API, backed by public
RPC reverse records) and - the security-relevant part - verify the
name's forward resolution points back at the same address. A reverse
record whose name forwards ELSEWHERE is an identity-spoofing setup:
the address presents as a well-known name it does not control.

Keyless read-only lookups. Detection only.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from ._cat4_common import (artifact_dicts, fetch_json, find_addresses,
                           all_texts)
from .base import Cost, Ctx, Plugin, PluginResult, Target

ENS_API = "https://api.ensideas.com/ens/resolve/"
MAX_ADDR = 5


def analyse_reverse_records(records: List[Dict[str, Any]]
                            ) -> List[Dict[str, Any]]:
    """Pure: reverse-resolution records -> spoofing hits.

    Record shape: {"address": str, "primary_name": str|None,
                   "forward_resolves_to": str|None}
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(records, list):
        return hits
    for rec in records:
        if not isinstance(rec, dict):
            continue
        addr = str(rec.get("address") or "")
        name = rec.get("primary_name")
        fwd = rec.get("forward_resolves_to")
        if name and fwd and addr and \
                str(fwd).lower() != addr.lower():
            hits.append({"kind": "reverse_forward_mismatch",
                         "address": addr, "primary_name": str(name),
                         "forward_resolves_to": str(fwd)})
        elif name and fwd is None and addr:
            hits.append({"kind": "reverse_unverifiable",
                         "address": addr, "primary_name": str(name)})
    return hits


class EnsReverseLookupPlugin(Plugin):
    id = "ens_reverse_lookup"
    label = "ENS Reverse Lookup"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Keyless ENS reverse resolution for discovered "
                   "addresses, with forward-resolution verification "
                   "to catch name-spoofing setups.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            records: List[Dict[str, Any]] = []
            for d in artifact_dicts(ctx):
                for rec in d.get("ens_reverse_records") or []:
                    if isinstance(rec, dict):
                        records.append(rec)
            if not records:
                addrs: List[str] = []
                norm = (target.normalized or "").strip()
                if norm.startswith("0x") and len(norm) == 42:
                    addrs.append(norm)
                for _w, text, _u in await all_texts(ctx, target):
                    for a in find_addresses(text):
                        if a not in addrs:
                            addrs.append(a)
                for addr in addrs[:MAX_ADDR]:
                    data = await fetch_json(ctx, ENS_API + addr)
                    if not isinstance(data, dict):
                        continue
                    name = data.get("name") or data.get("primary")
                    if not name:
                        continue
                    fwd_data = await fetch_json(ctx, ENS_API + str(name))
                    fwd = None
                    if isinstance(fwd_data, dict):
                        fwd = fwd_data.get("address")
                    records.append({"address": addr,
                                    "primary_name": name,
                                    "forward_resolves_to": fwd})
            for hit in analyse_reverse_records(records):
                sev = ("high" if hit["kind"] ==
                       "reverse_forward_mismatch" else "low")
                findings.append(self._f(
                    "web3", f"ens_{hit['kind']}",
                    f"ENS reverse record for {hit['address']} claims "
                    f"{hit['primary_name']}"
                    + (f" but that name resolves forward to "
                       f"{hit.get('forward_resolves_to')}"
                       if hit["kind"] == "reverse_forward_mismatch"
                       else " (forward resolution unavailable)"),
                    source="ens reverse lookup", confidence=85,
                    evidence={
                        "severity": sev, "hit": hit,
                        "remediation": "Do not trust a reverse ENS name "
                        "for identity or payment decisions unless its "
                        "forward resolution matches the address."}))
            res = self._ok(findings,
                           f"{len(records)} reverse records checked"
                           if not findings else
                           f"{len(findings)} ENS spoofing signals")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
