"""Tor RPC node scanner (Cat-4 variant of crypto_infra_rpc).

Tor-specific lane: takes .onion RPC endpoints referenced by the
target (or supplied probe results from the operator's own Tor
client) and grades them read-only - chain, client version, exposed
rpc_modules, CORS posture. An anonymised node exposing admin/debug/
personal namespaces is the critical shape: its operator cannot be
traced, and neither can whoever abuses it.

This environment has no Tor client, so live .onion probing degrades
cleanly to 'needs Tor probe data'; supplied probe results are fully
analysed. Detection only.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ._cat4_common import all_texts, artifact_dicts
from .base import Cost, Ctx, Plugin, PluginResult, Target

ONION_RE = re.compile(
    r"(?:https?://)?([a-z2-7]{16,56}\.onion)(?::(\d+))?(/[^\s'\"`]*)?")
DANGEROUS_MODULES = {"admin", "debug", "personal", "miner", "txpool"}


def extract_onion_endpoints(text: str) -> List[str]:
    out: List[str] = []
    for m in ONION_RE.finditer(text or ""):
        ep = m.group(1)
        if ep not in out:
            out.append(ep)
    return out


def analyse_onion_probe(probe: Any) -> List[Dict[str, Any]]:
    """Pure: one .onion RPC probe result -> exposure hits.

    Shape: {"endpoint","chain","client_version","modules":[],
            "cors_origin": str|None}
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(probe, dict) or not probe.get("endpoint"):
        return hits
    modules = {str(m).lower() for m in probe.get("modules") or []}
    dangerous = sorted(modules & DANGEROUS_MODULES)
    base = {"endpoint": probe.get("endpoint"),
            "chain": probe.get("chain"),
            "client_version": probe.get("client_version"),
            "modules": sorted(modules)}
    if dangerous:
        hits.append({**base, "kind": "dangerous_rpc_modules",
                     "dangerous": dangerous})
    if probe.get("cors_origin") == "*":
        hits.append({**base, "kind": "wildcard_cors"})
    return hits


class TorRpcNodeScannerPlugin(Plugin):
    id = "tor_rpc_node_scanner"
    label = "Tor (.onion) RPC Node Scanner"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Grade .onion RPC endpoints referenced by the "
                   "target: exposed rpc_modules (admin/debug/personal) "
                   "and CORS, from supplied Tor probe results.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            probes: List[Dict[str, Any]] = []
            for d in artifact_dicts(ctx):
                for p in d.get("onion_rpc_probes") or []:
                    if isinstance(p, dict):
                        probes.append(p)
            endpoints: List[str] = []
            for _w, text, _u in await all_texts(ctx, target):
                for ep in extract_onion_endpoints(text):
                    if ep not in endpoints:
                        endpoints.append(ep)
            probed_eps = {str(p.get("endpoint")) for p in probes}
            for ep in endpoints:
                if ep not in probed_eps:
                    findings.append(self._f(
                        "web3", "onion_rpc_endpoint_referenced",
                        f"Target references a Tor .onion RPC endpoint: "
                        f"{ep} (grading needs operator Tor probe data)",
                        source="tor rpc node scanner", confidence=70,
                        evidence={
                            "severity": "medium", "hit": {"endpoint": ep},
                            "remediation": "Treat anonymised RPC "
                            "endpoints as untrusted: responses cannot "
                            "be attributed and may be manipulated."}))
            sev_map = {"dangerous_rpc_modules": "high",
                       "wildcard_cors": "medium"}
            for probe in probes[:10]:
                for hit in analyse_onion_probe(probe):
                    findings.append(self._f(
                        "web3", f"onion_rpc_{hit['kind']}",
                        f".onion RPC {hit['endpoint']}: "
                        f"{hit['kind'].replace('_', ' ')} - modules "
                        f"{', '.join(hit['modules'])}"
                        f"{' (dangerous: ' + ', '.join(hit.get('dangerous', [])) + ')' if hit.get('dangerous') else ''}",
                        source="tor rpc node scanner", confidence=90,
                        evidence={
                            "severity": sev_map.get(hit["kind"], "low"),
                            "hit": hit,
                            "remediation": "Never expose admin/debug/"
                            "personal namespaces on any RPC endpoint, "
                            "anonymised or not; anyone can drive the "
                            "node with them."}))
            res = self._ok(findings,
                           "no .onion RPC endpoints found"
                           if not findings else
                           f"{len(findings)} .onion RPC signals")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
