"""IPFS gateway resolver (Cat-4 variant of cp_ipfs_cid).

Takes CIDs referenced by the target (or supplied as artifacts),
resolves them keylessly across public gateways (ipfs.io, dweb.link,
cloudflare-ipfs.com), and reports per-CID content availability,
cross-gateway divergence (same CID serving different bytes - an
integrity problem), and content that no gateway can serve.

Read-only GETs of immutable content addresses. Detection only.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List

from ..ratelimit import fetch
from ._cat4_common import all_texts, artifact_dicts
from .base import Cost, Ctx, Plugin, PluginResult, Target

GATEWAYS = ("https://ipfs.io/ipfs/", "https://dweb.link/ipfs/",
            "https://cloudflare-ipfs.com/ipfs/")
CID_RE = re.compile(
    r"(?:ipfs://)?(Qm[1-9A-HJ-NP-Za-km-z]{44}|baf[a-z2-7]{24,60})")
MAX_CIDS = 3


def extract_cids(text: str) -> List[str]:
    out: List[str] = []
    for m in CID_RE.finditer(text or ""):
        cid = m.group(1)
        if cid not in out:
            out.append(cid)
    return out


def analyse_gateway_results(cid: str,
                            results: Dict[str, Dict[str, Any]]
                            ) -> List[Dict[str, Any]]:
    """Pure: per-CID gateway probe results -> integrity hits.

    results maps gateway base URL -> {"status": int, "sha256": str}.
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(results, dict) or not results:
        return hits
    results = {g: r for g, r in results.items() if isinstance(r, dict)}
    if not results:
        return hits
    ok = {g: r for g, r in results.items() if r.get("status") == 200}
    hashes = {r.get("sha256") for r in ok.values() if r.get("sha256")}
    if len(hashes) > 1:
        hits.append({"kind": "gateway_divergence", "cid": cid,
                     "gateways_ok": sorted(ok),
                     "distinct_hashes": len(hashes)})
    if not ok:
        hits.append({"kind": "unavailable_everywhere", "cid": cid,
                     "gateways_tried": sorted(results)})
    return hits


class IpfsGatewayResolverPlugin(Plugin):
    id = "ipfs_gateway_resolver"
    label = "IPFS Gateway Resolver"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Resolve referenced CIDs across public IPFS "
                   "gateways; report availability, cross-gateway "
                   "content divergence and unservable CIDs.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        notes = []
        try:
            cids: List[str] = []
            # Operator-supplied probe results skip live probing.
            supplied: Dict[str, Dict[str, Any]] = {}
            for d in artifact_dicts(ctx):
                for cid, res in (d.get("gateway_results") or {}).items():
                    if isinstance(res, dict):
                        supplied[str(cid)] = res
                        if str(cid) not in cids:
                            cids.append(str(cid))
            for where, text, url in await all_texts(ctx, target):
                for cid in extract_cids(text):
                    if cid not in cids:
                        cids.append(cid)
            for cid in cids[:MAX_CIDS]:
                if cid in supplied:
                    results = supplied[cid]
                else:
                    results = {}
                    for gw in GATEWAYS:
                        try:
                            r = await fetch(ctx.http, ctx.limiter,
                                            "GET", gw + cid, timeout=12,
                                            max_retries=0)
                            body = (r.text or "")[:200000]
                            results[gw] = {
                                "status": r.status_code,
                                "sha256": hashlib.sha256(
                                    body.encode("utf-8", "replace")
                                ).hexdigest() if body else ""}
                        except Exception:
                            results[gw] = {"status": 0, "sha256": ""}
                    if not any(v.get("status") == 200
                               for v in results.values()):
                        notes.append(f"{cid[:16]}: gateways unreachable")
                for hit in analyse_gateway_results(cid, results):
                    sev = ("high" if hit["kind"] == "gateway_divergence"
                           else "medium")
                    findings.append(self._f(
                        "web3", f"ipfs_{hit['kind']}",
                        f"IPFS CID {cid}: {hit['kind'].replace('_', ' ')}"
                        f" across public gateways",
                        source="ipfs gateway resolver", confidence=85,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Pin content with a reputable "
                            "pinning setup and serve it from a gateway "
                            "you control; divergence for one CID means "
                            "a gateway is serving wrong bytes."}))
            res = self._ok(findings,
                           "; ".join(notes) if notes and not findings
                           else (f"{len(findings)} IPFS integrity issues"
                                 if findings else "no CIDs to resolve"))
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
