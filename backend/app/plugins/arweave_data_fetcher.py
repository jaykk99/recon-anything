"""Arweave data fetcher (Cat-4 SHIP).

Finds Arweave transaction IDs / ar:// references in target pages,
bundles and supplied artifacts, fetches the permanently-stored
payload keylessly from public Arweave gateways, and flags the
recon-relevant cases: a mirrored copy of the frontend source living
forever on Arweave, and mirrored content that DIVERGES from the live
site (an old build, a fork, or a phishing twin that can never be
taken down).

Keyless read-only GETs (arweave.net gateway). Detection only.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ..ratelimit import fetch
from ._cat4_common import all_texts
from .base import Cost, Ctx, Plugin, PluginResult, Target

GATEWAY = "https://arweave.net/"
AR_REF_RE = re.compile(r"ar://([A-Za-z0-9_\-]{43})")
TXID_RE = re.compile(
    r"(?:arweave\.net|ar-io\.net|tx/)([A-Za-z0-9_\-]{43})")
MAX_TX = 3


def extract_arweave_refs(text: str) -> List[str]:
    out: List[str] = []
    for pat in (AR_REF_RE, TXID_RE):
        for m in pat.finditer(text or ""):
            if m.group(1) not in out:
                out.append(m.group(1))
    return out


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


def analyse_mirror(live_text: str, mirrored_text: str,
                   txid: str) -> List[Dict[str, Any]]:
    """Pure: compare a live page with its Arweave mirror."""
    hits: List[Dict[str, Any]] = []
    if not mirrored_text or not isinstance(mirrored_text, str):
        return hits
    looks_frontend = ("<html" in mirrored_text.lower()
                      or "<script" in mirrored_text.lower()
                      or "function" in mirrored_text)
    if not looks_frontend:
        return hits
    live_n, mir_n = _norm(live_text), _norm(mirrored_text)
    if live_n and mir_n and live_n != mir_n:
        hits.append({"kind": "mirror_divergence", "txid": txid,
                     "live_len": len(live_n), "mirror_len": len(mir_n)})
    else:
        hits.append({"kind": "frontend_mirror_found", "txid": txid,
                     "mirror_len": len(mir_n)})
    return hits


class ArweaveDataFetcherPlugin(Plugin):
    id = "arweave_data_fetcher"
    label = "Arweave Data Fetcher"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Fetch Arweave-hosted payloads referenced by the "
                   "target (ar:// / tx ids) from keyless gateways; "
                   "flag mirrored frontend source and live divergence.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        notes = []
        try:
            texts = await all_texts(ctx, target)
            live_text = ""
            for where, text, _u in texts:
                if where == "page":
                    live_text = text
            # Supplied mirror contents (operator artifacts) skip fetching.
            supplied: Dict[str, str] = {}
            from ._cat4_common import artifact_dicts
            for d in artifact_dicts(ctx):
                for txid, body in (d.get("arweave_mirrors") or {}).items():
                    supplied[str(txid)] = str(body)
            refs: List[str] = list(supplied)
            for where, text, _u in texts:
                for txid in extract_arweave_refs(text):
                    if txid not in refs:
                        refs.append(txid)
            for txid in refs[:MAX_TX]:
                mirrored = supplied.get(txid)
                if mirrored is None:
                    try:
                        r = await fetch(ctx.http, ctx.limiter, "GET",
                                        GATEWAY + txid, timeout=15,
                                        max_retries=1)
                        if r.status_code != 200:
                            notes.append(f"{txid[:12]}: gateway "
                                         f"status {r.status_code}")
                            continue
                        mirrored = r.text[:300000]
                    except Exception:
                        notes.append(f"{txid[:12]}: gateway unreachable")
                        continue
                for hit in analyse_mirror(live_text, mirrored, txid):
                    sev = ("medium" if hit["kind"] == "mirror_divergence"
                           else "low")
                    findings.append(self._f(
                        "web3", f"arweave_{hit['kind']}",
                        f"Arweave tx {txid}: "
                        f"{hit['kind'].replace('_', ' ')} - permanent "
                        f"frontend mirror "
                        f"({hit.get('mirror_len', 0)} chars)",
                        source="arweave data fetcher",
                        source_url=GATEWAY + txid, confidence=80,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Arweave content cannot be "
                            "removed. If the mirror is not yours, treat "
                            "it as a permanent phishing-twin risk and "
                            "warn users to verify the canonical domain."}))
            res = self._ok(findings,
                           "; ".join(notes) if notes and not findings
                           else (f"{len(findings)} Arweave mirrors found"
                                 if findings else "no Arweave refs"))
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
