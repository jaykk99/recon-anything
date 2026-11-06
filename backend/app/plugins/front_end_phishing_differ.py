"""Front-end phishing differ (Cat-4 SHIP).

Structural DOM diff between a suspect page and the legitimate
project's reference page (operator-supplied reference HTML or a
reference URL on the discovery bus): injected wallet-connect
overlays, swapped payment/deposit addresses, extra form fields, and
scripts loaded from hosts the reference does not use - the anatomy
of a cloned-DApp phishing front end.

Keyless: fetches the two pages only. Detection only.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from ._cat4_common import ADDR_RE, artifact_texts, fetch
from .base import Cost, Ctx, Plugin, PluginResult, Target

OVERLAY_HINTS = ("web3modal", "walletconnect", "connect-wallet",
                 "wallet-modal", "rainbowkit", "connectkit")
FORM_FIELD_RE = re.compile(r"<(?:input|select|textarea)\b[^>]*"
                           r"(?:name|id)=[\"']([^\"']+)[\"']", re.I)
SCRIPT_HOST_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)


def _features(html: str) -> Dict[str, Any]:
    html = html or ""
    low = html.lower()
    return {
        "addresses": {a.lower() for a in ADDR_RE.findall(html)},
        "form_fields": {m.lower() for m in FORM_FIELD_RE.findall(html)},
        "script_hosts": {urlparse(s).netloc.lower()
                         for s in SCRIPT_HOST_RE.findall(html)
                         if urlparse(s).netloc},
        "overlays": {h for h in OVERLAY_HINTS if h in low},
        "forms": len(re.findall(r"<form\b", low)),
    }


def diff_frontends(suspect_html: str, reference_html: str
                   ) -> List[Dict[str, Any]]:
    """Pure: structural diff suspect vs legitimate reference."""
    hits: List[Dict[str, Any]] = []
    if not isinstance(suspect_html, str) or \
            not isinstance(reference_html, str):
        return hits
    s, r = _features(suspect_html), _features(reference_html)
    swapped = s["addresses"] - r["addresses"]
    removed = r["addresses"] - s["addresses"]
    if swapped and removed:
        hits.append({"kind": "payment_address_swapped",
                     "injected": sorted(swapped)[:3],
                     "removed": sorted(removed)[:3]})
    elif swapped and r["addresses"]:
        hits.append({"kind": "extra_payment_address",
                     "injected": sorted(swapped)[:3]})
    new_fields = s["form_fields"] - r["form_fields"]
    sensitive = {f for f in new_fields
                 if any(k in f for k in ("seed", "mnemonic", "private",
                                         "phrase", "keystore", "password"))}
    if sensitive:
        hits.append({"kind": "credential_form_fields_added",
                     "fields": sorted(sensitive)[:6]})
    elif new_fields:
        hits.append({"kind": "extra_form_fields",
                     "fields": sorted(new_fields)[:6]})
    new_overlays = s["overlays"] - r["overlays"]
    if new_overlays:
        hits.append({"kind": "injected_wallet_overlay",
                     "overlays": sorted(new_overlays)})
    new_hosts = s["script_hosts"] - r["script_hosts"]
    if new_hosts:
        hits.append({"kind": "foreign_script_hosts",
                     "hosts": sorted(new_hosts)[:6]})
    return hits


class FrontEndPhishingDifferPlugin(Plugin):
    id = "front_end_phishing_differ"
    label = "Front-End Phishing Differ"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Structural DOM diff of the target page against "
                   "the legitimate reference page: swapped payment "
                   "addresses, injected wallet overlays, extra form "
                   "fields, foreign script hosts.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            reference = ""
            try:
                refs = ctx.consume("cat4_reference_html")
                if refs and isinstance(refs[0], str):
                    reference = refs[0]
            except Exception:
                reference = ""
            if not reference:
                arts = artifact_texts(ctx)
                for a in arts:
                    if "<html" in a.lower() and "reference" in a[:200].lower():
                        reference = a
                        break
            suspect = ""
            if target.type in ("domain", "url"):
                from ._cat4_common import gather_page_texts
                for where, text, _u in await gather_page_texts(ctx, target):
                    if where == "page":
                        suspect = text
            else:
                arts = artifact_texts(ctx)
                suspect = arts[0] if arts else ""
            if not suspect or not reference:
                res = self._degraded(
                    "needs both a suspect page and a reference page "
                    "(cat4_reference_html artifact) to diff")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res
            for hit in diff_frontends(suspect, reference):
                sev = ("high" if hit["kind"] in
                       ("payment_address_swapped",
                        "credential_form_fields_added",
                        "injected_wallet_overlay") else "medium")
                findings.append(self._f(
                    "web3", f"phishing_diff_{hit['kind']}",
                    f"Front-end diff vs legitimate reference: "
                    f"{hit['kind'].replace('_', ' ')} - "
                    f"{ {k: v for k, v in hit.items() if k != 'kind'} }",
                    source="front-end phishing differ", confidence=85,
                    evidence={
                        "severity": sev, "hit": hit,
                        "remediation": "If this page is not yours, "
                        "report it to the hosting provider and warn "
                        "users; if it is yours, audit the deploy "
                        "pipeline for injected content."}))
            res = self._ok(findings,
                           "pages structurally identical"
                           if not findings else
                           f"{len(findings)} phishing-diff signals")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
