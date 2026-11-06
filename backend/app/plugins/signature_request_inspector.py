"""Signature request inspector (Cat-4 variant of cp_drainer_ethsign).

A DECODER, not just a flag: parses EIP-712 typed-data payloads found
in operator-supplied bundles/artifacts into domain, types and values,
and grades each payload for hidden approval/transfer semantics -
Permit / PermitSingle types, spender fields, unlimited amounts,
far-future deadlines - the payloads users blind-sign every day.

Operator-supplied artifacts only. Static/local decoding. No signing.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from ._cat4_common import all_texts, artifact_dicts, parse_json_maybe
from .base import Cost, Ctx, Plugin, PluginResult, Target

PERMIT_TYPES = ("Permit", "PermitSingle", "PermitBatch",
                "TransferWithAuthorization", "ReceiveWithAuthorization")
MAX_UINT_HINT = 10 ** 60


def _iter_typed_data(obj: Any, out: List[Dict[str, Any]], depth: int = 0):
    if depth > 4 or len(out) > 10:
        return
    if isinstance(obj, dict):
        if "types" in obj and "primaryType" in obj and \
                isinstance(obj.get("types"), dict):
            out.append(obj)
        for v in obj.values():
            _iter_typed_data(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _iter_typed_data(v, out, depth + 1)
    elif isinstance(obj, str) and obj.strip().startswith("{"):
        parsed = parse_json_maybe(obj)
        if parsed is not None:
            _iter_typed_data(parsed, out, depth + 1)


def grade_typed_data(td: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pure: one EIP-712 payload -> risk hits with decoded fields."""
    hits: List[Dict[str, Any]] = []
    if not isinstance(td, dict):
        return hits
    primary = str(td.get("primaryType") or "")
    domain = td.get("domain") if isinstance(td.get("domain"), dict) else {}
    message = td.get("message") if isinstance(td.get("message"), dict) \
        else {}
    decoded = {"primary_type": primary,
               "domain_name": domain.get("name"),
               "verifying_contract": domain.get("verifyingContract"),
               "message_keys": sorted(message)[:12]}
    if primary in PERMIT_TYPES or "spender" in message:
        hits.append({**decoded, "kind": "permit_style_payload"})
    amt = message.get("value", message.get("amount"))
    try:
        if amt is not None and int(str(amt), 0) > MAX_UINT_HINT:
            hits.append({**decoded, "kind": "unlimited_amount"})
    except (TypeError, ValueError):
        pass
    deadline = message.get("deadline", message.get("validBefore"))
    try:
        if deadline is not None and \
                int(str(deadline), 0) > 2_000_000_000:  # past ~2033
            hits.append({**decoded, "kind": "far_future_deadline"})
    except (TypeError, ValueError):
        pass
    if "spender" in message and primary not in PERMIT_TYPES:
        hits.append({**decoded, "kind": "hidden_spender_field"})
    return hits


def extract_typed_data(texts: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for text in texts:
        if not isinstance(text, str):
            continue
        parsed = parse_json_maybe(text)
        if parsed is not None:
            _iter_typed_data(parsed, out)
        # embedded JSON blobs inside JS bundles
        for m in re.finditer(r"\{[^{}]*\"primaryType\"[^{}]*", text):
            blob = text[m.start():m.start() + 4000]
            end = blob.rfind("}")
            if end > 0:
                parsed = parse_json_maybe(blob[:end + 1])
                if parsed is not None:
                    _iter_typed_data(parsed, out)
    return out


class SignatureRequestInspectorPlugin(Plugin):
    id = "signature_request_inspector"
    label = "Signature Request Inspector (EIP-712 decoder)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Decode EIP-712 typed-data payloads in supplied "
                   "bundles/artifacts into domain/types/values and "
                   "grade hidden approval/transfer semantics.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            payloads: List[Dict[str, Any]] = []
            for d in artifact_dicts(ctx):
                _iter_typed_data(d, payloads)
            texts = [t for _w, t, _u in await all_texts(ctx, target)]
            payloads.extend(extract_typed_data(texts))
            seen = set()
            for td in payloads:
                key = json.dumps(td, sort_keys=True, default=str)[:200]
                if key in seen:
                    continue
                seen.add(key)
                for hit in grade_typed_data(td):
                    sev = ("high" if hit["kind"] in
                           ("permit_style_payload", "unlimited_amount",
                            "hidden_spender_field") else "medium")
                    findings.append(self._f(
                        "web3", f"eip712_{hit['kind']}",
                        f"EIP-712 {hit['primary_type']} payload for "
                        f"{hit.get('domain_name') or 'unknown domain'}: "
                        f"{hit['kind'].replace('_', ' ')} "
                        f"(fields: {', '.join(hit['message_keys'])})",
                        source="signature request inspector",
                        confidence=85,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Show users the fully decoded "
                            "typed data before prompting; never ask for "
                            "permit signatures with unlimited amounts "
                            "or open-ended deadlines."}))
            res = self._ok(findings,
                           f"{len(payloads)} typed-data payloads decoded"
                           if not findings else
                           f"{len(findings)} risky signature payloads")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
