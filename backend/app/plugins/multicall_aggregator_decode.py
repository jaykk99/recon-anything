"""Multicall aggregator decoder (Cat-4 SHIP).

Decodes Multicall aggregate / tryAggregate / aggregate3 calldata
(from supplied artifacts, bundles, or target calldata) into per-call
entries - target, selector, decoded function name - and flags the
dangerous pattern: value-moving or approval-granting subcalls hidden
inside an innocent-looking batch of reads, plus undecodable subcall
selectors that cannot be accounted for.

Local ABI decoding only (plus selector identification). Read-only.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ._cat4_common import (APPROVAL_SELECTORS, HEXDATA_RE,
                           READONLY_SELECTORS, VALUE_MOVING_SELECTORS,
                           artifact_dicts, all_texts, selector_name)
from .base import Cost, Ctx, Plugin, PluginResult, Target

BATCH_SELECTORS = {"252dba42", "bce38bd7", "82ad56cb"}


def _word(data: bytes, off: int) -> int:
    chunk = data[off:off + 32]
    if len(chunk) < 32:
        raise ValueError("short word")
    return int.from_bytes(chunk, "big")


def _decode_calls(data: bytes, has_flag: bool,
                  arr_off: Optional[int] = None) -> List[Dict[str, Any]]:
    """Decode the (address[,bool],bytes)[] array body of a batch."""
    if arr_off is None:
        arr_off = _word(data, 0)
    n = _word(data, arr_off)
    if n > 500:
        raise ValueError("implausible batch size")
    base = arr_off + 32
    calls: List[Dict[str, Any]] = []
    for i in range(n):
        rel = _word(data, base + 32 * i)
        t_off = base + rel
        target = "0x" + data[t_off + 12:t_off + 32].hex()
        if has_flag:
            data_rel = _word(data, t_off + 64)
            b_off = t_off + data_rel
        else:
            data_rel = _word(data, t_off + 32)
            b_off = t_off + data_rel
        blen = _word(data, b_off)
        payload = data[b_off + 32:b_off + 32 + blen]
        sel = payload[:4].hex() if len(payload) >= 4 else ""
        calls.append({"target": target, "selector": "0x" + sel,
                      "name": selector_name(sel) or "",
                      "data_len": blen})
    return calls


def decode_multicall(calldata: Any) -> List[Dict[str, Any]]:
    """Pure: multicall calldata hex -> per-subcall entries."""
    if not isinstance(calldata, str):
        return []
    h = calldata.strip().lower().replace("0x", "")
    if len(h) < 8 or len(h) % 2:
        return []
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return []
    sel = h[:8]
    if sel not in BATCH_SELECTORS:
        return []
    body = raw[4:]
    try:
        if sel == "252dba42":            # aggregate: array offset word 0
            return _decode_calls(body, has_flag=False)
        if sel == "82ad56cb":            # aggregate3: array offset word 0
            return _decode_calls(body, has_flag=True)
        # tryAggregate(bool, calls[]): array offset is word 1
        return _decode_calls(body, has_flag=False,
                             arr_off=_word(body, 32))
    except Exception:
        return []


def analyse_batch(calldata: Any) -> List[Dict[str, Any]]:
    """Pure: decoded batch -> risky-subcall hits."""
    hits: List[Dict[str, Any]] = []
    for call in decode_multicall(calldata):
        sel = call["selector"].replace("0x", "")
        if sel in APPROVAL_SELECTORS:
            hits.append({**call, "kind": "hidden_approval_subcall"})
        elif sel in VALUE_MOVING_SELECTORS:
            hits.append({**call, "kind": "hidden_value_subcall"})
        elif sel and sel not in READONLY_SELECTORS and not call["name"]:
            hits.append({**call, "kind": "undecodable_subcall"})
    return hits


class MulticallAggregatorDecodePlugin(Plugin):
    id = "multicall_aggregator_decode"
    label = "Multicall Aggregator Decoder"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Decode Multicall aggregate/tryAggregate/"
                   "aggregate3 calldata into per-call entries; flag "
                   "hidden approval/value subcalls inside batches.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            blobs: List[str] = []
            for d in artifact_dicts(ctx):
                for key in ("calldata", "multicall_calldata"):
                    if isinstance(d.get(key), str):
                        blobs.append(d[key])
                for c in d.get("calldatas") or []:
                    if isinstance(c, str):
                        blobs.append(c)
            for _w, text, _u in await all_texts(ctx, target):
                for m in HEXDATA_RE.finditer(text):
                    h = m.group(0)
                    if h[2:10].lower() in BATCH_SELECTORS:
                        blobs.append(h)
            decoded = 0
            for blob in blobs[:10]:
                calls = decode_multicall(blob)
                decoded += len(calls)
                for hit in analyse_batch(blob):
                    sev = ("high" if hit["kind"] in
                           ("hidden_approval_subcall",
                            "hidden_value_subcall") else "medium")
                    findings.append(self._f(
                        "web3", f"multicall_{hit['kind']}",
                        f"Multicall batch hides a "
                        f"{hit['kind'].replace('_', ' ')}: "
                        f"{hit['name'] or hit['selector']} on "
                        f"{hit['target']}",
                        source="multicall aggregator decoder",
                        confidence=90,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Never sign or relay a batch "
                            "you have not decoded call-by-call; "
                            "approvals inside batches bypass per-call "
                            "wallet warnings."}))
            res = self._ok(findings,
                           f"{decoded} subcalls decoded"
                           if not findings else
                           f"{len(findings)} risky subcalls")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
