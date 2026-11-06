"""Prototype pollution hunter (Cat 6 #159, VARIANT of proto_pollution). Static merger-loop analysis only."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Guard merge helpers against __proto__/constructor/prototype keys, freeze Object.prototype where feasible, and use Map or null-prototype objects for untrusted data.'


def _to_text(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    return str(data)


def _to_bytes(data) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    return str(data).encode("utf-8", errors="ignore")


def _mask(value: str) -> tuple:
    v = str(value or "")
    fp = hashlib.sha256(v.encode("utf-8", errors="ignore")).hexdigest()[:12]
    masked = (v[:4] + "***") if len(v) > 4 else "***"
    return masked, fp


def _strings(data: bytes, min_len: int = 4) -> List[str]:
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    return out


def analyze_proto_pollution_static(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    if re.search(r"\[\s*['\"]__proto__['\"]\s*\]\s*=(?!=)|\.__proto__\s*=(?!=)", text):
        out.append({"key": "proto_direct_write", "severity": "high",
                    "value": "Code writes directly to __proto__ - prototype pollution primitive in supplied source"})
    if re.search(r"constructor\s*(?:\[|\.)\s*['\"]?prototype", text) and re.search(r"=(?!=)", text):
        out.append({"key": "proto_constructor_write", "severity": "medium",
                    "value": "Code reaches constructor.prototype with an assignment nearby - a common pollution path"})
    guarded = bool(re.search(r"__proto__['\"]?\s*(?:===|!==|==|!=)|key\s*===?\s*['\"]__proto__|includes\s*\(\s*['\"]__proto__|hasOwnProperty.*__proto__|polluted", text))
    merge_pat = re.search(r"(?:function\s+(?:deep)?[Mm]erge|(?:deep)?[Mm]erge\s*=|function\s+extend|Object\.assign\s*\()", text)
    recursive_merge = bool(re.search(r"for\s*\([^)]*(?:in|of)[^)]*\)\s*\{[^}]{0,300}(?:typeof[^}]{0,120}object|arguments\.callee|\w+\s*\([^)]*\[)", text, re.S))
    if merge_pat and not guarded and (recursive_merge or re.search(r"JSON\.parse", text)):
        out.append({"key": "proto_unsafe_merge", "severity": "high",
                    "value": "Recursive/unchecked merge of parsed or external data with no __proto__ guard - classic prototype pollution shape"})
    elif merge_pat and not guarded and re.search(r"\[key\]\s*=|\[k\]\s*=", text):
        out.append({"key": "proto_merge_no_guard", "severity": "medium",
                    "value": "Dynamic-key merge/assign loop with no __proto__/constructor guard visible"})
    return out


async def _gather(ctx: Ctx, target: Target):
    sources = []
    for kind in ("artifacts", "supplied_code", "code_samples",
                 "supplied_files", "files", "bundles", "storage_dumps"):
        try:
            items = ctx.consume(kind)
        except Exception:
            items = []
        for it in items or []:
            if isinstance(it, dict):
                txt = it.get("text") or it.get("content") or it.get("body") or ""
                lbl = it.get("name") or it.get("url") or kind
            else:
                txt, lbl = it, kind
            if txt:
                sources.append((str(lbl), txt))
    try:
        base = None
        if target.type == "url" and target.normalized:
            base = target.normalized
        elif target.type == "domain" and target.normalized:
            base = "https://" + target.normalized
        if base:
            page = await ctx.fetch_page(base, timeout=10)
            txt = ""
            if isinstance(page, dict):
                txt = page.get("text") or ""
            elif isinstance(page, str):
                txt = page
            elif page is not None:
                txt = getattr(page, "text", "") or ""
            if txt:
                sources.append((base, txt))
            try:
                js_urls = ctx.consume("js_files")
            except Exception:
                js_urls = []
            for u in list(js_urls or [])[:5]:
                if not isinstance(u, str):
                    continue
                p2 = await ctx.fetch_page(u, timeout=10)
                t2 = ""
                if isinstance(p2, dict):
                    t2 = p2.get("text") or ""
                elif isinstance(p2, str):
                    t2 = p2
                elif p2 is not None:
                    t2 = getattr(p2, "text", "") or ""
                if t2:
                    sources.append((u, t2))
    except Exception:
        pass
    return sources


class PrototypePollutionHunterPlugin(Plugin):
    id = 'prototype_pollution_hunter'
    label = 'Prototype Pollution Hunter (Static Source)'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Static source lane for prototype pollution: unsafe merge/assign loops and __proto__/constructor.prototype writes in supplied JS bundles.'
    phase = 2
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        seen = set()
        try:
            sources = await _gather(ctx, target)
        except Exception:
            sources = []
        for label, data in sources:
            try:
                hits = analyze_proto_pollution_static(data)
            except Exception:
                hits = []
            for h in hits or []:
                dedup = (h.get("key"), h.get("value"))
                if dedup in seen:
                    continue
                seen.add(dedup)
                ev = {"severity": h.get("severity", "low"),
                       "remediation": h.get("remediation") or REMEDIATION}
                if h.get("evidence"):
                    ev.update(h["evidence"])
                findings.append(self._f(
                    'web', h["key"], h["value"], source=label,
                    source_url=label if str(label).startswith("http") else None,
                    confidence=85, evidence=ev))
        res = self._ok(findings, reason=f"{len(sources)} source(s), {len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
