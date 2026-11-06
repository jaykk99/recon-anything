"""Crypto subtle hook detector (Cat 6 #174). STATIC detector - no live WebCrypto interception."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Keep keys non-extractable, never persist key material to web storage, and never monkey-patch crypto.subtle.'


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


def analyze_crypto_subtle(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    if re.search(r"(?:crypto\.)?subtle\.exportKey\s*\(\s*['\"]raw['\"]", text):
        out.append({"key": "subtle_raw_key_export", "severity": "high",
                    "value": "crypto.subtle.exportKey('raw', ...) exports raw key material into page context"})
    if re.search(r"localStorage\.setItem\s*\([^)]*(?:key|token|secret)|sessionStorage\.setItem\s*\([^)]*(?:key|token|secret)", text, re.I) and "subtle" in text:
        out.append({"key": "subtle_key_in_storage", "severity": "high",
                    "value": "WebCrypto-related key/token material is written to localStorage/sessionStorage"})
    if re.search(r"(?:crypto\.subtle|subtle)\s*=\s*|Object\.defineProperty\s*\([^)]*subtle|subtle\.(?:encrypt|decrypt|sign|importKey)\s*=\s*", text):
        out.append({"key": "subtle_hooked", "severity": "high",
                    "value": "Code assigns to or wraps crypto.subtle itself - a hooking pattern that can skim keys and plaintexts"})
    if re.search(r"subtle\.importKey\s*\(\s*['\"]raw['\"][^)]*,\s*(?:['\"][A-Za-z0-9+/=]{16,}['\"]|keyMaterial|password)", text):
        out.append({"key": "subtle_hardcoded_key_material", "severity": "medium",
                    "value": "crypto.subtle.importKey uses literal or password-derived key material visible in the bundle"})
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


class CryptoSubtleHookPlugin(Plugin):
    id = 'crypto_subtle_hook'
    label = 'WebCrypto Subtle Exposure (Static)'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Static detection of WebCrypto subtle.* exposure in supplied bundles: raw key export, keys persisted to storage, and code that hooks or wraps crypto.subtle itself.'
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
                hits = analyze_crypto_subtle(data)
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
