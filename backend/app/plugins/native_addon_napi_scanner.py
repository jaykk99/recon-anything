"""N-API addon scanner (Cat 6 #162). Static binary-strings + wrapper scan."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Replace unsafe string functions, check every napi_status return, and validate buffer lengths before copying in native addons.'


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


def analyze_napi(data) -> List[dict]:
    out = []
    raw = _to_bytes(data)
    text = _to_text(data)
    if not raw:
        return out
    hay = text if len(text) > 50 else "\n".join(_strings(raw, 4))
    unsafe = [f for f in ("strcpy", "strcat", "sprintf", "gets", "memcpy") if re.search(r"\b" + f + r"\b", hay)]
    has_napi = "napi_" in hay
    checks_status = "napi_ok" in hay or "napi_status" in hay
    if unsafe and has_napi:
        sev = "high" if not checks_status else "medium"
        out.append({"key": "napi_unsafe_string_fn", "severity": sev,
                    "value": f"N-API addon references unsafe memory functions ({', '.join(unsafe)})" + ("" if checks_status else " with no napi_status/napi_ok checks visible")})
    if re.search(r"napi_get_buffer_info|napi_get_arraybuffer_info", hay) and not re.search(r"length\s*[<>]=?|if\s*\([^)]*length", hay):
        out.append({"key": "napi_unchecked_buffer", "severity": "medium",
                    "value": "Addon reads N-API buffer info without a visible length bound check nearby"})
    if re.search(r"Buffer\.allocUnsafe|binding\.|process\.binding", text):
        out.append({"key": "napi_wrapper_unsafe_buffer", "severity": "medium",
                    "value": "JS wrapper uses allocUnsafe/process.binding around the native addon - uninitialized memory can leak into JS"})
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


class NativeAddonNapiScannerPlugin(Plugin):
    id = 'native_addon_napi_scanner'
    label = 'Native Addon (N-API) Scanner'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Scan supplied .node N-API addons and wrappers for memory-handling bug patterns: unsafe C string functions and unchecked N-API buffer use.'
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
                hits = analyze_napi(data)
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
