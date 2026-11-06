"""Wasm memory growth tracker (Cat 6 #175, VARIANT of da_wasm_surface). Memory-section and grow-site analysis."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Set a finite maximum memory, bound memory.grow results, and rate-limit allocation loops in Wasm hosts.'


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


def _parse_memory_section(raw: bytes):
    if len(raw) < 9 or raw[:4] != b"\x00asm":
        return None
    i = 8
    def uleb(pos):
        r = 0; s = 0
        while pos < len(raw):
            b = raw[pos]; pos += 1
            r |= (b & 0x7F) << s
            if not (b & 0x80):
                break
            s += 7
        return r, pos
    while i < len(raw):
        sec = raw[i]; i += 1
        size, i = uleb(i)
        body_start = i
        if sec == 5 and size > 0:
            count, j = uleb(i)
            if count >= 1:
                flags, j = uleb(j)
                initial, j = uleb(j)
                maximum = None
                if flags & 1:
                    maximum, j = uleb(j)
                return {"initial": initial, "maximum": maximum}
        i = body_start + size
    return None

def analyze_wasm_memory(data) -> List[dict]:
    out = []
    raw = _to_bytes(data)
    text = _to_text(data)
    mem = None
    try:
        mem = _parse_memory_section(raw)
    except Exception:
        mem = None
    if mem is not None:
        if mem["maximum"] is None:
            out.append({"key": "wasm_memory_unbounded", "severity": "medium",
                        "value": f"Wasm memory section declares {mem['initial']} initial page(s) with NO maximum - memory can grow until the host is exhausted"})
        elif mem["maximum"] and mem["maximum"] > 65536:
            out.append({"key": "wasm_memory_huge_max", "severity": "low",
                        "value": f"Wasm memory maximum is {mem['maximum']} pages - an unusually large growth ceiling"})
    if raw and b"\x40\x00" in raw and raw[:4] == b"\x00asm":
        if mem is not None and mem["maximum"] is None:
            out.append({"key": "wasm_memory_grow_present", "severity": "low",
                        "value": "Wasm module contains memory.grow instructions alongside unbounded memory"})
    if text:
        if re.search(r"(?:while|for)\s*\([^)]*\)\s*\{[^}]{0,200}memory\.grow\s*\(", text, re.S) or re.search(r"memory\.grow\s*\([^)]*\)\s*;?\s*(?:while|for)", text):
            out.append({"key": "wasm_grow_in_loop", "severity": "medium",
                        "value": "Host JS calls memory.grow inside a loop - allocation-driven exhaustion pattern"})
        elif re.search(r"\.grow\s*\(\s*(?:\d{4,}|delta|amount|pages)", text) and "WebAssembly" in text:
            out.append({"key": "wasm_grow_large_delta", "severity": "low",
                        "value": "Host JS grows Wasm memory by a large or caller-controlled page count"})
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


class WasmMemoryGrowthTrackerPlugin(Plugin):
    id = 'wasm_memory_growth_tracker'
    label = 'Wasm Memory Growth Tracker'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Analyze Wasm memory posture in supplied modules/code: memory section initial/max pages, memory.grow call sites and growth loops (exhaustion risk).'
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
                hits = analyze_wasm_memory(data)
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
