"""Context isolation audit (Cat 6 #154). Static scan of main/preload/renderer sources."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Enable contextIsolation everywhere and expose only narrow, validated functions through contextBridge - never raw ipcRenderer, require, fs or process.'


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


def analyze_context_isolation(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    if re.search(r"contextIsolation\s*:\s*false", text):
        out.append({"key": "context_isolation_disabled", "severity": "high",
                    "value": "contextIsolation:false merges preload and page contexts - page scripts can tamper with privileged preload code"})
    for m in re.finditer(r"exposeInMainWorld\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\{[^}]{0,600}\}|[A-Za-z_$][\w$.]*)", text, re.S):
        name, surface = m.group(1), m.group(2)
        danger = [w for w in ("ipcRenderer", "require", "fs", "process", "child_process", "shell", "exec")
                  if re.search(r"\b" + w + r"\s*[:,}]", surface) or surface.strip() == w]
        if danger:
            out.append({"key": "context_bridge_privileged_exposure", "severity": "high",
                        "value": f"contextBridge '{name}' exposes privileged surface: {', '.join(sorted(set(danger)))}"})
    if "contextBridge" not in text and re.search(r"require\s*\(\s*['\"](?:fs|child_process|electron)['\"]\s*\)", text) and "preload" in text.lower():
        out.append({"key": "preload_privileged_no_bridge", "severity": "medium",
                    "value": "Preload script reaches privileged APIs without a contextBridge boundary"})
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


class ContextIsolationAuditPlugin(Plugin):
    id = 'context_isolation_audit'
    label = 'Electron Context Isolation Audit'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Audit the Electron isolation boundary in supplied bundles: per-window contextIsolation state and dangerous contextBridge exposures.'
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
                hits = analyze_context_isolation(data)
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
