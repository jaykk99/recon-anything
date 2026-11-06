"""Electron nodeIntegration check (Cat 6 #153). Static config/source scan."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Set nodeIntegration:false and contextIsolation:true on every BrowserWindow, disable the remote module, and keep Node out of webviews.'


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


def analyze_node_integration(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    ni = bool(re.search(r"nodeIntegration\s*:\s*true", text))
    ci_off = bool(re.search(r"contextIsolation\s*:\s*false", text))
    if ni and ci_off:
        out.append({"key": "electron_node_integration_no_isolation", "severity": "high",
                    "value": "BrowserWindow combines nodeIntegration:true with contextIsolation:false - renderer JS gets full Node access"})
    elif ni:
        out.append({"key": "electron_node_integration", "severity": "high",
                    "value": "BrowserWindow sets nodeIntegration:true - renderer content can reach Node APIs"})
    elif ci_off:
        out.append({"key": "electron_context_isolation_off", "severity": "medium",
                    "value": "BrowserWindow sets contextIsolation:false without nodeIntegration - preload and page share one context"})
    if re.search(r"enableRemoteModule\s*:\s*true", text):
        out.append({"key": "electron_remote_module", "severity": "high",
                    "value": "enableRemoteModule:true exposes privileged main-process modules to the renderer"})
    if re.search(r"<webview[^>]+(?:nodeintegration|allowpopups)", text, re.I):
        out.append({"key": "electron_webview_node", "severity": "high",
                    "value": "<webview> tag enables Node integration or popups for embedded content"})
    if re.search(r"sandbox\s*:\s*false", text) and "BrowserWindow" in text:
        out.append({"key": "electron_sandbox_off", "severity": "medium",
                    "value": "BrowserWindow sets sandbox:false - renderer process runs unsandboxed"})
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


class ElectronNodeIntegrationCheckPlugin(Plugin):
    id = 'electron_node_integration_check'
    label = 'Electron Node Integration Check'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Flag Electron webPreferences risks in supplied source: nodeIntegration:true, contextIsolation:false, enableRemoteModule, unsafe webview.'
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
                hits = analyze_node_integration(data)
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
