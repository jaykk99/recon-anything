"""vm2 sandbox escape test (Cat 6 #166, VARIANT of js_retire/supplychain). Static detection only - no escape is executed."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Stop running untrusted code in vm2; use a separate process or a maintained isolate runtime, and freeze intrinsics if vm2 must stay.'


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


def analyze_vm2(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    uses = bool(re.search(r"require\s*\(\s*['\"]vm2['\"]\s*\)|from\s+['\"]vm2['\"]|new\s+(?:NodeVM|VM|VM2)\s*\(", text))
    if not uses:
        return out
    frozen = bool(re.search(r"freeze\s*\(|frozen_modules|eval\s*:\s*false|wasm\s*:\s*false", text))
    escape_shape = bool(re.search(r"constructor\.constructor|__proto__|this\.constructor|process\.mainModule", text))
    if escape_shape:
        out.append({"key": "vm2_escape_shape", "severity": "high",
                    "value": "Code around vm2 contains a known sandbox-escape shape (constructor/process access path) in or near the sandboxed code"})
    if not frozen:
        out.append({"key": "vm2_unhardened", "severity": "medium",
                    "value": "vm2 VM/NodeVM is used without visible intrinsics freezing or eval/wasm restrictions - historically escape-prone configuration"})
    ver = re.search(r"['\"]vm2['\"]\s*:\s*['\"][\^~]?(\d+)\.(\d+)\.(\d+)", text)
    if ver:
        v = tuple(int(x) for x in ver.groups())
        if v < (3, 9, 20):
            out.append({"key": "vm2_old_version", "severity": "high",
                        "value": f"package manifest pins vm2 {'.'.join(str(x) for x in v)} - versions before 3.9.20 carry public sandbox escapes"})
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


class Vm2SandboxEscapeTestPlugin(Plugin):
    id = 'vm2_sandbox_escape_test'
    label = 'vm2 Sandbox Escape Audit (Static)'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Static vm2 audit of supplied code: VM/NodeVM usage, known escape shapes (constructor/process paths), and missing intrinsics freezing.'
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
                hits = analyze_vm2(data)
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
