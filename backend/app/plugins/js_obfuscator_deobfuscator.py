"""JS obfuscator deobfuscator (Cat 6 #157). Local static analysis only."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Ship readable, auditable bundles; obfuscation hides behavior from reviewers and is a common malware/drainer trait.'


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


def analyze_obfuscation(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text or len(text) < 40:
        return out
    score = 0
    signals = []
    hex_ids = len(re.findall(r"\b_0x[0-9a-f]{4,}\b", text))
    if hex_ids >= 5:
        score += 2; signals.append(f"{hex_ids} hex-renamed identifiers (_0x...)")
    if re.search(r"var\s+_0x[0-9a-f]+\s*=\s*\[", text) or re.search(r"const\s+_0x[0-9a-f]+\s*=\s*\[", text):
        score += 2; signals.append("rotated string-array table present")
    if re.search(r"eval\s*\(\s*(?:function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k|atob\s*\()", text):
        score += 2; signals.append("packed eval / atob decode stub present")
    if len(re.findall(r"\\x[0-9a-fA-F]{2}", text)) >= 20:
        score += 1; signals.append("dense \\x escape sequences")
    if len(re.findall(r"\[['\"][^'\"]{1,30}['\"]\]\s*\(", text)) >= 10:
        score += 1; signals.append("string-indexed property call pattern")
    if score >= 3:
        out.append({"key": "js_obfuscated_bundle", "severity": "medium" if score < 5 else "high",
                    "value": f"Bundle shows strong obfuscation (score {score}): {'; '.join(signals)}. Deobfuscation outline: resolve the string-array rotation first, then rename _0x identifiers by call site."})
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


class JsObfuscatorDeobfuscatorPlugin(Plugin):
    id = 'js_obfuscator_deobfuscator'
    label = 'JS Obfuscator Detector / Deobfuscation Outline'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Detect obfuscated JS in supplied bundles (hex identifiers, string arrays, packed eval) and outline the deobfuscation structure.'
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
                hits = analyze_obfuscation(data)
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
