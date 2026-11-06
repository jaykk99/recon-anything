"""Browserify dependency splitter (Cat 6 #161, VARIANT of sourcemap/jsdeep). Map-less module-table splitting."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Rebuild bundles without secrets or internal endpoints; Browserify bundles are fully readable by anyone who downloads them.'


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


MODULE_RE = re.compile(r"(?m)(?:^|[,{])\s*(\d+)\s*:\s*\[\s*function\s*\(\s*require\s*,\s*module\s*,\s*exports\s*\)")

def analyze_browserify(data) -> List[dict]:
    out = []
    text = _to_text(data)
    if not text:
        return out
    mods = list(MODULE_RE.finditer(text))
    if len(mods) < 2:
        return out
    spans = []
    for i, m in enumerate(mods):
        end = mods[i + 1].start() if i + 1 < len(mods) else len(text)
        spans.append((m.group(1), text[m.start():end]))
    for mid, body in spans:
        for pat, what in [(r"AKIA[0-9A-Z]{16}", "AWS access key"),
                          (r"ghp_[A-Za-z0-9]{20,}", "GitHub token"),
                          (r"(?i)(?:password|api[_-]?key|secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "hardcoded credential")]:
            mm = re.search(pat, body)
            if mm:
                masked, fp = _mask(mm.group(0))
                out.append({"key": "browserify_module_secret", "severity": "high",
                            "value": f"Browserify module {mid} contains a {what} (masked {masked}, sha256:{fp})",
                            "evidence": {"module": mid, "masked": masked, "fingerprint": fp}})
                break
        m2 = re.search(r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s'\"`]*", body)
        if m2:
            out.append({"key": "browserify_module_internal_url", "severity": "low",
                        "value": f"Browserify module {mid} references an internal endpoint: {m2.group(0)[:100]}"})
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


class BrowserifyDependencySplitterPlugin(Plugin):
    id = 'browserify_dependency_splitter'
    label = 'Browserify Dependency Splitter'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Split map-less Browserify bundles in supplied artifacts into per-module entries and flag modules carrying secrets or internal endpoints (masked).'
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
                hits = analyze_browserify(data)
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
