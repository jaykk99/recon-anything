"""Electron crash dump extractor (Cat 6 #179, VARIANT of da_crash_dump). Operator-supplied artifacts ONLY, masked evidence."""
from __future__ import annotations

import hashlib
import re
import time
from typing import List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = 'Treat crash dumps as sensitive: scrub secrets before sharing, restrict dump storage, and rotate any credential found in one.'


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


def analyze_crash_dump(data) -> List[dict]:
    out = []
    raw = _to_bytes(data)
    if not raw:
        return out
    is_mdmp = raw[:4] == b"MDMP"
    text = _to_text(data)
    looks_dump = is_mdmp or "Crashpad" in text or "minidump" in text.lower() or "EXCEPTION_" in text
    if not looks_dump:
        return out
    strs = _strings(raw, 5) if raw else []
    mods = sorted({s for s in strs if re.search(r"(?i)\.(?:dll|so|dylib|exe)$", s.strip())})[:40]
    if is_mdmp:
        out.append({"key": "crash_dump_parsed", "severity": "low",
                    "value": f"Electron minidump parsed: {len(mods)} module name(s) recovered" + (f" ({', '.join(mods[:5])})" if mods else "")})
    for m in re.finditer(r"EXCEPTION_[A-Z_]+", text):
        out.append({"key": "crash_exception_context", "severity": "low",
                    "value": f"Crash dump exception context: {m.group(0)}"})
        break
    joined = "\n".join(strs) if strs else text
    for pat, what in [(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT session token"),
                      (r"ghp_[A-Za-z0-9]{20,}", "GitHub token"),
                      (r"AKIA[0-9A-Z]{16}", "AWS access key"),
                      (r"(?i)(?:password|api[_-]?key|secret)\s*[:=]\s*\S{6,}", "credential string")]:
        mm = re.search(pat, joined)
        if mm:
            masked, fp = _mask(mm.group(0))
            out.append({"key": "crash_dump_secret_remnant", "severity": "high",
                        "value": f"Crash dump retains a {what} in memory strings (masked {masked}, sha256:{fp})",
                        "evidence": {"masked": masked, "fingerprint": fp}})
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


class ElectronCrashDumpExtractorPlugin(Plugin):
    id = 'electron_crash_dump_extractor'
    label = 'Electron Crash Dump Extractor (Masked)'
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = 'web'
    description = 'Parse operator-supplied Electron Crashpad/minidump artifacts: module list, exception context, and masked secret-shaped string remnants.'
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
                hits = analyze_crash_dump(data)
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
                    'leak', h["key"], h["value"], source=label,
                    source_url=label if str(label).startswith("http") else None,
                    confidence=85, evidence=ev))
        res = self._ok(findings, reason=f"{len(sources)} source(s), {len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
