"""TruffleHog-style high-entropy secret scanner.

Scans the homepage, first-party JS bundles, and exposed .git directories
for high-entropy strings (likely secrets) using Shannon entropy scoring.
Also probes for exposed .git metadata (/.git/HEAD, /.git/config) and flags
the exposure so truffle-style git-history analysis can be done offline.

Detection only: read-only GETs of public pages. Full values shown.
Authorized testing only.
"""
from __future__ import annotations

import math
import re
import time
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, finding_value, is_placeholder

REMED_KEY = "api_key"

# Minimum Shannon entropy per character to flag (base64-ish strings score ~5.5-6)
ENTROPY_THRESHOLD = 4.5
MIN_LEN = 20
MAX_LEN = 120

# Skip strings that look like common non-secrets
SKIP_RE = re.compile(
    r"^(?:[0-9a-f]{8}-[0-9a-f]{4}|[A-Z][a-z]+(?:[A-Z][a-z]+)+|"  # uuids, camelCase
    r"https?://|data:|//[a-z0-9.-]+\.[a-z]{2,}|"  # urls
    r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})$", re.I)


def shannon_entropy(s: str) -> float:
    """Shannon entropy per character."""
    if not s:
        return 0.0
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def candidate_strings(text: str) -> List[str]:
    """Extract quoted / assigned string candidates that could be secrets."""
    out: List[str] = []
    # quoted strings: "...." or '....'
    for m in re.finditer(r"""['"]([A-Za-z0-9_\-+/=]{20,120})['"]""", text):
        out.append(m.group(1))
    # key=value assignments: key=VALUE or key: VALUE
    for m in re.finditer(
            r"""(?i)(?:secret|token|key|password|passwd|pwd|auth|credential)"""
            r"""\s*[:=]\s*['"]?([A-Za-z0-9_\-+/=]{20,120})['"]?""", text):
        out.append(m.group(1))
    return out


class TruffleScanPlugin(Plugin):
    id = "truffle_scan"
    label = "TruffleHog Entropy Scan"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("High-entropy string detection (TruffleHog-style) across "
                   "pages, JS, and exposed .git metadata.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        seen: Set[str] = set()

        def emit(match: str, where: str, entropy: float, url: str | None):
            m = match.strip()[:120]
            if len(m) < MIN_LEN or is_placeholder(m):
                return
            if SKIP_RE.match(m):
                return
            key = ("entropy_secret", m)
            if key in seen:
                return
            seen.add(key)
            findings.append(self._f(
                "leak", "entropy_secret",
                finding_value("high", "high-entropy string", m, where),
                source=f"entropy scan: {where}", source_url=url,
                confidence=70, passive=passive,
                evidence=evidence_block(
                    m, "high_entropy", REMED_KEY, "high",
                    extra={"entropy": round(entropy, 2)})))

        async def scan_text(text: str, where: str, url: str | None):
            for cand in candidate_strings(text):
                ent = shannon_entropy(cand)
                if ent >= ENTROPY_THRESHOLD:
                    emit(cand, where, ent, url)

        # 1. Homepage
        try:
            page = await ctx.fetch_page(base, timeout=25)
            if page:
                html = page["text"][:500000]
                await scan_text(html, "homepage HTML", page.get("url"))
                page_url = page.get("url") or base
                # 2. First-party JS bundles
                srcs = re.findall(
                    r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
                srcs = [s for s in srcs if not s.startswith("data:")][:20]
                for src in srcs:
                    full = urljoin(page_url, src)
                    host = urlparse(full).netloc
                    if host and not host.endswith(domain):
                        continue
                    try:
                        r = await fetch(ctx.http, ctx.limiter, "GET", full,
                                        timeout=12)
                        if r.status_code == 200 and r.text:
                            await scan_text(r.text[:300000],
                                            f"JS bundle {src[:60]}", full)
                    except Exception:
                        continue
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:150]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # 3. Exposed .git metadata (flag only, no repo download)
        git_paths = ["/.git/HEAD", "/.git/config"]
        for gp in git_paths:
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base + gp,
                                timeout=10)
                body = r.text[:500]
                exposed = (
                    r.status_code == 200
                    and ("ref:" in body or "[core]" in body or "repositoryformatversion" in body)
                )
                if exposed:
                    findings.append(self._f(
                        "leak", "git_exposed",
                        finding_value("high", ".git directory", gp,
                                      "publicly readable"),
                        source="git exposure probe", source_url=base + gp,
                        confidence=90, passive=passive,
                        evidence=evidence_block(
                            body[:200], "git_exposed", "git_exposed", "high")))
            except Exception:
                continue

        res = self._ok(findings, f"{len(findings)} high-entropy/exposure hits")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
