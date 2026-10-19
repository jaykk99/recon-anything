"""Hash identifier (OSINT: hash recovery category).

Pure offline analysis: scans page text and JS for hash-looking
strings and identifies the likely algorithm by length and alphabet.
Useful for CTFs and credential analysis. No network calls beyond the
initial page fetch. No cracking is performed.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

HASH_TYPES = [
    ("md5", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"), "MD5"),
    ("sha1", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"), "SHA-1"),
    ("sha256", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"), "SHA-256"),
    ("sha512", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])"), "SHA-512"),
    ("bcrypt", re.compile(r"\$2[aby]\$[./A-Za-z0-9]{53}"), "bcrypt"),
    ("argon2", re.compile(r"\$argon2(?:id|i|d)\$[^$]+\$[^$]+\$[A-Za-z0-9+/=]+"), "Argon2"),
    ("ntlm", re.compile(r"(?i)ntlm[:=]\s*([a-fA-F0-9]{32})"), "NTLM"),
    ("mysql_old", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{16}(?![a-fA-F0-9])"), "MySQL old password hash (16 hex)"),
    ("jwt_like", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "JWT (not a hash, but often mistaken)"),
]


class HashidPlugin(Plugin):
    id = "hashid"
    label = "Hash Identifier"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Identify hash algorithms in page text and JS (CTF helper)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:400000]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        seen = set()
        for hid, pat, label in HASH_TYPES:
            for m in pat.finditer(html):
                val = m.group(1) if m.groups() else m.group(0)
                # skip obvious non-hashes
                if re.fullmatch(r"0+", val) or re.fullmatch(r"f+", val, re.I):
                    continue
                key = (hid, val[:40])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._f(
                    "web", "hash_identified",
                    f"Possible {label}: {val[:16]}...{val[-8:] if len(val) > 24 else ''} "
                    f"(full value in evidence)",
                    source="hash scan", source_url=page_url,
                    confidence=60, passive=passive,
                    evidence={"hash_type": label, "value": val[:200],
                              "note": "Identification only. No cracking performed."}))
                if len(seen) >= 20:
                    break
            if len(seen) >= 20:
                break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} hash-like strings identified")
        res.duration_ms = dur
        return res
