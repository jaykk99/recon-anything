"""Credential strength assessor (defensive OSINT only).

For passwords/hashes found in PUBLIC sources (the target's own public
pages, JS bundles, or public dumps already surfaced by other plugins):

- Identify the hash type (MD5, SHA-1, SHA-256, bcrypt, Argon2, NTLM...).
- Check hashes against PUBLIC cracked-hash lookups where a keyless
  API exists. If a hash is already publicly cracked, the finding shows
  the plaintext so the owner can force a reset.
- Assess crackability without cracking anything ourselves:
  unsalted fast hashes (MD5/SHA-1) = trivially crackable -> HIGH;
  salted slow hashes (bcrypt/Argon2) = effectively safe -> LOW.

We NEVER brute-force, dictionary-attack, or attempt logins. The only
plaintexts we report are ones already public in cracked databases or
appearing next to the hash in the same public source.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, is_placeholder, redact

# (id, regex, label, crackability verdict, severity)
HASH_PATTERNS: List[Tuple[str, re.Pattern, str, str, str]] = [
    ("md5", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"),
     "MD5", "unsalted fast hash: crackable in seconds on a GPU", "high"),
    ("sha1", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"),
     "SHA-1", "unsalted fast hash: crackable in seconds on a GPU", "high"),
    ("sha256", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"),
     "SHA-256", "fast hash: crackable if unsalted and password is weak",
     "medium"),
    ("sha512", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])"),
     "SHA-512", "fast hash: crackable if unsalted and password is weak",
     "medium"),
    ("bcrypt", re.compile(r"\$2[aby]\$[./A-Za-z0-9]{53}"),
     "bcrypt", "slow salted hash: not practically crackable", "low"),
    ("argon2", re.compile(r"\$argon2(?:id|i|d)\$[^$\s]+\$[^$\s]+\$[A-Za-z0-9+/=]+"),
     "Argon2", "slow salted hash: not practically crackable", "low"),
    ("ntlm", re.compile(r"(?i)\bntlm[:=]\s*([a-fA-F0-9]{32})"),
     "NTLM", "fast unsalted hash: crackable in seconds on a GPU", "high"),
]

# Plaintext password assignments near identity keywords in public JS/HTML.
PLAINTEXT_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|db[_-]?pass|smtp[_-]?pass)\s*[:=]\s*"
    r"['\"]([^'\"\s]{4,64})['\"]",
    re.M,
)

# Public cracked-hash lookups (keyless, best-effort). Most free rainbow
# APIs have died or need keys, so the offline strength verdict below is
# the always-on value; these are checked opportunistically.
RAINBOW_SOURCES = [
    # name, url template, plaintext extractor
    ("gromweb", "https://md5.gromweb.com/?md5={h}",
     lambda d: d.get("string") or d.get("plaintext")),
]


async def _public_crack_lookup(h: str, ctx: Ctx) -> Optional[str]:
    """Best-effort check of keyless public cracked-hash databases.
    Returns the plaintext only if it is already public. Never cracks."""
    for name, tpl, extract in RAINBOW_SOURCES:
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            tpl.format(h=h.lower()), timeout=15,
                            headers={"Accept": "application/json"})
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        try:
            s = str(extract(data) or "").strip()
        except Exception:
            continue
        if s and not is_placeholder(s) and len(s) <= 128:
            return s
    return None


class CredentialStrengthPlugin(Plugin):
    id = "credential_strength"
    label = "Credential Strength"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = ("Assess hashes/passwords found in public sources: hash "
                   "type, public cracked-DB lookup, crackability verdict. "
                   "No cracking performed.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        seen = set()

        page = await ctx.fetch_page(base, timeout=25)
        texts: List[Tuple[str, Optional[str]]] = []
        if page and page.get("text"):
            texts.append((page["text"][:400000], page.get("url")))

        html = texts[0][0] if texts else ""
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        page_url = texts[0][1] if texts else base
        for src in srcs[:15]:
            if src.startswith("data:"):
                continue
            full = urljoin(page_url or base, src)
            host = urlparse(full).netloc
            if host and not host.endswith(domain):
                continue
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=20)
                if r.status_code == 200:
                    texts.append((r.text[:400000], full))
            except Exception:
                continue

        for text, url in texts:
            await self._scan_hashes(text, url, ctx, findings, seen, passive)
            self._scan_plaintexts(text, url, findings, seen, passive)

        # Never silent: the page fetch failing, or a clean scan, must say
        # so as a finding, not as an empty result.
        if not texts:
            findings.append(self._f(
                "leak", "credential_note",
                f"Credential scan skipped: could not fetch {base} "
                f"(target unreachable or blocked)",
                source="credential scan", confidence=50, passive=passive,
                evidence=evidence_block("", "cred_no_page", "credential",
                                        "low")))
        elif not findings:
            findings.append(self._f(
                "leak", "credential_note",
                f"No hashes or plaintext passwords found in "
                f"{len(texts)} public sources on {domain}",
                source="credential scan", confidence=70, passive=passive,
                evidence=evidence_block("", "cred_clean", "credential",
                                        "low")))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"scanned {len(texts)} sources, "
                       f"{len(findings)} credential findings")
        res.duration_ms = dur
        return res

    async def _scan_hashes(self, text: str, url: Optional[str], ctx: Ctx,
                           findings: List[Finding], seen: set,
                           passive: bool) -> None:
        for hid, pat, label, verdict, sev in HASH_PATTERNS:
            for m in pat.finditer(text):
                h = m.group(1) if hid == "ntlm" else m.group(0)
                key = f"{hid}:{h.lower()}"
                if key in seen or is_placeholder(h):
                    continue
                seen.add(key)
                plaintext: Optional[str] = None
                if hid == "md5":
                    plaintext = await _public_crack_lookup(h, ctx)
                if plaintext:
                    value = (f"HIGH: {label} hash {h} is ALREADY CRACKED "
                             f"in a public database. Plaintext: {plaintext}")
                    ev = evidence_block(h, "hash_cracked_public", "credential",
                                        "high",
                                        {"hash": h, "type": label,
                                         "plaintext": plaintext,
                                         "source": "public rainbow table",
                                         "action": ("Force-reset this "
                                                    "credential now.")})
                else:
                    value = (f"{label} hash {redact(h, 8)} found "
                             f"({verdict})")
                    ev = evidence_block(h, "hash_strength", "credential", sev,
                                        {"hash": h, "type": label,
                                         "verdict": verdict,
                                         "cracked_in_public_db":
                                             False if hid == "md5" else None,
                                         "action": (
                                             "If this is a live credential, "
                                             "rotate it and re-hash with "
                                             "bcrypt/Argon2.")})
                findings.append(self._f(
                    "leak", "hash_analyzed", value,
                    source=f"credential scan: {url or 'page'}",
                    source_url=url, confidence=75, passive=passive,
                    evidence=ev))

    def _scan_plaintexts(self, text: str, url: Optional[str],
                         findings: List[Finding], seen: set,
                         passive: bool) -> None:
        for m in PLAINTEXT_RE.finditer(text):
            pw = m.group(1)
            if pw in seen or is_placeholder(pw) or len(pw) < 4:
                continue
            seen.add(pw)
            value = (f"HIGH: plaintext password {redact(pw, 3)} exposed in "
                     f"public {'JS' if url and url.endswith('.js') else 'page'}")
            ev = evidence_block(pw, "plaintext_password", "credential",
                                "high",
                                {"password": pw, "url": url,
                                 "action": ("Rotate this password "
                                            "immediately; it is public.")})
            findings.append(self._f(
                "leak", "plaintext_password", value,
                source=f"credential scan: {url or 'page'}",
                source_url=url, confidence=80, passive=passive,
                evidence=ev))
