"""Hash cracker: breach/verdict analyzer + direct-mode cracker.

Two modes with deliberately different powers:

SCAN MODE (hashes found on a target's public surface): ANALYSIS ONLY.
- Identifies the algorithm (MD5, SHA-1, SHA-256, bcrypt, Argon2, NTLM...)
- Checks PUBLIC breach data only:
    * HIBP Pwned Passwords API via k-anonymity (SHA-1 hashes only,
      keyless: only the first 5 chars of the hash leave the box)
    * Keyless public rainbow databases (MD5): status only
- Issues a crackability verdict: fast unsalted hashes (MD5/SHA-1/NTLM)
  are crackable in seconds on a GPU -> HIGH; slow salted hashes
  (bcrypt/Argon2/scrypt) are not practically crackable -> LOW.
- NEVER runs the cracking engine and NEVER puts a recovered plaintext
  in a finding. Scan findings carry type, breach-DB status, verdict
  and remediation only.

DIRECT MODE (the user submits a hash as the target): the full tool.
- The same analysis (public-DB plaintexts may be shown here: the user
  submitted the hash themselves), PLUS the bundled dictionary+rules
  engine (hashcrack_engine, SecLists 10k wordlist) tries to crack the
  submitted hash, time-boxed to DIRECT_CRACK_TIMEBOX_S (60s).
- Result finding: type, CRACKED + plaintext, or NOT CRACKED, plus the
  time taken.

All native Python, zero API keys, keyless throughout.
"""
from __future__ import annotations

import asyncio
import hashlib
import html as html_lib
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from . import hashcrack_engine as engine
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, is_placeholder, redact

# (id, fullmatch regex, label, verdict, severity)
HASH_SPECS: List[Tuple[str, re.Pattern, str, str, str]] = [
    ("md5", re.compile(r"[a-fA-F0-9]{32}"),
     "MD5", "unsalted fast hash: crackable in seconds on a GPU", "high"),
    ("sha1", re.compile(r"[a-fA-F0-9]{40}"),
     "SHA-1", "unsalted fast hash: crackable in seconds on a GPU", "high"),
    ("sha256", re.compile(r"[a-fA-F0-9]{64}"),
     "SHA-256", "fast hash: crackable if unsalted and password is weak",
     "medium"),
    ("sha512", re.compile(r"[a-fA-F0-9]{128}"),
     "SHA-512", "fast hash: crackable if unsalted and password is weak",
     "medium"),
    ("ntlm", re.compile(r"(?i)ntlm[:=]\s*([a-fA-F0-9]{32})"),
     "NTLM", "fast unsalted hash: crackable in seconds on a GPU", "high"),
    ("md5crypt", re.compile(r"\$1\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22}"),
     "MD5-crypt", "salted but fast: crackable with modest GPU effort",
     "medium"),
    ("sha256crypt", re.compile(r"\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}"),
     "SHA-256-crypt", "salted, tunable cost: strong if rounds are high",
     "low"),
    ("sha512crypt", re.compile(r"\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}"),
     "SHA-512-crypt", "salted, tunable cost: strong if rounds are high",
     "low"),
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),
     "bcrypt", "slow salted hash: not practically crackable", "low"),
    ("scrypt", re.compile(r"\$scrypt\$[^$\s]+\$[^$\s]+\$[A-Za-z0-9+/=]+"),
     "scrypt", "memory-hard salted hash: not practically crackable", "low"),
    ("argon2", re.compile(r"\$argon2(?:id|i|d)\$[^$\s]+\$[^$\s]+\$[^$\s]+\$[A-Za-z0-9+/=]+"),
     "Argon2", "memory-hard salted hash: not practically crackable", "low"),
    ("pbkdf2", re.compile(r"\$pbkdf2-sha(?:256|512)\$[^$\s]+\$[^$\s]+\$[A-Za-z0-9+/=]+"),
     "PBKDF2", "salted, tunable iterations: strong if iterations are high",
     "low"),
]

# Scan regexes for finding hashes embedded in page text/JS.
SCAN_RES: List[Tuple[str, re.Pattern]] = [
    ("md5", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")),
    ("sha1", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")),
    ("sha256", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")),
    ("sha512", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])")),
    ("ntlm", re.compile(r"(?i)\bntlm[:=]\s*([a-fA-F0-9]{32})")),
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    ("argon2", re.compile(r"\$argon2(?:id|i|d)\$[^$\s]+\$[^$\s]+\$[^$\s]+\$[A-Za-z0-9+/=]+")),
    ("md5crypt", re.compile(r"\$1\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22}")),
    ("sha512crypt", re.compile(r"\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}")),
]

# Cap on external public-DB lookups so the plugin stays fast.
MAX_SHA1_LOOKUPS = 5
MAX_MD5_LOOKUPS = 5

# Gromweb result page anchor: "... was successfully reversed into the
# string <a class="String" href="/?string=X">X</a>". The JSON API the
# plugin originally used is gone (the endpoint serves HTML only now),
# so parse the page - and ALWAYS re-verify a candidate by re-hashing
# it before trusting it, so parser drift can never produce a wrong
# "plaintext".
_GROMWEB_ANCHOR = re.compile(
    r"was successfully reversed into the string\s*"
    r"<a[^>]*>(?P<text>[^<]+)</a>", re.IGNORECASE)
_GROMWEB_HREF = re.compile(
    r"was successfully reversed into the string\s*"
    r"<a[^>]*href=\"/\?string=(?P<href>[^\"]+)\"", re.IGNORECASE)


def _identify(standalone: str) -> Optional[Tuple[str, str, str, str, str]]:
    """Identify a standalone hash string. Returns (hid, value, label,
    verdict, severity) or None."""
    s = standalone.strip()
    for hid, pat, label, verdict, sev in HASH_SPECS:
        m = pat.fullmatch(s)
        if m:
            return hid, (m.group(1) if m.groups() else m.group(0)), label, verdict, sev
    return None


async def _hibp_sha1_count(sha1hex: str, ctx: Ctx) -> Optional[int]:
    """K-anonymity check: is this SHA-1 in public breach data?

    Only the first 5 hex chars leave the box. If the remaining suffix
    appears in the response, the password behind the hash is breached.
    Returns the breach count, 0 if not found, None on error.
    """
    try:
        prefix = sha1hex[:5].upper()
        suffix = sha1hex[5:].upper()
        r = await fetch(
            ctx.http, ctx.limiter, "GET",
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=12, max_retries=0,
            headers={"User-Agent": "ReconAnything-hashcracker/1.0"})
        if r.status_code != 200:
            return None
        for line in r.text.splitlines():
            sfx, _, count = line.partition(":")
            if sfx.strip().upper() == suffix:
                try:
                    return int(count.strip())
                except ValueError:
                    return 1
        return 0
    except Exception:
        return None


def _verified_md5(candidate: Optional[str], target_hex: str) -> Optional[str]:
    """Return the candidate only if MD5(candidate) == target. This is
    verification of a public-DB claim, never a guess. Deliberately no
    placeholder filter here: "password" is on the placeholder list,
    and it is also the most common real plaintext - the re-hash check
    is the stronger gate by far."""
    if not candidate:
        return None
    candidate = candidate.strip()
    if not candidate or len(candidate) > 128:
        return None
    if hashlib.md5(candidate.encode()).hexdigest() == target_hex.lower():
        return candidate
    return None


async def _md5_rainbow_lookup(h: str, ctx: Ctx) -> Optional[str]:
    """Best-effort check of a keyless public MD5 rainbow database.
    Returns the plaintext only if it is already public AND re-verifies
    against the requested hash. Never cracks."""
    try:
        r = await fetch(
            ctx.http, ctx.limiter, "GET",
            f"https://md5.gromweb.com/?md5={h.lower()}",
            timeout=12, max_retries=0,
            headers={"Accept": "application/json",
                     "User-Agent": "ReconAnything-hashcracker/1.0"})
        if r.status_code != 200:
            return None
        # JSON API (historical): {"string": "..."}.
        try:
            data = r.json()
            if isinstance(data, dict):
                s = str(data.get("string") or data.get("plaintext")
                        or "").strip()
                v = _verified_md5(s, h)
                if v:
                    return v
        except Exception:
            pass
        # HTML result page (what the endpoint serves today).
        body = r.text or ""
        for pat, is_href in ((_GROMWEB_ANCHOR, False),
                             (_GROMWEB_HREF, True)):
            m = pat.search(body)
            if m:
                raw = m.group("href") if is_href else m.group("text")
                cand = unquote(html_lib.unescape(raw))
                v = _verified_md5(cand, h)
                if v:
                    return v
    except Exception:
        pass
    return None


class HashcrackerPlugin(Plugin):
    id = "hashcracker"
    label = "Hash Cracker (Defensive)"
    accepts = ["domain", "url", "file_hash"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    requires_keys: List[str] = []
    description = ("Identify hash types and check public breach/rainbow "
                   "databases (HIBP k-anonymity, keyless). Direct mode "
                   "(submit a hash as the target): also cracks it with "
                   "the bundled dictionary+rules engine, time-boxed "
                   "60s. Scan mode is analysis-only: verdicts, never "
                   "plaintexts.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        findings: List[Finding] = []
        analyzed = 0

        # --- Direct mode: the target itself is a standalone hash ---
        direct = _identify(target.normalized)
        if direct:
            hid, val, label, verdict, sev = direct
            f = await self._analyze_one(
                hid, val, label, verdict, sev, ctx,
                source="direct hash analysis", source_url=None,
                passive=passive, direct=True,
                do_sha1=(hid == "sha1"), do_md5=(hid == "md5"))
            findings.append(f)
            cf = await self._direct_crack(hid, val, label, passive)
            if cf is not None:
                findings.append(cf)
            res = self._ok(findings, f"analyzed 1 submitted hash ({label})")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # --- Scan mode: find hashes on the target's public pages ---
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        try:
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
        sha1_checks = 0
        md5_checks = 0
        for hid, pat in SCAN_RES:
            spec = next((s for s in HASH_SPECS if s[0] == hid), None)
            if spec is None:
                continue
            _, _, label, verdict, sev = spec
            for m in pat.finditer(html):
                val = m.group(1) if m.groups() else m.group(0)
                if (re.fullmatch(r"0+", val) or re.fullmatch(r"f+", val, re.I)
                        or is_placeholder(val)):
                    continue
                key = f"{hid}:{val.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                # Budget the public-DB lookups so scans stay fast.
                allow_sha1 = (hid == "sha1" and sha1_checks < MAX_SHA1_LOOKUPS)
                allow_md5 = (hid == "md5" and md5_checks < MAX_MD5_LOOKUPS)
                if allow_sha1:
                    sha1_checks += 1
                if allow_md5:
                    md5_checks += 1
                f = await self._analyze_one(
                    hid, val, label, verdict, sev, ctx,
                    source=f"hash scan: {page_url}", source_url=page_url,
                    passive=passive, direct=False,
                    do_sha1=allow_sha1, do_md5=allow_md5)
                findings.append(f)
                analyzed += 1
                if analyzed >= 20:
                    break
            if analyzed >= 20:
                break

        res = self._ok(findings, f"{analyzed} hashes identified and assessed")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _direct_crack(self, hid: str, val: str, label: str,
                            passive: bool) -> Optional[Finding]:
        """Direct mode only: run the bundled dictionary+rules engine on
        the hash the user submitted. Time-boxed; runs in a thread so the
        worker's event loop never blocks. Returns None for hash formats
        the engine does not cover (crypt/Argon2/scrypt/PBKDF2) - the
        analysis finding already carries their verdict."""
        kind, _algos = engine.identify(val)
        if kind == "unknown":
            return None
        try:
            r = await asyncio.to_thread(
                engine.crack_submitted, val, engine.DIRECT_CRACK_TIMEBOX_S)
        except Exception:
            return None
        tried = r.get("candidates_tried") or 0
        secs = r.get("seconds") or 0
        if r.get("cracked"):
            value = (f"CRACKED: {r['type']} hash {redact(val, 8)} is "
                     f"'{r['plaintext']}' (direct-mode dictionary+rules "
                     f"crack, rule: {r.get('rule')}, {tried} candidates "
                     f"in {secs}s). Anyone holding this hash and a "
                     f"wordlist gets the same result.")
            ev = evidence_block(val, "hash_cracked_direct", "credential",
                                "high",
                                {"hash_type": r["type"],
                                 "cracked": True,
                                 "plaintext": r["plaintext"],
                                 "rule": r.get("rule"),
                                 "candidates_tried": tried,
                                 "seconds": secs,
                                 "engine": "bundled SecLists 10k "
                                           "dictionary + rules "
                                           "(user-submitted hash only)",
                                 "action": ("Rotate this credential "
                                            "immediately and re-hash with "
                                            "bcrypt or Argon2id.")})
            return self._f("leak", "hash_cracked_direct", value,
                           "direct hash crack (user-submitted)",
                           confidence=100, evidence=ev, passive=passive,
                           exploitability="public_poc")
        note = r.get("error") or r.get("note") or ""
        box = " Time box reached." if r.get("timed_out") else ""
        value = (f"NOT CRACKED: {r['type']} hash {redact(val, 8)} "
                 f"resisted the bundled dictionary+rules attack "
                 f"({tried} candidates in {secs}s).{box} "
                 f"A larger wordlist or GPU rig may still crack a weak "
                 f"password; the crackability verdict above stands."
                 + (f" Note: {note}" if note else ""))
        ev = evidence_block(val, "hash_crack_attempt", "credential", "low",
                            {"hash_type": r["type"], "cracked": False,
                             "candidates_tried": tried, "seconds": secs,
                             "timed_out": bool(r.get("timed_out")),
                             "engine": "bundled SecLists 10k dictionary "
                                       "+ rules (user-submitted hash "
                                       "only)",
                             "action": ("No action needed from this check "
                                        "alone; follow the verdict finding "
                                        "for this hash.")})
        return self._f("leak", "hash_crack_attempt", value,
                       "direct hash crack (user-submitted)",
                       confidence=80, evidence=ev, passive=passive,
                       exploitability="theoretical")

    async def _analyze_one(self, hid: str, val: str, label: str,
                           verdict: str, sev: str, ctx: Ctx, source: str,
                           source_url: Optional[str], passive: bool,
                           direct: bool = False,
                           do_sha1: bool = False,
                           do_md5: bool = False) -> Finding:
        """Identify + assess one hash. Public-DB lookups only.

        `direct` is True only when the user submitted this hash
        themselves; only then may a public-DB plaintext appear in the
        finding. In scan mode the looked-up plaintext is discarded:
        the finding reports the cracked-in-public-DB status only.
        """
        breached_count: Optional[int] = None
        plaintext: Optional[str] = None
        cracked_public = False

        # SHA-1: HIBP k-anonymity (only 5 hash chars leave the box).
        if hid == "sha1" and do_sha1:
            breached_count = await _hibp_sha1_count(val, ctx)
            cracked_public = bool(breached_count and breached_count > 0)

        # MD5: keyless public rainbow database.
        if hid == "md5" and do_md5:
            found = await _md5_rainbow_lookup(val, ctx)
            cracked_public = found is not None
            if direct:
                plaintext = found

        if cracked_public:
            if plaintext:
                value = (f"HIGH: {label} hash {redact(val, 8)} is ALREADY "
                         f"CRACKED in a public database. "
                         f"Plaintext: {plaintext}")
            elif breached_count:
                value = (f"HIGH: {label} hash {redact(val, 8)} appears in "
                         f"public breach data ({breached_count} breaches). "
                         f"The password is compromised.")
            else:
                value = (f"HIGH: {label} hash {redact(val, 8)} is ALREADY "
                         f"CRACKED in a public database. "
                         f"The password is compromised.")
            ev = evidence_block(val, "hash_cracked_public", "credential",
                                "high",
                                {"hash_type": label, "verdict": verdict,
                                 "breach_count": breached_count,
                                 "plaintext_public": plaintext,
                                 "lookup": "public breach/rainbow database "
                                           "(k-anonymity for HIBP)",
                                 "action": ("Rotate this credential "
                                            "immediately and re-hash with "
                                            "bcrypt or Argon2id.")})
            return self._f("leak", "hash_cracked_public", value, source,
                           source_url=source_url, confidence=95,
                           evidence=ev, passive=passive,
                           exploitability="public_poc")

        # Not in public DBs: report the crackability verdict.
        if breached_count == 0 and hid == "sha1":
            extra_note = " Not found in HIBP breach data."
        elif hid == "sha1" and not do_sha1:
            extra_note = " Breach-DB lookup skipped (scan budget)."
        else:
            extra_note = ""
        value = (f"{label} hash {redact(val, 8)} found. {verdict}."
                 f"{extra_note}")
        ev = evidence_block(val, "hash_strength", "credential", sev,
                            {"hash_type": label, "verdict": verdict,
                             "cracked_in_public_db": False,
                             "breach_count": breached_count,
                             "action": ("If this protects a live account, "
                                        "rotate it and re-hash with bcrypt "
                                        "or Argon2id.")})
        return self._f("leak", "hash_analyzed", value, source,
                       source_url=source_url, confidence=75,
                       evidence=ev, passive=passive,
                       exploitability="theoretical")
