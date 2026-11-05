"""Dnstwist-style typosquat detection (Tier-1 OSINT).

Generates lookalike permutations of the target domain the way
dnstwist does - omission, transposition, repetition, hyphenation,
character replacement, homoglyphs (o->0, l->1, rn->m, ...), vowel
swaps, subdomain-style dots and TLD swaps - then checks each
permutation for DNS registration via keyless DNS-over-HTTPS A/NS
lookups. A permutation that resolves is a registered lookalike:
a phishing / brand-abuse candidate worth a finding. Generation is
pure and capped; lookups are read-only public DNS data.
"""
from __future__ import annotations

import time
from typing import Dict, List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_PERMUTATIONS = 160
MAX_CHECKS = 90
ALT_TLDS = ("com", "net", "org", "io", "co", "info", "xyz", "online")
HOMOGLYPHS = {
    "o": ["0"], "l": ["1"], "i": ["1"], "a": ["@"],
    "e": ["3"], "s": ["5"], "g": ["9"], "b": ["8"],
}
KEYBOARD_NEIGHBORS = {
    "a": "s", "s": "d", "d": "f", "e": "r", "r": "t", "t": "y",
    "o": "p", "i": "o", "n": "m", "m": "n", "c": "v", "v": "b",
}


def split_domain(domain: str):
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return domain.lower(), ""
    return ".".join(parts[:-1]), parts[-1]


def generate_permutations(domain: str) -> Dict[str, str]:
    """{permuted_domain: technique} - deduped, capped, deterministic."""
    name, tld = split_domain(domain)
    out: Dict[str, str] = {}
    if not name or not tld:
        return out

    def add(candidate: str, technique: str):
        candidate = candidate.lower()
        if candidate and candidate != domain and candidate not in out \
                and len(out) < MAX_PERMUTATIONS:
            out[candidate] = technique

    n = len(name)
    for i in range(n):  # omission
        add(name[:i] + name[i + 1:] + "." + tld, "omission")
    for i in range(n - 1):  # transposition
        if name[i] != name[i + 1]:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:] + "." + tld,
                "transposition")
    for i in range(n):  # repetition
        add(name[:i] + name[i] + name[i:] + "." + tld, "repetition")
    for i in range(n):  # replacement by keyboard neighbor
        repl = KEYBOARD_NEIGHBORS.get(name[i])
        if repl:
            add(name[:i] + repl + name[i + 1:] + "." + tld, "replacement")
    for i, ch in enumerate(name):  # homoglyphs
        for glyph in HOMOGLYPHS.get(ch, []):
            add(name[:i] + glyph + name[i + 1:] + "." + tld, "homoglyph")
    if "rn" in name:  # multi-char homoglyph
        add(name.replace("rn", "m", 1) + "." + tld, "homoglyph")
    if "m" in name:
        add(name.replace("m", "rn", 1) + "." + tld, "homoglyph")
    for i in range(1, n):  # hyphen insertion
        add(name[:i] + "-" + name[i:] + "." + tld, "hyphenation")
    if "-" in name:  # hyphen removal
        add(name.replace("-", "") + "." + tld, "hyphenation")
    for i, ch in enumerate(name):  # vowel swap
        if ch in "aeiou":
            for v in "aeiou":
                if v != ch:
                    add(name[:i] + v + name[i + 1:] + "." + tld,
                        "vowel_swap")
                    break
    for alt in ALT_TLDS:  # TLD swap
        if alt != tld:
            add(name + "." + alt, "tld_swap")
    add(name + ".com." + tld, "subdomain_style")  # e.g. name.com.tld look
    return out


async def resolves(ctx: Ctx, name: str) -> bool:
    """True when DoH returns any A or NS answer for name."""
    for rtype in ("A", "NS"):
        try:
            resp = await fetch(
                ctx.http, ctx.limiter, "GET",
                f"https://dns.google/resolve?name={quote(name)}"
                f"&type={rtype}", timeout=10, max_retries=1,
                headers={"accept": "application/dns-json"})
            if resp.status_code != 200:
                continue
            data = resp.json()
            answers = data.get("Answer") or []
            if any(isinstance(a, dict) and a.get("data") for a in answers):
                return True
        except Exception:
            continue
    return False


class DnstwistPlugin(Plugin):
    timeout_s = 90
    id = "dnstwist"
    label = "Dnstwist Typosquat Check"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = ("Typosquat permutation generation (omission, "
                   "transposition, homoglyph, TLD-swap and more, "
                   "dnstwist-style) with DNS registration checks for "
                   "each permutation; flags registered lookalikes.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        perms = generate_permutations(domain)
        findings: List[Finding] = []
        checked = 0
        for candidate, technique in list(perms.items())[:MAX_CHECKS]:
            checked += 1
            try:
                live = await resolves(ctx, candidate)
            except Exception:
                live = False
            if not live:
                continue
            sev = "medium" if technique in ("homoglyph", "tld_swap") \
                else "low"
            findings.append(self._f(
                "identity", "typosquat_registered",
                f"{candidate} ({technique} of {domain}) is registered "
                f"and resolves",
                source="dnstwist/DoH", confidence=80, passive=True,
                evidence={"permutation": candidate,
                          "technique": technique, "severity": sev,
                          "remediation": "Review this lookalike domain "
                                         "for phishing/brand abuse; "
                                         "consider defensive registration "
                                         "or a takedown if it imitates "
                                         "the brand."}))
            self._checkpoint(findings)
        res = self._ok(findings, f"{len(findings)} registered lookalikes "
                                 f"of {len(perms)} permutations "
                                 f"({checked} DNS-checked)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
