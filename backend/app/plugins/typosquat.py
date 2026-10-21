"""Typosquat / lookalike domain detection plugin.

Generates common typosquat variants of the target domain (character
omission, adjacent swap, keyboard-adjacent substitution, double
character, missing/extra hyphen, wrong TLD from a short list) and
checks which ones actually resolve. Registered lookalikes are phishing
infrastructure risk - and also domains Jay may want to defensively
hold.

Detection only: DNS A lookups of generated names. No contact, no
registration attempts, nothing beyond resolution.
"""
from __future__ import annotations

import asyncio
import time
from typing import List

import dns.asyncresolver

from ..classifier import domain_from_target
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

# keyboard-adjacent substitutions (qwerty)
ADJACENT = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujbn", "i": "ujko",
    "j": "huiknm", "k": "jiolm", "l": "kop", "m": "njk",
    "n": "bhjm", "o": "iklp", "p": "ol", "q": "wa", "r": "edft",
    "s": "awedxz", "t": "rfgy", "u": "yhji", "v": "cfgb",
    "w": "qeas", "x": "zsdc", "y": "tghu", "z": "asx",
    "0": "9", "1": "2q", "2": "13qw", "3": "24we", "4": "35er",
    "5": "46rt", "6": "57ty", "7": "68yu", "8": "79ui", "9": "80io",
}
ALT_TLDS = ["com", "net", "org", "io", "co"]
MAX_VARIANTS = 120


def _variants(name: str) -> List[str]:
    """Generate typosquat variants of a single-label domain name."""
    out = set()
    n = len(name)
    for i in range(n):
        out.add(name[:i] + name[i + 1:])          # omission
        out.add(name[:i] + name[i] * 2 + name[i + 1:])  # doubling
        if i < n - 1:
            out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])  # swap
        for sub in ADJACENT.get(name[i].lower(), "")[:3]:
            out.add(name[:i] + sub + name[i + 1:])  # substitution
    out.add(name.replace("-", ""))               # missing hyphen
    if "-" not in name:
        for i in range(1, n):
            out.add(name[:i] + "-" + name[i:])   # extra hyphen
    out.discard(name)
    out = {v for v in out if 2 <= len(v) <= 63 and v != name}
    return sorted(out)[:MAX_VARIANTS]


class TyposquatPlugin(Plugin):
    id = "typosquat"
    label = "Typosquat Domains"
    accepts = ["domain"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Generate typosquat variants and report which ones "
                   "actually resolve (phishing risk / defensive holds).")
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain or target.type != "domain":
            return self._skipped("needs a bare domain target")
        labels = domain.split(".")
        if len(labels) < 2:
            return self._skipped("not a valid domain")
        name, tld = ".".join(labels[:-1]), labels[-1]
        if len(name) < 3:
            return self._skipped("domain label too short for variants")

        res = dns.asyncresolver.Resolver(configure=False)
        res.nameservers = ["8.8.8.8", "1.1.1.1"]
        res.timeout = 4
        res.lifetime = 6
        variants = [f"{v}.{tld}" for v in _variants(name)]
        # wrong-TLD variants of the exact name
        variants += [f"{name}.{t}" for t in ALT_TLDS if t != tld]
        variants = list(dict.fromkeys(variants))[:MAX_VARIANTS + 5]

        async def _resolves(d: str) -> str | None:
            try:
                ans = await res.resolve(d, "A")
                ips = [str(rr) for rr in ans][:3]
                return ",".join(ips)
            except Exception:
                return None

        results = await asyncio.gather(*(_resolves(v) for v in variants))
        hits = [(v, ips) for v, ips in zip(variants, results) if ips]
        findings: List = []
        for v, ips in hits[:25]:
            findings.append(self._f(
                "infra", "typosquat_registered",
                f"Lookalike domain resolves: {v} -> {ips}",
                source="typosquat scan", confidence=95, passive=True,
                evidence={"severity": "medium", "domain": v, "ips": ips,
                          "remediation": (
                              f"Review {v}: if it is not yours, it may be "
                              "phishing infrastructure - consider a "
                              "defensive registration or a takedown report; "
                              "if it IS yours, keep it.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"checked {len(variants)} variants, {len(hits)} resolve")
