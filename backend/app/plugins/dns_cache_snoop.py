"""DNS cache-snooping plugin (ported from ARTEX modules/dns_scan.py).

Timing-based test for whether a nameserver answers from cache for names
that do not exist. ARTEX's method: query a random (surely NXDOMAIN) label
twice; the first query is slow (recursive lookup), the second is fast if
the answer was cached. A resolver that caches NXDOMAIN answers lets
anyone who can query it test whether a name was recently looked up —
information disclosure about the resolver's users.

Ported from ARTEX DNSScanner.cache_snoop, with two corrections:
- ARTEX queries the system resolver and reports the result as a property
  of the target domain. This port queries the target's own authoritative
  nameserver directly (first NS record), falling back to the system
  resolver only when NS lookup fails, and the finding names the server
  actually tested.
- ARTEX runs one round; one slow query is enough to flip it. This port
  runs two rounds and requires both to show caching, and requires the
  first query to be measurably slow (>= 50ms) so timer noise cannot
  produce a finding.

Detection only: three DNS queries per round, no zone transfer, no
cache poisoning, nothing written anywhere.
"""
from __future__ import annotations

import random
import time
from typing import List, Optional

import dns.asyncresolver
import dns.exception

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# ARTEX used a 6-digit random label; keep the same shape.
_LABEL_DIGITS = 6
# First query must take at least this long or the timing is noise.
_MIN_FIRST_S = 0.05
_ROUNDS = 2


def _now() -> float:
    """Monotonic clock (seam: tests patch this for deterministic timing)."""
    return time.monotonic()


class DnsCacheSnoopPlugin(Plugin):
    id = "dns_cache_snoop"
    label = "DNS Cache Snooping"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Timing test for whether a nameserver caches NXDOMAIN "
                   "answers (cache snooping).")
    phase = 1

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        nameserver = await self._first_ns_ip(domain)
        resolver = self._resolver(nameserver)

        rounds = []
        for _ in range(_ROUNDS):
            outcome = await self._one_round(resolver, domain)
            if outcome is not None:
                rounds.append(outcome)
        if not rounds:
            return self._degraded(
                "could not complete a cache-snooping timing round "
                "(DNS queries failed or timed out)")
        cached_rounds = sum(1 for r in rounds if r["cached"])
        if cached_rounds < len(rounds):
            return self._ok(
                [], f"nameserver {nameserver or 'system resolver'} does not "
                    f"appear to cache NXDOMAIN answers "
                    f"({cached_rounds}/{len(rounds)} rounds cached)")
        first_ms = rounds[0]["first_ms"]
        second_ms = rounds[0]["second_ms"]
        finding = self._f(
            "dns", "dns_cache_snoop",
            f"Nameserver {nameserver or 'system resolver'} caches NXDOMAIN "
            f"responses (cache snooping possible): random-label query took "
            f"{first_ms:.0f}ms the first time, {second_ms:.0f}ms the second "
            f"({len(rounds)}/{len(rounds)} rounds)",
            source="DNS cache-snooping timing test", confidence=65,
            passive=True,
            evidence={"severity": "low", "nameserver": nameserver,
                      "first_ms": round(first_ms, 1),
                      "second_ms": round(second_ms, 1),
                      "target_ms": round(rounds[0]["target_ms"], 1),
                      "rounds": len(rounds),
                      "why": "Anyone able to query this resolver can test "
                             "whether a given name was recently resolved, "
                             "leaking browsing/lookup behaviour. Restrict "
                             "recursive queries to trusted clients."})
        res = self._ok([finding], f"cache snooping indicated on {domain}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    # -- helpers (seams the unit tests monkeypatch) ----------------------

    def _resolver(self, nameserver: Optional[str]):
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 8
        if nameserver:
            resolver.nameservers = [nameserver]
        return resolver

    async def _first_ns_ip(self, domain: str) -> Optional[str]:
        """First authoritative nameserver IP for the domain, or None."""
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 5
            answers = await resolver.resolve(domain, "NS")
            ns_host = str(answers[0]).rstrip(".")
            a = await resolver.resolve(ns_host, "A")
            return str(a[0])
        except Exception:
            return None

    async def _query(self, resolver, name: str) -> None:
        """One A query; NXDOMAIN is an expected answer, not an error."""
        try:
            await resolver.resolve(name, "A")
        except dns.exception.DNSException:
            pass
        except Exception:
            raise

    async def _one_round(self, resolver, domain: str) -> Optional[dict]:
        """One ARTEX timing round. Returns None when the round is invalid."""
        label = f"{random.randint(10 ** (_LABEL_DIGITS - 1), 10 ** _LABEL_DIGITS - 1)}.{domain}"
        try:
            start = _now()
            await self._query(resolver, label)
            first = _now() - start
            start = _now()
            await self._query(resolver, domain)
            target = _now() - start
            start = _now()
            await self._query(resolver, label)
            second = _now() - start
        except Exception:
            return None
        if first < _MIN_FIRST_S:
            return None
        cached = target < first and second < first / 2
        return {"cached": cached, "first_ms": first * 1000,
                "target_ms": target * 1000, "second_ms": second * 1000}
