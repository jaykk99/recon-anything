"""Keyless public-RPC provider pool for the deep lane (Track 2).

WHY THIS EXISTS
---------------
The deep lane's wall time is network-bound: one contract's read set
(code + balance + ~8 storage words + view getters + fuzz probes) is
20-30 JSON-RPC calls, and on master each call was its own HTTP POST,
re-looping the chain's endpoint list from the top every time. A dead
or rate-limited first endpoint was therefore paid for on EVERY call
(the flat 120s cooldown in contract_chain helped, but a single 429
marked a host "dead" for two minutes while a genuinely dead host got
retried the moment the flat window expired).

This module is the pool layer the batched transports sit on:

- ENDPOINTS: per-chain lists of KEYLESS public JSON-RPC endpoints
  (plain HTTPS, no API key anywhere - no Alchemy/Infura/QuickNode).
  ``EXTRA_KEYLESS_RPCS`` widens each chain's ``contract_chain.CHAINS``
  list; the pool merges both at call time so config changes in
  contract_chain keep applying.
- ROTATION: successive ``order()`` calls start at successive healthy
  endpoints (per-chain round-robin cursor), so load spreads across
  providers instead of always hammering the first one.
- BREAKER: a dead-host breaker mirroring the continuous scanner's
  HostHealth (~/workspace/recon-continuous/runner.py, 2026-11-09):
  hard failures (429 / 5xx / transport errors) trip only after a
  streak of 5, soft failures after a streak of 10 and only once some
  host has demonstrably succeeded (a total egress outage must not
  poison every host), cooldowns escalate 60s -> 300s -> 600s, and a
  single half-open probe is allowed through when a cooldown expires.
  Cooling endpoints are never dropped from the order - they sort
  last as a fallback, so the pool can never make a chain unreachable
  (same contract as contract_chain._rpc_order).
- 429 BACKOFF: a 429 additionally arms a per-host exponential
  backoff window (2s, 4s, 8s ... capped at 60s) during which the
  host is skipped. Nobody sleeps in the hot path: the backoff is a
  "do not select before" timestamp, and failover to the next
  endpoint is immediate (the shared RateLimiter separately honors
  Retry-After for the endpoints it paces).
- STATS: per-host call/success/streak/trip counters plus suppressed
  selections, so benchmarks report issued-request counts from
  instrumentation, not estimates.

Read-only throughout: the pool only orders endpoints and records
outcomes for read calls (eth_call / eth_getCode / eth_getStorageAt /
eth_getBalance). Nothing here builds or broadcasts a transaction,
and nothing here can stamp a finding VERIFIED_REAL - it is pure
transport plumbing below the detection layer.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Dict, List
from urllib.parse import urlparse

# Additional keyless public endpoints per chain id, merged after the
# chain's own contract_chain.CHAINS rpc_urls. Plain HTTPS POST
# endpoints only: no API-key query params, no sign-up routes. These
# are the long-standing free community endpoints (PublicNode, dRPC,
# BlastAPI public, 1RPC, Ankr's keyless front door, Merkle) - the
# same class of endpoint the repo already uses, just more of them so
# rotation and failover have somewhere to go.
EXTRA_KEYLESS_RPCS: Dict[str, tuple] = {
    "ethereum": (
        "https://eth.drpc.org",
        "https://rpc.ankr.com/eth",
        "https://1rpc.io/eth",
        "https://eth-mainnet.public.blastapi.io",
        "https://eth.merkle.io",
    ),
    "bsc": (
        "https://bsc.drpc.org",
        "https://1rpc.io/bnb",
        "https://bsc-mainnet.public.blastapi.io",
    ),
    "polygon": (
        "https://polygon.drpc.org",
        "https://rpc.ankr.com/polygon",
        "https://1rpc.io/matic",
        "https://polygon-mainnet.public.blastapi.io",
    ),
    "arbitrum": (
        "https://arbitrum.drpc.org",
        "https://rpc.ankr.com/arbitrum",
        "https://1rpc.io/arb",
        "https://arbitrum-one.public.blastapi.io",
    ),
    "base": (
        "https://base.drpc.org",
        "https://rpc.ankr.com/base",
        "https://1rpc.io/base",
        "https://base-mainnet.public.blastapi.io",
    ),
    "optimism": (
        "https://optimism.drpc.org",
        "https://rpc.ankr.com/optimism",
        "https://1rpc.io/op",
        "https://optimism-mainnet.public.blastapi.io",
    ),
}

# Breaker tuning (env-overridable, defaults mirror the continuous
# scanner's HostHealth so both lanes treat a dead host the same way).
HARD_STREAK = int(os.environ.get("RECON_RPC_HARD_STREAK", "5"))
SOFT_STREAK = int(os.environ.get("RECON_RPC_SOFT_STREAK", "10"))
COOLDOWNS_S = (60.0, 300.0, 600.0)
THROTTLE_BASE_S = float(os.environ.get("RECON_RPC_THROTTLE_BASE_S", "2"))
THROTTLE_MAX_S = float(os.environ.get("RECON_RPC_THROTTLE_MAX_S", "60"))


def throttle_backoff_s(streak: int) -> float:
    """Exponential backoff window after the n-th consecutive 429."""
    if streak <= 0:
        return 0.0
    return min(THROTTLE_MAX_S, THROTTLE_BASE_S * (2 ** (streak - 1)))


class RpcPool:
    """Per-chain endpoint ordering + health for keyless public RPCs.

    One process-wide instance (``POOL``) is shared by every batched
    transport, exactly like the continuous scanner's process-wide
    HostHealth: health learned by one plugin protects all the others.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hosts: Dict[str, Dict] = {}
        self._cursors: Dict[str, int] = {}
        self.suppressed = 0
        self.probes = 0
        # A failure only proves a HOST is dead when the network path
        # demonstrably works (some host succeeded recently). During
        # a total egress outage every host fails at once; those
        # failures earn only the shortest cooldown.
        self.successes_total = 0
        self.last_success_any = 0.0

    # -- endpoint lists ------------------------------------------------

    @staticmethod
    def endpoints(chain_id: str, base_urls) -> List[str]:
        """Chain config URLs + pool extras, de-duplicated, in order."""
        out: List[str] = []
        for u in list(base_urls) + list(EXTRA_KEYLESS_RPCS.get(chain_id, ())):
            if u not in out:
                out.append(u)
        return out

    # -- health bookkeeping (mirrors the scanner's HostHealth) ---------

    def _st(self, url: str) -> Dict:
        return self._hosts.setdefault(url, {
            "hard": 0, "soft": 0, "successes": 0, "calls": 0,
            "dead_until": 0.0, "throttle_until": 0.0, "throttle_streak": 0,
            "probe": False, "trips": 0})

    def _maybe_trip(self, st: Dict) -> None:
        now = time.monotonic()
        if st["dead_until"] > now:
            return
        hard = st["hard"] >= HARD_STREAK
        # Soft rule arms only once SOME host has succeeded: with zero
        # successes anywhere, 100% failure is an outage signature,
        # not evidence against this specific host.
        soft = (st["successes"] == 0
                and st["soft"] >= SOFT_STREAK
                and self.successes_total > 0)
        if not (hard or soft):
            return
        network_works = (self.successes_total > 0
                         and now - self.last_success_any <= 30.0)
        if network_works:
            cd = COOLDOWNS_S[min(st["trips"], len(COOLDOWNS_S) - 1)]
        else:
            cd = COOLDOWNS_S[0]
        st["trips"] += 1
        st["dead_until"] = now + cd

    def note_response(self, url: str, status: int) -> None:
        """Fold one HTTP response from ``url`` into its health."""
        with self._lock:
            st = self._st(url)
            st["calls"] += 1
            if status == 429:
                st["hard"] += 1
                st["soft"] += 1
                st["probe"] = False
                st["throttle_streak"] += 1
                st["throttle_until"] = (
                    time.monotonic()
                    + throttle_backoff_s(st["throttle_streak"]))
                self._maybe_trip(st)
            elif status >= 500:
                st["hard"] += 1
                st["soft"] += 1
                st["probe"] = False
                self._maybe_trip(st)
            elif status < 400:
                st["successes"] += 1
                st["hard"] = 0
                st["soft"] = 0
                st["throttle_streak"] = 0
                st["throttle_until"] = 0.0
                st["dead_until"] = 0.0
                st["probe"] = False
                st["trips"] = 0
                self.successes_total += 1
                self.last_success_any = time.monotonic()
            else:  # other 4xx: host answered (alive), soft evidence only
                st["hard"] = 0
                st["soft"] += 1
                if st["probe"]:
                    st["probe"] = False
                    if not (st["successes"] == 0
                            and st["soft"] >= SOFT_STREAK):
                        st["dead_until"] = 0.0
                self._maybe_trip(st)

    def note_transport_error(self, url: str) -> None:
        """The request never got an HTTP response (connect/timeout)."""
        with self._lock:
            st = self._st(url)
            st["calls"] += 1
            st["hard"] += 1
            st["soft"] += 1
            st["probe"] = False
            self._maybe_trip(st)

    def note_batch_failure(self, url: str) -> None:
        """The endpoint answered HTTP 200 but its body was unusable
        as a batch response (not a list, or no item matched a
        request id) - it is batch-hostile even if it serves single
        calls fine. Counted as a hard failure for SELECTION only:
        the pool's order drives the batched transports, while the
        legacy single-call readers keep their own ordering and are
        unaffected. Does not double-count the HTTP call itself
        (note_response already recorded it)."""
        with self._lock:
            st = self._st(url)
            st["hard"] += 1
            st["soft"] += 1
            st["probe"] = False
            self._maybe_trip(st)

    # -- selection -------------------------------------------------------

    @staticmethod
    def _available(st: Dict, now: float) -> bool:
        return st["dead_until"] <= now and st["throttle_until"] <= now

    def allows(self, url: str) -> bool:
        """True when ``url`` may be selected now. A host whose
        cooldown just expired gets exactly one half-open probe."""
        now = time.monotonic()
        with self._lock:
            st = self._st(url)
            if st["dead_until"] <= 0 and st["throttle_until"] <= 0:
                return True
            if st["dead_until"] > now or st["throttle_until"] > now:
                self.suppressed += 1
                return False
            if st["probe"]:
                self.suppressed += 1
                return False
            st["probe"] = True
            self.probes += 1
            return True

    def order(self, chain_id: str, base_urls) -> List[str]:
        """Endpoints for one call: healthy ones first, rotated
        round-robin per chain; cooling/throttled ones last, in
        config order, as a never-drop fallback (a call whose every
        endpoint is cooling still tries them all, exactly like
        contract_chain._rpc_order)."""
        urls = self.endpoints(chain_id, base_urls)
        now = time.monotonic()
        with self._lock:
            healthy, cooling = [], []
            for u in urls:
                st = self._hosts.get(u)
                if st is None or self._available(st, now):
                    healthy.append(u)
                else:
                    cooling.append(u)
            if healthy:
                cur = self._cursors.get(chain_id, 0) % len(healthy)
                self._cursors[chain_id] = cur + 1
                healthy = healthy[cur:] + healthy[:cur]
            return healthy + cooling

    # -- introspection ---------------------------------------------------

    def stats(self) -> Dict:
        now = time.monotonic()
        with self._lock:
            return {
                "suppressed": self.suppressed,
                "probes": self.probes,
                "successes_total": self.successes_total,
                "hosts": {u: {"calls": s["calls"],
                              "successes": s["successes"],
                              "hard_streak": s["hard"],
                              "soft_streak": s["soft"],
                              "throttle_streak": s["throttle_streak"],
                              "trips": s["trips"],
                              "cooling": s["dead_until"] > now,
                              "throttled": s["throttle_until"] > now}
                          for u, s in sorted(self._hosts.items())
                          if s["calls"]},
            }

    def reset(self) -> None:
        """Forget all health/cursor state (tests, operator resets)."""
        with self._lock:
            self._hosts.clear()
            self._cursors.clear()
            self.suppressed = 0
            self.probes = 0
            self.successes_total = 0
            self.last_success_any = 0.0


POOL = RpcPool()


def host_of(url: str) -> str:
    return urlparse(url).netloc
