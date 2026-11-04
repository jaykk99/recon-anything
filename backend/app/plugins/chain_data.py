"""Shared chain-data layer: one fetch per contract, shared by all
EVM contract plugins in a run.

Before this module, every contract plugin (contract_recon,
contract_logic, crypto_drain_scanner, and each of the 100 generated
BSC detectors in bsc_common) ran its own identical fetch sequence
per address: eth_getCode over the chain's RPC list, then verified
source via Blockscout -> Sourcify (-> Etherscan). One RPC outage
degraded 100+ plugins at once, and a healthy scan paid the same
round trips ~104 times for one contract.

This layer fixes the hitting path without changing what any plugin
detects:

- ``get_chain_data(ctx, chain, address, key)`` performs the fetch
  sequence ONCE per (chain, address) per run and caches the result
  on the run context (``ctx.shared``), the same per-run cache +
  singleflight pattern ``Ctx.fetch_page`` already uses for web
  pages. Concurrent plugins share the in-flight fetch instead of
  thundering-herding the RPC endpoints.
- The shared record carries an explicit status so failure can no
  longer masquerade as a clean skip:
    ok        - bytecode + verified source retrieved
    no_source - bytecode retrieved, no verified source anywhere
                (bytecode-only lane; NOT the same as clean)
    no_code   - address holds no contract code (EOA / wrong chain)
    degraded  - every RPC route failed; nothing was retrieved and
                NO conclusion can be drawn about the contract
- Successful results are cached for the whole run. A degraded
  result is cached only for DEGRADED_TTL_S seconds: chain routes
  flap, and a plugin later in the same run must get a real retry
  instead of inheriting an early failure forever.
- Endpoints are read from ``contract_chain.CHAINS`` (via the Chain
  objects passed in) at call time, so config-level endpoint-list
  changes apply to this layer with no extra wiring.
- The underlying calls still go through ``contract_chain`` module
  attributes (``cc.rpc_get_code`` etc.), preserving the existing
  test-suite stubbing points.

Read-only throughout: eth_getCode, eth_getBalance and explorer
source reads. Never transacts, never calls a contract function.

Phase 2B additions (perf/scan-throughput):

- ``_fetch_once`` reads code + balance in ONE batched JSON-RPC
  POST (``contract_chain.rpc_batch``) when an HTTP client is
  available, falling back to the per-call helpers when the batch
  fails - same results, fewer round trips and limiter slots.
- ``get_implementation`` memoizes proxy resolution per
  (chain, address) per run with the same singleflight pattern:
  before this, every plugin re-ran ``resolve_implementation``
  (up to 3 eth_getStorageAt reads) for the same contract.
- ``stats(ctx)`` exposes cheap counters (fetch sequences started,
  cache hits, batched reads) so benchmarks can prove dedupe
  instead of asserting it.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import contract_chain as cc

DEGRADED_TTL_S = 20.0

STATUS_OK = "ok"
STATUS_NO_SOURCE = "no_source"
STATUS_NO_CODE = "no_code"
STATUS_DEGRADED = "degraded"

_CACHE_KEY = "_chain_data_cache"
_INFLIGHT_KEY = "_chain_data_inflight"
_IMPL_KEY = "_chain_data_impl_cache"
_IMPL_INFLIGHT_KEY = "_chain_data_impl_inflight"
_STATS_KEY = "_chain_data_stats"


def _bump(ctx: Any, name: str) -> None:
    shared = getattr(ctx, "shared", None)
    if not isinstance(shared, dict):
        return
    st = shared.setdefault(_STATS_KEY, {})
    st[name] = st.get(name, 0) + 1


def stats(ctx: Any) -> Dict[str, int]:
    """Per-run dedupe counters for this layer (benchmark evidence).

    fetch_sequences: real _fetch_once executions (one per contract
    per run when sharing works); cache_hits: get_chain_data calls
    served from the shared record; batched_reads: _fetch_once calls
    whose code+balance came from a single batched POST;
    impl_resolutions / impl_cache_hits: same pair for
    get_implementation.
    """
    shared = getattr(ctx, "shared", None)
    if not isinstance(shared, dict):
        return {}
    return dict(shared.get(_STATS_KEY, {}))


@dataclass
class ChainData:
    """One contract's shared chain data for a run."""
    chain_id: str
    address: str
    status: str = STATUS_DEGRADED
    code_hex: Optional[str] = None        # None = never retrieved
    source: Optional[Dict[str, Any]] = None  # fetch_verified_source dict
    balance_wei: Optional[int] = None
    fetched_at: float = 0.0
    _functions: Optional[List[Dict[str, str]]] = field(
        default=None, repr=False)

    @property
    def has_code(self) -> bool:
        return bool(self.code_hex) and self.code_hex != "0x" \
            and len(self.code_hex) >= 4

    @property
    def source_text(self) -> Optional[str]:
        if not self.source:
            return None
        return self.source.get("source")

    def functions(self) -> List[Dict[str, str]]:
        """Function extraction over the verified source, computed
        once and shared: the extraction pass is part of the hot
        scanning step every source plugin repeats per contract."""
        if self._functions is None:
            src = self.source_text
            self._functions = cc.extract_functions(src) if src else []
        return self._functions


def _cache(ctx: Any) -> Dict[str, ChainData]:
    shared = getattr(ctx, "shared", None)
    if shared is None:
        # Contexts without a shared bus (some unit fakes) get a
        # private dict hung off the ctx object itself; caching then
        # still works for that ctx's lifetime.
        cache = getattr(ctx, "_chain_data_cache_fallback", None)
        if cache is None:
            cache = {}
            try:
                ctx._chain_data_cache_fallback = cache
            except Exception:
                pass
        return cache
    return shared.setdefault(_CACHE_KEY, {})


def _inflight(ctx: Any) -> Dict[str, Any]:
    shared = getattr(ctx, "shared", None)
    if shared is None:
        return {}
    return shared.setdefault(_INFLIGHT_KEY, {})


def cached_status(ctx: Any, chain: cc.ChainConfig,
                  address: str) -> Optional[str]:
    """Status of the cached record for (chain, address), or None
    when nothing has been fetched in this run yet."""
    rec = _cache(ctx).get(f"{chain.id}:{address.lower()}")
    return rec.status if rec else None


async def _fetch_once(ctx: Any, chain: cc.ChainConfig, address: str,
                      etherscan_key: Optional[str]) -> ChainData:
    _bump(ctx, "fetch_sequences")
    rec = ChainData(chain_id=chain.id, address=address,
                    fetched_at=time.monotonic())
    code: Optional[str] = None
    balance: Optional[int] = None
    # Batched read: code + balance in one POST when a real HTTP
    # client is present. Any batch failure falls back to the
    # per-call helpers, so results are identical either way.
    if getattr(ctx, "http", None) is not None:
        try:
            results = await cc.rpc_batch(ctx, chain, [
                ("eth_getCode", [address, "latest"]),
                ("eth_getBalance", [address, "latest"])])
        except Exception:
            results = None
        if results is not None and isinstance(results[0], str):
            code = results[0]
            _bump(ctx, "batched_reads")
            if isinstance(results[1], str):
                try:
                    balance = int(results[1], 16)
                except ValueError:
                    balance = None
    if code is None:
        code = await cc.rpc_get_code(ctx, chain, address)
    if code is None:
        rec.status = STATUS_DEGRADED
        return rec
    rec.code_hex = code
    if not rec.has_code:
        rec.status = STATUS_NO_CODE
        return rec
    rec.balance_wei = balance
    if rec.balance_wei is None and \
            getattr(ctx, "http", None) is not None:
        try:
            rec.balance_wei = await cc.rpc_get_balance(
                ctx, chain, address)
        except Exception:
            rec.balance_wei = None
    rec.source = await cc.fetch_verified_source(
        ctx, chain, address, etherscan_key)
    rec.status = STATUS_OK if rec.source else STATUS_NO_SOURCE
    return rec


async def get_chain_data(ctx: Any, chain: cc.ChainConfig,
                         address: str,
                         etherscan_key: Optional[str] = None
                         ) -> ChainData:
    """Shared per-run fetch for one contract. See module docstring
    for the status contract and the degraded TTL rule."""
    cache = _cache(ctx)
    key = f"{chain.id}:{address.lower()}"
    rec = cache.get(key)
    if rec is not None:
        if rec.status != STATUS_DEGRADED:
            _bump(ctx, "cache_hits")
            return rec
        if time.monotonic() - rec.fetched_at < DEGRADED_TTL_S:
            _bump(ctx, "cache_hits")
            return rec
        # Stale degraded record: fall through and retry for real.

    inflight = _inflight(ctx)
    task = inflight.get(key)
    if task is None:
        task = asyncio.get_running_loop().create_task(
            _fetch_once(ctx, chain, address, etherscan_key))
        inflight[key] = task
        task.add_done_callback(
            lambda _t: inflight.pop(key, None))
    rec = await asyncio.shield(task)
    cache[key] = rec
    return rec


# -- Drop-in equivalents of the contract_chain calls the plugins ---
# -- used to make individually, now served from the shared record --

async def get_code(ctx: Any, chain: cc.ChainConfig,
                   address: str) -> Optional[str]:
    """eth_getCode result, shared. None only when every RPC route
    failed (same contract as cc.rpc_get_code)."""
    rec = await get_chain_data(ctx, chain, address)
    if rec.status == STATUS_DEGRADED:
        return None
    return rec.code_hex


async def get_source(ctx: Any, chain: cc.ChainConfig, address: str,
                     etherscan_key: Optional[str] = None
                     ) -> Optional[Dict[str, Any]]:
    """Verified-source dict, shared. Same shape/None contract as
    cc.fetch_verified_source."""
    rec = await get_chain_data(ctx, chain, address, etherscan_key)
    return rec.source


# -- Shared proxy resolution ----------------------------------------
# resolve_implementation costs up to 3 eth_getStorageAt reads and
# every scaffolding plugin used to pay it per contract. The result
# is a pure function of (chain, address, code, source metadata) for
# the life of a run, so memoize it with the same singleflight
# pattern as the fetch layer. Resolution failures are NOT cached:
# the caller gets the empty result its own try/except would have
# produced, and a later plugin may retry.

def _impl_cache(ctx: Any) -> Dict[str, Dict[str, str]]:
    shared = getattr(ctx, "shared", None)
    if shared is None:
        cache = getattr(ctx, "_chain_data_impl_fallback", None)
        if cache is None:
            cache = {}
            try:
                ctx._chain_data_impl_fallback = cache
            except Exception:
                pass
        return cache
    return shared.setdefault(_IMPL_KEY, {})


def _impl_inflight(ctx: Any) -> Dict[str, Any]:
    shared = getattr(ctx, "shared", None)
    if shared is None:
        return {}
    return shared.setdefault(_IMPL_INFLIGHT_KEY, {})


async def get_implementation(ctx: Any, chain: cc.ChainConfig,
                             address: str,
                             code_hex: Optional[str] = None,
                             source_meta: Optional[Dict[str, Any]] = None
                             ) -> Dict[str, str]:
    """cc.resolve_implementation, shared per run.

    Same return shape ({"implementation", "via", "beacon"}). The
    first caller's (code_hex, source_meta) wins for the run - in
    practice every plugin passes the same shared code/source for
    the same contract, which is exactly the duplication this
    removes.
    """
    cache = _impl_cache(ctx)
    key = f"{chain.id}:{address.lower()}"
    rec = cache.get(key)
    if rec is not None:
        _bump(ctx, "impl_cache_hits")
        return rec
    inflight = _impl_inflight(ctx)
    task = inflight.get(key)
    if task is None:
        _bump(ctx, "impl_resolutions")

        async def _resolve() -> Dict[str, str]:
            return await cc.resolve_implementation(
                ctx, chain, address, code_hex, source_meta)

        task = asyncio.get_running_loop().create_task(_resolve())
        inflight[key] = task
        task.add_done_callback(
            lambda _t: inflight.pop(key, None))
    rec = await asyncio.shield(task)
    cache[key] = rec
    return rec
