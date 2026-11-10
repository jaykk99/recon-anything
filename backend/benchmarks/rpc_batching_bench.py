"""Track 2 benchmark: deep-lane RPC round-trips, before vs after.

Measures the REAL deep-lane read set for N cached contracts twice:

BEFORE (master's composition, still expressible with master's APIs):
  - chain_data's fetch batch: rpc_batch([eth_getCode, eth_getBalance])
    -> 1 POST (master already batched this pair in Phase 2B)
  - 8 storage words, one rpc_get_storage_at POST each
    (deep_layers: EIP-1967 implementation/admin/beacon slots +
    layout slots 0x0-0x4)
  - 4 view getters, one contract_sim.eth_call POST each
    (deep_layers token params: decimals/totalSupply/cap/totalAssets)
  - the contract_sim fuzz probes for the contract's verified
    source (extract_probe_functions + boundary_cases, capped like
    the plugin: 12 functions, 48 probes), one eth_call POST each

AFTER (Track 2 composition):
  - the same fetch batch (unchanged)
  - rpc_get_storage_batch: all 8 storage words in 1 POST
  - eth_call_read_batch: all 4 getters in 1 POST
  - eth_call_batch: all fuzz probes in ceil(n/50) POSTs

Round-trips are COUNTED by wrapping the ratelimit fetch binding in
contract_chain and contract_sim (every issued HTTP POST increments
the counter) - instrumented, never estimated. Wall time is measured
per phase with contracts processed concurrently (--concurrency in
flight, identical for both phases).

Contracts come from the cached million-sweep set
(~/workspace/recon-million-2026-11-06/fetch_cache.sqlite, table
``codes``; sources from bench/source_cache.sqlite), Ethereum only,
first --limit addresses (sorted) holding real bytecode and a
verified source. All reads are read-only eth_call / eth_get* calls
to keyless public RPC endpoints. Nothing is broadcast, ever.

Usage:
  python benchmarks/rpc_batching_bench.py [--limit 100]
      [--concurrency 8] [--out results.json]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import net  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import contract_sim as cs  # noqa: E402
from app.plugins import deep_layers as dl  # noqa: E402

FETCH_CACHE = os.path.expanduser(
    "~/workspace/recon-million-2026-11-06/fetch_cache.sqlite")
SOURCE_CACHE = os.path.expanduser(
    "~/workspace/recon-million-2026-11-06/bench/source_cache.sqlite")
CHAIN_ID = "ethereum"

STORAGE_SLOTS = ([cc.EIP1967_IMPLEMENTATION_SLOT, dl.EIP1967_ADMIN_SLOT,
                  cc.EIP1967_BEACON_SLOT]
                 + [f"0x{i:064x}" for i in range(5)])
GETTERS = ["decimals()", "totalSupply()", "cap()", "totalAssets()"]


class BenchCtx:
    """Minimal run context: real HTTP client + real rate limiter,
    fresh shared bus per contract per phase (so the per-run caches
    in contract_chain can never hide a round-trip)."""

    def __init__(self, http, limiter):
        self.keys = {}
        self.mode = "active"
        self.http = http
        self.limiter = limiter
        self.cache = None
        self.run_id = "bench"
        self.module_overrides = {}
        self.shared = {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


class PostCounter:
    """Wraps a module's ``fetch`` binding and counts issued POSTs."""

    def __init__(self):
        self.n = 0

    def wrap(self, module):
        orig = module.fetch

        async def counting(*args, **kwargs):
            self.n += 1
            return await orig(*args, **kwargs)

        module.fetch = counting
        return orig

    def unwrap(self, module, orig):
        module.fetch = orig


def load_contracts(limit):
    codes = sqlite3.connect(FETCH_CACHE)
    srcs = sqlite3.connect(SOURCE_CACHE)
    out = []
    for addr, code in codes.execute(
            "SELECT address, code FROM codes WHERE chain=? "
            "ORDER BY address", (CHAIN_ID,)):
        if not code or len(code) <= 4:
            continue
        row = srcs.execute(
            "SELECT source FROM sources WHERE chain=? AND address=?",
            (CHAIN_ID, addr)).fetchone()
        if not row:
            continue
        try:
            source = json.loads(row[0]).get("source") or ""
        except Exception:
            source = ""
        if not source:
            continue
        out.append((addr, source))
        if len(out) >= limit:
            break
    return out


def probe_jobs(source, addr):
    """The fuzz probe calldata list, built exactly as
    contract_sim._simulate_on_chain builds its jobs."""
    funcs = cs.extract_probe_functions(source)
    jobs = []
    left = cs.MAX_PROBES_PER_CONTRACT
    for fn in funcs[:cs.MAX_FUZZ_FUNCTIONS]:
        if left <= 0:
            break
        head = cs.function_selector(fn["canonical"])
        for values, _label in cs.boundary_cases(fn["types"], addr):
            if left <= 0:
                break
            enc = cs.encode_call_args(fn["types"], values)
            if enc is None:
                break
            left -= 1
            jobs.append(head + enc)
    return jobs


async def before_contract(ctx, chain, addr, jobs):
    await cc.rpc_batch(ctx, chain, [
        ("eth_getCode", [addr, "latest"]),
        ("eth_getBalance", [addr, "latest"])])
    for slot in STORAGE_SLOTS:
        await cc.rpc_get_storage_at(ctx, chain, addr, slot)
    for sig in GETTERS:
        await dl.eth_call_read(ctx, chain, addr, sig)
    for data in jobs:
        await cs.eth_call(ctx, chain, addr, data, cs.FUZZ_CALLER)


async def after_contract(ctx, chain, addr, jobs):
    await cc.rpc_batch(ctx, chain, [
        ("eth_getCode", [addr, "latest"]),
        ("eth_getBalance", [addr, "latest"])])
    await cc.rpc_get_storage_batch(ctx, chain, addr, STORAGE_SLOTS)
    await dl.eth_call_read_batch(ctx, chain, addr, GETTERS)
    await cs.eth_call_batch(ctx, chain, [
        {"to": addr, "data": data, "sender": cs.FUZZ_CALLER}
        for data in jobs])


async def run_phase(contracts, jobs_by_addr, http, limiter, fn,
                    concurrency):
    chain = cc.CHAINS[CHAIN_ID]
    sem = asyncio.Semaphore(concurrency)

    async def one(addr, _source):
        async with sem:
            await fn(BenchCtx(http, limiter), chain, addr,
                     jobs_by_addr[addr])

    t0 = time.monotonic()
    await asyncio.gather(*(one(a, s) for a, s in contracts))
    return time.monotonic() - t0


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    contracts = load_contracts(args.limit)
    jobs_by_addr = {a: probe_jobs(s, a) for a, s in contracts}
    logical = {a: 2 + len(STORAGE_SLOTS) + len(GETTERS) + len(j)
               for a, j in jobs_by_addr.items()}
    print(f"contracts: {len(contracts)}  chain: {CHAIN_ID}")
    print(f"logical reads: total={sum(logical.values())} "
          f"avg/contract={sum(logical.values()) / max(1, len(contracts)):.1f} "
          f"(2 fetch + {len(STORAGE_SLOTS)} storage + {len(GETTERS)} "
          f"getters + fuzz probes)")

    counter = PostCounter()
    orig_cc = counter.wrap(cc)
    orig_cs = counter.wrap(cs)
    limiter = RateLimiter(default_rps=200.0)
    results = {}
    try:
        async with net.async_client() as http:
            for name, fn in (("before", before_contract),
                             ("after", after_contract)):
                counter.n = 0
                wall = await run_phase(contracts, jobs_by_addr, http,
                                       limiter, fn, args.concurrency)
                results[name] = {
                    "http_posts": counter.n,
                    "posts_per_contract": counter.n / max(1, len(contracts)),
                    "wall_s": round(wall, 2),
                }
                print(f"{name}: {counter.n} HTTP POSTs "
                      f"({results[name]['posts_per_contract']:.2f}/contract) "
                      f"in {wall:.1f}s")
    finally:
        counter.unwrap(cc, orig_cc)
        counter.unwrap(cs, orig_cs)

    b, a = results["before"], results["after"]
    red = 100.0 * (1 - a["http_posts"] / max(1, b["http_posts"]))
    print(f"round-trip reduction: {red:.1f}%  "
          f"wall: {b['wall_s']}s -> {a['wall_s']}s")
    report = {"chain": CHAIN_ID, "contracts": len(contracts),
              "logical_reads_total": sum(logical.values()),
              "before": b, "after": a,
              "round_trip_reduction_pct": round(red, 1)}
    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
