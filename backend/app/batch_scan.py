"""High-throughput batch contract scanner (detection only, CPU-bound).

The per-target runner in app/runner.py is async and network-bound: it
fetches each contract's verified source from a public explorer, one
target at a time, politely rate-limited. That is the right design for
scanning an address someone hands you, but it cannot sustain the
throughput needed to sweep a large corpus (e.g. "1,000,000 contracts in
20 minutes" = ~833 contracts/second). No public explorer API will serve
source that fast, and nothing about re-fetching is parallelism-friendly.

This module is the other lane: it runs the SAME detection logic
(contract_chain.analyze_contract_source plus the canonical 6-tuple RULES
detectors that the contract plugins use) over sources that have ALREADY
been fetched - a directory of .sol files, or a JSONL corpus of
{address, chain, source} records - with no network at all, across a
multiprocessing pool, with every regex compiled once per worker.

Measured single-core cost on ~9 KB of Solidity:
  analyze_contract_source           ~2.4 ms   (~410/sec/core)
  + full RULES sweep                ~22 ms    (~45/sec/core)
So 833/sec is reachable on ~16-24 cores; the CLI reports the achieved
rate and the projected time for 1,000,000 contracts so you can size the
box. Getting the corpus itself (Sourcify's repo export, a BigQuery dump
of verified sources, your own crawl) is a separate, upstream step - this
lane assumes the source is already on disk.

Nothing here touches a chain, signs anything, or makes a request. It is
a pure function of the source text, exactly like the analyzer it wraps.

Usage:
    python -m app.batch_scan --input ./corpus --workers 16 --out findings.jsonl
    python -m app.batch_scan --input contracts.jsonl --workers 24 --limit 100000
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import sys
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# Rules compiled once per process. Populated by _load_rules(); in a Pool
# each worker loads its own copy via _init_worker (fork inherits, spawn
# rebuilds), so the hot loop never recompiles a pattern.
_RULES: List[Tuple[Any, Any, str, str, str, str, str]] = []


def _load_rules() -> List[Tuple[Any, Any, str, str, str, str, str]]:
    """Harvest the canonical 6-tuple contract RULES from the plugin set and
    compile each (pattern, guard) once.

    The contract plugins share one rule shape consumed as
    ``for pattern, guard, key, severity, value, remediation in RULES``
    (see app/plugins/_cat3_common.py and siblings). We read that module
    attribute directly rather than instantiating plugins, so this stays a
    plain CPU table with no ctx, no async, no network.
    """
    global _RULES
    if _RULES:
        return _RULES
    import importlib
    import pkgutil

    pkg = importlib.import_module("app.plugins")
    rules: List[Tuple[Any, Any, str, str, str, str, str]] = []
    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name in ("base", "registry"):
            continue
        try:
            module = importlib.import_module(f"app.plugins.{mod.name}")
        except Exception:
            continue
        raw = getattr(module, "RULES", None)
        if not isinstance(raw, (list, tuple)):
            continue
        for r in raw:
            if not isinstance(r, (list, tuple)) or len(r) != 6:
                continue
            pattern, guard, key, severity, value, remediation = r
            if not isinstance(pattern, str) or not isinstance(key, str):
                continue
            try:
                cpat = re.compile(pattern, re.I | re.S)
            except re.error:
                continue
            cguard = None
            if isinstance(guard, str) and guard:
                try:
                    cguard = re.compile(guard, re.I | re.S)
                except re.error:
                    cguard = None
            rules.append((cpat, cguard, key, str(severity or "medium"),
                          str(value or ""), str(remediation or ""),
                          mod.name))
    _RULES = rules
    return _RULES


def scan_source(src: str,
                meta: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Run the full CPU detection stack over one contract source.

    Combines the structured analyzer (contract_chain.analyze_contract_source)
    with the shared RULES detectors. Returns a list of finding dicts. Never
    raises on a bad rule - a single detector failing must not drop the
    whole contract.
    """
    meta = meta or {}
    findings: List[Dict[str, Any]] = []

    # Structured analyzer (proxy/privileged/identity/etc).
    try:
        from .plugins.contract_chain import analyze_contract_source
        findings.extend(analyze_contract_source(src, meta))
    except Exception as e:  # noqa: BLE001
        findings.append({"kind": "error", "severity": "low",
                         "title": "analyzer error",
                         "detail": f"{type(e).__name__}: {e}"})

    # Shared RULES sweep: fire when the pattern matches and the guard
    # (a "but not if this is present" exclusion) does not - the exact
    # semantics the plugins use.
    for cpat, cguard, key, severity, value, remediation, pid in _load_rules():
        try:
            if not cpat.search(src):
                continue
            if cguard is not None and cguard.search(src):
                continue
        except Exception:  # noqa: BLE001
            continue
        findings.append({
            "kind": "rule", "key": key, "severity": severity,
            "title": value or key, "detail": value,
            "remediation": remediation, "plugin": pid,
        })
    return findings


@dataclasses.dataclass
class ContractRecord:
    address: str
    chain: str
    source: str
    meta: Dict[str, Any] = dataclasses.field(default_factory=dict)


def _iter_corpus(path: pathlib.Path,
                 limit: Optional[int]) -> Iterator[ContractRecord]:
    """Yield contract records from either a directory of .sol files or a
    JSONL file whose records carry at least a ``source`` field."""
    n = 0
    if path.is_dir():
        for f in sorted(path.rglob("*.sol")):
            if limit is not None and n >= limit:
                return
            try:
                src = f.read_text(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            yield ContractRecord(address=f.stem, chain="", source=src)
            n += 1
        return
    # JSONL
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if limit is not None and n >= limit:
                return
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            src = rec.get("source") or rec.get("source_code") or ""
            if not src:
                continue
            yield ContractRecord(
                address=str(rec.get("address", "")),
                chain=str(rec.get("chain", "")),
                source=src,
                meta=rec.get("meta") or {})
            n += 1


# ---------------------------------------------------------------------------
# Plugins engine: run the REAL contract-applicable plugins over each source,
# fully offline. The source is pre-seeded into ctx.shared["_source_cache"]
# (which fetch_verified_source checks first), and the network is killed at
# the socket level per worker - the same dead-network conditions the
# resilience gate (tests/test_plugin_resilience.py) proves every plugin
# survives. So this runs the actual detection logic, not a reimplementation,
# and no plugin can throw or reach out.
# ---------------------------------------------------------------------------
_PLUGIN_STATE: Dict[str, Any] = {}
# Chain ids whose source cache we seed, so whichever chain a plugin resolves
# for the address, it hits the pre-fetched source instead of the network.
_CHAIN_IDS = ("ethereum", "bsc", "polygon", "arbitrum", "base", "optimism")


class _BatchCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None

    async def cached(self, source, target, fn, ttl=None):
        return await fn(), False


class _BatchCtx:
    """A ctx that carries pre-fetched source and no live network."""

    def __init__(self, source: str, address: str,
                 target_type: str) -> None:
        self.run_id = "batch"
        self.mode = "passive"
        self.http = None
        self.cache = _BatchCache()
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.module_overrides = {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        src_cache = {(cid, address.lower()): source for cid in _CHAIN_IDS}
        self.shared = {"_source_cache": src_cache}

    def publish(self, kind, item):
        b = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in b:
                b.append(item)
        else:
            b.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url, timeout=10):
        return None

    async def probe(self, url, timeout=8):
        return {"status": 0, "headers": {}, "text": "", "url": url}


def _kill_network() -> None:
    """Make all outbound TCP/DNS fail in this process, without breaking the
    asyncio event loop (which needs socketpair())."""
    import socket as _socket

    def _dead(*a, **k):
        raise ConnectionError("network disabled (batch scan)")

    _socket.create_connection = _dead  # type: ignore[assignment]
    _socket.socket.connect = _dead     # type: ignore[assignment]
    try:
        import dns.asyncresolver as _ar

        class _DeadResolver:
            def __init__(self, *a, **k):
                pass

            async def resolve(self, *a, **k):
                import dns.resolver as _r
                raise _r.NXDOMAIN()
        _ar.Resolver = _DeadResolver  # type: ignore[assignment]
    except Exception:  # noqa: BLE001
        pass


def _init_plugin_worker(target_type: str) -> None:
    """Pool initializer for the plugins engine: kill network, build the
    plugin set once, and keep one event loop per worker."""
    import asyncio

    _kill_network()
    from .plugins.registry import for_target
    plugins = for_target(target_type)
    # module-level fetch stubs, mirroring the resilience fixture
    for p in plugins:
        mod = sys.modules.get(p.__class__.__module__)
        if mod is None:
            continue

        async def _boom(*a, **k):
            raise ConnectionError("network disabled (batch scan)")
        if hasattr(mod, "fetch"):
            mod.fetch = _boom  # type: ignore[attr-defined]
        if hasattr(mod, "fetch_many"):
            async def _boom_many(*a, **k):
                reqs = a[2] if len(a) > 2 else k.get("requests", [])
                return [None] * len(reqs)
            mod.fetch_many = _boom_many  # type: ignore[attr-defined]
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _PLUGIN_STATE["plugins"] = plugins
    _PLUGIN_STATE["loop"] = loop
    _PLUGIN_STATE["target_type"] = target_type


def _scan_one_plugins(rec_tuple: Tuple[str, str, str, Dict[str, Any]]
                      ) -> Tuple[str, str, int, List[Dict[str, Any]]]:
    import asyncio
    from .plugins import base

    address, chain, source, _meta = rec_tuple
    plugins = _PLUGIN_STATE["plugins"]
    loop = _PLUGIN_STATE["loop"]
    ttype = _PLUGIN_STATE["target_type"]
    ctx = _BatchCtx(source, address or "0x0", ttype)
    target = base.Target(raw=address or "0x0", type=ttype,
                         normalized=address or "0x0")

    async def _run_all():
        async def _one(p):
            try:
                return await asyncio.wait_for(p.run(target, ctx), timeout=15)
            except Exception:  # noqa: BLE001
                return None
        return await asyncio.gather(*[_one(p) for p in plugins])

    findings: List[Dict[str, Any]] = []
    try:
        results = loop.run_until_complete(_run_all())
    except Exception:  # noqa: BLE001
        results = []
    for res in results:
        if res is None:
            continue
        for f in getattr(res, "findings", []) or []:
            findings.append({
                "key": getattr(f, "key", ""),
                "severity": getattr(f, "severity", ""),
                "plugin": getattr(f, "plugin_id", ""),
                "value": getattr(f, "value", ""),
            })
    return address, chain, len(source), findings


def _init_worker() -> None:
    # Ensure this worker has its rules compiled before the first task.
    _load_rules()


def _scan_one(rec_tuple: Tuple[str, str, str, Dict[str, Any]]
              ) -> Tuple[str, str, int, List[Dict[str, Any]]]:
    address, chain, source, meta = rec_tuple
    m = dict(meta or {})
    findings = scan_source(source, m)
    return address, chain, len(source), findings


def scan_corpus(input_path: str,
                workers: int = 0,
                limit: Optional[int] = None,
                out_path: Optional[str] = None,
                engine: str = "rules",
                target_type: str = "crypto_wallet",
                progress_every: int = 20000) -> Dict[str, Any]:
    """Scan a whole corpus and return a throughput + findings summary.

    engine="rules"   -> the compiled RULES + structured analyzer (fast,
                        ~tens of contracts/sec/core).
    engine="plugins" -> the real contract-applicable plugins, run offline
                        (faithful, slower; benchmark on your hardware).

    Writes one JSON object per contract (with findings) to ``out_path``
    if given. Prints progress to stderr. Pure CPU - safe to pin to every
    core on the box."""
    import multiprocessing as mp

    path = pathlib.Path(input_path)
    if not path.exists():
        raise FileNotFoundError(input_path)
    workers = workers or (os.cpu_count() or 1)

    out_fh = open(out_path, "w", encoding="utf-8") if out_path else None
    scanned = 0
    findings_total = 0
    sev_counts: Dict[str, int] = {}
    start = time.perf_counter()

    def _records() -> Iterable[Tuple[str, str, str, Dict[str, Any]]]:
        for rec in _iter_corpus(path, limit):
            yield (rec.address, rec.chain, rec.source, rec.meta)

    ctx = mp.get_context("fork" if sys.platform != "win32" else "spawn")
    if engine == "plugins":
        pool = ctx.Pool(workers, initializer=_init_plugin_worker,
                        initargs=(target_type,))
        scan_fn = _scan_one_plugins
        rules_loaded = None
    else:
        # fork keeps the parent's compiled rules; load them once up front so
        # the children inherit a warm table instead of each rebuilding it.
        _load_rules()
        pool = ctx.Pool(workers, initializer=_init_worker)
        scan_fn = _scan_one
        rules_loaded = len(_load_rules())
    with pool:
        for address, chain, nbytes, findings in pool.imap_unordered(
                scan_fn, _records(), chunksize=64):
            scanned += 1
            findings_total += len(findings)
            for f in findings:
                s = f.get("severity", "")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            if out_fh is not None:
                out_fh.write(json.dumps({
                    "address": address, "chain": chain,
                    "findings": findings}) + "\n")
            if progress_every and scanned % progress_every == 0:
                el = time.perf_counter() - start
                rate = scanned / el if el else 0
                print(f"  {scanned:,} scanned  {rate:,.0f}/s  "
                      f"{findings_total:,} findings", file=sys.stderr)

    if out_fh is not None:
        out_fh.close()
    elapsed = time.perf_counter() - start
    rate = scanned / elapsed if elapsed else 0
    return {
        "engine": engine,
        "scanned": scanned,
        "elapsed_s": round(elapsed, 2),
        "contracts_per_sec": round(rate, 1),
        "workers": workers,
        "findings_total": findings_total,
        "severity_breakdown": dict(sorted(sev_counts.items())),
        "rules_loaded": rules_loaded,
        "projected_1m_minutes": (round((1_000_000 / rate) / 60, 1)
                                 if rate else None),
    }


def _main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="High-throughput, network-free batch contract scanner.")
    ap.add_argument("--input", required=True,
                    help="directory of .sol files, or a .jsonl corpus with "
                         "{address, chain, source} records")
    ap.add_argument("--workers", type=int, default=0,
                    help="worker processes (default: all cores)")
    ap.add_argument("--limit", type=int, default=None,
                    help="scan at most this many contracts")
    ap.add_argument("--out", default=None,
                    help="write findings JSONL here")
    ap.add_argument("--engine", choices=["rules", "plugins"], default="rules",
                    help="rules: compiled RULES + analyzer (fast). "
                         "plugins: the real contract plugins, run offline.")
    ap.add_argument("--target-type", default="crypto_wallet",
                    help="plugin target type to select for --engine plugins "
                         "(crypto_wallet for EVM addresses, solana_contract, stacks_contract)")
    args = ap.parse_args(argv)

    summary = scan_corpus(args.input, workers=args.workers,
                          limit=args.limit, out_path=args.out,
                          engine=args.engine, target_type=args.target_type)
    print(json.dumps(summary, indent=2))
    rate = summary["contracts_per_sec"]
    if rate:
        need = 1_000_000 / 1200  # 833/sec for 1M in 20 min
        print(f"\n{rate:,.0f} contracts/sec on {summary['workers']} workers. "
              f"1M in 20 min needs {need:,.0f}/sec: "
              + ("MET." if rate >= need
                 else f"scale to ~{need / (rate / summary['workers']):.0f} "
                      f"cores at this per-core rate."), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
