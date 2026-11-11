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
import contextlib
import dataclasses
import json
import os
import pathlib
import re
import sys
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


class BatchAlreadyRunning(RuntimeError):
    """Raised when another batch already holds the single-batch lock."""


_BATCH_LOCK_PATH = os.environ.get("RECON_BATCH_LOCK", "/tmp/recon_batch.lock")


@contextlib.contextmanager
def single_batch_lock(path: Optional[str] = None, blocking: bool = False):
    """Only one batch at a time. Overlapping batches were rescanning the
    same contracts (wasted work, double network cost); this holds an
    exclusive OS file lock for the duration. A second batch gets
    BatchAlreadyRunning (blocking=False) or waits (blocking=True). The lock
    is released on exit and auto-dropped if the process dies, so a crash
    can't wedge it. No-op on platforms without fcntl."""
    p = path or _BATCH_LOCK_PATH
    try:
        import fcntl
    except Exception:  # noqa: BLE001 - e.g. Windows: lock unavailable
        yield
        return
    fh = open(p, "w")
    try:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(fh, flags)
        except OSError:
            raise BatchAlreadyRunning(
                f"another batch holds {p}; not starting a second one")
        try:
            yield
        finally:
            try:
                fcntl.flock(fh, fcntl.LOCK_UN)
            except Exception:  # noqa: BLE001
                pass
    finally:
        fh.close()

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

    # Source audit (fund-drain / access-control / reentrancy classes). This
    # catches drain-class issues the RULES regex sweep misses, so the fast
    # rules/tiered engines no longer need the full plugin engine to find
    # them. A crash here surfaces as an error finding, never a silent empty
    # (a scanner that reports a contract "clean" because it threw is a false
    # negative).
    try:
        from .plugins.contract_audit import audit_source
        for a in audit_source(src):
            findings.append({"kind": a.get("check", "audit"),
                             "key": a.get("check", "audit"),
                             "severity": a.get("severity", "low"),
                             "function": a.get("function", ""),
                             "title": (a.get("detail", "") or "")[:80],
                             "detail": a.get("detail", ""),
                             "code": a.get("code", ""),
                             "plugin": "contract_audit"})
    except Exception as e:  # noqa: BLE001
        findings.append({"kind": "error", "severity": "low",
                         "title": "audit error",
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
class FindingFilter:
    """A runtime filter over scan output - set any field to narrow what you
    see, no code change needed. A finding is kept only if it matches every
    field that is set (kinds/severities match that finding; min_confidence
    is its confidence; tiers is its confidence tier). chains filters whole
    contracts. Empty = keep everything."""
    kinds: Optional[set] = None
    severities: Optional[set] = None
    tiers: Optional[set] = None
    chains: Optional[set] = None
    min_confidence: int = 0

    def any_set(self) -> bool:
        return bool(self.kinds or self.severities or self.tiers
                    or self.chains or self.min_confidence)

    def contract_ok(self, chain: str) -> bool:
        return not self.chains or (chain or "").lower() in self.chains

    def filter_findings(self, findings: List[Dict[str, Any]],
                        address: str) -> List[Dict[str, Any]]:
        if not (self.kinds or self.severities or self.tiers
                or self.min_confidence):
            return findings
        tier_by_id = {}
        if self.tiers:
            from . import confidence
            rows = [{"target_id": address,
                     "key": f.get("kind") or f.get("key", ""),
                     "value": "", "plugin": "c", "evidence": {},
                     "confidence": f.get("confidence"),
                     "severity": f.get("severity")} for f in findings]
            for i, r in enumerate(confidence.annotate_confidence(rows)):
                tier_by_id[i] = r["confidence_tier"]
        out = []
        for i, f in enumerate(findings):
            if self.kinds and (f.get("kind") or f.get("key", "")) \
                    not in self.kinds:
                continue
            if self.severities and f.get("severity", "") not in self.severities:
                continue
            if self.min_confidence and (f.get("confidence") or 0) \
                    < self.min_confidence:
                continue
            if self.tiers and tier_by_id.get(i) not in self.tiers:
                continue
            out.append(f)
        return out


@dataclasses.dataclass
class ContractRecord:
    address: str
    chain: str
    source: str
    # Pre-fetched chain data (from your Tier-1 pass). When present, the
    # plugins engine serves the deep plugins' rpc_get_code / rpc_get_storage
    # reads straight from these instead of hitting live RPC - which is what
    # lets the deep analysis run at corpus speed instead of network speed.
    bytecode: str = ""
    storage: Dict[str, str] = dataclasses.field(default_factory=dict)
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
            bytecode = rec.get("bytecode") or rec.get("code") or ""
            storage = rec.get("storage") or {}
            if not src and not bytecode:
                continue  # nothing to analyze offline
            yield ContractRecord(
                address=str(rec.get("address", "")),
                chain=str(rec.get("chain", "")),
                source=src,
                bytecode=str(bytecode),
                storage={str(k).lower(): str(v)
                         for k, v in storage.items()} if isinstance(
                             storage, dict) else {},
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

    def __init__(self, source: str, address: str, target_type: str,
                 bytecode: str = "",
                 storage: Optional[Dict[str, str]] = None) -> None:
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
        addr = address.lower()
        # Seed the same caches the live deep plugins read from, for every
        # chain id (whichever a plugin resolves, it hits the pre-fetched
        # data). With bytecode + storage seeded, rpc_get_code /
        # rpc_get_storage_at return instantly and nothing touches the
        # network - the deep analysis runs at corpus speed, not RPC speed.
        self.shared: Dict[str, Any] = {
            "_source_cache": {(cid, addr): source for cid in _CHAIN_IDS},
        }
        if bytecode:
            self.shared["_code_cache"] = {
                (cid, addr): bytecode for cid in _CHAIN_IDS}
        if storage:
            self.shared["_storage_cache"] = {
                (cid, addr, slot.lower()): word
                for cid in _CHAIN_IDS
                for slot, word in storage.items()}

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
    _meta = _meta or {}
    ctx = _BatchCtx(source, address or "0x0", ttype,
                    bytecode=_meta.get("_bytecode", ""),
                    storage=_meta.get("_storage") or {})
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


# ---------------------------------------------------------------------------
# Tiered engine: sweep everything with the fast rules engine, then escalate
# only the contracts that flagged to the heavy full-plugin engine. Mirrors
# the Tier-1 (fast, wide) / deep (slow, narrow) split: full depth on 1M
# becomes "rules sweep on 1M + full plugins on the few thousand that matter"
# instead of the full plugin cost on every contract.
# ---------------------------------------------------------------------------
_TIER1_ESC: set = set()
_TIER1_MIN_COUNT: int = 1
_TIER1_TIERS: set = {"confirmed"}


def _init_tier1_worker(escalate_severities: Tuple[str, ...],
                       min_count: int = 1,
                       escalate_tiers: Tuple[str, ...] = ("confirmed",)
                       ) -> None:
    global _TIER1_ESC, _TIER1_MIN_COUNT, _TIER1_TIERS
    _TIER1_ESC = set(escalate_severities)
    _TIER1_MIN_COUNT = max(1, int(min_count))
    _TIER1_TIERS = set(escalate_tiers)
    _load_rules()


def _confidence_tiers(findings: List[Dict[str, Any]],
                      address: str) -> set:
    """Confidence tiers present in a finding set, via the same read-time
    scorer the UI uses. The confirmed tier is the selective escalation
    signal - it is reserved for unambiguous drains, so escalating on it
    (instead of raw high severity) is what makes the deep pass small."""
    from . import confidence
    rows = [{"target_id": address, "key": f.get("kind") or f.get("key", ""),
             "value": f.get("function") or f.get("title", ""),
             "plugin": f.get("plugin", "contract"), "evidence": {},
             "confidence": f.get("confidence"), "severity": f.get("severity")}
            for f in findings]
    return {r["confidence_tier"]
            for r in confidence.annotate_confidence(rows)}


def _scan_one_tier1(rec_tuple: Tuple[str, str, str, Dict[str, Any]]
                    ) -> Tuple[str, str, int, List[Dict[str, Any]],
                               Optional[Dict[str, Any]]]:
    """Tier-1 rules scan. Returns findings plus the FULL record only when
    the contract escalates - it has at least _TIER1_MIN_COUNT distinct
    finding keys at an escalate severity. Counting DISTINCT keys (not raw
    hits) is deliberate: on real data one rule often fires many times, so
    raw count is a noisy signal; distinct keys measures how many different
    things flagged. The heavy source crosses to tier 2 only for the flagged
    subset, not all 1M."""
    address, chain, source, meta = rec_tuple
    m = dict(meta or {})
    findings = scan_source(source, m)
    # Escalate on the confirmed confidence tier (the selective signal) when
    # configured; otherwise fall back to distinct-key severity counting.
    if _TIER1_TIERS:
        flag = bool(_confidence_tiers(findings, address) & _TIER1_TIERS)
    else:
        esc_keys = {f.get("key", "") for f in findings
                    if f.get("severity", "") in _TIER1_ESC}
        flag = len(esc_keys) >= _TIER1_MIN_COUNT
    record = None
    if flag:
        record = {
            "address": address, "chain": chain, "source": source,
            "bytecode": m.get("_bytecode", ""),
            "storage": m.get("_storage") or {},
        }
    return address, chain, len(source), findings, record


def _scan_tiered(path: pathlib.Path, workers: int, limit: Optional[int],
                 out_path: Optional[str], target_type: str,
                 escalate_severities: Tuple[str, ...],
                 escalate_min_count: int,
                 progress_every: int,
                 escalate_tiers: Tuple[str, ...] = ("confirmed",)
                 ) -> Dict[str, Any]:
    import multiprocessing as mp
    import tempfile

    workers = workers or (os.cpu_count() or 1)

    def _records() -> Iterable[Tuple[str, str, str, Dict[str, Any]]]:
        for rec in _iter_corpus(path, limit):
            meta = dict(rec.meta)
            if rec.bytecode:
                meta["_bytecode"] = rec.bytecode
            if rec.storage:
                meta["_storage"] = rec.storage
            yield (rec.address, rec.chain, rec.source, meta)

    _load_rules()
    mpctx = mp.get_context("fork" if sys.platform != "win32" else "spawn")
    esc_fh = tempfile.NamedTemporaryFile(
        "w", suffix=".escalate.jsonl", delete=False, encoding="utf-8")
    t1_scanned = 0
    t1_findings = 0
    flagged = 0
    start = time.perf_counter()
    with mpctx.Pool(workers, initializer=_init_tier1_worker,
                    initargs=(tuple(escalate_severities),
                              escalate_min_count,
                              tuple(escalate_tiers))) as pool:
        for address, chain, nbytes, findings, record in pool.imap_unordered(
                _scan_one_tier1, _records(), chunksize=64):
            t1_scanned += 1
            t1_findings += len(findings)
            if record is not None:
                flagged += 1
                esc_fh.write(json.dumps(record) + "\n")
            if progress_every and t1_scanned % progress_every == 0:
                el = time.perf_counter() - start
                print(f"  tier1 {t1_scanned:,}  "
                      f"{t1_scanned / el if el else 0:,.0f}/s  "
                      f"{flagged:,} flagged", file=sys.stderr)
    esc_fh.close()
    t1_elapsed = time.perf_counter() - start
    t1_rate = t1_scanned / t1_elapsed if t1_elapsed else 0

    # Tier 2: full plugin engine over ONLY the flagged subset.
    if flagged:
        tier2 = scan_corpus(esc_fh.name, workers=workers, engine="plugins",
                            target_type=target_type, out_path=out_path,
                            progress_every=progress_every)
    else:
        tier2 = {"scanned": 0, "contracts_per_sec": 0, "findings_total": 0,
                 "elapsed_s": 0.0, "severity_breakdown": {}}
    try:
        os.unlink(esc_fh.name)
    except OSError:
        pass

    return {
        "engine": "tiered",
        "escalate_severities": list(escalate_severities),
        "escalate_min_distinct_keys": escalate_min_count,
        "tier1": {
            "scanned": t1_scanned,
            "contracts_per_sec": round(t1_rate, 1),
            "findings_total": t1_findings,
            "elapsed_s": round(t1_elapsed, 2),
            "flagged_for_escalation": flagged,
            "flag_rate_pct": round(100 * flagged / t1_scanned, 2)
            if t1_scanned else 0,
        },
        "tier2_plugins": {
            "scanned": tier2.get("scanned", 0),
            "contracts_per_sec": tier2.get("contracts_per_sec", 0),
            "findings_total": tier2.get("findings_total", 0),
            "elapsed_s": tier2.get("elapsed_s", 0.0),
            "severity_breakdown": tier2.get("severity_breakdown", {}),
        },
        "wall_elapsed_s": round(t1_elapsed + tier2.get("elapsed_s", 0.0), 2),
        "projected_1m_minutes": (round((1_000_000 / t1_rate) / 60, 1)
                                 if t1_rate else None),
    }


def scan_corpus(input_path: str,
                workers: int = 0,
                limit: Optional[int] = None,
                out_path: Optional[str] = None,
                engine: str = "rules",
                target_type: str = "crypto_wallet",
                escalate_severities: Tuple[str, ...] = ("high", "critical"),
                escalate_min_count: int = 1,
                escalate_tiers: Tuple[str, ...] = ("confirmed",),
                find_filter: Optional[FindingFilter] = None,
                progress_every: int = 20000) -> Dict[str, Any]:
    """Scan a whole corpus and return a throughput + findings summary.

    find_filter: a FindingFilter to narrow the output at runtime (by kind,
    severity, confidence tier, chain, or min confidence) - "filter what you
    want to see" without touching code. Only matching findings are written
    and counted; contracts left with nothing are skipped in the output.

    engine="rules"   -> the compiled RULES + structured analyzer (fast,
                        ~tens of contracts/sec/core).
    engine="plugins" -> the real contract-applicable plugins, run offline
                        (faithful, slower; benchmark on your hardware).
    engine="tiered"  -> rules sweep across all, then the full plugin engine
                        on only the contracts that flagged at an escalate
                        severity. Full depth on a huge corpus for roughly
                        the cost of the rules sweep plus a small deep pass.

    Writes one JSON object per contract (with findings) to ``out_path``
    if given. Prints progress to stderr. Pure CPU - safe to pin to every
    core on the box."""
    import multiprocessing as mp

    path = pathlib.Path(input_path)
    if not path.exists():
        raise FileNotFoundError(input_path)
    workers = workers or (os.cpu_count() or 1)

    if engine == "tiered":
        return _scan_tiered(path, workers, limit, out_path, target_type,
                            escalate_severities, escalate_min_count,
                            progress_every, escalate_tiers=escalate_tiers)

    out_fh = open(out_path, "w", encoding="utf-8") if out_path else None
    scanned = 0
    findings_total = 0
    sev_counts: Dict[str, int] = {}
    start = time.perf_counter()

    def _records() -> Iterable[Tuple[str, str, str, Dict[str, Any]]]:
        for rec in _iter_corpus(path, limit):
            meta = dict(rec.meta)
            if rec.bytecode:
                meta["_bytecode"] = rec.bytecode
            if rec.storage:
                meta["_storage"] = rec.storage
            yield (rec.address, rec.chain, rec.source, meta)

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
    flt = find_filter or FindingFilter()
    matched_contracts = 0
    with pool:
        for address, chain, nbytes, findings in pool.imap_unordered(
                scan_fn, _records(), chunksize=64):
            scanned += 1
            # Apply the runtime filter: drop the contract if it's out of
            # chain scope, then keep only findings that match.
            if not flt.contract_ok(chain):
                findings = []
            elif flt.any_set():
                findings = flt.filter_findings(findings, address)
            if findings:
                matched_contracts += 1
            findings_total += len(findings)
            for f in findings:
                s = f.get("severity", "")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            if out_fh is not None and (findings or not flt.any_set()):
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
        "matched_contracts": matched_contracts if flt.any_set() else scanned,
        "filtered": flt.any_set(),
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
    ap.add_argument("--escalate-severity", default="high,critical",
                    help="for --engine tiered: comma-separated severities "
                         "that escalate a contract to the full plugin engine "
                         "(default high,critical)")
    ap.add_argument("--escalate-min-count", type=int, default=1,
                    help="for --engine tiered severity mode: escalate only "
                         "when a contract has at least this many DISTINCT "
                         "finding keys at an escalate severity")
    ap.add_argument("--escalate-tier", default="confirmed",
                    help="for --engine tiered: confidence tier(s) that "
                         "escalate to the full plugin engine (default "
                         "'confirmed' - the selective signal; empty string "
                         "falls back to --escalate-severity)")
    ap.add_argument("--engine", choices=["rules", "plugins", "tiered"],
                    default="rules",
                    help="rules: compiled RULES + analyzer (fast). "
                         "plugins: the real contract plugins, run offline.")
    ap.add_argument("--target-type", default="crypto_wallet",
                    help="plugin target type to select for --engine plugins "
                         "(crypto_wallet for EVM addresses, solana_contract, stacks_contract)")
    ap.add_argument("--no-lock", action="store_true",
                    help="skip the single-batch lock (allow overlapping runs)")
    # Runtime output filters - narrow what you see without editing code.
    ap.add_argument("--only-kind", default="",
                    help="comma-separated finding kinds to keep "
                         "(e.g. selfdestruct,delegatecall,reentrancy)")
    ap.add_argument("--only-severity", default="",
                    help="comma-separated severities to keep "
                         "(e.g. critical,high)")
    ap.add_argument("--only-tier", default="",
                    help="comma-separated confidence tiers to keep "
                         "(e.g. confirmed)")
    ap.add_argument("--only-chain", default="",
                    help="comma-separated chains to keep (e.g. ethereum,bsc)")
    ap.add_argument("--min-confidence", type=int, default=0,
                    help="keep only findings at or above this confidence")
    args = ap.parse_args(argv)

    # Read-only hardblock: a detection tool has no business holding signing
    # material. Refuse to run an autonomous batch if a key/seed is present.
    from app.rpc_guard import RpcWriteBlocked, enforce_read_only_env
    try:
        enforce_read_only_env()
    except RpcWriteBlocked as e:
        print(f"refusing to run: {e}", file=sys.stderr)
        return 2

    def _set(s):
        v = {x.strip().lower() for x in s.split(",") if x.strip()}
        return v or None
    find_filter = FindingFilter(
        kinds=_set(args.only_kind),
        severities=_set(args.only_severity),
        tiers=_set(args.only_tier),
        chains=_set(args.only_chain),
        min_confidence=args.min_confidence)

    lock = (contextlib.nullcontext() if args.no_lock
            else single_batch_lock())
    try:
        with lock:
            esc = tuple(s.strip() for s in args.escalate_severity.split(",")
                        if s.strip())
            summary = scan_corpus(args.input, workers=args.workers,
                                  limit=args.limit, out_path=args.out,
                                  engine=args.engine,
                                  target_type=args.target_type,
                                  escalate_severities=esc,
                                  escalate_min_count=args.escalate_min_count,
                                  escalate_tiers=tuple(
                                      x.strip() for x in
                                      args.escalate_tier.split(",")
                                      if x.strip()),
                                  find_filter=find_filter)
    except BatchAlreadyRunning as e:
        print(f"skipped: {e}", file=sys.stderr)
        return 0
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
