"""Run ReconAnything's deep-audit detectors (batches 20, 20b, 21, 22, 23,
24 = 30 detectors) against the targets in targets.json, read-only.

Detection only, read-only live probes only. NO broadcast transactions,
NO moving funds. Verified source is fetched through the backend's own
keyless routes (Blockscout -> Sourcify v2 -> Sourcify repo); a target
with no verified source is recorded as skipped honestly, never faked.

This driver lives in the repo so the scan is reproducible from a master
checkout: it uses this repo's own backend (../../backend) and writes its
outputs next to itself.

Outputs (all under this script's directory):
  findings-<address>.jsonl   one row per finding
  candidates-<address>.jsonl candidate rows only (high/critical +
                             CALLER / CALLER-SUPPLIED)
  summary-<address>.json     counts, source status, timing

Usage:
  python3 scan_impl30.py                      # all targets in targets.json
  python3 scan_impl30.py 0x5C7F...            # one target (cronos default)
  python3 scan_impl30.py ethereum:0xfe18...   # chain-qualified
"""
import argparse
import asyncio
import datetime
import json
import os
import sys
import time
from pathlib import Path

os.environ["NO_PROXY"] = "localhost,127.0.0.1"
os.environ["no_proxy"] = "localhost,127.0.0.1"

HOME = Path(__file__).resolve().parent
# This repo's own backend (scans/crypto-com-2026-11-18/ -> repo root/backend).
BACKEND = str(HOME.parent.parent / "backend")
sys.path.insert(0, BACKEND)

import httpx  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402

# New-detector modules on master: batch 20, 20b, 21, 22, 24 (5 each = 25).
NEW_MODULES = {
    "deep_audit20", "deep_audit20b", "deep_audit21",
    "deep_audit22", "deep_audit23", "deep_audit24",
}

LIMITER = RateLimiter(default_rps=10.0)
TIMEOUT_CAP_S = 120

# Cronos (chain 25) runtime injection - the master backend has no
# Cronos config (same gap the Nov 15/16 drivers worked around).
CRONOS_RPCS = (
    "https://cronos.drpc.org",
    "https://evm.cronos.org",
    "https://cronos-evm-rpc.publicnode.com",
    "https://evm-cronos.crypto.org",
)
CRONOS = cc.ChainConfig(
    id="cronos", name="Cronos", chain_id=25,
    rpc_urls=CRONOS_RPCS,
    blockscout_api="https://cronos.blockscout.com/api",
    explorer_address="https://cronoscan.com/address/{addr}",
    native="CRO")
cc.CHAINS["cronos"] = CRONOS
cc.CHAIN_ALIASES.update({"cronos": "cronos", "cro": "cronos"})
try:
    from app import rpc_pool as _rpc_pool  # noqa: E402
    _rpc_pool.EXTRA_KEYLESS_RPCS["cronos"] = CRONOS_RPCS
except Exception:
    pass

FAIL_KEYS = {"contract_source_unavailable", "contract_no_code"}
SRC_CACHES = ["~/workspace/recon-verify/src_cache"]


class Cache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        pass


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def clean_ev(ev, cap=4000):
    out = {}
    for k, v in (ev or {}).items():
        s = v if isinstance(v, str) else json.dumps(v, default=str)
        out[k] = s[:cap]
    return out


def recipient_class(f):
    ev = f.get("evidence") or {}
    rc = str(ev.get("report_class") or "").lower()
    rec = str(ev.get("recipient") or "").upper()
    if rc == "candidate":
        return rec if rec in ("CALLER", "CALLER-SUPPLIED") \
            else "CALLER-SUPPLIED"
    if rc == "trigger_only":
        return "TRIGGER_ONLY"
    if rec in ("CALLER", "CALLER-SUPPLIED"):
        return rec
    if rec in ("FIXED", "HOLDER-SELF", "HOLDER_SELF"):
        return rec
    return "UNKNOWN"


def fetch_sourcify_v2(chain, address):
    import httpx as _hx
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return None
    url = (f"https://sourcify.dev/server/v2/contract/{cfg.chain_id}/"
           f"{address}?fields=sources,compilation")
    try:
        r = _hx.get(url, timeout=30,
                    headers={"User-Agent": "crypto-com-deep-scan"})
        if r.status_code != 200:
            return None
        return cc._parse_sourcify_v2_payload(r.json(), address)
    except Exception:
        return None


async def fetch_source_async(http, chain, address):
    """Verified source via the backend's own keyless routes
    (Blockscout -> Sourcify v2 -> Sourcify repo, httpx-based)."""
    try:
        ctx = Ctx(run_id="crypto-com-impl-scan-2026-11-18", mode="passive",
                  http=http, cache=Cache(), keys={},
                  limiter=LIMITER, source_type="website")
        src = await cc.fetch_verified_source(
            ctx, cc.CHAINS[chain], address)
    except Exception:
        src = None
    if src is None:
        src = fetch_sourcify_v2(chain, address)
    return src


async def scan_one(address, chain, plugins, concurrency, max_minutes):
    t0 = time.monotonic()
    deadline = t0 + max_minutes * 60
    raw = f"{chain}:{address}"
    notes, findings = [], []
    plugins_run, errors = [], 0

    by_id = {p.id: p for p in plugins}
    sem = asyncio.Semaphore(concurrency)
    ctx_holder = [None, raw]

    async def run_plugin(plugin, http):
        ctx = ctx_holder[0]
        if ctx is None:
            ctx = Ctx(run_id="crypto-com-impl-scan-2026-11-18",
                      mode="passive",
                      http=http, cache=Cache(), keys={},
                      limiter=LIMITER, source_type="website")
            ctx_holder[0] = ctx
        target = Target(raw=raw, type="crypto_wallet", normalized=raw)
        try:
            return await asyncio.wait_for(
                plugin.run(target, ctx),
                timeout=min(int(getattr(plugin, "timeout_s", 60) or 60),
                            TIMEOUT_CAP_S))
        except Exception as e:  # noqa: BLE001
            return ("error", str(e)[:200])

    async with httpx.AsyncClient(timeout=30) as http:
        src = await fetch_source_async(http, chain, address)
        source_acquired = src is not None
        if not source_acquired:
            # All 25 new detectors are verified-source-only.
            notes.append("source-required plugins skipped (25): no "
                         "verified source; detectors cannot run "
                         "without source, coverage is 0 for this "
                         "target (recorded honestly, not faked)")
            run_ids = []
        else:
            run_ids = [p.id for p in plugins]

        async def _one(pid):
            async with sem:
                if time.monotonic() > deadline:
                    return (pid, None, "deadline")
                return (pid, await run_plugin(by_id[pid], http), None)

        results = await asyncio.gather(*[_one(pid) for pid in run_ids])

    for pid, res, note in results:
        plugins_run.append(pid)
        if note == "deadline":
            notes.append(f"{pid}: skipped, global deadline reached")
            continue
        if res is None:
            continue
        if isinstance(res, tuple):
            errors += 1
            notes.append(f"{pid}: {res[1]}")
            continue
        for f in res.findings:
            ev = clean_ev(f.evidence)
            rec = {
                "plugin": pid, "key": f.key,
                "severity": (ev.get("severity") or f.bounty_value),
                "bounty_value": f.bounty_value,
                "confidence": f.confidence,
                "value": str(f.value)[:2000],
                "evidence": ev,
            }
            rec["recipient_class"] = recipient_class(rec)
            findings.append(rec)

    candidates = []
    for f in findings:
        sev = str(f.get("severity") or "").lower()
        if sev in ("high", "critical") and \
                f["recipient_class"] in ("CALLER", "CALLER-SUPPLIED"):
            candidates.append({
                "plugin": f["plugin"], "key": f["key"],
                "severity": f["severity"],
                "recipient_class": f["recipient_class"],
                "function": (f.get("evidence") or {}).get("function", ""),
                "value": f["value"][:800],
                "validation": None,
            })
    return {
        "chain": chain, "address": address,
        "status": "genuine" if source_acquired else "degraded",
        "degraded_reason": None if source_acquired
            else "no verified source; source-required detectors skipped",
        "plugins_run": plugins_run,
        "plugins_run_count": len(plugins_run), "errors": errors,
        "notes": notes, "source_acquired": source_acquired,
        "source_origin": (src or {}).get("origin") if src else None,
        "contract_name": (src or {}).get("contract_name", "") if src else "",
        "source_text": (src or {}).get("source", "") if src else "",
        "findings": findings, "candidates": candidates,
        "secs": round(time.monotonic() - t0, 1),
        "scanned_at": now_iso(),
    }


def load_targets():
    tj = HOME / "targets.json"
    tgts = []
    for row in json.loads(tj.read_text()):
        tgts.append((row["chain"], row["address"].lower(),
                     row.get("name", "")))
    return tgts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=None,
                    help="0x address or chain:0x address (default: all)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--max-minutes", type=float, default=30)
    args = ap.parse_args()

    if args.target:
        raw = args.target.strip()
        chain, addr = cc.parse_target_address(raw)
        if addr is None:
            addr = raw
        if chain is None:
            chain = "cronos"
        targets = [(chain, addr.lower(), "")]
    else:
        targets = load_targets()

    registry = discover()
    new_ids = sorted(
        pid for pid, cls in registry.items()
        if cls.__module__.rsplit(".", 1)[-1] in NEW_MODULES)
    print(f"registry={len(registry)} new30_present={len(new_ids)} "
          f"ids={new_ids}", flush=True)
    if len(new_ids) != 30:
        print("WARNING: expected 30 new detectors, found "
              f"{len(new_ids)}", flush=True)
    plugins = [registry[pid]() for pid in new_ids]

    for chain, addr, name in targets:
        t_start = time.monotonic()
        rec = asyncio.run(scan_one(addr, chain, plugins,
                                   args.concurrency, args.max_minutes))
        slug = addr.lower()
        findings_path = HOME / f"findings-{slug}.jsonl"
        cand_path = HOME / f"candidates-{slug}.jsonl"
        summary_path = HOME / f"summary-{slug}.json"
        src_text = rec.pop("source_text", "")
        with findings_path.open("w") as fh:
            for f in rec["findings"]:
                fh.write(json.dumps({**f, "chain": chain,
                                     "address": addr}) + "\n")
        with cand_path.open("w") as fh:
            for c in rec["candidates"]:
                fh.write(json.dumps({**c, "chain": chain,
                                     "address": addr}) + "\n")
        from collections import Counter
        sev_counts = Counter(str(f.get("severity") or "?").lower()
                             for f in rec["findings"])
        summary = {
            "chain": chain, "address": addr, "name": name,
            "scanned_at": rec["scanned_at"],
            "status": rec["status"],
            "degraded_reason": rec["degraded_reason"],
            "source_acquired": rec["source_acquired"],
            "source_origin": rec["source_origin"],
            "contract_name": rec["contract_name"],
            "source_chars": len(src_text),
            "registry_total": len(registry),
            "plugins_run": rec["plugins_run_count"],
            "plugins_errored": rec["errors"],
            "findings_count": len(rec["findings"]),
            "findings_by_severity": dict(sev_counts),
            "candidates_count": len(rec["candidates"]),
            "secs": rec["secs"],
            "total_secs": round(time.monotonic() - t_start, 1),
            "notes": rec["notes"][:20],
            "outputs": {"findings": str(findings_path),
                        "candidates": str(cand_path),
                        "summary": str(summary_path)},
        }
        summary_path.write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
