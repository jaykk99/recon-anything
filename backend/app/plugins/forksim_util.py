"""Shared helpers for the Tier-9 fork-simulation plugins.

HARD RULE (Jay's no-simulation rule, binding on every Tier-9 plugin):
fork / local-chain simulation is an ANALYSIS signal only. Every
finding built on this module MUST carry ``sim_evidence`` markers:
``verdict == "UNVERIFIED"``, ``sim_derived is True`` and
``proof_type == "simulation_only_not_proof"``. A sim-derived finding
is NEVER ``VERIFIED_REAL`` and is never presented as proof.
``VERIFIED_REAL`` still requires a live-chain stranger probe with
positive value evidence (the auto_validator lane's bar).

Work collection is shared so every Tier-9 plugin resolves its target
the same way the other web3 lanes do:

- ``ctx.shared["tier9_sources"]``: explicit ``{address, chain,
  source}`` dicts injected by tests / upstream lanes (no network);
- otherwise contract addresses from the target string or the
  discovery bus, with verified source fetched keyless through
  ``contract_chain`` (Blockscout / Sourcify), exactly like
  ``zeroday_contract_guards``.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from . import contract_chain as cc

MAX_ADDRESSES = 3
MAX_CHAIN_PAIRS = 3

SIM_SOURCE = "tier9 fork-sim analysis (sim-derived, UNVERIFIED)"


def sim_evidence(severity: str, **kw: Any) -> Dict[str, Any]:
    """Evidence dict carrying the mandatory sim/UNVERIFIED markers."""
    ev: Dict[str, Any] = dict(kw)
    ev.update({
        "severity": severity,
        "verdict": "UNVERIFIED",
        "verification_status": "UNVERIFIED",
        "review_status": "pending human review - sim-derived lead only",
        "sim_derived": True,
        "proof_type": "simulation_only_not_proof",
        "not_verified_real": True,
        "scope_note": ("Produced by fork/local simulation or static "
                       "simulation analysis. UNVERIFIED by design: "
                       "VERIFIED_REAL requires a live-chain stranger "
                       "probe with positive value evidence."),
        "remediation": kw.get("remediation") or (
            "Treat as an unproven sim-derived lead: feed it to the "
            "live validator queue (auto_validator) and confirm with a "
            "live-chain read-only stranger probe before acting."),
    })
    return ev


def is_gated(fn_text: str, fn_signature: str = "") -> bool:
    """True when a function carries a recognisable access gate."""
    blob = f"{fn_signature} {fn_text}"
    return bool(re.search(
        r"only[A-Z_]\w*|onlyOwner|onlyAdmin|onlyRole|nonReentrant\b.*"
        r"|require\s*\(\s*(msg\.sender|_msgSender\(\))\s*==|"
        r"require\s*\(\s*hasRole|_checkRole|_checkOwner|"
        r"if\s*\(\s*(msg\.sender|_msgSender\(\))\s*!=", blob))


def collect_addresses(target: Any, ctx: Any) -> List[Tuple[Optional[str], str]]:
    out: List[Tuple[Optional[str], str]] = []
    seen = set()

    def add(chain_hint: Optional[str], addr: str) -> None:
        addr = (addr or "").strip()
        if not cc.ADDRESS_RE.match(addr):
            return
        if addr.lower() == cc.ZERO_ADDRESS or addr.lower() in seen:
            return
        seen.add(addr.lower())
        out.append((chain_hint, addr))

    for raw in (getattr(target, "normalized", ""), getattr(target, "raw", "")):
        chain_hint, addr = cc.parse_target_address(raw or "")
        if addr:
            add(chain_hint, addr)
            break
    for kind in ("contract_addresses", "crypto_addresses"):
        try:
            items = ctx.consume(kind)
        except Exception:
            items = []
        for item in items:
            a = item if isinstance(item, str) else str(
                item.get("address", "") if isinstance(item, dict) else "")
            add(None, a)
    return out[:MAX_ADDRESSES]


async def collect_source_work(target: Any, ctx: Any) -> List[Dict[str, Any]]:
    """[{chain, chain_id, address, source, origin}] for the target.

    Injected ``tier9_sources`` win (tests / upstream lanes); otherwise
    verified source is fetched keyless per chain, like the other
    web3 lanes. Malformed injected entries are skipped, never fatal.
    """
    shared = getattr(ctx, "shared", {}) or {}
    injected = shared.get("tier9_sources")
    if isinstance(injected, list) and injected:
        work: List[Dict[str, Any]] = []
        for item in injected[:MAX_ADDRESSES]:
            if not isinstance(item, dict):
                continue
            src = item.get("source")
            if not isinstance(src, str) or not src.strip():
                continue
            work.append({
                "chain": item.get("chain") or "ethereum",
                "chain_id": item.get("chain_id") or "ethereum",
                "address": str(item.get("address") or ""),
                "source": src,
                "origin": str(item.get("origin") or "injected"),
            })
        if work:
            return work

    key = None
    try:
        key = (ctx.keys or {}).get("etherscan") or os.environ.get(
            "ETHERSCAN_API_KEY") or None
    except Exception:
        key = None
    work = []
    pairs = 0
    for chain_hint, addr in collect_addresses(target, ctx):
        chain_ids = [chain_hint] if chain_hint else list(cc.DEFAULT_CHAIN_ORDER)
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS.get(cid)
            if chain is None:
                continue
            try:
                code = await cc.rpc_get_code(ctx, chain, addr)
                if code is None or code == "0x" or len(code) < 4:
                    continue
                pairs += 1
                meta = await cc.fetch_verified_source(ctx, chain, addr, key)
            except Exception:
                continue
            if meta and meta.get("source"):
                work.append({
                    "chain": chain.name,
                    "chain_id": cid,
                    "address": addr,
                    "source": meta["source"],
                    "origin": meta.get("origin", ""),
                })
                break
    return work


async def run_analyzer_plugin(plugin: Any, target: Any, ctx: Any,
                              analyzer: Any) -> Any:
    """Common run() for source-analyzer Tier-9 plugins.

    ``analyzer(source, item) -> [{key, severity, detail, function?,
    check?, confidence?}]``. Every hit becomes a sim-marked finding.
    No work -> skipped (ok/0 with reason), never an exception.
    """
    t0 = time.monotonic()
    try:
        work = await collect_source_work(target, ctx)
    except Exception as e:  # never throw fatally
        res = plugin._skipped(f"source collection failed: {str(e)[:160]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
    if not work:
        res = plugin._skipped(
            "no contract source to analyze: scan a contract address "
            "(optionally chain-prefixed) or a target whose pages "
            "reference one with verified source")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
    findings = []
    for item in work:
        try:
            hits = analyzer(item["source"], item) or []
        except Exception:
            continue
        for hit in hits:
            sev = str(hit.get("severity") or "low")
            ev = sim_evidence(
                sev,
                address=item["address"], chain=item["chain_id"],
                check=hit.get("check", hit.get("key", "")),
                function=hit.get("function", ""),
                tool_origin=hit.get("tool_origin", plugin.id))
            if hit.get("extra"):
                ev.update(hit["extra"])
            findings.append(plugin._f(
                "web3", hit["key"],
                f"{sev.upper()}: {hit['detail']} "
                f"[SIM-DERIVED - UNVERIFIED, not proof]",
                source=SIM_SOURCE,
                source_url=(cc.explorer_url(cc.CHAINS[item["chain_id"]],
                                            item["address"])
                            if item["address"] and item["chain_id"] in cc.CHAINS
                            else None),
                confidence=int(hit.get("confidence", 60)), passive=True,
                evidence=ev))
    res = plugin._ok(findings, f"{plugin.id}: analyzed {len(work)} "
                               f"source(s), {len(findings)} sim-derived "
                               f"UNVERIFIED finding(s)")
    res.duration_ms = int((time.monotonic() - t0) * 1000)
    return res
