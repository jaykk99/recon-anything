"""The investigator loop (Wave 1.1): the researcher, not the scanner.

The repo had 1,433 plugins but no loop: nothing picked a target,
formed an attack story, chose the next test from the last result, or
ran until a verdict. This module is that loop:

    pick target (value-first queue)
      -> read everything (source, proxy chain, related contracts)
      -> form a concrete attack story (hypothesis)
      -> select the next test from the last result
      -> test on fork (plan sequences; sim only, never proof)
      -> prove live read-only (validator, published candidates)
      -> chain to the next contract
      -> write up (bounty pack when the pack rule fires)

State persists per investigation after every phase; the loop stops on
a verdict, not on budget alone. Detection only: no exploit execution,
no fund-taking, no broadcast transactions. VERIFIED_REAL comes only
from the validator's live-probe bar; fork/simulation stays UNVERIFIED.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from ..batch_scan import scan_source
from ..valuation import value_band
from .fork import fork_step
from .hypothesis import form_hypothesis
from .picker import meets_live_floor, target_value_usd
from .publish import (candidates_from_findings, filter_metered,
                      publish_validator_candidates)
from .reporting import pack_should_generate, write_pack
from .state import (BOUNTY_FLOOR_USD, Investigation, default_store_dir,
                    new_investigation_id)
from .validate import aggregate_verdict, validate_candidates

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_ZERO_ADDRESS = "0x" + "0" * 40


def _related_addresses(source: str, self_address: str) -> List[str]:
    """Other contract addresses mentioned in the source: proxy
    implementations, linked tokens, libraries. Chaining leads."""
    if not source:
        return []
    seen = []
    for m in _ADDRESS_RE.findall(source):
        low = m.lower()
        if low == (self_address or "").lower() or low == _ZERO_ADDRESS:
            continue
        if low not in seen:
            seen.append(low)
    return seen


def run_investigation(address: str, chain: str,
                      source: Optional[str] = None,
                      contract_name: str = "",
                      value_usd: Optional[float] = None,
                      native_usd: Optional[float] = None,
                      token_positions: Optional[List[Dict[str, Any]]] = None,
                      scope: Optional[List[str]] = None,
                      live: bool = False,
                      store_dir: Optional[str] = None,
                      out_dir: Optional[str] = None,
                      ctx: Any = None,
                      related_sources: Optional[Dict[str, str]] = None,
                      chain_depth: int = 1,
                      investigation_id: Optional[str] = None) -> Investigation:
    """Run the full loop over one contract. Returns the persisted
    Investigation (verdict set, pack written when the rule fires).

    ``source`` is the verified source text when the caller has it; when
    absent and no ctx can fetch it, the loop closes UNVERIFIED naming
    the missing source instead of guessing. ``live`` enforces the
    $100k realizable-value floor on known values.
    """
    store_dir = store_dir or default_store_dir()
    out_dir = out_dir or os.path.join(store_dir, "packs")
    inv = Investigation(
        id=investigation_id or new_investigation_id(address, chain),
        address=address, chain=chain or "",
        scope=list(scope or []),
        value_usd=(value_usd if value_usd is not None
                   else target_value_usd(
                       {"native_usd": native_usd,
                        "token_positions": token_positions})),
    )
    inv.value_band = value_band(inv.value_usd)

    # --- PICK: value-first gate (live path only) ---
    if live and not meets_live_floor(inv.value_usd):
        inv.transition(
            "VERDICT",
            f"below ${BOUNTY_FLOOR_USD:,.0f} realizable-value floor "
            f"(value ${inv.value_usd:,.0f}); skipped live path")
        inv.verdict = "SKIPPED"
        inv.transition("CLOSED", "skipped: value floor")
        inv.save(store_dir)
        return inv
    inv.transition("PICKED",
                   f"value ${inv.value_usd} ({inv.value_band})"
                   if inv.value_usd is not None
                   else "value unknown; not filtered as dust")
    inv.save(store_dir)

    # --- READ: everything the loop can read from the source ---
    inv.transition("READ", "reading source, proxy chain, related contracts")
    findings: List[Dict[str, Any]] = []
    proxy_notes: List[str] = []
    if source:
        try:
            from ..plugins.contract_chain import analyze_contract_source
            chain_findings = analyze_contract_source(
                source, {"address": address, "chain": chain})
            findings.extend(chain_findings)
            proxy_notes.append(
                f"contract_chain: {len(chain_findings)} finding(s)")
        except Exception as e:  # noqa: BLE001 - a broken analyzer
            # never drops the contract; it is recorded, not hidden.
            inv.notes.append(f"[READ] contract_chain error: {e}")
        # Full CPU detection stack, deep lanes included: this is the
        # loop-driven scan, so deep_audit12-19, bsc_*, recipient_first,
        # deep_lowlevel and deep_solana all run (batch_scan deep mode).
        findings.extend(scan_source(
            source, {"address": address, "chain": chain}, deep=True))
    else:
        inv.notes.append(
            "[READ] no verified source supplied; source-dependent "
            "detection skipped (degraded, not clean)")
    inv.findings = findings
    inv.save(store_dir)

    # --- HYPOTHESIS: one concrete attack story, from candidates ---
    # Candidates are built here (not in the probe phase) so the story
    # is about something the loop will actually validate: drain-kind
    # high/critical findings, minus caller-metered payouts (a withdraw
    # that pays at most the caller's own balance is settled by the
    # static read; no stranger drain to hypothesize about).
    inv.transition("HYPOTHESIS", "forming attack story from findings")
    raw_candidates = candidates_from_findings(
        findings, address, chain, source=source,
        contract_name=contract_name)
    inv.candidates, metered = filter_metered(
        raw_candidates, source=source, contract_name=contract_name)
    for s in metered:
        inv.notes.append(
            f"[HYPOTHESIS] candidate dropped: {s.get('kind')} "
            f"{s.get('function')} - {s.get('skip_reason')}")
    if inv.candidates:
        backed = {(c["kind"], c["function"]) for c in inv.candidates}
        backing = [f for f in findings
                   if (str(f.get("kind") or f.get("check") or ""),
                       str(f.get("function") or "")) in backed]
        inv.hypothesis = form_hypothesis(backing, address, chain)
    if inv.hypothesis is None:
        inv.notes.append("[HYPOTHESIS] no drain/takeover story in findings")
    inv.save(store_dir)

    # --- FORK_TEST: plan sequences (sim only, never proof) ---
    inv.transition("FORK_TEST", "planning fork sequences")
    inv.fork = fork_step(source or "")
    inv.save(store_dir)

    # --- LIVE_PROBE: publish candidates, run the validator ---
    inv.transition("LIVE_PROBE", "publishing candidates; running validator")
    bus: Dict[str, List[Dict[str, Any]]] = {}
    published = publish_validator_candidates(bus, inv.candidates)
    inv.notes.append(
        f"[LIVE_PROBE] published {published} candidate(s) to "
        f"validator_candidates")
    # Validate what was published, not a separate list: the bus
    # round-trip is the wiring this wave fixes.
    queued = list(bus.get("validator_candidates", []))
    inv.verdicts = validate_candidates(queued, ctx=ctx)
    inv.save(store_dir)

    # --- CHAIN: related contracts become child investigations ---
    inv.transition("CHAIN", "chaining to related contracts")
    related = _related_addresses(source or "", address)
    for rel in related:
        child = Investigation(
            id=new_investigation_id(rel, chain),
            address=rel, chain=chain or "",
            scope=list(scope or []),
            value_usd=None)
        child.transition("PICKED", f"chained from {address}")
        child.save(store_dir)
        inv.chained.append({"address": rel, "chain": chain,
                            "investigation_id": child.id,
                            "status": "queued"})
        # Recurse only when the caller supplied that contract's source
        # and depth remains: the loop follows evidence, not guesses.
        if (related_sources and rel.lower() in
                {k.lower(): v for k, v in related_sources.items()}
                and chain_depth > 0):
            src_map = {k.lower(): v for k, v in related_sources.items()}
            child_run = run_investigation(
                rel, chain, source=src_map[rel.lower()],
                scope=scope, live=live, store_dir=store_dir,
                out_dir=out_dir, ctx=ctx,
                related_sources=related_sources,
                chain_depth=chain_depth - 1)
            inv.chained[-1]["status"] = child_run.verdict or "done"
            inv.chained[-1]["investigation_id"] = child_run.id
    inv.save(store_dir)

    # --- VERDICT: stops on verdict, not budget alone ---
    inv.transition("VERDICT", "aggregating validator verdicts")
    if not inv.candidates:
        inv.verdict = "CLEAN"
        inv.notes.append("[VERDICT] zero validator candidates; clean close")
    else:
        inv.verdict = aggregate_verdict(inv.verdicts)
        missing = sorted({m for v in inv.verdicts
                          for m in (v.get("missing") or [])})
        if missing:
            inv.notes.append(
                f"[VERDICT] missing evidence: {', '.join(missing)}")
    inv.save(store_dir)

    # --- PACK: report generator, called when the rule fires ---
    if pack_should_generate(inv.verdict, inv.value_usd, inv.findings):
        pack_dir = os.path.join(out_dir, inv.id)
        manifest = write_pack(inv, pack_dir, source=source)
        if manifest:
            inv.report = manifest
            inv.transition("PACKED", f"pack written to {pack_dir}")
        else:
            inv.notes.append("[PACKED] pack rule fired but write failed")
    inv.transition("CLOSED", f"verdict {inv.verdict}")
    inv.save(store_dir)
    return inv


def run_queue(targets: List[Dict[str, Any]], **kwargs: Any
              ) -> List[Investigation]:
    """Run the loop over a value-first queue. One target at a time;
    a failure on one target never drops the rest."""
    from .picker import order_targets
    out = []
    for t in order_targets(targets):
        try:
            out.append(run_investigation(
                t.get("address", ""), t.get("chain", ""),
                source=t.get("source"),
                value_usd=t.get("value_usd"),
                scope=t.get("scope"), **kwargs))
        except Exception as e:  # noqa: BLE001 - queue keeps moving
            inv = Investigation(
                id=new_investigation_id(t.get("address", ""), t.get("chain", "")),
                address=t.get("address", ""), chain=t.get("chain", ""))
            inv.verdict = "SKIPPED"
            inv.notes.append(f"[PICKED] queue error: {e}")
            out.append(inv)
    return out
