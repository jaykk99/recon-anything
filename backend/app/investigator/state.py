"""Investigator-loop state: one investigation, persisted per phase.

The loop stops on a verdict, not on budget alone. Every phase transition
is recorded with a timestamp so an investigation can be resumed, audited,
or picked up by another lane, and so a "clean" close is distinguishable
from a run that died mid-loop.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# Phases, in order. VERDICT is terminal; PACKED/CLOSED follow it.
PHASES = (
    "PICKED",      # target picked from the value-first queue
    "READ",        # source / bytecode / proxy chain / related contracts read
    "HYPOTHESIS",  # concrete attack story formed from the findings
    "FORK_TEST",   # fork sequences planned (sim only, never proof)
    "LIVE_PROBE",  # validator run on the published candidates
    "CHAIN",       # related contracts discovered, children queued
    "VERDICT",     # terminal verdict reached
    "PACKED",      # bounty pack written (when the pack rule fires)
    "CLOSED",      # done: verdict stands, nothing left to do
)

TERMINAL_PHASES = ("VERDICT", "PACKED", "CLOSED")

# Final verdicts. CLEAN means the loop ran and produced zero validator
# candidates. SKIPPED means the target never entered the loop (value
# floor, no source, out of scope).
VERDICTS = (
    "VERIFIED_REAL", "TRIGGER_ONLY", "FALSE_POSITIVE", "UNVERIFIED",
    "CLEAN", "SKIPPED",
)

# Bounty-grade floor: the loop's live path only spends live-probe effort
# on contracts whose realizable value clears $100k. An unknown value is
# never filtered (we cannot assess it, so it is not dust).
BOUNTY_FLOOR_USD = 100_000.0


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def new_investigation_id(address: str, chain: str) -> str:
    """Stable id for (chain, address) plus a short random suffix."""
    base = hashlib.sha256(
        f"{(chain or '').lower()}:{(address or '').lower()}".encode()
    ).hexdigest()[:12]
    return f"inv-{base}-{uuid.uuid4().hex[:6]}"


@dataclass
class Investigation:
    """One loop run over one contract target."""
    id: str
    address: str
    chain: str
    phase: str = "PICKED"
    verdict: Optional[str] = None
    scope: List[str] = field(default_factory=list)  # bounty programs / notes
    value_usd: Optional[float] = None  # realizable value, None = unknown
    value_band: str = "unknown"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    hypothesis: Optional[Dict[str, Any]] = None
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    verdicts: List[Dict[str, Any]] = field(default_factory=list)
    fork: Dict[str, Any] = field(default_factory=dict)
    chained: List[Dict[str, Any]] = field(default_factory=list)
    report: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def transition(self, phase: str, note: str = "") -> None:
        if phase not in PHASES:
            raise ValueError(f"unknown investigation phase: {phase!r}")
        self.phase = phase
        self.updated_at = _now()
        self.history.append(
            {"phase": phase, "at": self.updated_at, "note": note})
        if note:
            self.notes.append(f"[{phase}] {note}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Investigation":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self, store_dir: str) -> str:
        os.makedirs(store_dir, exist_ok=True)
        path = os.path.join(store_dir, f"{self.id}.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
        return path

    @classmethod
    def load(cls, store_dir: str, inv_id: str) -> "Investigation":
        path = os.path.join(store_dir, f"{inv_id}.json")
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    @classmethod
    def list_ids(cls, store_dir: str) -> List[str]:
        if not os.path.isdir(store_dir):
            return []
        return sorted(
            f[:-5] for f in os.listdir(store_dir) if f.endswith(".json"))


def default_store_dir() -> str:
    return os.environ.get("RECON_INVESTIGATIONS_DIR") or os.path.join(
        os.getcwd(), "investigations")
