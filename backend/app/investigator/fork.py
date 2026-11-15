"""Fork step: plan multi-call sequences, never proof.

The fork step plans the stateful sequences (setup call, then the
sensitive call) that a single eth_call cannot test - deposit-then-
sweep, set-then-withdraw - using the existing anvil_fork_probe
planner, which is a pure function of source. Execution, when a caller
supplies it, runs against a local fork only.

HARD RULE (inherited from anvil_fork_probe): fork simulation is an
analysis signal only. Every fork outcome is recorded sim_derived and
is NEVER fed to the validator as proof and NEVER promotes a finding
to VERIFIED_REAL. VERIFIED_REAL requires the validator's live-chain
stranger probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def plan_fork(source: str) -> List[Dict[str, Any]]:
    """Plan stateful probe sequences for one contract source.

    Returns [{setup: fn|None, target: fn}] (max 8, per the planner).
    Empty source plans nothing; a planner crash plans nothing rather
    than failing the investigation.
    """
    if not source:
        return []
    try:
        from ..plugins.anvil_fork_probe import plan_sequences
        seqs = plan_sequences(source) or []
        return [{"setup": (s.get("setup") or {}).get("name"),
                 "target": (s.get("target") or {}).get("name"),
                 "target_fn": s.get("target") or {}}
                for s in seqs]
    except Exception:  # noqa: BLE001 - planning must not kill the loop
        return []


def fork_step(source: str) -> Dict[str, Any]:
    """Run the fork step: plan only, record honestly.

    ``executed`` is False unless a caller executes sequences through
    the async loop path; this sync step never executes anything and
    never claims a simulation result it did not measure.
    """
    seqs = plan_fork(source)
    return {
        "engine": "anvil_fork_probe.plan_sequences",
        "planned": seqs,
        "planned_count": len(seqs),
        "executed": False,
        "executed_count": 0,
        "outcomes": [],
        "sim_derived": True,
        "note": ("fork sequences planned from source; simulation is "
                 "analysis signal only, never proof - VERIFIED_REAL "
                 "needs the live stranger probe"),
    }
