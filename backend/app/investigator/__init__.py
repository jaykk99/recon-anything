"""Investigator loop: the researcher that drives the 1,433 plugins.

Pick a target value-first, read everything, form a concrete attack
story, test on fork, prove live read-only through the validator,
chain to the next contract, and write the bounty pack. Detection
only; fork/simulation is never proof.
"""
from __future__ import annotations

from .fork import fork_step, plan_fork
from .hypothesis import DRAIN_KINDS, form_hypothesis
from .loop import run_investigation, run_queue
from .picker import meets_live_floor, order_targets, target_value_usd
from .publish import (candidates_from_findings, filter_metered,
                      publish_validator_candidates)
from .reporting import pack_should_generate, write_pack
from .state import (BOUNTY_FLOOR_USD, Investigation, default_store_dir,
                    new_investigation_id)
from .validate import (LOOP_MAX_CANDIDATES, aggregate_verdict,
                       validate_candidates)

__all__ = [
    "BOUNTY_FLOOR_USD",
    "DRAIN_KINDS",
    "LOOP_MAX_CANDIDATES",
    "Investigation",
    "aggregate_verdict",
    "candidates_from_findings",
    "filter_metered",
    "default_store_dir",
    "fork_step",
    "form_hypothesis",
    "meets_live_floor",
    "new_investigation_id",
    "order_targets",
    "pack_should_generate",
    "plan_fork",
    "publish_validator_candidates",
    "run_investigation",
    "run_queue",
    "target_value_usd",
    "validate_candidates",
    "write_pack",
]
