"""Autonomous multi-agent swarm for ReconAnything.

A small team of researcher agents, coordinated, not a free-for-all:

- Scout: picks up a target, reads everything about it.
- Hypothesizer: writes a concrete attack story.
- ForkTester: tests the story on a local fork (or its honest
  stand-in when no local EVM is installed).
- LiveProber: read-only live eth_call probes from an unfunded
  stranger; verdicts come only from the existing validator path.
- Reporter: writes up the evidence.
- Coordinator: assigns targets, caps concurrency, dedupes, enforces
  the rules.

Pure Python stdlib, no new dependencies. Detection only.
"""
from __future__ import annotations

from .bus import Blackboard
from .coordinator import Coordinator
from .fork import ForkTesterAgent
from .hypothesis import HypothesizerAgent
from .probe import LiveProberAgent
from .reporter import ReporterAgent
from .rules import (BOUNTY_FLOOR_USD, READONLY_METHODS,
                    STRANGER_ADDRESS)
from .scout import ScoutAgent

__all__ = [
    "Blackboard", "Coordinator",
    "ScoutAgent", "HypothesizerAgent", "ForkTesterAgent",
    "LiveProberAgent", "ReporterAgent",
    "STRANGER_ADDRESS", "READONLY_METHODS", "BOUNTY_FLOOR_USD",
]

__version__ = "1.0.0"
