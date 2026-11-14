"""Sheaf theory + hypergraph signal processing for ReconAnything.

Hyperedges for multi-entity events, sheaves (local data spaces on
hyperedges), restriction maps, and cohomology-style consistency
checking: local sections that fail to glue into a global section
flag a hole in the target's cover story.

Triage only. Never predicts VERIFIED_REAL. Detection only.
Pure Python stdlib.
"""
from __future__ import annotations

from .hyperedges import build_all, latest_owner_map
from .sheaf import (CheckResult, Fact, Hyperedge, Obstruction, Stalk,
                    check_cover, consistency, cover_obstructions,
                    rank_inconsistencies, restrict, restrict_all,
                    to_hypergraph_nn)

__all__ = [
    "Fact",
    "Stalk",
    "Hyperedge",
    "CheckResult",
    "Obstruction",
    "build_all",
    "latest_owner_map",
    "restrict",
    "restrict_all",
    "consistency",
    "check_cover",
    "cover_obstructions",
    "rank_inconsistencies",
    "to_hypergraph_nn",
]
