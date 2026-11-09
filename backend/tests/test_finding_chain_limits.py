"""Lock the finding-chain safety invariants and the breadth wiring.

Breadth (items/probes/sublinks) is tunable and may grow. Depth and the
never-a-target block are NOT knobs: MAX_CHAIN_DEPTH must stay 2 (the
anti-runaway invariant - one extra hop, nothing published back, so a chain
can't loop or fan out), and crypto.com must stay blocked. This test fails
if either is ever weakened.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import config, finding_chain as fc  # noqa: E402


def test_chain_depth_is_fixed_at_two():
    assert fc.MAX_CHAIN_DEPTH == 2, (
        "chain depth must stay 2 - raising it breaks the anti-runaway "
        "guarantee (one extra hop, nothing published back).")


def test_never_a_target_block_intact():
    assert "crypto.com" in fc.BLOCKED_DOMAINS


def test_breadth_reads_from_config():
    assert fc.MAX_CHAIN_ITEMS == config.CHAIN_MAX_ITEMS
    assert fc.MAX_CHAIN_PROBES == config.CHAIN_MAX_PROBES
    assert fc.MAX_SUBLINKS_PER_ITEM == config.CHAIN_MAX_SUBLINKS
    # breadth may grow but should not silently shrink below the new floor
    assert fc.MAX_CHAIN_ITEMS >= 40
    assert fc.MAX_CHAIN_PROBES >= 60
