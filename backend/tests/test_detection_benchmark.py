"""Ground-truth detection benchmark against known historical drain classes.

Proves the deep analyzer flags the drain path on canonical already-exploited
patterns (Parity, DAO-style, tx.origin, delegatecall) and does NOT flag the
safe control. This is the labelled set that lets confidence/severity
calibration be validated instead of guessed. In CI so detection can't
silently regress below the known-answer bar.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins.contract_chain import analyze_contract_source  # noqa: E402
from benchmarks.known_vuln_contracts import CASES  # noqa: E402

_DRAIN_KINDS = {"selfdestruct", "full_balance_withdraw", "delegatecall",
                "tx_origin", "ownership_takeover_path"}


def test_every_known_drain_is_flagged():
    misses = []
    for c in CASES:
        if not c.drainable:
            continue
        kinds = {f.get("kind") for f in analyze_contract_source(c.source, {})}
        if not (kinds & c.expect_any):
            misses.append(f"{c.name} ({c.reference}): expected one of "
                          f"{sorted(c.expect_any)}, got {sorted(kinds)}")
    assert not misses, "known-drainable contracts not flagged:\n" + \
        "\n".join(misses)


def test_safe_control_has_no_drain_finding():
    for c in CASES:
        if c.drainable:
            continue
        kinds = {f.get("kind") for f in analyze_contract_source(c.source, {})}
        bad = kinds & _DRAIN_KINDS
        assert not bad, f"{c.name} is a safe control but flagged {sorted(bad)}"
