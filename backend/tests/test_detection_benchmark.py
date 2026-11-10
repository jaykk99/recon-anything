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


def test_unambiguous_drains_reach_confirmed_tier():
    """The confidence tier must promote genuine drains to 'confirmed' and
    leave the safe control out - the fix for deep scans showing 0 confirmed.
    Checks the three unambiguous kinds (ungated selfdestruct, tx.origin auth,
    ungated full-balance withdraw); reentrancy/ownership-init/delegatecall
    are known detection gaps tracked separately."""
    from app import confidence

    def confirmed_kinds(src):
        rows = [{"target_id": "0x1", "key": f.get("kind", ""),
                 "value": f.get("function") or f.get("title", ""),
                 "plugin": "contract", "evidence": {},
                 "confidence": f.get("confidence"),
                 "severity": f.get("severity")}
                for f in analyze_contract_source(src, {})]
        return {r["key"] for r in confidence.annotate_confidence(rows)
                if r["confidence_tier"] == "confirmed"}

    by_name = {c.name: c for c in CASES}
    for name in ("unprotected_selfdestruct", "txorigin_auth",
                 "unprotected_withdraw"):
        assert confirmed_kinds(by_name[name].source), \
            f"{name} should reach the confirmed tier"
    # the safe, access-gated control must never show a confirmed finding
    assert not confirmed_kinds(by_name["safe_gated_control"].source)
