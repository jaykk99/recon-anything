"""Deep-audit batch-6 detectors (Financial + Oracle slices).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate at the spec severity; the FIXED-recipient variant
(recipient-carrying specs) MUST fire trigger-only at low
severity (never a candidate); every clean control MUST stay
silent under ALL nine detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the registry discovers exactly 1165 plugins
including all nine.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit6_fixtures as fx  # noqa: E402
from app.plugins.deep_audit6 import SPECS, SPECS_BY_ID, \
    analyze_deep6_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]

EXPECTED_SEVERITY = {
    "unchecked_math_user_input": "high",
    "strict_balance_equality": "medium",
    "swap_fixed_min_amount_out": "medium",
    "swap_deadline_unbound": "medium",
    "shadowed_state_variable_legacy": "low",
    "hardcoded_decimals_scaling": "low",
    "twap_observe_window_short": "medium",
    "chainlink_price_unbounded": "medium",
    "view_price_no_reentrancy_protection": "medium",
}


def hits_for(src, pid):
    return analyze_deep6_source(src, SPECS_BY_ID[pid])


def test_nine_plugins_registered():
    assert len(IDS) == 9
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_795():
    reg = discover()
    assert len(reg) == 1165, \
        f"registry size {len(reg)}, expected 1165"


def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["code"], f"{pid}: no code evidence"
            assert h["detail"], f"{pid}: no detail"
            assert h["gate_analysis"], \
                f"{pid}: no gate analysis (validator-ready bar)"
            assert h["report_class"] == "candidate", (
                f"{pid}: vuln fixture must be a candidate, got "
                f"{h['report_class']} ({h.get('recipient')})")
            assert h["severity"] == EXPECTED_SEVERITY[pid], (
                f"{pid}: severity {h['severity']}, expected "
                f"{EXPECTED_SEVERITY[pid]}")
            assert h["recipient"] in (
                "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_variant_fires_trigger_only_never_candidate():
    for pid, src in fx.VARIANT.items():
        hits = hits_for(src, pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_clean_controls_silent_under_all_nine():
    for clean_id, src in fx.CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {clean_id} clean "
                f"control: {hits}")


def test_no_cross_talk_between_detectors():
    for pid in IDS:
        for other in IDS:
            if other == pid:
                continue
            hits = hits_for(fx.VULN[pid], other)
            assert hits == [], (
                f"{other}: fired on {pid}'s vulnerable "
                f"fixture: {hits}")
    for pid, src in fx.VARIANT.items():
        for other in IDS:
            if other == pid:
                continue
            hits = hits_for(src, other)
            assert hits == [], (
                f"{other}: fired on {pid}'s variant "
                f"fixture: {hits}")


# ---------------------------------------------------------------------------
# Targeted slice checks beyond the fixture matrix
# ---------------------------------------------------------------------------

_ROUTER = fx._ROUTER_IFACE


def test_swap_exact_eth_min_position_zero():
    src = _ROUTER + """
contract EthSwapMin {
    IRouterLike public router;
    function swap(address[] calldata path) public payable {
        router.swapExactETHForTokens(500, path, msg.sender, block.timestamp + 600);
    }
}
"""
    hits = hits_for(src, "swap_fixed_min_amount_out")
    assert hits and hits[0]["report_class"] == "candidate"
    assert hits_for(src, "swap_deadline_unbound") == []


def test_swap_tokens_for_exact_eth_deadline_only():
    src = _ROUTER + """
contract ExactOutSwap {
    IRouterLike public router;
    function swap(uint256 amountOut, uint256 maxIn, address[] calldata path) public {
        router.swapTokensForExactETH(amountOut, maxIn, path, msg.sender, 1893456000);
    }
}
"""
    hits = hits_for(src, "swap_deadline_unbound")
    assert hits and hits[0]["report_class"] == "candidate"
    # amountOut at position 0 is NOT a min-out: no min fire
    assert hits_for(src, "swap_fixed_min_amount_out") == []


def test_swap_zero_min_out_stays_silent():
    src = _ROUTER + """
contract ZeroMinSwap {
    IRouterLike public router;
    function swap(uint256 amountIn, address[] calldata path) public {
        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp + 600);
    }
}
"""
    assert hits_for(src, "swap_fixed_min_amount_out") == []


def test_twap_period_constant_short():
    src = fx._OBSERVE_IFACE + """
contract TwapConstShort {
    IPoolObserveLike public oracle;
    uint256 public constant PERIOD = 900;
    function getPrice(address token, uint128 amountIn) public view returns (uint256) {
        return oracle.consult(token, amountIn);
    }
}
"""
    hits = hits_for(src, "twap_observe_window_short")
    assert hits and hits[0]["severity"] == "medium"


def test_unchecked_gated_local_result_fires():
    # The FIN-001 slice in one shape: caller-gated function,
    # result lands in a local that is then stored.
    hits = hits_for(fx.VULN["unchecked_math_user_input"],
                    "unchecked_math_user_input")
    assert hits
    assert "caller-gated" in hits[0]["gate_analysis"]


def test_shadow_requires_legacy_pragma():
    modern = fx.CLEAN["shadowed_state_variable_legacy"]
    assert hits_for(modern,
                    "shadowed_state_variable_legacy") == []
    legacy = fx.VULN["shadowed_state_variable_legacy"]
    hits = hits_for(legacy, "shadowed_state_variable_legacy")
    assert hits and "totalShares" in hits[0]["detail"]
