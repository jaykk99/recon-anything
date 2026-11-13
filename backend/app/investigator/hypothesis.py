"""Hypothesis formation: turn findings into a concrete attack story.

A finding is not a story. The loop picks the single most valuable
finding (drain/takeover kind, highest severity, with a named function)
and states, in one dict: what the attacker calls, what moves, who
receives it, and what test comes next. The next test is selected from
the last result, not from a fixed list - a hypothesis with no payout
path asks for a fork sequence; a hypothesis with a payout path asks
for a live stranger probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Fund-loss / takeover kinds, mirroring audit_report._DRAINABLE_KINDS.
# A finding of one of these kinds with a named function is a story; any
# other high-severity finding is a lead, not a story.
DRAIN_KINDS = frozenset({
    "full_balance_withdraw", "fund_drain", "unprotected_withdraw",
    "ownership_takeover_path", "ownership_takeover_fallback",
    "selfdestruct", "tx_origin", "delegatecall_untrusted",
    "missing_access_control", "reentrancy",
    "bytecode_selfdestruct", "bytecode_delegatecall",
    "rugcheck_honeypot", "honeypot",
    # Recipient-first / deep-audit payout kinds: the recipient is the
    # caller or a caller-supplied address, so the payout is stranger
    # reachable in principle until the validator proves otherwise.
    "recipient_mint_to_caller", "recipient_unbacked_claim",
    "recipient_overdraw_withdraw", "recipient_rescue_to_param",
    "recipient_bridge_release_unproven",
    "zero_amount_withdrawal_full_balance", "residual_balance_sweep_ungated",
    "zero_amount_withdraw_all", "vesting_release_cancel_double_debit",
    "intent_deposit_ghost_credit_no_rollback",
    "aa_execute_ungated", "vault_underwrites_attacker_created_pool",
    "lending_collateral_price_provider_unvalidated",
    "callback_token_cei_violation",
})

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _kind_of(f: Dict[str, Any]) -> str:
    return str(f.get("kind") or f.get("check") or f.get("key") or "")


def _severity_of(f: Dict[str, Any]) -> str:
    return str(f.get("severity") or "info").lower()


def _recipient_of(f: Dict[str, Any]) -> str:
    ev = f.get("evidence") or {}
    if isinstance(ev, dict):
        r = ev.get("recipient") or ev.get("recipient_class")
        if r:
            return str(r)
    detail = str(f.get("detail") or "")
    if "msg.sender" in detail:
        return "msg.sender (caller)"
    return "unknown"


def form_hypothesis(findings: List[Dict[str, Any]], address: str,
                    chain: str) -> Optional[Dict[str, Any]]:
    """Build the attack story from the best finding, or None.

    Ranking: drain kind first, then severity, then a named function.
    Findings whose report_class is trigger_only are leads, not stories:
    the value lands at a fixed destination, so there is no stranger
    payout to hypothesize about.
    """
    stories = []
    for f in findings:
        ev = f.get("evidence") or {}
        if isinstance(ev, dict) and ev.get("report_class") == "trigger_only":
            continue
        kind = _kind_of(f)
        sev = _severity_of(f)
        fn = str(f.get("function") or "")
        stories.append((0 if kind in DRAIN_KINDS else 1,
                        _SEV_RANK.get(sev, 4),
                        0 if fn else 1, f))
    if not stories:
        return None
    stories.sort(key=lambda t: (t[0], t[1], t[2]))
    _, _, _, best = stories[0]
    kind = _kind_of(best)
    fn = str(best.get("function") or "")
    if kind not in DRAIN_KINDS and _severity_of(best) not in ("critical", "high"):
        return None
    return {
        "address": address,
        "chain": chain,
        "kind": kind,
        "severity": _severity_of(best),
        "function": fn,
        "title": str(best.get("title") or best.get("detail", ""))[:200],
        "detail": str(best.get("detail") or ""),
        "code": str(best.get("code") or ""),
        "recipient": _recipient_of(best),
        "story": (
            f"Call {fn or '(unknown function)'} ({kind}) on {address} "
            f"({chain}): the flagged path moves contract value to "
            f"{_recipient_of(best)} with no gate the static read could "
            f"see. Next test: fork the call sequence, then a live "
            f"read-only stranger probe to measure what a stranger "
            f"actually receives."),
        # Next test is chosen from this result by the loop: a story
        # with a named payout function goes to fork first.
        "next_test": "fork_sequence" if fn else "read_source_deeper",
    }
