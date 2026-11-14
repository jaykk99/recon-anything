"""Hypothesizer: turn findings into one concrete attack story.

A finding is not a story. The Hypothesizer picks the single most
valuable finding (drain/takeover kind, highest severity, with a named
function) and states, in one dict: what the attacker calls, what
moves, who receives it, and what test comes next. A hypothesis with
no payout path asks for a fork sequence; a hypothesis with a payout
path asks for a live stranger probe.

Reuses the investigator loop's ``form_hypothesis`` when that module
exists (branch feat/nn-swarm is cut from master, where it does not);
the local fallback below implements the same vocabulary so the swarm
works standalone.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Fund-loss / takeover kinds, mirroring
# investigator/hypothesis.py DRAIN_KINDS (and audit_report drainable
# kinds). A finding of one of these kinds with a named function is a
# story; any other high-severity finding is a lead, not a story.
DRAIN_KINDS = frozenset({
    "full_balance_withdraw", "fund_drain", "unprotected_withdraw",
    "ownership_takeover_path", "ownership_takeover_fallback",
    "selfdestruct", "tx_origin", "delegatecall_untrusted",
    "missing_access_control", "reentrancy",
    "bytecode_selfdestruct", "bytecode_delegatecall",
    "rugcheck_honeypot", "honeypot",
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


def _function_of(f: Dict[str, Any]) -> str:
    ev = f.get("evidence") or {}
    if isinstance(ev, dict):
        for k in ("function", "fn", "target_fn"):
            if ev.get(k):
                return str(ev[k])
    return str(f.get("function") or "")


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


def _fallback_hypothesis(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Local story picker: same vocabulary as the investigator loop."""
    if not findings:
        return {"story": None, "kind": "no_story",
                "reason": "no findings to form a story from",
                "next_test": "none"}

    def rank(f: Dict[str, Any]):
        kind = _kind_of(f)
        return (0 if kind in DRAIN_KINDS else 1,
                _SEV_RANK.get(_severity_of(f), 4),
                0 if _function_of(f) else 1)

    best = sorted(findings, key=rank)[0]
    kind = _kind_of(best)
    fn = _function_of(best)
    recipient = _recipient_of(best)
    is_story = kind in DRAIN_KINDS and bool(fn)
    if is_story:
        story = (f"Stranger calls {fn}() on the target; the {kind} "
                 f"finding says value moves to {recipient}.")
        next_test = "live_probe" if recipient not in ("unknown",) else "fork_sequence"
    elif kind in DRAIN_KINDS:
        story = (f"{kind} flagged but no function is named: a lead, "
                 "not a story yet.")
        next_test = "fork_sequence"
    else:
        story = (f"Strongest finding is {kind} "
                 f"({_severity_of(best)}), not a drain/takeover kind: "
                 "a lead, not a story.")
        next_test = "fork_sequence"
    return {
        "story": story,
        "kind": "story" if is_story else "lead",
        "finding_kind": kind,
        "function": fn,
        "recipient": recipient,
        "severity": _severity_of(best),
        "next_test": next_test,
        "engine": "swarm-hypothesis-fallback",
    }


class HypothesizerAgent:
    """Role agent: write the concrete attack story."""

    name = "hypothesizer"

    def run(self, scout_report: Dict[str, Any], board: Any) -> Dict[str, Any]:
        key = str(scout_report.get("key") or "")
        findings = scout_report.get("findings") or []
        hypothesis: Optional[Dict[str, Any]] = None
        try:
            from ..investigator.hypothesis import form_hypothesis  # type: ignore
            hypothesis = form_hypothesis(findings)
            if isinstance(hypothesis, dict):
                hypothesis.setdefault("engine", "investigator.form_hypothesis")
        except Exception:  # noqa: BLE001 - fallback is the standalone path
            hypothesis = None
        if not hypothesis:
            hypothesis = _fallback_hypothesis(findings)
        hypothesis["agent"] = self.name
        hypothesis["findings_considered"] = len(findings)
        board.post(self.name, key, "hypothesis", hypothesis)
        return hypothesis
