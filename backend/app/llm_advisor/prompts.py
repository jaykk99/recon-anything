"""Prompts for the LLM advisor. Detection only, always.

Every prompt tells the model the same hard rules: findings are
UNVERIFIED until a live read-only probe proves otherwise, the model
never claims verification, never writes fund-moving exploit code, and
only proposes read-only detection checks. The advisor is a triage
brain, not a prover: the NN scorer ranks, the LLM reasons, the live
probe (or a human) decides.
"""
from __future__ import annotations

import json
from typing import Dict, List

SYSTEM = (
    "You are a smart-contract and web security researcher working "
    "detection-only for ReconAnything. Rules you never break: "
    "(1) every finding is UNVERIFIED until a live read-only probe proves "
    "it, and you never claim otherwise; "
    "(2) you only propose read-only detection checks (GET/HEAD/eth_call), "
    "never transactions, never fund movement, never exploit execution; "
    "(3) you write detection code, never exploit code; "
    "(4) be concrete: name the function, the check, and the exact evidence "
    "that would confirm or kill the finding. Keep answers short."
)


def _finding_lines(findings: List[Dict]) -> str:
    lines = []
    for f in findings:
        lines.append(json.dumps({
            "plugin": f.get("plugin"), "key": f.get("key"),
            "severity": f.get("severity"), "chain": f.get("chain"),
            "address": f.get("address"), "function": f.get("function"),
            "recipient_class": f.get("recipient_class"),
            "verdict": (f.get("validation") or {}).get("verdict"),
            "reason": (f.get("validation") or {}).get("reason"),
        }, default=str))
    return "\n".join(lines)


def rank_findings_prompt(findings: List[Dict]) -> str:
    """Rank real findings most-to-least promising, with missing evidence."""
    return (
        "Rank these REAL scanner findings (all UNVERIFIED) from most to "
        "least promising for a researcher, one line of reasoning each. "
        "For each, state exactly what evidence is missing and what single "
        "read-only check would confirm or kill it. Never claim any is "
        "verified.\n\n" + _finding_lines(findings))


def explain_candidate_prompt(candidate: Dict) -> str:
    """Plain-English explanation of one heuristic advisor candidate."""
    return (
        "In plain terms, under 120 words, explain this possible "
        "vulnerability to a non-technical owner: what it is, who could "
        "abuse it, and what damage it does. No code, no jargon without "
        "explaining it. The finding is UNVERIFIED: say what would prove "
        "it real.\n\n" + json.dumps({
            "name": candidate.get("name"), "severity": candidate.get("severity"),
            "confidence": candidate.get("confidence"),
            "why": candidate.get("why_viable"),
            "evidence": candidate.get("evidence_refs"),
        }, default=str))


def detector_prompt(candidate: Dict) -> str:
    """Ask for a small stdlib-only detector for the candidate's pattern."""
    return (
        "Write Python stdlib-only code, nothing else except a 1-line "
        "comment per function. Function detect(source: str) -> dict: "
        "given the source text of a contract or page, return "
        "{'flagged': bool, 'reason': str}. Flag True only for the pattern "
        "below, and only when no access-control guard is visible. The "
        "code must be syntactically valid and runnable. Pattern: "
        + str(candidate.get("name")) + ". Context: "
        + str(candidate.get("why_viable"))[:500])


def hypothesis_prompt(hypothesis: Dict) -> str:
    """Second-opinion on an investigator-loop hypothesis (PR #177 shape).

    The loop already built the story from static findings; the LLM
    stress-tests it: is the payout path coherent, what is the cheapest
    read-only check that kills it, and what is the most likely benign
    explanation? Never upgrades the hypothesis to verified.
    """
    return (
        "Stress-test this attack hypothesis from a scanner. Answer in 4 "
        "short bullets: (1) is the payout path coherent, yes/no and why; "
        "(2) the cheapest read-only check that would kill it; "
        "(3) the most likely benign explanation; "
        "(4) the next test to run, fork or live read-only probe. "
        "The hypothesis is UNVERIFIED: never call it confirmed.\n\n"
        + json.dumps(hypothesis, default=str)[:3000])
