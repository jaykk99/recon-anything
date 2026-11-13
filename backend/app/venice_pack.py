"""Venice analysis pack builder (keyless, backend-only).

Honest finding, checked 2026-11-12 against Venice's own docs and
public listings: there is NO free keyless programmatic way to call
Venice. The API needs either

  * an API key (``Authorization: Bearer $VENICE_API_KEY``), or
  * x402 per-request USDC payment from a crypto wallet (no key, no
    signup, but real money per call -- see docs.venice.ai x402).

The free tier is web chat only: venice.ai as a guest gives ~10 text
prompts/day on base models with a ~2,000-token context window, no
account needed. That chat is a browser UI with no public endpoint;
driving it from the backend would be scraping the web app to dodge
the API's auth, so this module does not do that.

What this module does instead -- the keyless path that actually
works: it turns a completed run into a complete, self-contained
analysis pack (findings + the heuristic advisor's ranked candidates
+ optional repo code excerpts) sized to fit the free guest chat's
~2k-token window. The operator pastes the pack into venice.ai,
picks ``venice-uncensored-1-2`` (Venice Uncensored 1.2, verified
live via GET /models on 2026-11-12), and Venice writes the
plain-English attack-path analysis. The backend does the hard work
(ranking, evidence); Venice does the synthesis; no key, no cost,
no network call from this module at all.

Detection only: the pack instructs the model to describe findings
in plain English (what an attacker could do, why it matters, what
to check next). It must not ask for executable exploit code or
instructions to take funds.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional

# Suggested model for the paste-in step, verified live 2026-11-12.
SUGGESTED_MODEL = "venice-uncensored-1-2"
# Free guest chat is ~2,000 tokens of context. Default pack budget
# leaves room for the model's answer (~1,500 tokens of pack).
DEFAULT_MAX_CHARS = 6000

_INSTRUCTIONS = (
    "You are a security analyst reviewing a detection-only recon scan. "
    "For each candidate below, explain in plain English: (1) what an "
    "attacker could do with it, (2) why it matters, (3) what to check "
    "next to confirm it. Detection only: do NOT write executable "
    "exploit code, do NOT give instructions to take funds or access "
    "accounts that are not the reviewer's own, and do NOT invent "
    "findings beyond the evidence listed."
)


def _truncate(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def collect_repo_context(paths: List[str], max_chars: int = 2000) -> List[Dict]:
    """Read the given repo files into pack-ready excerpts.

    The caller picks the files (the "scrape the repo" step); nothing
    here walks a repo on its own. Missing/unreadable files are skipped
    silently. Each excerpt is truncated to fit the shared budget.
    """
    out: List[Dict] = []
    remaining = max_chars
    for path in paths or []:
        if remaining <= 0:
            break
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, ValueError):
            continue
        per_file = min(len(text), remaining)
        out.append({"path": path, "excerpt": _truncate(text, per_file)})
        remaining -= per_file
    return out


def _append_block(lines: List[str], block: str, budget_left: int) -> int:
    """Append a block if it fits; truncate it if it almost fits."""
    if budget_left <= 0:
        return budget_left
    if len(block) + 1 <= budget_left:
        lines.append("")
        lines.append(block)
        return budget_left - len(block) - 1
    if budget_left > 80:
        # Keep the block's heading, cut its body.
        cut = _truncate(block, budget_left - 1)
        lines.append("")
        lines.append(cut)
        return 0
    return budget_left


def build_pack(candidates: List[Dict], findings: Optional[List[Dict]] = None,
               run_summary: Optional[Dict] = None,
               code_context: Optional[List[Dict]] = None,
               max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """Build the paste-ready Venice analysis pack (markdown).

    ``candidates`` is the heuristic advisor's ranked list (see
    ``app.vuln_advisor.advise``). ``findings`` adds raw evidence for
    the top candidates. ``code_context`` is a list of {"path",
    "excerpt"} dicts, e.g. from :func:`collect_repo_context`. The
    pack is hard-capped at ``max_chars`` so it fits the free guest
    chat's context window. Assembly is budget-aware and keeps the
    most important content first: header, then candidates in rank
    order, then instructions, then raw findings, then code excerpts.
    """
    header_lines = [
        "# ReconAnything analysis pack",
        "",
        "Paste into venice.ai guest chat (no account needed, ~10 free "
        f"text prompts/day). Suggested model: `{SUGGESTED_MODEL}`.",
    ]
    targets = (run_summary or {}).get("targets") or []
    if targets:
        first = targets[0]
        target = first.get("normalized") or first.get("raw") \
            if isinstance(first, dict) else str(first)
        header_lines.append(f"Target: {target}")

    cand_blocks: List[str] = []
    if candidates:
        for cand in candidates:
            parts = [
                f"### {cand.get('id')} -- {cand.get('name')} "
                f"[{cand.get('severity')}, confidence "
                f"{cand.get('confidence')}%]",
                "",
                f"Why viable: {cand.get('why_viable') or ''}",
                "",
                f"Confidence basis: {cand.get('confidence_basis') or ''}; "
                f"needs manual verification: "
                f"{cand.get('needs_manual_verification')}",
            ]
            for ref in (cand.get("evidence_refs") or [])[:3]:
                parts.append(
                    f"- evidence: {ref.get('plugin')}/{ref.get('key')}: "
                    f"{_truncate(str(ref.get('value') or ''), 120)}")
            cand_blocks.append("\n".join(parts))
    else:
        cand_blocks.append(
            "## Ranked candidates\n\nNone. The scan produced no advisor "
            "candidates.")

    instructions_block = "## Instructions for the model\n\n" + _INSTRUCTIONS
    short_instructions = (
        "## Instructions for the model\n\nAnalyze each candidate: what "
        "could an attacker do, why it matters, what to check next. "
        "Detection only: no exploit code, no fund-taking instructions.")

    findings_block = ""
    if findings:
        parts = ["## Raw findings (top evidence)", ""]
        for f in findings[:10]:
            parts.append(
                f"- {f.get('plugin')}/{f.get('key')}: "
                f"{_truncate(str(f.get('value') or ''), 140)}")
        findings_block = "\n".join(parts)

    code_blocks: List[str] = []
    for item in code_context or []:
        code_blocks.append(
            "## Repo code excerpts\n\n"
            f"### {item.get('path')}\n\n```\n"
            f"{item.get('excerpt') or ''}\n```")

    lines: List[str] = list(header_lines)
    budget_left = max_chars - len("\n".join(lines))
    # Candidates first: they are the content that matters most.
    for block in cand_blocks:
        budget_left = _append_block(lines, block, budget_left)
    if budget_left > len(instructions_block):
        budget_left = _append_block(lines, instructions_block, budget_left)
    elif budget_left > len(short_instructions):
        budget_left = _append_block(lines, short_instructions, budget_left)
    if findings_block:
        budget_left = _append_block(lines, findings_block, budget_left)
    for block in code_blocks:
        budget_left = _append_block(lines, block, budget_left)

    pack = "\n".join(lines)
    if len(pack) > max_chars:
        pack = pack[: max(0, max_chars - 3)].rstrip() + "..."
    return pack


def pack_size_note(pack: str) -> str:
    """One-line size note for the pack (chars + rough token estimate)."""
    return (f"Pack is {len(pack)} chars (~{len(pack) // 4} tokens). "
            "Free guest chat fits ~2,000 tokens total, so keep the "
            "model's reply short.")
