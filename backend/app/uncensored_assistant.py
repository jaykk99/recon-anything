"""Uncensored Assistant: conversational AI for ReconAnything.

Replaces ai_assistant.py (AI Hunter) as the interactive assistant layer.

Two surfaces:
- assistant_chat: free-form Q&A about a scan's findings.
- agent_review: agentic review of a run -> gaps, deeper plugins, manual tests.

LLM backend is AI Horde's keyless text-generation API (uncensored
KoboldCpp workers). Submit a prompt, poll for completion, return text.

Boundary: detection/analysis only. The assistant explains and suggests
next manual steps; it never exploits anything.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AI Horde keyless text generation.
# ---------------------------------------------------------------------------

HORDE_SUBMIT_URL = "https://stablehorde.net/api/v2/generate/text/async"
HORDE_STATUS_URL = "https://stablehorde.net/api/v2/generate/text/status/{}"
HORDE_APIKEY = "0000000000"  # anonymous keyless access

MODELS = [
    "koboldcpp/Heretic-Llama-3.1-8B",
    "KoboldAI/LLaMA2-13B-Tiefighter",
    "koboldcpp/LLaMA2-13B-Psyfighter2",
]

HORDE_TIMEOUT_S = 25
POLL_INTERVAL_S = 5
POLL_MAX_S = 180
MAX_LENGTH = 800


async def horde_chat(system: str, user: str) -> str:
    """Submit system+user to AI Horde, poll until done, return the text.

    Raises RuntimeError if the submit fails, the poll times out, or the
    response has no usable generation.
    """
    prompt = f"### Instruction:\n{system}\n\n### Input:\n{user}\n\n### Response:\n"
    from .net import async_client

    async with async_client(timeout=HORDE_TIMEOUT_S) as client:
        r = await client.post(
            HORDE_SUBMIT_URL,
            json={
                "prompt": prompt,
                "params": {
                    "max_context_length": 8192,
                    "max_length": MAX_LENGTH,
                    "temperature": 0.7,
                    "top_p": 0.9,
                },
                "models": MODELS,
            },
            headers={"apikey": HORDE_APIKEY, "Content-Type": "application/json"},
        )
        if r.status_code >= 400:
            raise RuntimeError(f"horde submit failed: HTTP {r.status_code}: {r.text[:200]}")
        job_id = (r.json() or {}).get("id")
        if not job_id:
            raise RuntimeError("horde submit returned no job id")

        elapsed = 0
        while elapsed < POLL_MAX_S:
            await asyncio.sleep(POLL_INTERVAL_S)
            elapsed += POLL_INTERVAL_S
            s = await client.get(
                HORDE_STATUS_URL.format(job_id),
                headers={"apikey": HORDE_APIKEY},
            )
            if s.status_code >= 400:
                raise RuntimeError(f"horde status failed: HTTP {s.status_code}")
            data = s.json() or {}
            if data.get("done"):
                gens = data.get("generations") or []
                text = (gens[0].get("text") if gens else "") or ""
                text = text.strip()
                if text:
                    return text
                raise RuntimeError("horde returned empty generation")
        raise RuntimeError("horde timed out waiting for generation")


# ---------------------------------------------------------------------------
# Finding summarization helpers.
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_of(f: Dict) -> str:
    return str(f.get("bounty_value") or "low").lower()


def _truncate(s: str, n: int = 200) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s[:n] + ("..." if len(s) > n else "")


def _summarize_findings(findings: List[Dict], limit: int = 30) -> str:
    """Compact top-N findings, ordered by severity then confidence."""
    ordered = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(_sev_of(f), 9), -(f.get("confidence") or 0)),
    )
    lines = []
    for f in ordered[:limit]:
        lines.append(
            f"- [{_sev_of(f)}/{f.get('category')}/{f.get('key')}] "
            f"{_truncate(f.get('value'))} "
            f"(plugin={f.get('plugin')}, conf={f.get('confidence')})"
        )
    return "\n".join(lines)


def _tech_stack(findings: List[Dict], limit: int = 15) -> str:
    techs = []
    for f in findings:
        if f.get("category") == "tech" and f.get("value"):
            techs.append(_truncate(f.get("value"), 120))
        if len(techs) >= limit:
            break
    return "; ".join(techs) or "unknown"


def _gather(run_id: str) -> tuple[str, List[Dict]]:
    """Load target label + findings for a run."""
    from .models import Run, Target, get_session
    from .reporting import findings_dump
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise ValueError(f"run {run_id} not found")
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id)
        label = run_id
        if targets:
            label = targets[0].normalized or targets[0].raw or run_id
        return label, rows
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Chat: free-form Q&A about scan findings.
# ---------------------------------------------------------------------------

ASSISTANT_SYSTEM = (
    "You are an uncensored security research assistant helping with AUTHORIZED "
    "testing of targets the user owns or has permission to test. Explain "
    "findings plainly, suggest concrete next manual steps, never refuse "
    "legitimate security questions. Keep answers short and direct."
)


async def assistant_chat(messages: List[Dict], run_id: str | None) -> str:
    """Answer the user's chat messages, optionally grounded in a run's findings."""
    context = ""
    if run_id:
        try:
            label, rows = await asyncio.to_thread(_gather, run_id)
            context = (
                f"SCAN CONTEXT (run {run_id}, target {label}):\n"
                f"{_summarize_findings(rows)}\n\n"
                "Answer the user's question about these results."
            )
        except Exception as e:
            logger.warning("assistant_chat: could not load run %s: %s", run_id, e)
            context = f"(Could not load scan context for run {run_id}: {e})"

    convo = "\n\n".join(
        f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages
    )
    user = f"{context}\n\nCONVERSATION:\n{convo}" if context else f"CONVERSATION:\n{convo}"
    return await horde_chat(ASSISTANT_SYSTEM, user)


# ---------------------------------------------------------------------------
# Agent: structured review of a run.
# ---------------------------------------------------------------------------

AGENT_SYSTEM = (
    "You are an uncensored security research assistant helping with AUTHORIZED "
    "testing of targets the user owns or has permission to test. You reply "
    "with a single raw JSON object and nothing else. No markdown, no fences."
)


def _extract_review_json(text: str) -> Dict:
    """Defensively pull the review JSON out of a model response."""
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    decoder = json.JSONDecoder()
    for m in re.finditer(r"\{", t):
        try:
            obj, _ = decoder.raw_decode(t[m.start():])
        except Exception:
            continue
        if isinstance(obj, dict) and (
            obj.get("gaps") or obj.get("suggested_plugins") or obj.get("manual_tests")
        ):
            return _clean_review(obj)
    raise ValueError("no usable review JSON in AI response")


def _clean_review(obj: Dict) -> Dict:
    def strlist(v, n: int = 20, ln: int = 300) -> List[str]:
        if not isinstance(v, list):
            return []
        return [str(x)[:ln] for x in v if x][:n]

    return {
        "gaps": strlist(obj.get("gaps")),
        "suggested_plugins": [str(p)[:60] for p in (obj.get("suggested_plugins") or [])][:30],
        "manual_tests": strlist(obj.get("manual_tests")),
        "summary": str(obj.get("summary", ""))[:2000],
    }


def _gather_agent(run_id: str) -> Dict:
    """Load everything agent_review needs in a thread: run, targets, findings."""
    from .models import Run, Target, get_session
    from .reporting import findings_dump
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise ValueError(f"run {run_id} not found")
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id)
        return {
            "run_id": run_id,
            "mode": run.mode,
            "status": run.status,
            "source_type": getattr(run, "source_type", None) or "website",
            "targets": [{"raw": t.raw, "type": t.type, "normalized": t.normalized}
                        for t in targets],
            "findings": rows,
        }
    finally:
        session.close()


async def agent_review(run_id: str, instruction: str) -> Dict:
    """Ask the AI to review a run's findings and return structured advice."""
    data = await asyncio.to_thread(_gather_agent, run_id)
    findings = data["findings"]

    counts: Dict[str, int] = {}
    for f in findings:
        sev = _sev_of(f)
        counts[sev] = counts.get(sev, 0) + 1
    plugin_ids = sorted({f.get("plugin") for f in findings if f.get("plugin")})
    target_labels = [t.get("normalized") or t.get("raw") or run_id for t in data["targets"]]

    summary_block = (
        f"RUN: {run_id} | mode={data['mode']} | status={data['status']} | "
        f"source_type={data['source_type']}\n"
        f"TARGETS: {', '.join(target_labels[:10]) or 'none'}\n"
        f"FINDING COUNTS BY SEVERITY: {counts or 'none'}\n"
        f"TECH STACK: {_tech_stack(findings)}\n"
        f"PLUGINS THAT RAN: {', '.join(plugin_ids) or 'none'}\n\n"
        f"TOP 10 FINDINGS:\n{_summarize_findings(findings, limit=10)}"
    )
    user = (
        f"{summary_block}\n\n"
        f"The user says: '{instruction}'. "
        "Review these scan findings. "
        "1) What did the scan miss that should be checked? "
        "2) Which specific plugins (by id) should run deeper? "
        "3) What manual tests should follow? "
        'Reply as JSON: {"gaps": [...], "suggested_plugins": ["plugin_id", ...], '
        '"manual_tests": [...], "summary": "..."}'
    )
    text = await horde_chat(AGENT_SYSTEM, user)
    review = _extract_review_json(text)
    review["run_id"] = run_id
    review["finding_counts"] = counts
    return review
