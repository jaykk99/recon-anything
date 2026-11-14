"""LLM enrichment for heuristic advisor candidates + investigator hypotheses.

Fail-soft by design: any LLM failure leaves the heuristic candidates
untouched and records the error, so the advisor never breaks a run.
Enrichment NEVER changes ``verified`` / ``needs_manual_verification`` /
confidence: the LLM reasons, it does not prove. Only a live read-only
probe (safe_tester) or a human can do that.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from . import prompts
from .client import chat


def enrich_candidates(candidates: List[Dict], findings: List[Dict],
                      max_candidates: int = 3,
                      max_tokens: int = 600) -> List[Dict]:
    """Add ``llm_analysis`` to the top candidates (in place, also returned).

    Per candidate: plain-English explanation + the read-only check that
    would confirm/kill it, from the live model. One extra call ranks
    all findings first so the explanation order follows the model's
    ranking, not just severity. Total calls: 1 + up to max_candidates.
    On any failure the candidate keeps ``llm_analysis: None`` plus an
    ``llm_error`` note. Never raises.
    """
    out = list(candidates or [])
    if not out:
        return out
    ranking = None
    try:
        text, model, _tried = chat(
            [{"role": "system", "content": prompts.SYSTEM},
             {"role": "user", "content": prompts.rank_findings_prompt(findings[:12])}],
            max_tokens=max_tokens)
        ranking = {"text": text, "model": model}
    except Exception as e:  # noqa: BLE001 - enrichment is optional
        ranking = {"error": str(e)[:200]}
    for cand in out[:max_candidates]:
        entry: Dict = {"ranking": ranking}
        try:
            text, model, _tried = chat(
                [{"role": "system", "content": prompts.SYSTEM},
                 {"role": "user",
                  "content": prompts.explain_candidate_prompt(cand)}],
                max_tokens=300)
            entry.update({"explanation": text, "model": model})
        except Exception as e:  # noqa: BLE001
            entry["error"] = str(e)[:200]
        cand["llm_analysis"] = entry
    for cand in out[max_candidates:]:
        cand.setdefault("llm_analysis", None)
    return out


def draft_detector(candidate: Dict, max_tokens: int = 600) -> Dict:
    """Ask the model for a stdlib-only detector for one candidate.

    Returns {"code": str|None, "model": str|None, "error": str|None}.
    The code is returned as text only: callers must syntax-check it
    (compile()) and run it in a sandbox before trusting it. Never raises.
    """
    text: str | None = None
    try:
        text, model, _tried = chat(
            [{"role": "system", "content": prompts.SYSTEM},
             {"role": "user", "content": prompts.detector_prompt(candidate)}],
            max_tokens=max_tokens)
        code = text
        if "```" in code:
            parts = code.split("```")
            code = parts[1] if len(parts) > 1 else code
            code = code.replace("python", "", 1).strip()
        compile(code, "<llm-detector>", "exec")
        return {"code": code, "model": model, "error": None}
    except SyntaxError as e:
        return {"code": text, "model": None,
                "error": f"detector did not compile: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"code": None, "model": None, "error": str(e)[:200]}


def stress_hypothesis(hypothesis: Dict, max_tokens: int = 400) -> Dict:
    """Second opinion on an investigator-loop hypothesis (PR #177).

    Returns {"text": str|None, "model": str|None, "error": str|None}.
    The hypothesis dict is returned unchanged; this only adds the
    model's stress-test. Never marks anything verified. Never raises.
    """
    try:
        text, model, _tried = chat(
            [{"role": "system", "content": prompts.SYSTEM},
             {"role": "user",
              "content": prompts.hypothesis_prompt(hypothesis)}],
            max_tokens=max_tokens)
        return {"text": text, "model": model, "error": None}
    except Exception as e:  # noqa: BLE001
        return {"text": None, "model": None, "error": str(e)[:200]}
