"""Recon -> remediation coding workflow.

After a scan finishes, take the findings the neural engine (nn_engine)
ranks as most actionable and have an LLM draft, for each one:

  * a concrete fix (what to change and why), and
  * a regression test that fails while the weakness is present and
    passes once it is fixed.

Defensive by construction:
  * Input is the already-masked findings dump (show_secrets=False), and
    anything that still looks like a credential is redacted before it
    leaves the process.
  * The system prompt confines output to fixes and tests. It never asks
    for exploit code, and nothing here touches a target, signs a
    transaction, or executes generated code.
  * Output is written to files for a human to review. Nothing is applied.

The LLM is a pluggable provider, same gates for all of them:
  RECON_LLM_PROVIDER  "anthropic" (default) | "openai"
  anthropic: ANTHROPIC_API_KEY, optional RECON_LLM_MODEL
  openai   : RECON_LLM_BASE_URL (any OpenAI-compatible endpoint, including
             a self-hosted open-weights server), RECON_LLM_API_KEY (optional
             for local servers), RECON_LLM_MODEL (required)

CLI:  python -m app.remediation <run_id> [--min-score 40] [--limit 5]
                                          [--out remediation_out]
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

SYSTEM_PROMPT = (
    "You are a defensive security engineer. You are given one finding from "
    "an automated, detection-only reconnaissance scan of a system the "
    "operator owns or is authorized to assess. Respond with exactly two "
    "fenced blocks.\n"
    "1) ```fix``` - a concise, concrete remediation: what to change, where, "
    "and why it closes the weakness.\n"
    "2) ```python``` - a pytest regression test that fails while the "
    "weakness is present and passes once fixed, using only the finding's "
    "own evidence. Read-only checks; no network calls to third parties.\n"
    "Never produce exploit code, payloads, credential use, or steps to "
    "attack a system. If the finding cannot be fixed or tested without "
    "that, say so inside the fix block instead."
)

# Credential-shaped strings are redacted even from masked rows (defence in
# depth: evidence blobs sometimes carry raw tokens).
_REDACT = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b0x[0-9a-fA-F]{64}\b"),  # raw 32-byte keys / hashes
]


def redact(text: str) -> str:
    for rx in _REDACT:
        text = rx.sub("[REDACTED]", text)
    return text


def nn_score(row: Dict[str, Any]) -> int:
    ev = row.get("evidence")
    nn = ev.get("nn") if isinstance(ev, dict) else None
    try:
        return int(nn["score"]) if nn else -1
    except (KeyError, TypeError, ValueError):
        return -1


def select_queue(rows: List[Dict[str, Any]], min_score: int = 40,
                 limit: int = 5) -> List[Dict[str, Any]]:
    """Top findings by neural score, at or above ``min_score``.

    Rows without a score (engine unavailable) are skipped rather than
    guessed at. Informational findings never enter the queue.
    """
    ranked = []
    for r in rows:
        ev = r.get("evidence") if isinstance(r.get("evidence"), dict) else {}
        if str(ev.get("severity", "")).lower() == "info":
            continue
        s = nn_score(r)
        if s >= min_score:
            ranked.append((s, r))
    ranked.sort(key=lambda t: -t[0])
    return [r for _, r in ranked[:max(0, limit)]]


def build_prompt(row: Dict[str, Any]) -> str:
    ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    keep = {k: ev[k] for k in ("severity", "remediation", "attacker_impact",
                               "reason", "scope_note") if k in ev}
    payload = {
        "plugin": row.get("plugin"), "category": row.get("category"),
        "key": row.get("key"), "value": row.get("value"),
        "source": row.get("source"), "confidence": row.get("confidence"),
        "neural_score": nn_score(row), "evidence": keep,
    }
    return redact(json.dumps(payload, default=str, indent=2)[:6000])


# ---------------------------------------------------------------- providers

Completer = Callable[[str, str], str]  # (system, user) -> text


def _anthropic(system: str, user: str) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    r = httpx.post(
        "https://api.anthropic.com/v1/messages", timeout=120,
        headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
        json={"model": os.environ.get("RECON_LLM_MODEL", "claude-sonnet-5-5"),
              "max_tokens": 2000, "system": system,
              "messages": [{"role": "user", "content": user}]})
    r.raise_for_status()
    return "".join(b.get("text", "") for b in r.json().get("content", []))


def _openai(system: str, user: str) -> str:
    base = os.environ.get("RECON_LLM_BASE_URL", "").rstrip("/")
    model = os.environ.get("RECON_LLM_MODEL", "")
    if not base or not model:
        raise RuntimeError("RECON_LLM_BASE_URL and RECON_LLM_MODEL are required")
    headers = {}
    if os.environ.get("RECON_LLM_API_KEY"):
        headers["Authorization"] = "Bearer " + os.environ["RECON_LLM_API_KEY"]
    r = httpx.post(base + "/chat/completions", timeout=120, headers=headers,
                   json={"model": model, "max_tokens": 2000,
                         "messages": [{"role": "system", "content": system},
                                      {"role": "user", "content": user}]})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def get_completer() -> Completer:
    name = os.environ.get("RECON_LLM_PROVIDER", "anthropic").lower()
    if name == "anthropic":
        return _anthropic
    if name == "openai":
        return _openai
    raise RuntimeError(f"unknown RECON_LLM_PROVIDER {name!r}")


# ----------------------------------------------------------------- pipeline

_BLOCK = re.compile(r"```(\w+)\s*\n(.*?)```", re.S)


def parse_response(text: str) -> Dict[str, str]:
    blocks = {m.group(1).lower(): m.group(2).strip()
              for m in _BLOCK.finditer(text or "")}
    return {"fix": blocks.get("fix", ""), "test": blocks.get("python", "")}


def run_pipeline(rows: List[Dict[str, Any]], complete: Optional[Completer] = None,
                 min_score: int = 40, limit: int = 5) -> List[Dict[str, Any]]:
    """Draft a fix + regression test for each queued finding."""
    complete = complete or get_completer()
    results = []
    for row in select_queue(rows, min_score, limit):
        item = {"id": row.get("id"), "key": row.get("key"),
                "plugin": row.get("plugin"), "score": nn_score(row)}
        try:
            parsed = parse_response(complete(SYSTEM_PROMPT, build_prompt(row)))
            item.update(parsed)
            item["status"] = "drafted" if parsed["fix"] and parsed["test"] \
                else "incomplete"
        except Exception as exc:  # one bad finding must not stop the batch
            item.update(status="error", error=str(exc)[:200])
        results.append(item)
    return results


def write_results(results: List[Dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for r in results:
        stem = f"{r['score']:03d}_{re.sub(r'[^A-Za-z0-9_-]', '_', str(r['key']))}_{r['id']}"
        (out_dir / f"{stem}.fix.md").write_text(r.get("fix", ""))
        if r.get("test"):
            (out_dir / f"test_{stem}.py").write_text(r["test"] + "\n")
    (out_dir / "index.json").write_text(json.dumps(
        [{k: v for k, v in r.items() if k not in ("fix", "test")}
         for r in results], indent=2))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("run_id")
    ap.add_argument("--min-score", type=int, default=40)
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--out", default="remediation_out")
    a = ap.parse_args(argv)
    from .models import get_session
    from .reporting import findings_dump
    session = get_session()
    try:
        rows = findings_dump(session, a.run_id, show_secrets=False)
    finally:
        session.close()
    results = run_pipeline(rows, min_score=a.min_score, limit=a.limit)
    write_results(results, Path(a.out))
    for r in results:
        print(f"{r['score']:>3}  {r['status']:<10} {r['key']}")
    print(f"{len(results)} drafted to {a.out}/ - review before applying.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
