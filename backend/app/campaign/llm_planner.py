"""Optional model-assisted planning that cannot widen scope.

The deterministic planner remains the source of truth. When a model is
configured it receives a compact situation report and may propose
intents; every proposal is parsed as data and validated against the
action catalog, the campaign scope, the attempt ledger and the approval
rules. Invalid proposals are dropped with a reason. A transport or JSON
error falls back to the deterministic plan for that round - it never
aborts a campaign.

No target body ever enters the prompt: titles, targets, tags and the
action catalog only.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .. import exploit_probes
from .models import Intent
from .planner import CONSOLE_ACTIONS
from .scope import Scope

ENV_URL = "RECON_CAMPAIGN_LLM_URL"
ENV_MODEL = "RECON_CAMPAIGN_LLM_MODEL"
ENV_KEY = "RECON_CAMPAIGN_LLM_API_KEY"

SYSTEM_PROMPT = (
    "You plan authorized, read-only security verification. Reply with "
    "JSON only: {\"intents\": [...]}. Never propose writes, deletion, "
    "credential use, authentication replay or exploit payloads."
)


def default_llm() -> Optional[Callable[[str], str]]:
    """An OpenAI-compatible chat callable, or None when unconfigured."""
    url = (os.environ.get(ENV_URL) or "").strip()
    if not url:
        return None
    model = (os.environ.get(ENV_MODEL) or "").strip() or "gpt-4o-mini"
    key = (os.environ.get(ENV_KEY) or "").strip()

    def call(prompt: str) -> str:
        payload = {
            "model": model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        headers = {"content-type": "application/json"}
        if key:
            headers["authorization"] = f"Bearer {key}"
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        return str(data["choices"][0]["message"]["content"])

    return call


def action_catalog() -> Dict[str, List[str]]:
    """Everything a model is allowed to ask for, by worker kind."""
    return {
        "recon": ["surface"],
        "probe": sorted(exploit_probes.PROBES),
        "impact": [f"enumerate:{c}" for c in sorted(CONSOLE_ACTIONS)],
        "verify": ["bucket-list"],
    }


def _strip_fences(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines)
    start, end = t.find("{"), t.rfind("}")
    if start >= 0 and end > start:
        t = t[start:end + 1]
    return t.strip()


def _situation(graph, scope: Scope, goals: Sequence[str],
               pending, limit: int) -> str:
    targets = ([a["value"] for a in graph.assets_of("url")]
               + [a["value"] for a in graph.assets_of("host")])
    findings = [
        {"target": f.get("target"), "title": f.get("title"),
         "severity": f.get("severity"), "tags": f.get("tags")}
        for f in graph.confirmed_findings()[:15]
    ]
    return json.dumps({
        "goals": list(goals),
        "authorized_hosts": list(scope.roots),
        "targets": sorted(set(targets))[:20],
        "already_attempted": sorted(graph.attempted_keys())[-60:],
        "pending_approval": sorted(pending),
        "confirmed_findings": findings,
        "allowed_actions": action_catalog(),
        "rules": [
            "target must be one of targets or authorized_hosts",
            "kind must be recon | probe | impact | verify",
            "action must appear in allowed_actions[kind]",
            "impact intents are approval-gated and cannot be self-approved",
            f"return at most {limit} intents",
        ],
    }, indent=2)


def _intent_from_row(row: Any, scope: Scope, graph, pending) -> Tuple[Optional[Intent], str]:
    if not isinstance(row, dict):
        return None, "not an object"
    kind = str(row.get("kind") or "").strip().lower()
    catalog = action_catalog()
    if kind not in catalog:
        return None, f"unknown kind {kind!r}"
    action = str(row.get("action") or "").strip()
    if action not in catalog[kind]:
        return None, f"action {action!r} is not allowed for {kind}"
    target = str(row.get("target") or "").strip()
    if not target:
        return None, "missing target"
    if "://" not in target:
        target = "https://" + target
    allowed, reason = scope.allows(target)
    if not allowed:
        return None, reason
    try:
        priority = int(row.get("priority") or 50)
    except (TypeError, ValueError):
        priority = 50
    why = [str(x) for x in (row.get("why") or [])
           if str(x) in graph.findings or str(x) in graph.assets]
    intent = Intent(
        kind=kind, action=action, target=target,
        goal=str(row.get("goal") or kind),
        why=why,
        requires_approval=(kind == "impact"),
        cost=2 if kind == "impact" else 1,
        priority=max(1, min(99, priority)),
        meta={"console": action.split(":", 1)[1]} if kind == "impact" else {},
    )
    if intent.key in graph.attempted_keys() or intent.key in pending:
        return None, "already attempted or pending"
    return intent, ""


def propose_intents(llm: Optional[Callable[[str], str]], graph, scope: Scope,
                    goals: Sequence[str], *, limit: int = 8,
                    pending: Sequence[str] = ()) -> Tuple[List[Intent], Dict[str, Any]]:
    """Ask the model for intents; return validated ones plus a report."""
    pending_set = set(pending or ())
    if llm is None:
        return [], {"enabled": False, "proposed": 0, "accepted": 0,
                    "dropped": []}
    meta: Dict[str, Any] = {"enabled": True, "proposed": 0,
                            "accepted": 0, "dropped": []}
    try:
        raw = llm(_situation(graph, scope, goals, pending_set, limit))
    except Exception as exc:  # a model failure never kills the campaign
        meta["error"] = f"model call failed: {str(exc)[:200]}"
        return [], meta
    try:
        data = json.loads(_strip_fences(raw))
    except (TypeError, ValueError):
        meta["error"] = "model returned invalid JSON"
        return [], meta
    rows = data.get("intents") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        meta["error"] = "model returned no intents list"
        return [], meta

    meta["proposed"] = len(rows)
    out: List[Intent] = []
    seen = set()
    for row in rows[:max(1, limit) * 2]:
        intent, reason = _intent_from_row(row, scope, graph, pending_set)
        if intent is None:
            meta["dropped"].append(reason)
            continue
        if intent.key in seen:
            continue
        seen.add(intent.key)
        out.append(intent)
    meta["accepted"] = len(out)
    return out[:limit], meta


def merge(deterministic: Sequence[Intent], proposed: Sequence[Intent],
          *, limit: int) -> List[Intent]:
    """Chained work first, then the model's picks, then the rest."""
    det = list(deterministic)
    model = list(proposed)
    ordered = ([i for i in det if i.kind == "impact"]
               + [i for i in model if i.kind == "impact"]
               + [i for i in model if i.kind != "impact"]
               + [i for i in det if i.kind != "impact"])
    out: List[Intent] = []
    seen = set()
    for intent in ordered:
        if intent.key in seen:
            continue
        seen.add(intent.key)
        out.append(intent)
        if len(out) >= limit:
            break
    return out
