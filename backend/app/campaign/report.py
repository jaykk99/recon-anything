"""Report rendering for a finished campaign.

The report is the handoff: what was proven, with the receipt that proves
it, ordered by kill-chain stage, plus exactly what the campaign would do
next if it were allowed to continue. It never upgrades a lead into a
verdict: anything without a captured response is labelled unconfirmed.
"""
from __future__ import annotations

from typing import Any, Dict, List

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev(f: Dict[str, Any]) -> int:
    return _SEV_RANK.get(str(f.get("severity") or "").lower(), 5)


def render(result: Dict[str, Any]) -> str:
    lines: List[str] = []
    add = lines.append

    add(f"# Campaign report: {result.get('objective') or '(no objective)'}")
    add("")
    add(f"- Campaign: `{result.get('id', '')}`")
    add(f"- Status: **{result.get('status', 'unknown')}**")
    add(f"- Why it stopped: {result.get('reason', '')}")
    add(f"- Goals: {', '.join(result.get('goals') or []) or '(none)'}")
    scope = result.get("scope") or {}
    add(f"- Scope roots: {', '.join(scope.get('roots') or []) or '(none)'}")
    add(f"- Active probing: {scope.get('allow_active')} · "
        f"impact enumeration: {scope.get('allow_exploit_confirm')} · "
        f"token replay: {scope.get('allow_auth_replay')}")
    budget = result.get("budget") or {}
    add(f"- Budget: {budget.get('requests_used', 0)}/"
        f"{budget.get('max_requests')} requests, "
        f"{budget.get('intents_used', 0)}/{budget.get('max_intents')} intents, "
        f"{budget.get('elapsed_s', 0)}s of {budget.get('max_seconds')}s")
    ev = result.get("evidence") or {}
    if ev.get("entries"):
        add(f"- Evidence archive: {ev['entries']} exchange(s), "
            f"{ev.get('bytes', 0)} bytes captured (body cap "
            f"{ev.get('body_cap', 0)} bytes)")
    llm = result.get("llm") or {}
    if llm.get("enabled"):
        rounds = llm.get("rounds") or []
        accepted = sum(int(r.get("accepted") or 0) for r in rounds)
        dropped = sum(len(r.get("dropped") or []) for r in rounds)
        add(f"- Planner: model-assisted ({accepted} accepted, "
            f"{dropped} dropped by validation)")
    add("")

    summary = result.get("summary") or {}
    add("## What was proven")
    add("")
    add(f"- {summary.get('confirmed_findings', 0)} confirmed finding(s) with "
        f"{summary.get('evidence_receipts', 0)} captured receipt(s)")
    add(f"- {summary.get('assets', 0)} asset(s), "
        f"{summary.get('attempts', 0)} attempt(s), "
        f"{summary.get('edges', 0)} graph edge(s)")
    by_sev = summary.get("confirmed_by_severity") or {}
    if by_sev:
        add("- By severity: " + ", ".join(
            f"{k} {v}" for k, v in sorted(by_sev.items(),
                                          key=lambda kv: _SEV_RANK.get(kv[0], 5))))
    add("")

    add("## Kill chain")
    add("")
    add("| stage | reached | strongest evidence |")
    add("|---|---|---|")
    for stage in result.get("kill_chain") or []:
        top = (stage.get("findings") or [{}])[0]
        detail = top.get("title") or ", ".join(stage.get("assets") or [])[:90] \
            or "-"
        add(f"| {stage.get('stage')} | {'yes' if stage.get('reached') else 'no'} "
            f"| {detail} |")
    add("")

    findings = [f for f in (result.get("graph") or {}).get("findings", {}).values()
                if f.get("confirmed")]
    findings.sort(key=lambda f: (_sev(f), -int(f.get("confidence") or 0)))
    add("## Confirmed findings, ranked")
    add("")
    if not findings:
        add("_No condition was confirmed in this campaign._")
    for i, f in enumerate(findings[:25], 1):
        tags = ", ".join(f.get("tags") or [])
        add(f"### {i}. [{f.get('severity', '?')}] {f.get('title')}")
        add("")
        add(f"- Target: `{f.get('target')}`")
        add(f"- Confidence: {f.get('confidence')}% · stage: {f.get('stage')}"
            + (f" · tags: {tags}" if tags else ""))
        add(f"- Action: `{f.get('action')}`")
        if f.get("detail"):
            add(f"- Detail: {f['detail'][:500]}")
        ev = f.get("evidence") or {}
        if ev.get("request"):
            add(f"- Receipt: `{ev.get('request')}` -> "
                f"{ev.get('status')} (sha256 `{(ev.get('body_sha256') or '')[:16]}`)")
            excerpt = (ev.get("body_excerpt") or "").strip().replace("\n", " ")
            if excerpt:
                add(f"- Captured: `{excerpt[:240]}`")
        add("")

    retests = result.get("retests") or []
    if retests:
        add("## Retests")
        add("")
        for r in retests:
            add(f"- `{r.get('finding_id', '')}` — **{r.get('verdict', '?')}** "
                f"({r.get('reason', '')})")
        add("")

    add("## Evidence receipts")
    add("")
    seen = 0
    for attempt in (result.get("graph") or {}).get("attempts", {}).values():
        for ev in attempt.get("evidence") or []:
            if not ev.get("request"):
                continue
            seen += 1
            if seen > 20:
                break
            add(f"- `{ev.get('request')}` -> {ev.get('status')} "
                f"sha256 `{(ev.get('body_sha256') or '')[:16]}` "
                f"({attempt.get('action')})")
            if ev.get("note"):
                add(f"  - {ev['note']}")
    if not seen:
        add("_No receipts were captured._")
    add("")

    pending = result.get("pending_approval") or []
    if pending:
        add("## Awaiting approval")
        add("")
        for it in pending:
            add(f"- `{it.get('action')}` on `{it.get('target')}` "
                f"(why: {', '.join(it.get('why') or []) or 'planned action'})")
        add("")
        add("Approve them with the campaign approve action, then resume the "
            "campaign: the graph and budget carry forward, so nothing "
            "already done is repeated.")
        add("")

    next_actions = result.get("next_actions") or []
    if next_actions:
        add("## What the planner would do next")
        add("")
        for it in next_actions:
            add(f"- {it.get('kind')}: `{it.get('action')}` on "
                f"`{it.get('target')}`")
        add("")

    add("## Boundaries")
    add("")
    add(result.get("boundary") or "")
    add("")
    add("_Detection and read-only confirmation only. A confirmed finding "
        "means the condition was observed, not that a payload was fired._")
    return "\n".join(lines) + "\n"
