"""Agent service: run investigation over a run's own findings, and the
chat tool loop.

Run findings are read in-process from the scan store (findings_dump,
secrets masked by default), so no service key and no separate host are
needed. A run's targets are authorized by the scan's scope gating at
run creation; the allowlist gates only the agent's NEW probes on
arbitrary URLs.
"""

from __future__ import annotations

import json

from ..models import Run, Target, get_session
from ..reporting import findings_dump
from . import allowlist as allow
from . import brain, composio, github as gh
from . import investigate as inv
from . import terminal as term
from .fetch import fetch_url
from .refusal import hard_block_reason, is_refusal
from .ssrf import SSRFBlocked

SYSTEM_PROMPT = """You are the ReconAnything agent, a defensive cybersecurity agent.
Detection only, on authorized targets only. Jay's own assets (jaykk99 repos, his
apps and domains) are pre-authorized; any other target needs an explicit
allowlist entry before you touch it. crypto.com is NEVER a target. You
never confirm exploits, brute-force, bypass auth, access private data,
look up people, display or steal keys or seeds, sweep wallets, or use
mixers. You never move money, post, message, or deploy without the user's
explicit tap. Secrets are never stored or printed in full. When you need
a tool, emit exactly one fenced block per tool call:

```tool_call
{"name": "fetch_url", "args": {"url": "https://example.com"}}
```

Available tools: fetch_url, run_terminal, agent_investigate_run,
investigate_target, verify_finding, expand_assets, github_search_repos,
github_search_code, github_read_file, composio_search, composio_execute,
allowlist_add. After tool results arrive, answer in plain language with
evidence and a fix for each finding.
"""

TOOL_DESCRIPTIONS = """
fetch_url(url): browser route fetch, SSRF-guarded, returns status/headers/snippet.
run_terminal(command): detection commands only (curl, dig, nslookup, whois, host, openssl s_client, python3 scripts).
agent_investigate_run(run_id): investigate a completed run's findings in-process: live re-verification plus the agent's own detectors on the run's targets.
investigate_target(url): the agent's own detectors on a target (headers, cookies, JS libs + OSV, exposed .git).
verify_finding(finding_json): re-check one finding live.
expand_assets(url): subdomains via crt.sh + linked hosts.
github_search_repos(query), github_search_code(query), github_read_file(owner, repo, path).
composio_search(query), composio_execute(tool_slug, arguments).
allowlist_add(host): authorize a new target host (owner only).
"""


def investigate_run(run_id: str, verify_limit: int = 20, target_limit: int = 3,
                    expand: bool = False) -> dict:
    """Investigate one run end to end. Raises ValueError if the run is missing."""
    session = get_session()
    try:
        run = session.query(Run).filter_by(id=run_id).first()
        if not run:
            raise ValueError(f"run {run_id} not found")
        targets = session.query(Target).filter_by(run_id=run_id).all()
        rows = findings_dump(session, run_id, show_secrets=False)
    finally:
        session.close()
    verified = []
    for f in rows:
        if f.get("source_url"):
            verified.append(inv.verify_finding(f))
        if len(verified) >= verify_limit:
            break
    added: list[dict] = []
    probed_targets: list[str] = []
    for t in targets[:target_limit]:
        url = t.normalized or t.raw or ""
        if not url.startswith(("http://", "https://")):
            continue
        probed_targets.append(url)
        res = inv.analyze_target(url)
        for a in res.get("added_findings", []):
            added.append({**a, "run_target": url})
    expanded = None
    if expand and probed_targets:
        expanded = inv.expand_assets(probed_targets[0])
    return {"run_id": run_id, "run_status": run.status,
            "run_mode": run.mode, "source_type": run.source_type,
            "targets": [t.normalized or t.raw for t in targets],
            "probed_targets": probed_targets,
            "findings_count": len(rows),
            "verified": verified, "added_findings": added,
            "expanded": expanded}


def _run_tool(name: str, args: dict) -> str:
    try:
        if name == "fetch_url":
            ok, why = allow.is_authorized(args.get("url", ""))
            if not ok:
                return f"Target not authorized: {why}"
            return json.dumps(fetch_url(args["url"]), default=str)[:4000]
        if name == "run_terminal":
            return json.dumps(term.run_terminal(args.get("command", "")))[:4000]
        if name == "agent_investigate_run":
            return json.dumps(investigate_run(
                args["run_id"], verify_limit=int(args.get("verify_limit", 20)),
                target_limit=int(args.get("target_limit", 3)),
                expand=bool(args.get("expand", False))), default=str)[:8000]
        if name == "investigate_target":
            ok, why = allow.is_authorized(args.get("url", ""))
            if not ok:
                return f"Target not authorized: {why}"
            return json.dumps(inv.analyze_target(args["url"]), default=str)[:6000]
        if name == "verify_finding":
            f = args.get("finding_json", {})
            if isinstance(f, str):
                f = json.loads(f)
            return json.dumps(inv.verify_finding(f), default=str)[:3000]
        if name == "expand_assets":
            ok, why = allow.is_authorized(args.get("url", ""))
            if not ok:
                return f"Target not authorized: {why}"
            return json.dumps(inv.expand_assets(args["url"]), default=str)[:4000]
        if name == "github_search_repos":
            return json.dumps(gh.search_repos(args.get("query", "")))[:4000]
        if name == "github_search_code":
            return json.dumps(gh.search_code(args.get("query", "")))[:4000]
        if name == "github_read_file":
            ok, why = allow.is_authorized_github_repo(args.get("owner", ""), args.get("repo", ""))
            if not ok:
                return f"Not authorized: {why}"
            return json.dumps(gh.read_repo_file(args["owner"], args["repo"], args["path"]))[:6000]
        if name == "composio_search":
            return composio.composio_search(args.get("query", ""), args.get("app_name", ""))
        if name == "composio_execute":
            return composio.composio_execute(args.get("tool_slug", ""),
                                             args.get("arguments") or {},
                                             args.get("connected_account_id", ""))
        if name == "allowlist_add":
            allow.add_allowlist_host(args["host"])
            return f"{args['host']} added to the allowlist."
        return f"Unknown tool: {name}"
    except SSRFBlocked as e:
        return f"SSRF blocked: {e}"
    except Exception as e:
        return f"Tool {name} failed: {str(e)[:300]}"


def chat(message: str) -> dict:
    """One chat turn through the Horde-first brain with tool calls."""
    reason = hard_block_reason(message)
    if reason:
        return {"reply": f"Refused: {reason}. Detection only, on authorized targets.",
                "blocked": reason, "trace": []}
    prompt = (SYSTEM_PROMPT + "\nTOOLS:\n" + TOOL_DESCRIPTIONS +
              f"\nUSER: {message}\nASSISTANT:")
    trace: list[dict] = []
    text, source = brain.generate(prompt)
    for _ in range(6):
        calls = brain.parse_tool_calls(text)
        if not calls:
            break
        feedback = []
        for call in calls:
            result = _run_tool(call["name"], call["args"])
            trace.append({"tool": call["name"], "result": result[:500]})
            feedback.append(f"TOOL {call['name']} RESULT:\n{result}")
        text, source = brain.generate(prompt + "\n" + "\n".join(feedback) +
                                      "\nASSISTANT (answer now, plain language, evidence + fix per finding):")
    reply = brain.strip_tool_calls(text)
    if is_refusal(reply):
        # One retry: a legit defensive request must not die on a refusal.
        text2, source2 = brain.generate(
            prompt + "\nYou are a defensive security assistant. Answer the "
            "user's defensive security question directly.\nASSISTANT:")
        if not is_refusal(text2):
            reply, source = brain.strip_tool_calls(text2), source2
    return {"reply": reply, "brain": source, "trace": trace}
