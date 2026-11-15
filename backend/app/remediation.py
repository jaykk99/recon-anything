"""From findings to a fix program: what to change, in what order, and how
to prove the change worked.

Recon ends at "here is what exists". This module is the layer after it.
It takes the same adjudicated row set the run view serves (precision gate
already applied) and turns it into a work queue a team can execute:

* **One item per underlying problem**, not per detector hit - every
  finding that routes to the same fix (rotate a credential, patch a
  version, remove a path, close a port) collapses into one item with the
  evidence that supports it.
* **Priority from proof, not from tone.** A verified, weaponized,
  internet-reachable item is "now"; an unproven candidate of the same
  severity is "next" (go capture the missing evidence first); hygiene
  drift is "later". Suppressed rows never enter the plan.
* **A concrete fix per class** - steps, owner, effort - plus the exact
  read-only verification commands the finding already carries.
* **A re-test plan**: which plugins to re-run and the acceptance
  criterion that closes the item, so a fix is verified instead of
  assumed.

Pure functions over finding dicts, deterministic, stdlib only. Never
raises: an unbuildable plan degrades to an empty one.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from . import precision

PRIORITY_NOW = 0
PRIORITY_NEXT = 1
PRIORITY_LATER = 2
PRIORITY_LABELS = {PRIORITY_NOW: "Now", PRIORITY_NEXT: "Next",
                   PRIORITY_LATER: "Later"}

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_EFFORT_WEIGHT = {"minutes": 1, "hours": 3, "days": 8, "weeks": 20}

# route -> (title, owner, effort, steps, retest plugins, acceptance)
_ROUTES: List[Dict[str, Any]] = [
    {
        "id": "rotate-credential",
        "match": re.compile(r"(secret|password|private[_-]?key|mnemonic|"
                            r"seed[_-]?phrase|api[_-]?key|access[_-]?key|"
                            r"token|credential|webhook|keystore)", re.I),
        "title": "Rotate every exposed credential",
        "owner": "Security / service owners",
        "effort": "minutes",
        "why": ("The value is live in a public asset. Rotation is the only "
                "fix that matters; removing the file alone does not undo the "
                "exposure - assume it is already copied."),
        "steps": [
            "Rotate each named credential at its provider (issue new, then "
            "revoke the old, in that order).",
            "Audit provider logs for use from unknown IPs/agents since the "
            "asset was published.",
            "Remove the secret from the served asset AND from the build/"
            "source that produced it, so the next deploy does not re-add it.",
            "If the asset is a JS bundle or a git history, purge it from the "
            "artifact and the history, then rebuild.",
        ],
        "retest": ["secrets", "gitleaks_scan", "js_secrets", "keyleak"],
        "acceptance": ("The re-scan finds no credential-shaped value in any "
                       "served asset, and the old value is rejected by the "
                       "provider."),
    },
    {
        "id": "patch-version",
        "match": re.compile(r"(cve|kev|vuln_js|vuln_lib|osv)", re.I),
        "title": "Patch the version-pinned vulnerable software",
        "owner": "Platform / infrastructure engineering",
        "effort": "days",
        "why": ("A specific version is being served and a public CVE covers "
                "it. Version-pinned matches are the least ambiguous signal a "
                "scan produces - the fix is an upgrade."),
        "steps": [
            "Confirm the version against the vendor's advisory (the finding "
            "names it).",
            "Upgrade to the first fixed release, or apply the vendor "
            "mitigation if an upgrade is not possible this week.",
            "If the component is end-of-life, remove or front it with a "
            "filtering proxy.",
            "Where CISA KEV lists it, treat as exploited-in-the-wild: check "
            "logs for the documented exploitation pattern.",
        ],
        "retest": ["cves", "js_retire", "fingerprint"],
        "acceptance": ("The re-scan reports the fixed version and no CVE "
                       "match for the component."),
    },
    {
        "id": "fix-takeover",
        "match": re.compile(r"(takeover|dangling[_-]?cname)", re.I),
        "title": "Remove or reclaim the takeover-prone DNS record",
        "owner": "DNS / infrastructure",
        "effort": "minutes",
        "why": ("A DNS record points at a resource the target no longer "
                "controls. Whoever claims it next inherits the subdomain, "
                "and with it cookies and mail for that name."),
        "steps": [
            "Delete the CNAME (or re-point it at a live resource you own).",
            "If the name must keep working, claim the resource at the "
            "provider and configure it before re-pointing.",
            "Sweep the zone for the same pattern on sibling hostnames.",
        ],
        "retest": ["takeover", "dns"],
        "acceptance": ("The re-scan finds no dangling CNAME and the hostname "
                       "resolves to a resource the target controls."),
    },
    {
        "id": "remove-exposure",
        "match": re.compile(r"(exposed|exposure|artifact|git|env|backup|"
                            r"dump|sourcemap|listing|phpinfo|bucket|s3_|"
                            r"hprof|pdb|wasm_)", re.I),
        "title": "Take the exposed file / listing off the public surface",
        "owner": "Web platform / DevOps",
        "effort": "hours",
        "why": ("The public can read something that was never meant to be "
                "served. The fix is at the edge or the web root, not in the "
                "application code."),
        "steps": [
            "Delete the path from the deploy artifact and redeploy (an "
            "edge rule alone leaves it one origin-bypass away).",
            "Add a deny rule for the path family (.git, .env, backups, "
            "source maps, directory listings) at the edge.",
            "Disable directory listing / debug endpoints at the server "
            "level.",
            "If the file carried secrets or personal data, rotate and "
            "notify per policy.",
        ],
        "retest": ["artifacts", "backup", "git_exposed", "filehunter"],
        "acceptance": ("Every path in the item returns 404/403 on re-scan "
                       "from a fresh client."),
    },
    {
        "id": "fix-web-vuln",
        "match": re.compile(r".*"),
        "title": "Fix the application-layer weakness",
        "owner": "Application security / the owning team",
        "effort": "days",
        "why": ("This is exploitable behaviour in the application itself, so "
                "it needs a code or configuration change plus a regression "
                "test - not a WAF rule."),
        "steps": [
            "Reproduce with the read-only command attached to the finding.",
            "Fix the root cause (encode the sink, parameterize the query, "
            "validate the origin, enforce authorization server-side).",
            "Add a regression test that fails on the vulnerable behaviour.",
            "Re-test the same request before closing.",
        ],
        "retest": [],
        "acceptance": ("The verification command no longer demonstrates the "
                       "weakness and the regression test is in CI."),
    },
    {
        "id": "harden-config",
        "match": re.compile(r"(header|cookie|hsts|csp|clickjack|sri|"
                            r"mixed_content|cache_control|tls|spf|dmarc|"
                            r"dkim|bimi|mta_sts|caa|ocsp|http2)", re.I),
        "title": "Harden the server and mail configuration",
        "owner": "Web platform",
        "effort": "hours",
        "why": ("Configuration drift, not a break-in path on its own. Cheap "
                "to fix, and it removes the shared root cause behind several "
                "other classes (clickjacking, cookie theft, downgrade)."),
        "steps": [
            "Apply the header/policy at the edge so every route inherits it.",
            "For cookies: Secure + HttpOnly + SameSite, with the __Host- "
            "prefix where possible.",
            "For mail: publish the SPF/DMARC/DKIM records the finding names, "
            "starting in report-only mode for DMARC.",
        ],
        "retest": ["headers", "cookie_security", "csp_audit", "tls"],
        "acceptance": ("The re-scan reports the header/policy present on the "
                       "same response it previously flagged."),
    },
    {
        "id": "close-service",
        "match": re.compile(r"(port_|_port|banner|service_)", re.I),
        "title": "Close or restrict the exposed network service",
        "owner": "Infrastructure / network",
        "effort": "hours",
        "why": ("A service is reachable from the internet that does not need "
                "to be. Exposure is the prerequisite for the next finding "
                "against it."),
        "steps": [
            "Bind the service to the private network or a management "
            "allowlist.",
            "Remove the public DNS/security-group rule that allowed it.",
            "If it must stay public, require authentication and patch it.",
        ],
        "retest": ["port_audit", "ports", "banners"],
        "acceptance": "The port is no longer reachable from an external host.",
    },
    {
        "id": "fix-contract",
        "match": re.compile(r"(drain|reentran|selfdestruct|unprotected|"
                            r"recipient_|validator_|storage_|bytecode_|"
                            r"proxy_)", re.I),
        "title": "Fix the smart-contract weakness",
        "owner": "Protocol / smart-contract team",
        "effort": "weeks",
        "why": ("Contract logic cannot be patched in place. The plan is a "
                "gated migration behind a timelock, with the exposure closed "
                "in the meantime."),
        "steps": [
            "Re-verify the finding with the read-only probe attached to it.",
            "Add the missing access gate or entitlement check in the "
            "implementation, with a regression test.",
            "Pause or cap the affected function until the fixed "
            "implementation is deployed behind the proxy.",
            "Re-run the validator against the new implementation after "
            "deployment.",
        ],
        "retest": ["auto_validator", "contract_logic", "contract_recon"],
        "acceptance": ("The validator returns FALSE_POSITIVE or the finding "
                       "disappears on the fixed implementation."),
    },
    {
        "id": "break-attack-path",
        "match": re.compile(r"attack_path", re.I),
        "title": "Break the chained attack path",
        "owner": "Cross-team (security lead coordinates)",
        "effort": "days",
        "why": ("No single component is a breach on its own - the chain is. "
                "Fixing the cheapest link closes the path, so start there."),
        "steps": [
            "Read the chain: each step names a component finding.",
            "Fix the cheapest or most isolated link first; that alone breaks "
            "the sequence.",
            "Re-run the scan and confirm the path is no longer synthesized.",
        ],
        "retest": ["correlation"],
        "acceptance": ("The re-scan produces no attack path containing these "
                       "components."),
    },
    {
        "id": "review-lead",
        "match": re.compile(r".*"),
        "title": "Review the remaining leads",
        "owner": "Security analyst",
        "effort": "hours",
        "why": ("These are unproven leads. They are listed last on purpose: "
                "spend time only after the proven items are closed."),
        "steps": [
            "Open the finding's verification command and run it read-only.",
            "If it confirms, promote it to a real item with an owner.",
            "If it does not, record the dead end so the next scan skips it.",
        ],
        "retest": [],
        "acceptance": "Each lead is either promoted or closed as a dead end.",
    },
]

_ROUTE_BY_ID = {r["id"]: r for r in _ROUTES}


def _family_of(row: Dict[str, Any]) -> str:
    fam = (row.get("precision") or {}).get("claim_family")
    if fam:
        return str(fam)
    return precision.claim_family(row)


def _route_for(row: Dict[str, Any]) -> Dict[str, Any]:
    family = _family_of(row)
    if row.get("key") == "attack_path" or row.get("plugin") == "correlation":
        return _ROUTE_BY_ID["break-attack-path"]
    by_family = {
        "secret": "rotate-credential",
        "cve": "patch-version",
        "takeover": "fix-takeover",
        "exposure": "remove-exposure",
        "web_vuln": "fix-web-vuln",
        "hygiene": "harden-config",
        "service": "close-service",
        "contract": "fix-contract",
        "contract_verdict": "fix-contract",
        "guess": "review-lead",
        "observation": "review-lead",
    }
    rid = by_family.get(family)
    if rid:
        return _ROUTE_BY_ID[rid]
    key = str(row.get("key") or "")
    for route in _ROUTES:
        if route["match"].search(key):
            return route
    return _ROUTE_BY_ID["review-lead"]


def _priority_for(item: Dict[str, Any]) -> int:
    sev = str(item.get("severity") or "low")
    verified = item.get("claim_status") == precision.CLAIM_VERIFIED
    kev = bool(item.get("kev"))
    exploit = str(item.get("exploitability") or "unknown")
    if verified and (sev == "high" and (kev or exploit in
                                       ("weaponized", "public_poc"))):
        return PRIORITY_NOW
    if verified and sev in ("high", "medium"):
        return PRIORITY_NOW if item["route_id"] in (
            "rotate-credential", "fix-takeover", "break-attack-path",
            "remove-exposure") else PRIORITY_NEXT
    if not verified and sev == "high":
        return PRIORITY_NEXT
    if verified:
        return PRIORITY_NEXT if item["route_id"] != "harden-config" \
            else PRIORITY_LATER
    return PRIORITY_LATER


def _row_commands(row: Dict[str, Any]) -> List[Dict[str, str]]:
    ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    out: List[Dict[str, str]] = []
    for cmd in (ev.get("commands") or [])[:3]:
        if isinstance(cmd, dict) and cmd.get("cmd"):
            out.append({"label": str(cmd.get("label") or "verify")[:80],
                        "cmd": str(cmd.get("cmd"))[:300]})
    return out


def _severity_of_row(row: Dict[str, Any]) -> str:
    ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    sev = str(ev.get("severity") or ev.get("risk") or "low").lower()
    if sev == "critical":
        return "high"
    return sev if sev in _SEVERITY_RANK else "low"


def build_plan(rows: List[Dict[str, Any]],
               run: Any = None) -> Dict[str, Any]:
    """Turn an adjudicated finding set into a prioritized fix program."""
    try:
        if rows and not any(isinstance(r, dict) and r.get("claim_status")
                            for r in rows):
            rows = precision.apply(rows)
        items: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            status = row.get("claim_status")
            if status == precision.CLAIM_SUPPRESSED:
                continue
            if status not in (precision.CLAIM_VERIFIED,
                              precision.CLAIM_CANDIDATE):
                continue
            family = _family_of(row)
            if family == "observation" and status == precision.CLAIM_VERIFIED:
                # Enumerated facts (a subdomain, a tech tag, an IP) are the
                # inventory, not a fix item.
                continue
            route = _route_for(row)
            key = f"{route['id']}:{family if route['id'] != 'fix-web-vuln' else row.get('key')}"
            item = items.get(key)
            ev = row.get("evidence") if isinstance(row.get("evidence"),
                                                   dict) else {}
            if item is None:
                item = {
                    "id": f"fix-{len(items) + 1}",
                    "route_id": route["id"],
                    "title": route["title"],
                    "family": family,
                    "claim_status": status,
                    "severity": _severity_of_row(row),
                    "exploitability": str(ev.get("exploitability")
                                          or "unknown"),
                    "kev": bool(ev.get("kev")),
                    "owner": route["owner"],
                    "effort": route["effort"],
                    "why": route["why"],
                    "steps": list(route["steps"]),
                    "retest": list(route["retest"]) or
                    sorted({str(row.get("plugin") or "scan")}),
                    "acceptance": route["acceptance"],
                    "findings": [],
                    "verify": [],
                }
                items[key] = item
            item["findings"].append({
                "id": row.get("id"), "plugin": row.get("plugin"),
                "key": row.get("key"),
                "value": str(row.get("value") or "")[:200],
                "claim_status": status,
                "missing": list((row.get("precision") or {})
                                .get("missing") or [])[:3],
            })
            for cmd in _row_commands(row):
                if cmd not in item["verify"] and len(item["verify"]) < 4:
                    item["verify"].append(cmd)
            if _SEVERITY_RANK.get(_severity_of_row(row), 2) < \
                    _SEVERITY_RANK.get(item["severity"], 2):
                item["severity"] = _severity_of_row(row)
            if status == precision.CLAIM_VERIFIED:
                item["claim_status"] = precision.CLAIM_VERIFIED
            if row.get("key") == "attack_path":
                item["effort"] = "days"
        plan = sorted(items.values(), key=lambda it: (
            it["claim_status"] != precision.CLAIM_VERIFIED,
            _SEVERITY_RANK.get(it["severity"], 2),
            _EFFORT_WEIGHT.get(it["effort"], 3),
            it["title"]))
        for item in plan:
            item["priority"] = _priority_for(item)
            item["priority_label"] = PRIORITY_LABELS[item["priority"]]
            item["finding_count"] = len(item["findings"])
            item["findings"] = item["findings"][:8]
        plan.sort(key=lambda it: (it["priority"],
                                  _SEVERITY_RANK.get(it["severity"], 2),
                                  -it["finding_count"]))
        for i, item in enumerate(plan, 1):
            item["id"] = f"fix-{i}"
        counts = {PRIORITY_LABELS[p]: 0 for p in PRIORITY_LABELS}
        for item in plan:
            counts[item["priority_label"]] += 1
        verified = [i for i in plan
                    if i["claim_status"] == precision.CLAIM_VERIFIED]
        candidates = [i for i in plan
                      if i["claim_status"] == precision.CLAIM_CANDIDATE]
        effort_units = sum(_EFFORT_WEIGHT.get(i["effort"], 3) * max(
            i["finding_count"], 1) for i in plan)
        return {
            "summary": {
                "items": len(plan),
                "verified_items": len(verified),
                "candidate_items": len(candidates),
                "priority": counts,
                "effort_units": effort_units,
                "effort_label": _effort_label(effort_units),
                "next_action": (plan[0]["title"] if plan else
                                "Nothing to fix: the run produced no "
                                "actionable weakness."),
                "posture": _posture(plan),
                "note": ("Priorities come from proof, not from severity "
                         "claims alone: candidates are 'next' because the "
                         "missing evidence has to be captured first, and "
                         "suppressed rows never enter the plan."),
            },
            "items": plan,
            "verification_plan": [{
                "item": i["title"],
                "retest_plugins": i["retest"],
                "acceptance": i["acceptance"],
            } for i in plan if i["priority"] <= PRIORITY_NEXT][:12],
        }
    except Exception:
        return {"summary": {"items": 0, "next_action": "",
                            "posture": {"score": 0, "grade": "?"}},
                "items": [], "verification_plan": []}


def _effort_label(units: int) -> str:
    if units <= 2:
        return "under an hour"
    if units <= 8:
        return "about a day"
    if units <= 24:
        return "a few days"
    if units <= 60:
        return "one to two weeks"
    return "several weeks"


def _posture(plan: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A single 0-100 posture number derived from the adjudicated plan."""
    score = 100
    for item in plan:
        if item["claim_status"] != precision.CLAIM_VERIFIED:
            continue
        sev = item["severity"]
        weight = {"high": 22, "medium": 8, "low": 3}.get(sev, 3)
        if item.get("kev") or item.get("exploitability") == "weaponized":
            weight += 10
        score -= weight
    score = max(0, min(100, score))
    grade = ("A" if score >= 90 else "B" if score >= 80 else
             "C" if score >= 65 else "D" if score >= 45 else "F")
    return {"score": score, "grade": grade,
            "basis": "verified findings only"}


def summary(rows: List[Dict[str, Any]], run: Any = None) -> Dict[str, Any]:
    return build_plan(rows, run)["summary"]


def to_markdown(rows: List[Dict[str, Any]], limit: int = 8) -> str:
    """A remediation section for the exported report."""
    plan = build_plan(rows)
    s = plan["summary"]
    if not plan["items"]:
        return ""
    lines = ["## Remediation plan", "",
             f"**{s['items']} items · {s['verified_items']} verified · "
             f"{s['priority']['Now']} now, {s['priority']['Next']} next · "
             f"effort {s['effort_label']}**", ""]
    for item in plan["items"][:limit]:
        lines.append(f"### {item['id']} [{item['priority_label']}] "
                     f"{item['title']}")
        lines.append(f"- Severity: **{item['severity']}** · proof: "
                     f"**{item['claim_status']}** · owner: {item['owner']} · "
                     f"effort: {item['effort']}")
        lines.append(f"- Why: {item['why']}")
        for step in item["steps"]:
            lines.append(f"  1. {step}")
        for f in item["findings"][:3]:
            lines.append(f"- Evidence: `{f['key']}` {f['value'][:140]} "
                         f"({f['plugin']}, {f['claim_status']})")
        if item["verify"]:
            lines.append("- Verify (read-only): " + "; ".join(
                f"{c['label']}: `{c['cmd']}`" for c in item["verify"][:2]))
        lines.append(f"- Re-test: run {', '.join(item['retest'])}. "
                     f"Done when: {item['acceptance']}")
        lines.append("")
    return "\n".join(lines)
