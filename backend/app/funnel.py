"""Manual-testing funnel: broad recon output -> a ranked human handoff.

The honest limit of a "recon anything" pipeline is in the name: it maps
surface fast and wide, it does not prove logic bugs. What it CAN do is
hand a human the short list worth testing by hand - which endpoint, why
it is interesting, how sure we are, and what to try first - instead of a
2,000-row findings dump.

This module builds that funnel. It groups findings by (manual-test class,
asset), scores each lead from severity / exploitability / confidence /
corroboration, and attaches the manual checks a tester would actually run.
Detection only: nothing here sends a request, a payload, or a login. The
text is a test PLAN, not an exploit.

Used by:
  * ``GET /api/runs/{id}/funnel`` (JSON),
  * the Markdown/HTML exports (a "Manual testing funnel" section),
  * the MCP tool ``recon_funnel``.

Pure stdlib, deterministic, never raises on bad input.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

_SEV_W = {"critical": 40, "high": 30, "medium": 20, "low": 8}
_EXPL_W = {"weaponized": 24, "public_poc": 16, "theoretical": 8, "unknown": 0}

_URL_HOST = re.compile(r"^[a-z][a-z0-9+.-]*://([^/:\s]+)", re.I)
_BARE_HOST = re.compile(r"^([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?$", re.I)


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def _evidence(row: Dict[str, Any]) -> Dict[str, Any]:
    ev = row.get("evidence")
    return ev if isinstance(ev, dict) else {}


def _sev(row: Dict[str, Any]) -> str:
    s = _norm(_evidence(row).get("severity") or _evidence(row).get("risk")
              or row.get("bounty_value"))
    return s if s in _SEV_W else "low"


def _expl(row: Dict[str, Any]) -> str:
    e = _norm(_evidence(row).get("exploitability"))
    return e if e in _EXPL_W else "unknown"


def _confidence(row: Dict[str, Any]) -> int:
    try:
        return max(0, min(100, int(row.get("confidence_score")
                                 or row.get("confidence") or 0)))
    except (TypeError, ValueError):
        return 0


_ADDR = re.compile(r"^(0x[a-f0-9]{40})$", re.I)


def asset_of(row: Dict[str, Any], fallback: str = "target") -> str:
    """Best host/asset label for a finding (source_url, then value).

    Chain findings have no host: the asset is the contract address the
    lead is about, shortened so a report line stays readable.
    """
    ev = row.get("evidence")
    if isinstance(ev, dict):
        addr = str(ev.get("contract") or "").strip()
        if _ADDR.match(addr):
            return f"{addr[:8]}\u2026{addr[-4:]}"
    for key in ("source_url", "url", "value"):
        raw = str(row.get(key) or "").strip()
        if not raw:
            continue
        m = _URL_HOST.match(raw)
        if m:
            return m.group(1).lower()
        first = raw.split()[0]
        m = _BARE_HOST.match(first)
        if m:
            return m.group(1).lower()
        if _ADDR.match(first):
            return f"{first[:8]}\u2026{first[-4:]}"
    return fallback


# ---------------------------------------------------------------------------
# Manual-test classes. Each is a detector-independent view: a class matches
# on the shared vocabulary plugins already emit (key / value / plugin id),
# so new plugins land in the right bucket without a mapping table.
# ---------------------------------------------------------------------------

CLASSES: List[Dict[str, Any]] = [
    {
        "id": "object_access",
        "title": "Object-level authorization (IDOR / BOLA)",
        "match": re.compile(r"idor|bola|object[_-]?level|insecure[_-]?direct|"
                            r"broken[_-]?object"),
        "why": ("Id-addressed endpoints and object references are where "
                "authorization is most often checked by the UI, not the "
                "API. Automated scanners can only flag the shape."),
        "checks": [
            "Create two accounts at the same privilege level; request the "
            "same object id as both and compare responses.",
            "Replay one account's request with the other account's session "
            "and with no session; note which of the three returns data.",
            "Try a sibling id class (numeric +/-1, UUID from another tenant, "
            "base64-decoded id) and record the status/body difference.",
        ],
    },
    {
        "id": "auth_boundary",
        "title": "Authentication / session boundary",
        "match": re.compile(r"jwt|auth[_-]?bypass|session|sso|oauth|saml|"
                            r"login|password[_-]?reset|mfa|token[_-]?forge|"
                            r"forgotten[_-]?password|remember[_-]?me"),
        "why": ("Token handling, reset flows and SSO callbacks are logic, "
                "not signatures: a scanner can see the algorithm, only a "
                "human can tell whether the app trusts the claim."),
        "checks": [
            "Log in as two roles; decode both tokens and diff every claim "
            "(role, tenant, scope, iss/aud, exp).",
            "Repeat the flow with the token's role/tenant claim edited and "
            "the signature left as-is; the app should reject on signature "
            "first.",
            "Walk the password-reset / invite flow end to end with the "
            "victim's identity but your own inbox, and check token reuse.",
        ],
    },
    {
        "id": "api_schema",
        "title": "API surface / schema exposure",
        "match": re.compile(r"openapi|swagger|graphql|introspection|api[_-]?docs|"
                            r"redoc|wadl|api[_-]?map"),
        "why": ("A published schema is a test plan handed over for free: "
                "every endpoint, argument and object type is listed. The "
                "interesting part is which of them enforce authz."),
        "checks": [
            "Walk every documented endpoint with no session and with a "
            "low-privilege session; record 200 vs 401 vs 403.",
            "For each mutation, send the documented minimum body and an "
            "empty body; compare error detail for internal type leakage.",
            "For GraphQL, list the mutation fields and try one admin-only "
            "mutation with a normal-user token.",
        ],
    },
    {
        "id": "input_handling",
        "title": "Input handling (injection / reflection candidates)",
        "match": re.compile(r"xss|sqli|injection|param[_-]?(discovery|fuzzer)|"
                            r"reflection|ssti|ldap|nosql|template|command"),
        "why": ("Parameter discovery shows WHERE input lands; whether a "
                "context is exploitable, and which encoding it needs, is a "
                "manual call on real responses."),
        "checks": [
            "Send a unique inert canary through each discovered parameter "
            "and grep the raw response, headers and any reflected JSON.",
            "Check the reflection context (HTML body, attribute, JS string, "
            "header) and whether the app encodes for that context.",
            "Try the same parameter twice (first/last wins) and as an array "
            "to spot parameter-pollution differences.",
        ],
    },
    {
        "id": "file_upload",
        "title": "File upload / import handling",
        "match": re.compile(r"upload|multipart|file[_-]?input|attachment|"
                            r"import[_-]?file|avatar"),
        "why": ("Upload handling is where content-type checks, filename "
                "handling, storage location and authorization meet - all "
                "logic a static scan cannot settle."),
        "checks": [
            "Upload a benign text file with a disguised content-type and an "
            "unusual extension; note where it is stored and whether it is "
            "served back inline.",
            "Try a filename with traversal characters and record the stored "
            "path in the response or download link.",
            "Upload as a low-privilege user to another user's object id and "
            "check ownership enforcement.",
        ],
    },
    {
        "id": "redirect_flow",
        "title": "Redirect / OAuth callback trust",
        "match": re.compile(r"open[_-]?redirect|redirect[_-]?uri|return[_-]?url|"
                            r"callback|next=|continue="),
        "why": ("Redirect targets decide whether a code or token leaks, and "
                "validators are frequently partial (prefix/suffix match)."),
        "checks": [
            "Supply an absolute off-site URL, a scheme-relative //host, and "
            "a host that only suffix-matches the allow-list; compare which "
            "are accepted.",
            "Run the full OAuth login with an off-site redirect_uri and see "
            "whether the code arrives before the redirect is rejected.",
            "Check whether the redirect decision happens server-side or in "
            "client JS.",
        ],
    },
    {
        "id": "cors_trust",
        "title": "CORS / cross-origin data exposure",
        "match": re.compile(r"cors|access-control-allow|origin[_-]?reflect|"
                            r"postmessage|websocket[_-]?origin"),
        "why": ("Whether a reflected Origin is dangerous depends on "
                "credentials and on what the endpoint returns - both need a "
                "real session."),
        "checks": [
            "Send an arbitrary Origin against an authenticated endpoint "
            "with a real session cookie; check ACAO + ACAC and whether the "
            "body differs from the same-origin response.",
            "Test the null origin and a subdomain-suffix origin.",
            "Re-check any WebSocket / postMessage handler's origin check.",
        ],
    },
    {
        "id": "business_logic",
        "title": "Business logic (price / balance / limits)",
        "match": re.compile(r"price|coupon|discount|cart|checkout|refund|"
                            r"paywall|blogic|race[_-]?condition|limit"),
        "why": ("Value flows are the classic scanner blind spot: every "
                "request is individually valid, and the bug is the sequence, "
                "the sign, or the unit."),
        "checks": [
            "Buy the cheapest item and edit price/quantity/currency fields "
            "at each step; record where the server re-prices.",
            "Run the same spend action twice concurrently and check whether "
            "both succeed against one balance.",
            "Check negative and zero values, and whether rounding/decimals "
            "are applied server-side.",
        ],
    },
    {
        "id": "exposed_admin",
        "title": "Administrative / management surface",
        "match": re.compile(r"admin|console|manage|actuator|phpmyadmin|"
                            r"dashboard|internal|control[_-]?panel"),
        "why": ("An exposed console is only interesting if it is reachable "
                "without the gate the app assumes (IP allow-list, SSO, "
                "basic auth)."),
        "checks": [
            "Request it with no session, a low-privilege session, and from a "
            "non-allow-listed position; record which gate answers.",
            "Check the default page for version/build strings and whether "
            "the gate is client-side.",
            "Confirm whether the same app exposes the admin API under /api "
            "with different protection.",
        ],
    },
    {
        "id": "secret_in_client",
        "title": "Secrets shipped to the client",
        "match": re.compile(r"js[_-]?secret|sourcemap|hardcoded|api[_-]?key|"
                            r"token[_-]?in|env[_-]?exposed|private[_-]?key|"
                            r"credential"),
        "why": ("A client-side secret is real only if it is live and scoped; "
                "automation can prove exposure, a human must check validity "
                "and blast radius (read-only)."),
        "checks": [
            "Confirm the value is served live (curl the bundle directly, not "
            "just a cache) and whether it differs per user/session.",
            "Identify the provider and scope from public docs only; do not "
            "use the key against the provider beyond a read-only identity "
            "call you are authorized to make.",
            "Search the same bundle for the sibling values (endpoints, "
            "project ids) that make the key usable.",
        ],
    },
    {
        "id": "crypto_flow",
        "title": "On-chain value flow (contract logic)",
        "match": re.compile(r"drain|withdraw|withdrawal|transfer|balance|"
                            r"wallet|mint|approve|permit|reentran|oracle|"
                            r"flash[_-]?loan|signature|ecrecover|"
                            r"access[_-]?control|delegatecall"),
        "why": ("Contract findings are candidate shapes against source; "
                "reachability, recipient and live state decide whether the "
                "value actually moves."),
        "checks": [
            "Read the flagged function and every modifier/gate on its call "
            "path in the verified source; confirm the recipient expression.",
            "Read the contract's live balance and the caller's entitlement "
            "at the same block; a zero balance or a caller-metered payout "
            "is not a drain.",
            "Reproduce locally against a fork with an unfunded stranger and "
            "check the balance delta, not the revert message.",
        ],
    },
    {
        "id": "infrastructure",
        "title": "Exposed service / infrastructure",
        "match": re.compile(r"port[_-]?(open|audit|scan)|ssh|rdp|database|"
                            r"redis|docker|kube|smb|ftp|telnet|memcached|"
                            r"elastic|mongo|postgres|mysql"),
        "why": ("Reachability is not access: the question is which "
                "authentication the service actually demands, and whether "
                "that is intended exposure."),
        "checks": [
            "Confirm the port is reachable from your authorized position "
            "(not just from the scanner).",
            "Read the banner/version only; check the vendor's public docs "
            "for the default auth posture of that version.",
            "Confirm with the owner whether the exposure is intentional "
            "before any further test.",
        ],
    },
    {
        "id": "transport_hardening",
        "title": "Transport / browser hardening",
        "match": re.compile(r"missing[_-]?(hsts|header|csp)|"
                            r"security[_-]?header|"
                            r"cookie[_-]?(flag|secure|httponly|samesite)|"
                            r"clickjack|hsts|\bcsp\b|spf|dmarc|dnssec|"
                            r"tls[_-]?(version|cipher|protocol|expired)"),
        "why": ("Hardening gaps are rarely a bug alone, but they decide what "
                "else is reachable (downgrade, cookie theft, framing) and "
                "a human can confirm the consequence on this app quickly."),
        "checks": [
            "Confirm the policy on a live authenticated response, not just "
            "the unauthenticated landing page.",
            "Request the same URL over http:// and note whether it "
            "redirects or serves content.",
            "Write down the concrete consequence for this app (session "
            "cookie scope, framing of an authenticated page) before "
            "reporting it.",
        ],
    },
    {
        "id": "dns_identity",
        "title": "DNS / identity takeover surface",
        "match": re.compile(r"takeover|dangling|cname|subdomain|mx|spf|dmarc|"
                            r"caa|dnssec"),
        "why": ("A dangling record is only exploitable if the pointed-to "
                "resource is claimable by you - a provider-specific fact a "
                "human must confirm without claiming it."),
        "checks": [
            "Resolve the record chain and confirm the final target's "
            "provider error / NXDOMAIN state.",
            "Check the provider's naming rules to see whether the name is "
            "claimable (do NOT claim it).",
            "Check what the subdomain still has access to (cookies scoped "
            "to the parent, OAuth callbacks, CORS allow-list).",
        ],
    },
    {
        "id": "deployment_lineage",
        "title": "Deployment lineage / shared operator",
        "match": re.compile(r"deployment[_-]?cluster|lineage|"
                            r"creator_|deployer|upgrade[_-]?authority|"
                            r"proxy[_-]?admin|admin[_-]?slot"),
        "why": ("A contract's risk depends on who can still act on it and "
                "what else that operator has shipped. Code review cannot "
                "see that; a shared deployer or funder can, but only as a "
                "hypothesis until a human confirms it."),
        "checks": [
            "Read owner() / admin() / the EIP-1967 admin slot on each "
            "contract in the cluster and note which cluster member still "
            "controls it (read-only call).",
            "Open the funding transaction on an explorer and confirm both "
            "sides are the same actor - not a shared exchange withdrawal "
            "address or a batching contract.",
            "Look for a second independent signal (same deployer nonce, "
            "same init-code hash, same CREATE2 salt) before treating the "
            "link as real.",
            "Write it down as a hypothesis with its evidence, never as "
            "attribution: shared funding is not proof of common control.",
        ],
    },
    {
        "id": "mobile_binary",
        "title": "Mobile app / binary internals",
        "match": re.compile(r"apk|ipa|android|ios|binary|firmware|jtag|"
                            r"debug[_-]?info|dwarf|manifest"),
        "why": ("Static extraction shows what shipped; whether a shipped "
                "key/endpoint is privileged needs a runtime check."),
        "checks": [
            "Diff the extracted endpoints against the public API surface; "
            "look for internal-only hosts.",
            "Check whether extracted keys are live and scoped (read-only "
            "identity call only, if authorized).",
            "Check exported components / deep links for entry points the "
            "web surface does not have.",
        ],
    },
]


def classify(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The first manual-test class a finding belongs to, or None."""
    if not isinstance(row, dict):
        return None
    blob = " ".join((_norm(row.get("plugin")), _norm(row.get("key")),
                     _norm(row.get("value"))[:200], _norm(row.get("category"))))
    for klass in CLASSES:
        if klass["match"].search(blob):
            return klass
    return None


def _lead_score(rows: Sequence[Dict[str, Any]],
                path_boost: bool = False) -> int:
    sev = max((_SEV_W.get(_sev(r), 8) for r in rows), default=0)
    expl = max((_EXPL_W.get(_expl(r), 0) for r in rows), default=0)
    conf = max((_confidence(r) for r in rows), default=0)
    plugins = {str(r.get("plugin") or r.get("plugin_id") or "")
               for r in rows}
    corroboration = min(18, max(0, len(plugins) - 1) * 6)
    path_bonus = 12 if path_boost else 0
    raw = sev + expl + conf // 4 + corroboration + path_bonus
    return max(0, min(100, raw))


def _evidence_ref(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "plugin": str(row.get("plugin") or row.get("plugin_id") or ""),
        "key": row.get("key"),
        "value": str(row.get("value") or "")[:200],
        "severity": _sev(row),
        "exploitability": _expl(row),
    }


def build_funnel(rows: Sequence[Dict[str, Any]],
                 host_hint: Optional[str] = None,
                 limit: int = 25) -> Dict[str, Any]:
    """Group findings into ranked manual-test leads.

    Returns ``{"target", "lead_count", "counts", "leads", "note"}``. Pure
    and deterministic; a malformed row is skipped rather than raising.
    """
    safe = [r for r in (rows or []) if isinstance(r, dict)]
    # A correlated attack path usually names several classes at once (or
    # none), so it lifts the whole funnel rather than one group.
    path_boost = any(_norm(r.get("key")) == "attack_path"
                     or _norm(r.get("plugin")) == "correlation"
                     for r in safe)
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for row in safe:
        klass = classify(row)
        if klass is None:
            continue
        key = (klass["id"], asset_of(row, host_hint or "target"))
        groups.setdefault(key, []).append(row)

    leads: List[Dict[str, Any]] = []
    for (class_id, asset), group in groups.items():
        klass = next(k for k in CLASSES if k["id"] == class_id)
        group = sorted(group, key=lambda r: (-_SEV_W.get(_sev(r), 0),
                                             -_confidence(r)))
        score = _lead_score(group, path_boost=path_boost)
        distinct_plugins = {str(r.get("plugin") or r.get("plugin_id") or "")
                            for r in group}
        leads.append({
            "id": f"{class_id}:{asset}",
            "class": class_id,
            "title": klass["title"],
            "asset": asset,
            "score": score,
            "confidence": max((_confidence(r) for r in group), default=0),
            "uncertainty": ("corroborated" if len(distinct_plugins) >= 2
                            else "single-signal"),
            "finding_count": len(group),
            "why": klass["why"],
            "manual_checks": list(klass["checks"]),
            "evidence": [_evidence_ref(r) for r in group[:5]],
        })
    leads.sort(key=lambda lead: (-lead["score"], lead["asset"], lead["class"]))
    leads = leads[:max(1, limit)]
    counts: Dict[str, int] = {}
    for lead in leads:
        counts[lead["class"]] = counts.get(lead["class"], 0) + 1
    return {
        "target": host_hint or (leads[0]["asset"] if leads else "target"),
        "lead_count": len(leads),
        "counts": counts,
        "leads": leads,
        "note": ("Automated recon maps surface; it does not prove logic "
                 "bugs. These are the leads worth a human's time, with the "
                 "uncertainty stated. Detection only - every check is a "
                 "read-only test plan, never a payload."),
    }


def render_markdown(rows: Sequence[Dict[str, Any]],
                    host_hint: Optional[str] = None,
                    limit: int = 12) -> str:
    """Markdown section for the report exports (empty string if no leads)."""
    funnel = build_funnel(rows, host_hint=host_hint, limit=limit)
    leads = funnel["leads"]
    if not leads:
        return ""
    out = ["## Manual testing funnel",
           "_Where to switch from automation to a human. Each lead says why "
           "it matters, how sure we are, and what to test first - read-only "
           "checks, no payloads._", ""]
    for i, lead in enumerate(leads, 1):
        out.append(f"### {i}. [{lead['score']}/100] {lead['title']} — "
                   f"`{lead['asset']}`")
        out.append(f"- **Uncertainty:** {lead['uncertainty']} "
                   f"({lead['finding_count']} finding(s), confidence "
                   f"{lead['confidence']})")
        out.append(f"- **Why manual:** {lead['why']}")
        keys = ", ".join(f"`{e['key']}` ({e['plugin']})"
                         for e in lead["evidence"][:4])
        out.append(f"- **Evidence:** {keys}")
        out.append("- **Try first:**")
        for check in lead["manual_checks"]:
            out.append(f"  1. {check}")
        out.append("")
    return "\n".join(out)


__all__ = ["CLASSES", "asset_of", "build_funnel", "classify",
           "render_markdown"]
