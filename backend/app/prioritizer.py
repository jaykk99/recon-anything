"""Finding prioritizer: auto-prioritize by exploitability.

Sort order (what Jay looks at first):
  1. Exploitability tier: weaponized > public_poc > theoretical > unknown
     (a weaponized medium beats a theoretical high - it can be used NOW)
  2. Severity within a tier: critical > high > medium > low
  3. Confidence, descending, as the final tiebreak

Bounty mode (Jay's order 2026-10-19): impact scoring 1-10 per finding.
Big-findings-first: impact x confidence. High-impact classes (RCE, SQLi,
SSTI, SSRF, XXE, auth-bypass/IDOR candidates, exposed secrets,
unauthenticated admin/API) rank above noise (missing headers, cookie
flags, version banners). Detection-only: impact measures POTENTIAL, the
human verifies.

Works on ``Finding`` dataclass instances, finding dicts (as published on
the "poc_findings" / "deduped_findings" bus), or DB row objects - any
object with ``evidence``/``confidence``/``bounty_value`` attributes or
keys. Never raises: unparseable findings sort last.

Usage:
    from backend.app.prioritizer import prioritize
    ordered = prioritize(findings)          # new sorted list
    top5 = prioritize(findings, limit=5)
    big = prioritize_bounty(findings)       # impact x confidence, big first
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Lower number = shown first.
EXPLOITABILITY_ORDER: Dict[str, int] = {
    "weaponized": 0,
    "public_poc": 1,
    "theoretical": 2,
    "unknown": 3,
}

SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _get(f: Any, name: str, default: Any = None) -> Any:
    """Read an attribute or dict key, whichever the finding offers."""
    if isinstance(f, dict):
        return f.get(name, default)
    return getattr(f, name, default)


def _evidence(f: Any) -> Dict[str, Any]:
    ev = _get(f, "evidence", None)
    return ev if isinstance(ev, dict) else {}


def exploitability_of(f: Any) -> str:
    """Exploitability tier, normalized to the 4 canonical levels."""
    ev = _evidence(f)
    raw = str(ev.get("exploitability") or _get(f, "exploitability", "")
              or "unknown").strip().lower().replace("-", "_")
    if raw in EXPLOITABILITY_ORDER:
        return raw
    # aliases (mirrors base.normalize_exploitability)
    if raw in ("exploit_public", "rce_public", "metasploit", "nuclei"):
        return "weaponized"
    if raw in ("poc", "proof_of_concept", "poc_public"):
        return "public_poc"
    return "unknown"


def severity_of(f: Any) -> str:
    """Severity, recovering 'critical' that base.normalize_risk folds.

    base._f normalizes evidence severity to low|medium|high, so a finding
    whose bounty tier is critical (BOUNTY_KEY_TIERS) would otherwise lose
    its critical standing. Check bounty_value and any raw severity first.
    """
    ev = _evidence(f)
    for candidate in (ev.get("severity"), ev.get("risk"),
                      _get(f, "severity", "")):
        s = str(candidate or "").strip().lower()
        if s == "critical":
            return "critical"
        if s in SEVERITY_ORDER:
            sev = s
            break
    else:
        sev = "low"
    if sev == "high" and str(_get(f, "bounty_value", "")).lower() == "critical":
        return "critical"
    return sev


def confidence_of(f: Any) -> int:
    try:
        return int(_get(f, "confidence", 0) or 0)
    except (TypeError, ValueError):
        return 0


def priority_key(f: Any) -> Tuple[int, int, int]:
    """Sort key: (exploitability rank, severity rank, -confidence)."""
    return (EXPLOITABILITY_ORDER[exploitability_of(f)],
            SEVERITY_ORDER[severity_of(f)],
            -confidence_of(f))


def priority_label(f: Any) -> str:
    """One-line human label, e.g. 'P1 weaponized/high (90%)'."""
    exp = exploitability_of(f)
    sev = severity_of(f)
    conf = confidence_of(f)
    rank = (EXPLOITABILITY_ORDER[exp] * 4 + SEVERITY_ORDER[sev]) // 2 + 1
    return f"P{rank} {exp}/{sev} ({conf}%)"


def prioritize(findings: List[Any],
               limit: Optional[int] = None) -> List[Any]:
    """Return findings sorted weaponized-first.

    Stable: findings that tie on all three keys keep their input order.
    Does not mutate the input list. ``limit`` caps the returned list.
    """
    ordered = sorted(findings, key=priority_key)
    if limit is not None:
        ordered = ordered[:max(limit, 0)]
    return ordered


def annotate(findings: List[Any]) -> List[Any]:
    """Stamp each finding's evidence with its priority rank + label.

    Mutates the evidence dict in place (best-effort) and returns the
    findings sorted by priority.
    """
    ordered = prioritize(findings)
    for i, f in enumerate(ordered, 1):
        try:
            ev = _evidence(f)
            if isinstance(ev, dict):
                ev["priority_rank"] = i
                ev["priority_label"] = priority_label(f)
        except Exception:
            pass
    return ordered


def top_by_tier(findings: List[Any]) -> Dict[str, List[Any]]:
    """Group findings by exploitability tier, each group prioritized."""
    tiers: Dict[str, List[Any]] = {t: [] for t in EXPLOITABILITY_ORDER}
    for f in findings:
        tiers[exploitability_of(f)].append(f)
    return {t: prioritize(fs) for t, fs in tiers.items()}


# ---------------------------------------------------------------------------
# Bounty-mode impact scoring (Jay's order 2026-10-19).
# Impact = how bad it COULD be (1-10). Detection-only: the human verifies.
# ---------------------------------------------------------------------------

# (compiled regex on "category:key", base impact). First match wins, so
# order matters: most specific / most dangerous first.
_IMPACT_RULES: List[Tuple[re.Pattern, int]] = [
    # --- 10: full compromise primitives -----------------------------------
    (re.compile(r"(rce|remote_code|command_exec|deserial|pickle|yaml_load|"
                r"objectinputstream)"), 10),
    (re.compile(r"sqli.*(union|error|stacked)|sqli$"), 10),
    (re.compile(r"ssti.*evaluated|template.*evaluated"), 10),
    (re.compile(r"auth_bypass|bypass.*auth|login_bypass"), 10),
    # --- 9: high-value data access / secrets ------------------------------
    (re.compile(r"ssrf"), 9),
    (re.compile(r"xxe|xml.*external"), 9),
    (re.compile(r"ssti"), 9),
    (re.compile(r"(idor|bola).*candidate|insecure_direct|broken_object"), 9),
    (re.compile(r"secret|api[_-]?key|private[_-]?key|token[_-]?leak|"
                r"keyleak|aws[_-]?key|credentials?_exposed|password.*exposed|"
                r"db[_-]?connection|conn[_-]?string"), 9),
    (re.compile(r"admin.*(unauth|exposed|no[_-]?auth)|unauthenticated.*admin"),
     9),
    # --- 8: strong candidates ---------------------------------------------
    (re.compile(r"sqli|sqli.*blind"), 8),
    (re.compile(r"traversal.*confirmed|path.*traversal.*confirmed|"
                r"lfi.*confirmed|rfi"), 8),
    (re.compile(r"cmdi|command_injection"), 8),
    (re.compile(r"open_redirect|unvalidated_redirect"), 8),
    (re.compile(r"\.env|config.*exposed|backup.*(sql|db)|database.*dump|"
                r"git.*exposed|svn.*exposed"), 8),
    (re.compile(r"graphql.*(risky|dangerous|introspection.*enabled)|"
                r"mutation.*exposed"), 8),
    (re.compile(r"proto.*pollution.*sink|prototype.*pollution"), 8),
    (re.compile(r"s3.*(public|open)|bucket.*(public|open)|"
                r"cloud.*bucket.*exposed"), 8),
    # --- 7: solid vulns ----------------------------------------------------
    (re.compile(r"xss.*(reflected|stored)|xss$"), 7),
    (re.compile(r"cors.*reflect|origin.*reflect"), 7),
    (re.compile(r"unauthenticated_api|api.*no[_-]?auth"), 7),
    (re.compile(r"jwt.*(weak|none|algo)|session.*fixation"), 7),
    (re.compile(r"idor|bola"), 7),
    (re.compile(r"csrf.*(token.*missing|no.*protection)"), 7),
    # --- 5-6: medium signal ------------------------------------------------
    (re.compile(r"info.*disclosure|information.*leak|verbose.*error|"
                r"stack.*trace|debug.*(enabled|page)"), 6),
    (re.compile(r"source[_-]?map"), 5),
    (re.compile(r"endpoint|api.*route|js_endpoint"), 5),
    # --- 1-2: noise (still shown, ranked last) ------------------------------
    (re.compile(r"missing.*header|header.*missing|"
                r"security.*header|x-frame-options|csp|hsts"), 2),
    (re.compile(r"cookie.*(httponly|samesite|secure)|cookie.*flag"), 2),
    (re.compile(r"version.*(banner|disclosure)|banner.*grab|"
                r"server.*version|x-powered-by"), 2),
    (re.compile(r"clickjack"), 2),
]

# Evidence flags that bump impact: unauthenticated access doubles value.
_UNAUTH_RES = re.compile(r"unauthenticated|no[_\- ]?auth|without[_\- ]?auth|"
                         r"anonymous|publicly[_\- ]?accessible", re.I)


def impact_of(f: Any) -> int:
    """Impact score 1-10: how bad this COULD be. Detection-only.

    Never raises: unparseable findings score 3 (neutral-low).
    """
    try:
        key = str(_get(f, "key", "") or "")
        cat = str(_get(f, "category", "") or "")
        sig = f"{cat}:{key}".lower()
        ev = _evidence(f)
        score = 4  # default: medium-low
        for rx, pts in _IMPACT_RULES:
            if rx.search(sig):
                score = pts
                break
        # severity evidence nudges unclassified keys
        sev = str(ev.get("severity", "") or "").lower()
        if score == 4:
            if sev == "critical":
                score = 8
            elif sev == "high":
                score = 6
            elif sev == "low":
                score = 3
        # unauthenticated = higher value (bounty hunters love these)
        blob = " ".join(str(v) for v in
                        (key, _get(f, "value", ""), ev.get("note", ""),
                         ev.get("remediation", "")))
        if _UNAUTH_RES.search(blob):
            score = min(10, score + 1)
        # proven exploitability bumps too
        if exploitability_of(f) in ("weaponized", "public_poc"):
            score = min(10, score + 1)
        return max(1, min(10, score))
    except Exception:
        return 3


def bounty_score(f: Any) -> float:
    """Ranking score for bounty mode: impact x confidence (0-1000)."""
    try:
        return float(impact_of(f)) * float(confidence_of(f))
    except Exception:
        return 0.0


def bounty_key(f: Any) -> Tuple[float, int]:
    """Sort key for bounty mode: (-impact*confidence, -confidence)."""
    return (-bounty_score(f), -confidence_of(f))


def prioritize_bounty(findings: List[Any],
                      limit: Optional[int] = None) -> List[Any]:
    """Big-findings-first ordering for bounty mode.

    Stable: ties keep input order. Does not mutate the input list.
    """
    ordered = sorted(findings, key=bounty_key)
    if limit is not None:
        ordered = ordered[:max(limit, 0)]
    return ordered


def annotate_impact(findings: List[Any]) -> List[Any]:
    """Stamp each finding dict's evidence with its impact score.

    Mutates evidence dicts in place (best-effort). Returns findings unchanged
    in order (sorting is the caller's job).
    """
    for f in findings:
        try:
            if isinstance(f, dict):
                ev = f.get("evidence")
                if isinstance(ev, dict) and "impact" not in ev:
                    ev["impact"] = impact_of(f)
            else:
                ev = _evidence(f)
                if isinstance(ev, dict) and "impact" not in ev:
                    ev["impact"] = impact_of(f)
        except Exception:
            pass
    return findings
