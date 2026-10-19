"""Finding prioritizer: auto-prioritize by exploitability.

Sort order (what Jay looks at first):
  1. Exploitability tier: weaponized > public_poc > theoretical > unknown
     (a weaponized medium beats a theoretical high - it can be used NOW)
  2. Severity within a tier: critical > high > medium > low
  3. Confidence, descending, as the final tiebreak

Works on ``Finding`` dataclass instances, finding dicts (as published on
the "poc_findings" / "deduped_findings" bus), or DB row objects - any
object with ``evidence``/``confidence``/``bounty_value`` attributes or
keys. Never raises: unparseable findings sort last.

Usage:
    from backend.app.prioritizer import prioritize
    ordered = prioritize(findings)          # new sorted list
    top5 = prioritize(findings, limit=5)
"""
from __future__ import annotations

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
