"""Shared helpers for the zero-day candidate hunters.

The hunters in this pack (zeroday_differential, zeroday_error_miner,
zeroday_contract_guards) exist to surface behavior that is NOT on any
known checklist: responses that change shape in ways the input change
cannot explain, public contract functions that break their own
contract's guard convention, error paths that disclose internals no
other probe reached.

Honesty contract (applies to every finding these plugins emit):

- Every candidate is labeled candidate_zero_day with a confidence and
  the anomaly evidence. A candidate is a lead for a human, never a
  verdict: the word that means "proven" never appears in these
  findings. Severity is capped at HIGH no matter how bad it looks -
  only a human replay can raise it.
- Evidence is request/response METADATA plus error text the target
  itself returned (status, sizes, field names, error messages). When
  a mutation makes a target return data it should not, the finding
  records the response SHAPE (status, size, field names) - never a
  dump of the returned records.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

CANDIDATE_KEY = "candidate_zero_day"

_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def cap_severity(severity: str, cap: str = "high") -> str:
    """Normalize a severity and clamp it at the cap (default high)."""
    sev = (severity or "low").strip().lower()
    if sev not in _SEV_RANK:
        sev = "low"
    if _SEV_RANK[sev] > _SEV_RANK[cap]:
        return cap
    return sev


def candidate_evidence(hunter: str, anomaly: str, confidence: int,
                       extra: Dict[str, Any] | None = None,
                       severity: str = "medium") -> Dict[str, Any]:
    """Build the standard evidence block for a candidate finding.

    Every candidate carries: the label, which hunter found it, the
    anomaly class, a numeric confidence, and review_status making the
    unproven state explicit in the data itself - not just the prose.
    """
    ev: Dict[str, Any] = dict(extra or {})
    ev.update({
        "candidate_zero_day": True,
        "hunter": hunter,
        "anomaly": anomaly,
        "review_status": "pending human review - not yet verified",
        "severity": cap_severity(str(ev.get("severity", severity))),
    })
    ev["confidence"] = max(1, min(100, int(confidence)))
    return ev


# ---------------------------------------------------------------------
# Internal-disclosure mining (error-path miner + differential hunter)
# ---------------------------------------------------------------------
# Each entry: (kind, severity, label, regexes, is_code_path).
# is_code_path marks disclosures that reveal the target's own source
# layout - a code path nothing else disclosed - which the error-path
# miner additionally labels as a candidate.

DISCLOSURE_PATTERNS: List = [
    ("internal_file_path", "medium",
     "internal source file path disclosed",
     [r"(?:/[\w.\-]+){2,}\.(?:py|php|rb|js|ts|java|go|cs|pl|scala|kt)"
      r"(?::\s*line\s*\d+|,\s*line\s*\d+|:\d+\b)",
      r"[A-Za-z]:\\(?:[\w.\-]+\\)+[\w.\-]+\.(?:cs|aspx|php|js|ts)\b",
      r"/(?:var/www|srv|opt|home/[\w.\-]+|usr/local|app|code)/[\w./\-]*\."
      r"(?:py|php|rb|js|ts|java|go|cs)\b"],
     True),
    ("sql_fragment", "medium",
     "SQL error detail disclosed",
     [r"You have an error in your SQL syntax[^<]{0,160}",
      r"(?:relation|table|column)\s+\"[^\"]+\"\s+does not exist",
      r"ORA-\d{5}[^<]{0,120}",
      r"(?:SQLite|sqlite3)[^\n<]{0,80}?(?:error|exception)[^<]{0,120}",
      r"unterminated quoted string[^<]{0,120}",
      r"syntax error at or near \"[^\"]+\"[^<]{0,80}",
      r"(?:PDOException|SQLSTATE\[)[^<]{0,140}"],
     False),
    ("debug_output", "high",
     "stack trace / debug output disclosed",
     [r"Traceback \(most recent call last\)",
      r"(?:^|\n)\s*at [\w.$]+\([\w.]+:\d+\)",
      r"werkzeug\.exceptions|Werkzeug Debugger",
      r"DEBUG\s*=\s*True|\"debug\"\s*:\s*true",
      r"Whoops, looks like something went wrong",
      r"Stack trace:\s*\n(?:.|\n){0,200}?#\d+\s"],
     False),
    ("internal_hostname", "medium",
     "internal hostname disclosed",
     [r"\b[\w\-]+(?:\.[\w\-]+)*\.(?:internal|intranet|corp|lan|local)\b"
      r"(?::\d{2,5})?",
      r"\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.[\w.\-]*internal\b",
      r"\blocalhost:\d{2,5}\b",
      r"\b[\w\-]+\.[\w\-]+\.svc\.cluster\.local\b"],
     False),
    ("internal_ip", "medium",
     "private-range IP address disclosed",
     [r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?\b",
      r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
      r"\b192\.168\.\d{1,3}\.\d{1,3}(?::\d{2,5})?\b"],
     False),
    ("env_var_name", "medium",
     "environment variable / config key name disclosed",
     [r"(?:KeyError|missing|unset|not set)[^\n<]{0,60}?"
      r"['\"]([A-Z][A-Z0-9_]{3,})['\"]",
      r"\bprocess\.env\.([A-Z][A-Z0-9_]{2,})",
      r"\b(?:DATABASE_URL|REDIS_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY|"
      r"PRIVATE_KEY|API_SECRET|DB_PASSWORD|JWT_SECRET)\b"
      r"[^\n<]{0,60}?(?:not set|missing|undefined|required)"],
     False),
    ("framework_version", "low",
     "framework / runtime version disclosed in error output",
     [r"\bDjango/\d+\.\d+(?:\.\d+)?",
      r"\bRuby on Rails\s*\d+\.\d+(?:\.\d+)?",
      r"\bLaravel\s*(?:Framework\s*)?\d+\.\d+(?:\.\d+)?",
      r"\bSpring Boot\s*v?\d+\.\d+(?:\.\d+)?",
      r"\bPHP/\d+\.\d+\.\d+",
      r"\bASP\.NET Version:\s*\d+\.\d+\.\d+",
      r"\bWerkzeug/\d+\.\d+(?:\.\d+)?",
      r"\bTomcat/\d+\.\d+(?:\.\d+)?"],
     False),
]

_COMPILED = [(kind, sev, label,
              [re.compile(p) for p in pats], is_path)
             for kind, sev, label, pats, is_path in DISCLOSURE_PATTERNS]

_SNIP = 220


def mine_disclosures(text: str) -> List[Dict[str, Any]]:
    """Mine a response body for internal disclosures.

    Returns distinct disclosures: [{kind, severity, label, match,
    context, is_code_path}]. Deduped by (kind, matched text) so the
    same leaked path in ten error pages is one finding. The match and
    its context are the target's own error text - shown in full per
    the standing findings rule.
    """
    if not text:
        return []
    out: List[Dict[str, Any]] = []
    seen = set()
    for kind, sev, label, pats, is_path in _COMPILED:
        for pat in pats:
            for m in pat.finditer(text):
                matched = (m.group(1) if m.lastindex else m.group(0))
                matched = (matched or m.group(0)).strip()
                dedup_key = (kind, matched.lower())
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                lo = max(0, m.start() - 60)
                hi = min(len(text), m.end() + 60)
                context = " ".join(text[lo:hi].split())[:_SNIP]
                out.append({"kind": kind, "severity": sev,
                            "label": label, "match": matched,
                            "context": context, "is_code_path": is_path})
    return out
