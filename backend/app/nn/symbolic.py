"""Neuro-symbolic layer: named, auditable rules over symbolic facts.

The neural net proposes a triage score; the symbolic layer can veto
it or boost / dampen it, and every combined decision cites which
rules fired. The neural net never overrides a symbolic veto on its
own: a veto forces the combined score to 0.0 (likely-false-positive)
no matter what the net said.

Facts come from the same real fields the features use (recipient,
gate, severity, proxy / implementation presence, source, confidence,
bounty, risk, counts). No rule reads a label, a verdict, or a
live-probe outcome.

Rules are validated on the TRAINING set only, before evaluation:
a boost needs coverage >= 20 rows and precision above the training
base rate; a dampen needs coverage >= 20 and precision below the
base rate; a veto needs coverage >= 20 and precision >= 0.90 on
label 0. Rules that fail validation are dropped and listed as
dropped with the reason — they are never silently kept.

The combined model still never predicts VERIFIED_REAL: its labels
are worth-validating / likely-false-positive only, same as the
scorer.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Sequence, Tuple

MIN_RULE_COVERAGE = 20
VETO_MIN_PRECISION = 0.90


def extract_facts(row: Dict) -> Dict:
    """Named symbolic facts for one row (data.py row shape)."""
    finding = row.get("finding") or {}
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    try:
        conf = float(finding.get("confidence") or 0)
    except (TypeError, ValueError):
        conf = 0.0
    try:
        count = float(finding.get("plugin_finding_count") or 1)
    except (TypeError, ValueError):
        count = 1.0
    recipient = str(finding.get("recipient_class") or "OTHER").upper()
    # The finding-level recipient_class is derived and lossy (it never
    # says FIXED / HOLDER-SELF in this data); the evidence recipient
    # holds the real value, so it is the fallback for both checks.
    ev_recipient = str(ev.get("recipient") or "").upper()
    gate = str(ev.get("gate_analysis") or "")
    return {
        "recipient_class": recipient,
        "recipient_is_caller": recipient in ("CALLER", "CALLER-SUPPLIED")
            or ev_recipient in ("CALLER", "CALLER-SUPPLIED"),
        "recipient_is_fixed": recipient in ("FIXED", "HOLDER-SELF")
            or ev_recipient in ("FIXED", "HOLDER-SELF"),
        "gated": bool(ev.get("gated")),
        "gate_no_caller": "no caller gate" in gate.lower(),
        "gate_present": bool(gate),
        "severity": str(finding.get("severity")
                        or ev.get("severity") or "").lower(),
        "risk": str(ev.get("risk") or "").lower(),
        "bounty_value": str(finding.get("bounty_value") or "").lower(),
        "confidence": max(0.0, min(100.0, conf)),
        "has_proxy": bool(ev.get("proxy_address")),
        "has_implementation": bool(ev.get("implementation_address")),
        "has_source": bool(ev.get("source_origin")),
        "source_origin": str(ev.get("source_origin") or ""),
        "contract_role": str(ev.get("contract_role") or "").lower(),
        "plugin": str(finding.get("plugin") or ""),
        "function": str(finding.get("function")
                        or ev.get("function") or ""),
        "plugin_finding_count": count,
        "evidence_count": len(ev),
        "detector_present": ev.get("detector_outcome") not in (None, ""),
    }


# Rule table: (name, kind, delta, description, condition).
# kind: "veto" forces combined 0.0; "boost"/"dampen" shift the
# neural score by delta (clipped to [0, 1] afterwards).
def _rule_table() -> List[Dict]:
    return [
        {
            "name": "VETO_FIXED_RECIPIENT",
            "kind": "veto",
            "delta": 0.0,
            "description": "Recipient is FIXED or HOLDER-SELF: by the "
                           "triage boundary only CALLER / "
                           "CALLER-SUPPLIED recipients can be "
                           "worth validating.",
            "condition": lambda f: f["recipient_is_fixed"],
        },
        {
            "name": "BOOST_NO_GATE_HIGH_SEV",
            "kind": "boost",
            "delta": 0.15,
            "description": "No caller gate on a high/critical finding: "
                           "an ungated sensitive path.",
            "condition": lambda f: (f["gate_no_caller"]
                                    and f["severity"] in ("high", "critical")),
        },
        {
            "name": "BOOST_PROXY_IMPL",
            "kind": "boost",
            "delta": 0.08,
            "description": "Proxy shell with a live implementation: "
                           "upgradeable surface worth a look.",
            "condition": lambda f: (f["has_proxy"]
                                    and f["has_implementation"]),
        },
        {
            "name": "DAMPEN_BYTECODE_ONLY",
            "kind": "dampen",
            "delta": -0.10,
            "description": "No verified source: bytecode-only finding, "
                           "harder to confirm.",
            "condition": lambda f: not f["has_source"],
        },
        {
            "name": "BOOST_CALLER_HIGH_CONF",
            "kind": "boost",
            "delta": 0.10,
            "description": "Caller-receivable finding at high "
                           "confidence (>= 80).",
            "condition": lambda f: (f["recipient_is_caller"]
                                    and f["confidence"] >= 80.0),
        },
        {
            "name": "BOOST_HIGH_BOUNTY",
            "kind": "boost",
            "delta": 0.05,
            "description": "High/critical bounty value on the finding.",
            "condition": lambda f: f["bounty_value"] in ("high", "critical"),
        },
        {
            "name": "DAMPEN_LOW_RISK_LOW_SEV",
            "kind": "dampen",
            "delta": -0.08,
            "description": "Low risk and low severity: weak signal.",
            "condition": lambda f: (f["risk"] == "low"
                                    and f["severity"] == "low"),
        },
        {
            "name": "BOOST_MULTI_FINDING",
            "kind": "boost",
            "delta": 0.05,
            "description": "Same plugin fired 5+ times on this "
                           "contract: corroborated pattern.",
            "condition": lambda f: f["plugin_finding_count"] >= 5,
        },
    ]


def validate_rules(rows: Sequence[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Validate the rule table on training rows only.

    Returns (kept, dropped); each entry carries coverage, precision
    and the base rate it was judged against. Precision for a boost is
    the share of covered rows labeled worth-validating; for a dampen
    it is the share labeled likely-FP; for a veto it is the share
    labeled likely-FP (must be >= 0.90).
    """
    labels = [int(r["label"]) for r in rows]
    n = len(labels)
    base_rate = sum(labels) / n if n else 0.0
    facts = [extract_facts(r) for r in rows]
    kept: List[Dict] = []
    dropped: List[Dict] = []
    for rule in _rule_table():
        covered = [i for i, f in enumerate(facts)
                   if rule["condition"](f)]
        cov = len(covered)
        if cov == 0:
            record = dict(rule)
            record.pop("condition", None)
            record.update({"coverage": 0, "precision": 0.0,
                           "base_rate": base_rate,
                           "status": "dropped: no coverage"})
            dropped.append(record)
            continue
        if rule["kind"] == "veto":
            prec = sum(1 for i in covered if labels[i] == 0) / cov
            ok = cov >= MIN_RULE_COVERAGE and prec >= VETO_MIN_PRECISION
            reason = "" if ok else (
                f"coverage {cov} < {MIN_RULE_COVERAGE}"
                if cov < MIN_RULE_COVERAGE
                else f"veto precision {prec:.3f} < {VETO_MIN_PRECISION}")
        elif rule["kind"] == "boost":
            prec = sum(1 for i in covered if labels[i] == 1) / cov
            ok = cov >= MIN_RULE_COVERAGE and prec > base_rate
            reason = "" if ok else (
                f"coverage {cov} < {MIN_RULE_COVERAGE}"
                if cov < MIN_RULE_COVERAGE
                else f"boost precision {prec:.3f} <= base rate {base_rate:.3f}")
        else:  # dampen
            prec = sum(1 for i in covered if labels[i] == 0) / cov
            ok = cov >= MIN_RULE_COVERAGE and (1.0 - prec) < base_rate
            reason = "" if ok else (
                f"coverage {cov} < {MIN_RULE_COVERAGE}"
                if cov < MIN_RULE_COVERAGE
                else f"dampen precision {prec:.3f} does not beat base rate "
                     f"{base_rate:.3f}")
        record = dict(rule)
        record.pop("condition", None)
        record.update({"coverage": cov, "precision": round(prec, 4),
                       "base_rate": round(base_rate, 4),
                       "status": "kept" if ok else f"dropped: {reason}"})
        (kept if ok else dropped).append(record)
    return kept, dropped


def _kept_rule_by_name(kept: Sequence[Dict]) -> Dict[str, Dict]:
    table = {r["name"]: r for r in _rule_table()}
    out = {}
    for k in kept:
        full = table.get(k["name"])
        if full is not None:
            out[k["name"]] = full
    return out


def apply_rules(facts: Dict, kept: Sequence[Dict]) -> Dict:
    """Apply kept rules to one row's facts. Returns {"adjustment",
    "fired": [names], "vetoed": bool, "details": [...]}."""
    rules = _kept_rule_by_name(kept)
    fired: List[str] = []
    details: List[Dict] = []
    adjustment = 0.0
    vetoed = False
    for name, rule in rules.items():
        try:
            hit = bool(rule["condition"](facts))
        except Exception:
            hit = False
        if not hit:
            continue
        fired.append(name)
        details.append({"rule": name, "kind": rule["kind"],
                        "delta": rule["delta"],
                        "description": rule["description"]})
        if rule["kind"] == "veto":
            vetoed = True
        else:
            adjustment += rule["delta"]
    return {"adjustment": round(adjustment, 4), "fired": fired,
            "vetoed": vetoed, "details": details}


def symbolic_score(facts: Dict, kept: Sequence[Dict]) -> Tuple[float, Dict]:
    """Rules-only score: 0.5 baseline shifted by fired rules, veto
    forces 0.0. Returns (score, apply_rules result)."""
    res = apply_rules(facts, kept)
    if res["vetoed"]:
        return 0.0, res
    return min(1.0, max(0.0, 0.5 + res["adjustment"])), res


def combine(neural_p: float, facts: Dict, kept: Sequence[Dict],
            threshold: float = 0.5) -> Dict:
    """Combine the neural score with the symbolic layer.

    A veto forces 0.0 regardless of the neural score. Otherwise the
    combined score is the neural score shifted by the fired rules'
    deltas, clipped to [0, 1]. Labels are triage-only.
    """
    res = apply_rules(facts, kept)
    if res["vetoed"]:
        p = 0.0
    else:
        p = min(1.0, max(0.0, float(neural_p) + res["adjustment"]))
    return {"neural_p": round(float(neural_p), 4),
            "combined_p": round(p, 4),
            "label": ("worth-validating" if p >= threshold
                      else "likely-false-positive"),
            "fired_rules": res["fired"],
            "rule_details": res["details"],
            "vetoed": res["vetoed"],
            "adjustment": res["adjustment"]}
