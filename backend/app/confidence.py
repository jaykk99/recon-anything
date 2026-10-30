"""Confidence scoring + noise filtering for findings (anti-SpiderFoot).

SpiderFoot's known weakness is volume: hundreds of modules firing
produces overwhelming noise and false positives that bury the real
signal. This module is the deterministic countermeasure. It runs at
READ time over the finding rows a run already produced (the same
findings_dump dict shape the API and exports serve), using ONLY data
already collected - no new network calls, no new external sources.

Three things happen to every row set:

1. MERGE - exact duplicates collapse. Two plugins reporting the same
   (target, key, normalized value) are one fact, not two findings.
   The merged row keeps the strongest plugin confidence, records
   every plugin/source that reported it (``also_from`` /
   ``also_sources``), and counts the copies (``merged_count``).

2. SCORE - every finding gets a 0-100 confidence score with a plain
   reason a human can audit. The score starts from the plugin's own
   stated confidence and moves on deterministic evidence rules:

   - corroboration: 2+ independent plugins reporting the same fact
     is the strongest cheap signal there is (+8 per extra plugin).
   - captured evidence: a finding carrying concrete artifacts
     (HTTP status, DNS records, matched content) beats an assertion.
   - direct probe: an actively verified finding beats a passive
     third-party mention.
   - chained proof: correlation attack paths cite the independent
     findings they chain; more components, more confidence.
   - heuristic discount: candidate lists and pattern inferences
     (username candidates, email patterns, *_note annotations) are
     guesses by construction and are CAPPED - they can never present
     as confirmed no matter what confidence the plugin claimed.

3. TIER - scores bucket into three tiers the UI filters on:
   ``confirmed`` (>= 75, "Confirmed signal"), ``likely`` (45-74),
   ``weak`` (< 45, "Weak signal"). The results UI shows confirmed +
   likely by default and hides weak noise behind a toggle, with the
   hidden count always visible so nothing is silently dropped.

Pure functions over row dicts; never raises (a scoring bug must not
break the run view - worst case a row keeps its plugin confidence).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

TIER_CONFIRMED = "confirmed"
TIER_LIKELY = "likely"
TIER_WEAK = "weak"

TIER_LABELS = {
    TIER_CONFIRMED: "Confirmed signal",
    TIER_LIKELY: "Likely",
    TIER_WEAK: "Weak signal",
}

CONFIRMED_MIN = 75
LIKELY_MIN = 45

# Keys that are inference by construction: candidate generators and
# pattern guesses. A plugin may claim any confidence for these; the
# claim is not evidence, so the score is capped in the Likely band.
HEURISTIC_KEYS = {
    "username_candidates", "email_pattern", "typosquat_candidate",
    "takeover_candidate", "takeover_possible", "dangling_candidate",
}
HEURISTIC_CAP = 55
# Annotation keys ("..._note") are commentary, not observations.
NOTE_CAP = 50

# Evidence keys that mean the plugin captured something concrete
# (a status, a record set, matched bytes) rather than asserting.
_EVIDENCE_ARTIFACT_KEYS = (
    "status", "status_code", "http_status", "records", "matched",
    "snippet", "content", "headers", "banner", "response",
)

_WS_RE = re.compile(r"\s+")


def normalize_value(value: Any) -> str:
    """Canonical form for duplicate detection: case/space/punct-stable."""
    v = str(value or "").lower().strip()
    v = _WS_RE.sub(" ", v)
    return v.rstrip(".! ")


def tier_for(score: int) -> str:
    if score >= CONFIRMED_MIN:
        return TIER_CONFIRMED
    if score >= LIKELY_MIN:
        return TIER_LIKELY
    return TIER_WEAK


def merge_duplicates(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse rows with the same (target_id, key, normalized value).

    The surviving row is the first occurrence, upgraded in place:
    confidence becomes the max of the group, ``merged_count`` counts
    the copies, ``also_from`` / ``also_sources`` list the other
    plugins / sources that reported the same fact. Row order is
    preserved (first occurrence wins its slot).
    """
    out: List[Dict[str, Any]] = []
    index: Dict[Any, Dict[str, Any]] = {}
    for row in rows:
        key = (row.get("target_id"), row.get("key"),
               normalize_value(row.get("value")))
        keep = index.get(key)
        if keep is None:
            row.setdefault("merged_count", 1)
            row.setdefault("also_from", [])
            row.setdefault("also_sources", [])
            index[key] = row
            out.append(row)
            continue
        keep["merged_count"] = int(keep.get("merged_count", 1)) + 1
        plugin = row.get("plugin")
        if plugin and plugin != keep.get("plugin") \
                and plugin not in keep["also_from"]:
            keep["also_from"].append(plugin)
        source = row.get("source")
        if source and source != keep.get("source") \
                and source not in keep["also_sources"]:
            keep["also_sources"].append(source)
        try:
            keep["confidence"] = max(int(keep.get("confidence") or 0),
                                     int(row.get("confidence") or 0))
        except (TypeError, ValueError):
            pass
        # A duplicate that was actively probed upgrades the keeper:
        # the fact was directly verified at least once.
        if row.get("passive") is False:
            keep["passive"] = False
        # Keep the richest evidence of the group.
        if not keep.get("evidence") and row.get("evidence"):
            keep["evidence"] = row.get("evidence")
    return out


def _score_one(row: Dict[str, Any]) -> (int, str):
    try:
        score = int(row.get("confidence") or 60)
    except (TypeError, ValueError):
        score = 60
    score = max(0, min(score, 100))
    reasons: List[str] = []
    key = str(row.get("key") or "")
    plugin = str(row.get("plugin") or "")
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) \
        else {}

    # Corroboration: independent plugins agreeing on the same fact.
    extra_plugins = len(row.get("also_from") or [])
    if extra_plugins:
        boost = min(8 * extra_plugins, 16)
        score += boost
        n = extra_plugins + 1
        reasons.append(f"reported by {n} independent plugins")
    extra_sources = len(row.get("also_sources") or [])
    if extra_sources and not extra_plugins:
        score += min(4 * extra_sources, 8)
        reasons.append("confirmed by multiple sources")

    # Captured evidence beats assertion.
    if any(k in evidence for k in _EVIDENCE_ARTIFACT_KEYS):
        score += 6
        reasons.append("backed by captured evidence")

    # Direct probe beats passive third-party data.
    if row.get("passive") is False:
        score += 6
        reasons.append("verified by direct probe")

    # Correlation attack paths cite the findings they chain.
    if key == "attack_path" or plugin == "correlation":
        comps = evidence.get("components")
        n = len(comps) if isinstance(comps, list) else 0
        if n > 1:
            score += min(4 * (n - 1), 12)
            reasons.append(f"chains {n} independent findings")

    # Version-pinned matches (a CVE tied to an observed version) are
    # much stronger than a banner guess.
    if evidence.get("version"):
        score += 5
        reasons.append("matched against an observed version")

    score = max(0, min(score, 100))

    # Heuristic caps apply AFTER boosts: a guess corroborated by
    # another guess is still a guess.
    if key in HEURISTIC_KEYS or key.endswith("_candidate"):
        if score > HEURISTIC_CAP:
            score = HEURISTIC_CAP
        reasons.append("heuristic inference, not directly observed")
    elif key.endswith("_note"):
        if score > NOTE_CAP:
            score = NOTE_CAP
        reasons.append("scanner annotation, not an observation")

    if not reasons:
        if extra_plugins or row.get("passive") is False:
            reasons.append("single strong observation")
        else:
            reasons.append("single plugin report")
    return score, "; ".join(reasons)


def annotate_confidence(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge duplicates, then stamp score/tier/reason on every row.

    Mutates and returns the merged list. Never raises.
    """
    try:
        merged = merge_duplicates(rows)
    except Exception:
        merged = rows
    for row in merged:
        try:
            score, reason = _score_one(row)
        except Exception:
            try:
                score = int(row.get("confidence") or 60)
            except (TypeError, ValueError):
                score = 60
            score = max(0, min(score, 100))
            reason = "plugin-stated confidence"
        row["confidence_score"] = score
        row["confidence_tier"] = tier_for(score)
        row["confidence_label"] = TIER_LABELS[row["confidence_tier"]]
        row["confidence_reason"] = reason
    return merged


def tier_counts(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {TIER_CONFIRMED: 0, TIER_LIKELY: 0, TIER_WEAK: 0}
    for row in rows:
        tier = row.get("confidence_tier")
        if tier in counts:
            counts[tier] += 1
    return counts
