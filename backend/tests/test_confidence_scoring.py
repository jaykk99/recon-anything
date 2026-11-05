"""Tests for app/confidence.py - scoring, tiering, duplicate merge.

The anti-SpiderFoot noise filter: deterministic rules over finding
rows (the findings_dump dict shape), no network, no DB.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.confidence import (annotate_confidence, merge_duplicates,  # noqa: E402
                            tier_counts, tier_for)


def _row(**kw):
    base = {"id": 1, "target_id": "t1", "plugin": "dns", "category": "dns",
            "key": "subdomain", "value": "api.example.com",
            "source": "dns", "source_url": None, "evidence": None,
            "confidence": 80, "passive": True, "bounty_value": "low"}
    base.update(kw)
    return base


# -- tiers ---------------------------------------------------------------

def test_tier_boundaries():
    assert tier_for(100) == "confirmed"
    assert tier_for(75) == "confirmed"
    assert tier_for(74) == "likely"
    assert tier_for(45) == "likely"
    assert tier_for(44) == "weak"
    assert tier_for(0) == "weak"


# -- merge ---------------------------------------------------------------

def test_merge_collapses_same_fact_from_two_plugins():
    rows = [_row(id=1, plugin="dns", confidence=70),
            _row(id=2, plugin="subdomains", confidence=90,
                 source="crt.sh")]
    out = merge_duplicates(rows)
    assert len(out) == 1
    assert out[0]["merged_count"] == 2
    assert out[0]["confidence"] == 90  # strongest claim survives
    assert out[0]["also_from"] == ["subdomains"]
    assert out[0]["also_sources"] == ["crt.sh"]


def test_merge_normalizes_value_variants():
    rows = [_row(id=1, value="API.Example.com"),
            _row(id=2, value="api.example.com."),
            _row(id=3, value="api.example.com  ")]
    out = merge_duplicates(rows)
    assert len(out) == 1
    assert out[0]["merged_count"] == 3


def test_merge_keeps_distinct_facts_apart():
    rows = [_row(id=1, value="api.example.com"),
            _row(id=2, value="admin.example.com"),
            _row(id=3, key="a", value="api.example.com"),
            _row(id=4, target_id="t2", value="api.example.com")]
    out = merge_duplicates(rows)
    assert len(out) == 4


def test_merge_active_duplicate_upgrades_keeper():
    rows = [_row(id=1, passive=True), _row(id=2, passive=False)]
    out = merge_duplicates(rows)
    assert out[0]["passive"] is False


# -- scoring -------------------------------------------------------------

def test_corroboration_raises_score_and_reason_names_it():
    rows = [_row(id=1, plugin="dns", confidence=70),
            _row(id=2, plugin="subdomains", confidence=70)]
    out = annotate_confidence(rows)
    assert len(out) == 1
    assert out[0]["confidence_score"] == 78  # 70 + 8 corroboration
    assert "2 independent plugins" in out[0]["confidence_reason"]
    assert out[0]["confidence_tier"] == "confirmed"


def test_heuristic_candidates_are_capped():
    out = annotate_confidence([_row(key="username_candidates",
                                    value="guessed handles", confidence=95)])
    assert out[0]["confidence_score"] <= 55
    assert out[0]["confidence_tier"] != "confirmed"
    assert "heuristic" in out[0]["confidence_reason"]


def test_note_keys_are_capped_lower():
    out = annotate_confidence([_row(key="hibp_note", confidence=90)])
    assert out[0]["confidence_score"] <= 50


def test_weak_single_low_confidence_report():
    out = annotate_confidence([_row(confidence=30)])
    assert out[0]["confidence_score"] == 30
    assert out[0]["confidence_tier"] == "weak"
    assert out[0]["confidence_label"] == "Weak signal"


def test_direct_probe_and_evidence_boost():
    out = annotate_confidence([_row(
        confidence=70, passive=False,
        evidence={"status_code": 200, "severity": "medium"})])
    # 70 + 6 evidence + 6 direct probe
    assert out[0]["confidence_score"] == 82
    assert out[0]["confidence_tier"] == "confirmed"


def test_attack_path_component_boost():
    comps = [{"plugin": "a"}, {"plugin": "b"}, {"plugin": "c"}]
    out = annotate_confidence([_row(
        plugin="correlation", key="attack_path", confidence=70,
        evidence={"components": comps})])
    assert out[0]["confidence_score"] == 78  # 70 + 4*2
    assert "chains 3 independent findings" in out[0]["confidence_reason"]


def test_score_clamped_to_100():
    rows = [_row(id=1, confidence=98, passive=False,
                 evidence={"status": 200}),
            _row(id=2, plugin="other", confidence=98)]
    out = annotate_confidence(rows)
    assert out[0]["confidence_score"] == 100


def test_every_row_gets_score_tier_reason():
    rows = [_row(id=1), _row(id=2, key="tech", value="nginx"),
            _row(id=3, key="a", value="1.2.3.4", confidence=95)]
    out = annotate_confidence(rows)
    for r in out:
        assert 0 <= r["confidence_score"] <= 100
        assert r["confidence_tier"] in ("confirmed", "likely", "weak")
        assert r["confidence_reason"]


def test_tier_counts():
    rows = annotate_confidence([
        _row(id=1, confidence=95),
        _row(id=2, key="tech", value="nginx", confidence=60),
        _row(id=3, key="a", value="1.2.3.4", confidence=10)])
    counts = tier_counts(rows)
    assert counts == {"confirmed": 1, "likely": 1, "weak": 1}
