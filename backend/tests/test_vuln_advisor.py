"""Tests for vuln_advisor honest-confidence labeling.

Every candidate must carry:
- confidence_basis: WHY we believe the number (direct evidence vs
  heuristic pattern match), and
- needs_manual_verification: False only when the scan directly
  observed the weakness; True for heuristics.

Also covers the 2026-10-20 templates keyed to the new audit plugins.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.vuln_advisor import advise  # noqa: E402


def _f(key, plugin="p", category="web", value="v", evidence=None,
       source_url=None):
    d = {"key": key, "plugin": plugin, "category": category, "value": value,
         "evidence": evidence or {}, "source": "s"}
    if source_url:
        d["source_url"] = source_url
    return d


def _summary():
    return {"targets": [{"normalized": "example.com"}]}


def test_every_candidate_has_confidence_basis():
    findings = [
        _f("graphql_introspection_enabled"),
        _f("phpinfo_exposed", source_url="https://example.com/phpinfo.php"),
        _f("cookie_flags_missing",
           evidence={"severity": "medium"}),
        _f("csp_unsafe_inline"),
        _f("tls_deprecated_version"),
        _f("ip_blocklisted", evidence={"ip": "1.2.3.4"}),
        _f("typosquat_registered", evidence={"domain": "examp1e.com"}),
        _f("hsts_bare_domain_downgrade"),
        _f("http_trace_enabled"),
        _f("smtp_cleartext_auth", evidence={"host": "mx.example.com"}),
        _f("error_stack_trace"),
        _f("debug_django_toolbar"),
    ]
    cands = advise(findings, _summary())
    assert cands, "no candidates produced"
    for c in cands:
        assert c.get("confidence_basis"), \
            f"{c['id']}: missing confidence_basis"
        assert "needs_manual_verification" in c, \
            f"{c['id']}: missing needs_manual_verification"
        assert isinstance(c["needs_manual_verification"], bool)


def test_direct_evidence_not_flagged_for_verification():
    findings = [
        _f("phpinfo_exposed", source_url="https://example.com/phpinfo.php"),
        _f("graphql_introspection_enabled"),
        _f("tls_deprecated_version"),
    ]
    cands = {c["id"]: c for c in advise(findings, _summary())}
    for cid in ("phpinfo", "graphql-introspection", "tls-deprecated"):
        assert cid in cands, f"{cid} not advised"
        assert cands[cid]["needs_manual_verification"] is False, cid
        assert "direct evidence" in cands[cid]["confidence_basis"], cid


def test_heuristics_flagged_for_verification():
    findings = [
        _f("cookie_flags_missing", evidence={"severity": "medium"}),
        _f("csp_unsafe_inline"),
    ]
    cands = {c["id"]: c for c in advise(findings, _summary())}
    assert cands["cookie-flags"]["needs_manual_verification"] is True
    assert cands["csp-bypass"]["needs_manual_verification"] is True
    assert "heuristic" in cands["cookie-flags"]["confidence_basis"]
    assert "heuristic" in cands["csp-bypass"]["confidence_basis"]


def test_no_findings_no_candidates():
    assert advise([], _summary()) == []


def test_ranking_severity_then_confidence():
    findings = [
        _f("cookie_flags_missing", evidence={"severity": "medium"}),
        _f("phpinfo_exposed", source_url="https://example.com/phpinfo.php"),
    ]
    cands = advise(findings, _summary())
    ids = [c["id"] for c in cands]
    # high (phpinfo) outranks medium (cookie-flags) regardless of confidence
    assert ids.index("phpinfo") < ids.index("cookie-flags")


def test_max_eight_candidates():
    findings = [
        _f("graphql_introspection_enabled"),
        _f("phpinfo_exposed", source_url="https://example.com/phpinfo.php"),
        _f("cookie_flags_missing", evidence={"severity": "medium"}),
        _f("csp_unsafe_inline"),
        _f("tls_deprecated_version"),
        _f("ip_blocklisted", evidence={"ip": "1.2.3.4"}),
        _f("typosquat_registered"),
        _f("hsts_bare_domain_downgrade"),
        _f("http_trace_enabled"),
        _f("smtp_cleartext_auth", evidence={"host": "mx.example.com"}),
        _f("error_stack_trace"),
        _f("debug_django_toolbar"),
        _f("artifact_exposed", value=".env"),
    ]
    cands = advise(findings, _summary())
    assert len(cands) <= 8
