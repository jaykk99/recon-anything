"""Precision gate: false positives are never presented as weaknesses.

These are the shapes that actually reach the run view from a wide plugin
registry, as pure engine tests: a CVE matched without a version, a
takeover claim on a CNAME that still resolves, a "missing header" report
on a page that never loaded, a backup "found" on a 403, a sample key from
documentation, a contract the validator already killed, and an attack
path chained out of those. Each one must come back judged, never silently
presented as a confirmed finding - and never silently deleted either.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.precision import (CLAIM_CANDIDATE, CLAIM_SUPPRESSED,  # noqa: E402
                           CLAIM_VERIFIED, apply, claim_family,
                           is_suppressed, judge_row, summary)

REAL_AWS_KEY = "AKIA2E0A8F3B244C9986"
SAMPLE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _row(**kw):
    row = {"id": kw.pop("id", 1), "plugin": "test", "category": "web",
           "key": "k", "value": "v", "source": "test", "source_url": None,
           "confidence": 80, "confidence_score": 80, "passive": False,
           "evidence": {"severity": "high"}}
    row.update(kw)
    return row


# ---------------------------------------------------------------------------
# CVE matching
# ---------------------------------------------------------------------------

def test_cve_without_observed_version_is_a_candidate_not_a_finding():
    row = _row(plugin="cves", key="cve_match",
               value="HIGH: Apache - RCE [CVE-2021-41773] (version not "
                     "disclosed - verify manually)",
               evidence={"severity": "high",
                         "detected_version": "unknown",
                         "cve": "CVE-2021-41773"})
    judged = judge_row(row)
    assert judged["claim_status"] == CLAIM_CANDIDATE
    assert "version" in " ".join(judged["missing"]).lower()


def test_cve_with_observed_version_is_verified():
    row = _row(plugin="cves", key="cve_match",
               value="HIGH: Apache 2.4.49 - path traversal [CVE-2021-41773]",
               evidence={"severity": "high",
                         "detected_version": "2.4.49",
                         "cve": "CVE-2021-41773"})
    assert judge_row(row)["claim_status"] == CLAIM_VERIFIED


# ---------------------------------------------------------------------------
# Exposures
# ---------------------------------------------------------------------------

def test_exposure_contradicted_by_404_is_suppressed_and_kept():
    row = _row(category="leak", key="artifact_exposed",
               value="/.env returned 404 - not found",
               evidence={"severity": "medium"})
    out = apply([row])
    assert len(out) == 1  # never deleted
    assert out[0]["claim_status"] == CLAIM_SUPPRESSED
    assert out[0]["suppressed"] is True
    assert "404" in out[0]["precision"]["reason"]
    assert out[0]["confidence_tier"] == "weak"


def test_exposure_with_200_is_verified():
    row = _row(category="leak", key="artifact_exposed",
               value="/.env returned 200 - dotenv: APP_KEY=base64:...",
               evidence={"severity": "high"}, passive=False)
    judged = judge_row(row)
    assert judged["claim_status"] == CLAIM_VERIFIED
    assert "200" in " ".join(judged["basis"])


def test_exposure_on_error_page_stays_candidate():
    row = _row(category="leak", key="artifact_exposed",
               value="/backup.zip returned 503 - service unavailable",
               evidence={"severity": "medium"})
    assert judge_row(row)["claim_status"] == CLAIM_CANDIDATE


def test_catch_all_baseline_page_is_not_an_exposure():
    row = _row(category="leak", key="artifact_exposed",
               value="/backup.zip returned 200",
               evidence={"severity": "high",
                         "note": "response identical to the 200 catch-all "
                                 "baseline for this host"})
    assert judge_row(row)["claim_status"] == CLAIM_SUPPRESSED


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

def test_documentation_sample_key_is_suppressed():
    row = _row(category="leak", key="exposed_aws_key", value=SAMPLE_AWS_KEY,
               evidence={"severity": "high"})
    judged = judge_row(row)
    assert judged["claim_status"] == CLAIM_SUPPRESSED
    assert "placeholder" in judged["reason"].lower()


def test_live_looking_key_is_verified():
    row = _row(category="leak", key="exposed_aws_key", value=REAL_AWS_KEY,
               source_url="https://target.example/app.js",
               evidence={"severity": "high", "snippet":
                         f'const k = "{REAL_AWS_KEY}"'})
    assert judge_row(row)["claim_status"] == CLAIM_VERIFIED


def test_named_password_without_a_value_stays_candidate():
    row = _row(category="leak", key="hardcoded_password",
               value="password field present in config object",
               evidence={"severity": "medium"})
    judged = judge_row(row)
    assert judged["claim_status"] == CLAIM_CANDIDATE
    assert judged["missing"]


# ---------------------------------------------------------------------------
# Takeover
# ---------------------------------------------------------------------------

def test_takeover_possible_is_never_confirmed():
    row = _row(category="infra", key="takeover_possible",
               value="blog.example.com CNAMEs to foo.herokuapp.com. Target "
                     "still resolves, so not confirmed dangling",
               evidence={"severity": "medium", "cname_target":
                         "foo.herokuapp.com"})
    judged = judge_row(row)
    assert judged["claim_status"] == CLAIM_CANDIDATE
    assert "unclaimed" in " ".join(judged["missing"]).lower()


def test_takeover_with_dangling_target_is_verified():
    row = _row(category="infra", key="subdomain_takeover",
               value="HIGH: old.example.com CNAMEs to gone.herokuapp.com and "
                     "looks CLAIMABLE",
               evidence={"severity": "high", "dangling": True,
                         "fingerprint_match": False})
    assert judge_row(row)["claim_status"] == CLAIM_VERIFIED


# ---------------------------------------------------------------------------
# Hygiene on a page that never loaded
# ---------------------------------------------------------------------------

def test_missing_header_on_failed_fetch_is_a_candidate():
    row = _row(key="missing_security_header",
               value="Strict-Transport-Security header missing",
               passive=True,
               evidence={"severity": "low", "status": 0})
    judged = judge_row(row)
    assert judged["claim_status"] == CLAIM_CANDIDATE
    assert "never loaded" in judged["reason"].lower()


def test_missing_header_on_a_served_page_is_verified():
    row = _row(key="missing_security_header",
               value="Content-Security-Policy header missing",
               passive=True,
               evidence={"severity": "low", "status": 200,
                         "headers": {"server": "nginx"}})
    assert judge_row(row)["claim_status"] == CLAIM_VERIFIED


# ---------------------------------------------------------------------------
# Contract verdicts are respected, not re-invented
# ---------------------------------------------------------------------------

def test_validator_false_positive_suppresses_the_row():
    row = _row(key="validator_verdict", value="withdraw: drain candidate",
               evidence={"severity": "high",
                         "verdict": {"verdict": "FALSE_POSITIVE",
                                     "reason": "stranger probe reverted"}})
    judged = judge_row(row)
    assert judged["claim_status"] == CLAIM_SUPPRESSED
    assert "validator" in judged["reason"].lower()


def test_validator_unverified_names_the_missing_evidence():
    row = _row(key="validator_verdict", value="withdraw: drain candidate",
               evidence={"severity": "high",
                         "verdict": {"verdict": "UNVERIFIED",
                                     "missing": ["measured receipt"]}})
    judged = judge_row(row)
    assert judged["claim_status"] == CLAIM_CANDIDATE
    assert "measured receipt" in " ".join(judged["missing"])


# ---------------------------------------------------------------------------
# Cross-row passes
# ---------------------------------------------------------------------------

def test_contradicting_port_states_both_become_candidates():
    open_row = _row(id=1, plugin="ports", key="port_open",
                    value="port 6379 open", evidence={"severity": "medium",
                                                      "port": 6379,
                                                      "host": "db.example"},
                    passive=False)
    closed_row = _row(id=2, plugin="port_audit", key="port_closed",
                      value="port 6379 closed", evidence={"severity": "low",
                                                          "port": 6379,
                                                          "host": "db.example"})
    apply([open_row, closed_row])
    assert open_row["claim_status"] == CLAIM_CANDIDATE
    assert "disagree" in open_row["precision"]["reason"].lower()


def test_attack_path_is_only_as_proven_as_its_weakest_component():
    secret = _row(id=1, category="leak", key="exposed_aws_key",
                  value=REAL_AWS_KEY, evidence={"severity": "high"})
    weak = _row(id=2, plugin="cves", key="cve_match",
                value="CVE-2021-41773 matched",
                evidence={"severity": "high",
                          "detected_version": "unknown"})
    path = _row(id=3, plugin="correlation", category="graph",
                key="attack_path", value="credential leak -> traversal",
                evidence={"severity": "high", "components": [
                    {"id": 1, "plugin": "test", "key": "exposed_aws_key"},
                    {"id": 2, "plugin": "cves", "key": "cve_match"}]})
    apply([secret, weak, path])
    assert path["claim_status"] == CLAIM_CANDIDATE
    assert path["needs_manual_verification"] is True
    assert any("cve_match" in m for m in path["precision"]["missing"])


def test_attack_path_with_a_suppressed_component_is_suppressed():
    dead = _row(id=1, category="leak", key="artifact_exposed",
                value="/.git/config returned 404",
                evidence={"severity": "high"})
    header = _row(id=2, key="missing_security_header",
                  value="HSTS missing",
                  evidence={"severity": "low", "status": 200})
    path = _row(id=3, plugin="correlation", category="graph",
                key="attack_path", value="git leak -> takeover",
                evidence={"severity": "high", "components": [
                    {"id": 1, "plugin": "test", "key": "artifact_exposed"},
                    {"id": 2, "plugin": "test",
                     "key": "missing_security_header"}]})
    apply([dead, header, path])
    assert dead["suppressed"] is True
    assert path["claim_status"] == CLAIM_SUPPRESSED


def test_attack_path_of_verified_components_is_verified():
    secret = _row(id=1, category="leak", key="exposed_aws_key",
                  value=REAL_AWS_KEY, evidence={"severity": "high"})
    header = _row(id=2, key="missing_security_header",
                  value="HSTS missing",
                  evidence={"severity": "low", "status": 200})
    path = _row(id=3, plugin="correlation", category="graph",
                key="attack_path", value="key -> admin",
                evidence={"severity": "high", "components": [
                    {"id": 1, "plugin": "test", "key": "exposed_aws_key"},
                    {"id": 2, "plugin": "test",
                     "key": "missing_security_header"}]})
    apply([secret, header, path])
    assert path["claim_status"] == CLAIM_VERIFIED


# ---------------------------------------------------------------------------
# Presentation contract
# ---------------------------------------------------------------------------

def test_candidate_is_capped_out_of_the_confirmed_tier():
    row = _row(plugin="cves", key="cve_match", value="CVE match",
               confidence=95, confidence_score=95,
               evidence={"severity": "high",
                         "detected_version": "unknown"})
    apply([row])
    assert row["confidence_tier"] != "confirmed"
    assert row["confidence_score"] <= 70
    assert row["needs_manual_verification"] is True


def test_suppressed_rows_sort_last_but_are_never_dropped():
    good = _row(id=1, key="tech", value="nginx")
    bad = _row(id=2, category="leak", key="artifact_exposed",
               value="/.env returned 403", evidence={"severity": "high"})
    out = apply([bad, good])
    assert len(out) == 2
    assert out[-1] is bad
    assert is_suppressed(bad)


def test_summary_counts_and_share_are_honest():
    rows = [
        _row(id=1, key="tech", value="nginx"),
        _row(id=2, plugin="cves", key="cve_match", value="CVE",
             evidence={"severity": "high", "detected_version": "unknown"}),
        _row(id=3, category="leak", key="artifact_exposed",
             value="/.env returned 404", evidence={"severity": "high"}),
    ]
    apply(rows)
    s = summary(rows)
    assert s["claims"][CLAIM_VERIFIED] == 1
    assert s["claims"][CLAIM_CANDIDATE] == 1
    assert s["claims"][CLAIM_SUPPRESSED] == 1
    assert s["graded"] == 3
    assert 0.0 < s["verified_share"] < 1.0
    assert s["suppressed"][0]["key"] == "artifact_exposed"
    assert len(s["candidates"]) == 1


def test_family_detection_covers_the_claim_classes():
    cases = {
        "cve_match": "cve",
        "exposed_aws_key": "secret",
        "subdomain_takeover": "takeover",
        "artifact_exposed": "exposure",
        "xss_reflected": "web_vuln",
        "missing_security_header": "hygiene",
        "tech": "observation",
    }
    for key, family in cases.items():
        assert claim_family(_row(key=key)) == family, key


def test_gate_never_raises_on_hostile_rows():
    hostile = [None, {}, {"key": None, "evidence": "not-a-dict"},
               {"key": "cve_match", "evidence": {"detected_version": None}},
               {"key": object(), "value": object(), "confidence": "x"},
               {"precison": {}}]
    out = apply(hostile)
    assert len(out) == len(hostile)
    for row in out:
        if isinstance(row, dict):
            assert row.get("claim_status") is not None
