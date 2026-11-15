"""Remediation plan: the run does not stop at "here is what exists".

The plan is built from the same adjudicated rows the run view serves, so
these tests pin the contract that matters: suppressed claims never enter
the plan, unproven candidates are ordered behind proven items (their
evidence comes first), every item carries a fix, a verification command
and a re-test acceptance criterion, and the posture score only counts
proven findings.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.precision import CLAIM_CANDIDATE, CLAIM_VERIFIED, apply  # noqa: E402
from app.remediation import build_plan, summary, to_markdown  # noqa: E402

REAL_AWS_KEY = "AKIA2E0A8F3B244C9986"
OTHER_KEY = "ghp_9f3aB7c1D2e4F6a8B0c2D4e6F8a0B2c4D6e8"
CMD = {"label": "list the exposed path", "cmd": "curl -sI https://t/.env"}


def _row(**kw):
    row = {"id": kw.pop("id", 1), "plugin": "test", "category": "web",
           "key": "k", "value": "v", "source": "test",
           "source_url": "https://t/", "confidence": 85,
           "confidence_score": 85, "passive": False,
           "evidence": {"severity": "high"}}
    row.update(kw)
    return row


def _secret_row(**kw):
    ev = {"severity": "high", "exploitability": "weaponized",
          "commands": [CMD], "remediation": "Rotate it now."}
    ev.update(kw.pop("evidence", {}) or {})
    row = _row(category="leak", key="exposed_aws_key", value=REAL_AWS_KEY,
               evidence=ev)
    row.update(kw)
    return row


def test_suppressed_claims_never_enter_the_plan():
    rows = [
        _secret_row(id=1),
        _row(id=2, category="leak", key="artifact_exposed",
             value="/.env returned 404", evidence={"severity": "high"}),
    ]
    apply(rows)
    plan = build_plan(rows)
    routes = {i["route_id"] for i in plan["items"]}
    assert "rotate-credential" in routes
    assert "remove-exposure" not in routes
    assert plan["summary"]["items"] == len(plan["items"])


def test_verified_weaponized_item_is_first_and_has_full_ownership_data():
    rows = [
        _row(id=1, plugin="cves", key="cve_match", value="CVE match",
             evidence={"severity": "high", "detected_version": "unknown"}),
        _secret_row(id=2),
    ]
    apply(rows)
    plan = build_plan(rows)
    first = plan["items"][0]
    assert first["route_id"] == "rotate-credential"
    assert first["priority_label"] == "Now"
    assert first["claim_status"] == CLAIM_VERIFIED
    assert first["owner"] and first["effort"] and first["steps"]
    assert first["verify"][0]["cmd"] == CMD["cmd"]
    assert first["retest"] and first["acceptance"]


def test_unproven_high_severity_is_scheduled_next_not_now():
    rows = [_row(id=1, plugin="cves", key="cve_match", value="CVE match",
                 evidence={"severity": "high",
                           "detected_version": "unknown"})]
    apply(rows)
    plan = build_plan(rows)
    item = plan["items"][0]
    assert item["claim_status"] == CLAIM_CANDIDATE
    assert item["priority_label"] == "Next"
    assert item["findings"][0]["missing"]


def test_hygiene_drift_is_scheduled_later():
    rows = [_row(id=1, key="missing_security_header", value="HSTS missing",
                 passive=True, evidence={"severity": "low", "status": 200})]
    apply(rows)
    plan = build_plan(rows)
    item = plan["items"][0]
    assert item["route_id"] == "harden-config"
    assert item["priority_label"] == "Later"


def test_same_fix_collapses_multiple_detections():
    rows = [
        _secret_row(id=1),
        _secret_row(id=2, key="exposed_github_token", value=OTHER_KEY),
    ]
    apply(rows)
    plan = build_plan(rows)
    rotate = [i for i in plan["items"]
              if i["route_id"] == "rotate-credential"]
    assert len(rotate) == 1
    assert rotate[0]["finding_count"] == 2


def test_inventory_rows_are_not_fix_items():
    rows = [_row(id=1, plugin="dns", category="dns", key="a",
                 value="203.0.113.9", evidence={"severity": "low"})]
    apply(rows)
    plan = build_plan(rows)
    assert plan["items"] == []
    assert "Nothing to fix" in plan["summary"]["next_action"]


def test_posture_counts_only_proven_findings():
    clean = build_plan([])["summary"]["posture"]
    rows = [_secret_row(id=1)]
    apply(rows)
    dirty = build_plan(rows)["summary"]["posture"]
    assert clean["score"] == 100 and clean["grade"] == "A"
    assert dirty["score"] < clean["score"]
    assert dirty["grade"] != "A"
    assert dirty["basis"] == "verified findings only"


def test_plan_grades_rows_itself_when_they_are_ungraded():
    rows = [_secret_row(id=1)]
    assert "claim_status" not in rows[0]
    plan = build_plan(rows)
    assert rows[0]["claim_status"] == CLAIM_VERIFIED
    assert plan["items"]


def test_attack_path_gets_its_own_item():
    rows = [
        _secret_row(id=1),
        _row(id=2, key="missing_security_header", value="HSTS missing",
             evidence={"severity": "low", "status": 200}),
        _row(id=3, plugin="correlation", category="graph", key="attack_path",
             value="key -> admin panel", evidence={
                 "severity": "high", "components": [
                     {"id": 1, "plugin": "test",
                      "key": "exposed_aws_key"},
                     {"id": 2, "plugin": "test",
                      "key": "missing_security_header"}]}),
    ]
    apply(rows)
    plan = build_plan(rows)
    path_items = [i for i in plan["items"]
                  if i["route_id"] == "break-attack-path"]
    assert len(path_items) == 1
    assert "chain" in path_items[0]["why"].lower()


def test_verification_plan_lists_retests_and_acceptance():
    rows = [_secret_row(id=1)]
    apply(rows)
    plan = build_plan(rows)
    assert plan["verification_plan"]
    first = plan["verification_plan"][0]
    assert "secrets" in first["retest_plugins"]
    assert first["acceptance"]


def test_markdown_section_is_report_ready():
    rows = [_secret_row(id=1)]
    apply(rows)
    md = to_markdown(rows)
    assert md.startswith("## Remediation plan")
    assert "Rotate every exposed credential" in md
    assert "Verify (read-only)" in md
    assert "Re-test" in md and "Done when" in md


def test_summary_alias_and_empty_run_are_safe():
    assert summary([])["items"] == 0
    assert to_markdown([]) == ""
    hostile = [None, {}, {"key": "x", "evidence": None}]
    plan = build_plan(hostile)
    assert isinstance(plan["items"], list)
