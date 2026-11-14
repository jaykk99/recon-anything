"""End-to-end: the precision verdicts and the remediation plan reach the
API and the report.

The engines are unit-tested in test_precision.py / test_remediation.py;
this file proves the wiring a client actually touches - run detail's
`executive_summary.precision`, the new `/api/runs/{id}/plan` endpoint,
and the Remediation plan section in the Markdown export.
"""
import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp.name}")
os.environ["ACCESS_CODE"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.models import Finding, Run, Target, get_session, init_db  # noqa: E402

RUN_ID = "plan-api-run"
REAL_KEY = "AKIA2E0A8F3B244C9986"


def _seed():
    init_db()
    session = get_session()
    try:
        session.query(Run).filter_by(id=RUN_ID).delete()
        session.query(Finding).filter_by(run_id=RUN_ID).delete()
        session.query(Target).filter_by(run_id=RUN_ID).delete()
        session.add(Run(id=RUN_ID, mode="passive", status="done",
                        source_type="website", summary={}))
        session.add(Target(id="tgt1", run_id=RUN_ID, raw="acme.test",
                           normalized="acme.test", type="domain"))
        rows = [
            # Proven: a live-looking credential in a served asset.
            Finding(run_id=RUN_ID, target_id="t1", plugin_id="secrets",
                    category="leak", key="exposed_aws_key", value=REAL_KEY,
                    source="direct probe",
                    source_url="https://acme.test/app.js", confidence=92,
                    evidence={"severity": "high",
                              "exploitability": "weaponized",
                              "commands": [{"label": "confirm the key",
                                            "cmd": "curl -s https://acme.test/app.js | grep AKIA"}]},
                    passive=False),
            # Unproven: CVE with no observed version.
            Finding(run_id=RUN_ID, target_id="t1", plugin_id="cves",
                    category="web", key="cve_match",
                    value="HIGH: nginx - CVE-2021-23017 (version not disclosed)",
                    source="CVE matcher", confidence=65,
                    evidence={"severity": "high",
                              "detected_version": "unknown",
                              "cve": "CVE-2021-23017"}),
            # Contradicted: the path is not there.
            Finding(run_id=RUN_ID, target_id="t1", plugin_id="artifacts",
                    category="leak", key="artifact_exposed",
                    value="/.env returned 404 - not found",
                    source="direct probe", confidence=80,
                    evidence={"severity": "high"}, passive=False),
            # Hygiene drift on a page that did load.
            Finding(run_id=RUN_ID, target_id="t1", plugin_id="headers",
                    category="web", key="missing_security_header",
                    value="Content-Security-Policy header missing",
                    source="header check", confidence=70,
                    evidence={"severity": "low", "status": 200,
                              "headers": {"server": "nginx"}}),
            # Inventory, not a fix item.
            Finding(run_id=RUN_ID, target_id="t1", plugin_id="dns",
                    category="dns", key="a", value="203.0.113.9",
                    source="DNS", confidence=95,
                    evidence={"severity": "low"}),
        ]
        for row in rows:
            session.add(row)
        session.commit()
    finally:
        session.close()


def test_plan_endpoint_and_run_detail_precision():
    _seed()
    with TestClient(app) as client:
        detail = client.get(f"/api/runs/{RUN_ID}")
        assert detail.status_code == 200
        payload = detail.json()
        precision_block = payload["executive_summary"]["precision"]
        assert precision_block["claims"]["suppressed"] == 1
        assert precision_block["claims"]["verified"] >= 2
        assert precision_block["suppressed"][0]["key"] == "artifact_exposed"
        assert precision_block["candidates"]

        plan = client.get(f"/api/runs/{RUN_ID}/plan")
        assert plan.status_code == 200
        body = plan.json()
        assert body["run_id"] == RUN_ID
        assert body["summary"]["items"] >= 2
        assert body["posture"]["grade"] in ("A", "B", "C", "D", "F")
        titles = [i["title"] for i in body["items"]]
        assert "Rotate every exposed credential" in titles
        routes = {i["route_id"] for i in body["items"]}
        assert "remove-exposure" not in routes, \
            "a suppressed claim entered the plan"
        first = body["items"][0]
        assert first["route_id"] == "rotate-credential"
        assert first["priority_label"] == "Now"
        assert first["verify"] and first["verify"][0]["cmd"]
        assert body["verification_plan"]

        md = client.get(f"/api/runs/{RUN_ID}/export?format=md")
        assert md.status_code == 200
        text = md.text
        assert "## Remediation plan" in text
        assert "Rotate every exposed credential" in text
        assert "Done when" in text


def test_plan_route_404s_on_an_unknown_run():
    _seed()
    with TestClient(app) as client:
        r = client.get("/api/runs/does-not-exist/plan")
        assert r.status_code == 404
