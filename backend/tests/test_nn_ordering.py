"""Neural-score ordering across the read surfaces (2026-11-14).

The neural engine (app/nn_engine.py) scores every finding at finalize and
`findings_dump` orders by that score, so the run-detail API, the exports
and the MCP tools all serve the same ranking. Covered here, against a
throwaway SQLite DB:

- rows carrying an explicit neural score sort by it (a high neural score
  outranks a worse severity label, which is the whole point of the model);
- rows from older runs with no persisted score are scored at read time
  (backfilled into evidence) and then ordered by the heuristic as before;
- a CISA KEV finding still ranks first regardless of score;
- the Markdown export's per-category tables are ordered by the score;
- ordering is stable and never mutates the caller's list.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models  # noqa: E402
from app.models import Finding, Run, Target  # noqa: E402
from app.prioritizer import nn_score_of, sort_by_nn  # noqa: E402
from app.reporting import findings_dump, to_markdown  # noqa: E402

_TMPDB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_tmp_nn_ordering.db")


@pytest.fixture()
def db():
    engine = create_engine(f"sqlite:///{_TMPDB}")
    models.Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        try:
            os.unlink(_TMPDB)
        except OSError:
            pass


def _mk_run(session, run_id):
    session.add(Run(id=run_id, mode="passive", status="done", summary={}))
    session.add(Target(id=f"t-{run_id}", run_id=run_id, raw="example.test",
                       type="domain", normalized="example.test"))
    session.commit()


def _add(session, run_id, plugin, key, *, nn=None, severity="low",
         confidence=80, category="web", value="evidence"):
    ev = {"severity": severity}
    if nn is not None:
        ev["nn"] = {"score": nn, "p": nn / 100.0, "band": "high",
                    "version": "test", "drivers": []}
    if severity == "low" and plugin == "kev_finding":
        ev["kev"] = True
    session.add(Finding(run_id=run_id, target_id=f"t-{run_id}",
                        plugin_id=plugin, category=category, key=key,
                        value=value, source="unit", source_url=None,
                        confidence=confidence, evidence=ev, passive=True,
                        bounty_value=severity, raw=None))
    session.commit()


def test_dump_orders_by_neural_score(db):
    _mk_run(db, "run-nn")
    # a benign-looking low sev row with a high neural score must come first
    _add(db, "run-nn", "p70", "k7", nn=70, severity="low")
    _add(db, "run-nn", "p95", "k95", nn=95, severity="medium")
    _add(db, "run-nn", "p20", "k20", nn=20, severity="critical")
    rows = findings_dump(db, "run-nn")
    assert [r["key"] for r in rows[:3]] == ["k95", "k7", "k20"]


def test_legacy_rows_are_scored_at_read_time(db):
    _mk_run(db, "run-legacy")
    _add(db, "run-legacy", "headers", "missing_hsts", severity="low")
    _add(db, "run-legacy", "keyharvest", "exposed_aws_access_key",
         severity="critical", value="AKIAIOSFODNN7EXAMPLE")
    rows = findings_dump(db, "run-legacy")
    for r in rows:
        assert isinstance((r["evidence"] or {}).get("nn", {}).get("score"), int)
    # and the backfilled score still puts the exposed key first
    assert rows[0]["key"] == "exposed_aws_access_key"
    assert nn_score_of(rows[0]) >= nn_score_of(rows[1])


def test_kev_still_leads_any_score(db):
    _mk_run(db, "run-kev")
    _add(db, "run-kev", "p100", "k100", nn=100, severity="critical")
    _add(db, "run-kev", "kev_finding", "k_kev", nn=1, severity="low")
    rows = findings_dump(db, "run-kev")
    assert rows[0]["key"] == "k_kev"


def test_markdown_export_uses_score_order(db):
    _mk_run(db, "run-md")
    _add(db, "run-md", "p10", "zzz_low_score", nn=10, severity="critical",
         category="web")
    _add(db, "run-md", "p90", "aaa_high_score", nn=90, severity="low",
         category="web")
    run = db.query(Run).filter_by(id="run-md").first()
    targets = db.query(Target).filter_by(run_id="run-md").all()
    md = to_markdown(run, targets, findings_dump(db, "run-md"))
    assert md.index("aaa_high_score") < md.index("zzz_low_score")


def test_sort_by_nn_is_stable_and_pure():
    rows = [
        {"plugin": "a", "category": "web", "key": "k1", "value": "",
         "confidence": 80, "evidence": {"severity": "low", "nn": {"score": 5}}},
        {"plugin": "b", "category": "web", "key": "k2", "value": "",
         "confidence": 80, "evidence": {"severity": "low", "nn": {"score": 5}}},
        {"plugin": "c", "category": "web", "key": "k3", "value": "",
         "confidence": 80, "evidence": {"severity": "high"}},
    ]
    out = sort_by_nn(rows)
    assert [r["key"] for r in out] == ["k1", "k2", "k3"]  # ties keep order
    assert [r["key"] for r in rows] == ["k1", "k2", "k3"]  # input untouched
