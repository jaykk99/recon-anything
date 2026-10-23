"""Hunter dilution fixes (Jay's order, 2026-10-23).

Three mechanisms, each proven here:

1. SEED-FIRST BUDGET (runner._claim_jobs): a run's seed jobs claim
   before its hunter-expanded jobs - a hunter job never takes a slot
   while claimable seed work for its run is still queued, even with
   a higher plugin priority. Hunter jobs fill leftover capacity once
   the seed queue drains, and seed jobs left queued SOLELY by the
   phase-2 rule do not deadlock them (those jobs are waiting on
   phase-1 producers, which may be the hunter jobs themselves).

2. HUNTER TARGET CAP + LINEAGE DEPTH (hunters.engine): at most
   MAX_HUNTER_TARGETS hunter-created targets per run, and expansion
   depth is per-asset lineage, with reverse-IP (cohosted) chains
   capped strictly at depth 2 and never taking a second reverse hop.

3. SELECTION-RESPECTING HUNTERS: when a run carries an explicit
   plugin selection, expansion and chaining enqueue ONLY selected
   plugins, on seed and expanded targets alike, and an asset whose
   rules hold no selected plugin never becomes a target.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models  # noqa: E402
from app import runner  # noqa: E402
from app.hunters import engine  # noqa: E402
from app.models import Finding as FindingRow  # noqa: E402
from app.models import PluginJob, Run, Target as TargetRow  # noqa: E402

_TMPDB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_tmp_dilution.db")


@pytest.fixture()
def db():
    eng = create_engine(f"sqlite:///{_TMPDB}")
    models.Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng)
    orig_engine, orig_factory = models.engine, models.SessionLocal
    models.engine, models.SessionLocal = eng, factory
    runner._run_clocks.clear()
    session = factory()
    yield session
    session.close()
    models.engine, models.SessionLocal = orig_engine, orig_factory
    eng.dispose()
    runner._run_clocks.clear()
    try:
        os.unlink(_TMPDB)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 1. Seed-first claiming
# ---------------------------------------------------------------------------

def _mk_claim_run(session, run_id, seed_ids):
    run = Run(id=run_id, mode="passive", status="running",
              summary={"queue_meta": {"mode": "passive",
                                      "plugin_ids": None,
                                      "seed_target_ids": seed_ids}})
    session.add(run)
    session.add(TargetRow(id=seed_ids[0], run_id=run_id,
                          raw="seed.test", type="domain",
                          normalized="seed.test"))
    session.add(TargetRow(id=f"{run_id}-hunt", run_id=run_id,
                          raw="expanded.test", type="domain",
                          normalized="expanded.test"))
    session.commit()
    return run


def _job(session, run_id, target_id, plugin_id, priority=2, phase=1,
         status="queued"):
    j = PluginJob(run_id=run_id, target_id=target_id,
                  plugin_id=plugin_id, phase=phase, priority=priority,
                  estimate_s=60, status=status)
    session.add(j)
    session.commit()
    return j


def test_seed_jobs_claim_before_hunter_jobs(db):
    _mk_claim_run(db, "run-dil-1", ["run-dil-1-seed"])
    seed = "run-dil-1-seed"
    hunt = "run-dil-1-hunt"
    s1 = _job(db, "run-dil-1", seed, "seed_plugin_a", priority=3)
    s2 = _job(db, "run-dil-1", seed, "seed_plugin_b", priority=3)
    # the hunter job outranks both seed jobs and is faster: under the
    # old global ordering it would claim first and starve the seed.
    hj = _job(db, "run-dil-1", hunt, "hunter_plugin", priority=1)
    claimed = runner._claim_jobs(db, limit=1)
    assert [j.id for j in claimed] == [s1.id]
    claimed = runner._claim_jobs(db, limit=1)
    assert [j.id for j in claimed] == [s2.id]
    db.refresh(hj)
    assert hj.status == "queued"  # waited through both seed claims
    claimed = runner._claim_jobs(db, limit=1)
    assert [j.id for j in claimed] == [hj.id]


def test_hunter_fills_in_while_seed_phase2_waits(db):
    # Seed phase-1 is RUNNING, seed phase-2 is queued behind the
    # phase rule, and a hunter phase-1 job is queued. The deferred
    # seed job must not deadlock the hunter job: it is waiting on
    # phase-1 producers, and the hunter job is one of them.
    _mk_claim_run(db, "run-dil-2", ["run-dil-2-seed"])
    seed = "run-dil-2-seed"
    hunt = "run-dil-2-hunt"
    _job(db, "run-dil-2", seed, "seed_phase1", phase=1, status="running")
    s2 = _job(db, "run-dil-2", seed, "seed_phase2", phase=2)
    hj = _job(db, "run-dil-2", hunt, "hunter_phase1", phase=1)
    claimed = runner._claim_jobs(db, limit=10)
    claimed_ids = [j.id for j in claimed]
    assert hj.id in claimed_ids
    assert s2.id not in claimed_ids  # still phase-deferred, not skipped
    db.refresh(s2)
    assert s2.status == "queued"


def test_hunter_waits_while_seed_claimable(db):
    # Both seed jobs are phase 2 and NO phase-1 work exists for the
    # run, so they are claimable right now: the hunter job must wait
    # even though slots are free. (The hunter job is phase 2 too -
    # a phase-1 hunter job would itself defer the seed jobs under
    # the phase rule, which is the deadlock case covered above.)
    _mk_claim_run(db, "run-dil-3", ["run-dil-3-seed"])
    seed = "run-dil-3-seed"
    hunt = "run-dil-3-hunt"
    s1 = _job(db, "run-dil-3", seed, "seed_p2_a", phase=2)
    s2 = _job(db, "run-dil-3", seed, "seed_p2_b", phase=2)
    hj = _job(db, "run-dil-3", hunt, "hunter_plugin", priority=1,
              phase=2)
    claimed = runner._claim_jobs(db, limit=2)
    assert {j.id for j in claimed} == {s1.id, s2.id}
    db.refresh(hj)
    assert hj.status == "queued"


def test_legacy_run_without_seed_record_unchanged(db):
    # No seed_target_ids and no hunters_accum: no gating at all,
    # global priority order applies exactly as before.
    run = Run(id="run-dil-4", mode="passive", status="running",
              summary={"queue_meta": {"plugin_ids": None}})
    db.add(run)
    db.commit()
    hi = _job(db, "run-dil-4", "any-t", "high_plugin", priority=1)
    _job(db, "run-dil-4", "other-t", "low_plugin", priority=3)
    claimed = runner._claim_jobs(db, limit=1)
    assert [j.id for j in claimed] == [hi.id]


# ---------------------------------------------------------------------------
# 2 + 3. Engine: cap, lineage depth, selection
# ---------------------------------------------------------------------------

def _mk_engine_run(session, run_id, domain, plugin_ids=None):
    summary = {}
    if plugin_ids is not None:
        summary = {"queue_meta": {"plugin_ids": plugin_ids}}
    run = Run(id=run_id, mode="passive", status="running",
              source_type="website", summary=summary)
    session.add(run)
    session.add(TargetRow(id=f"{run_id}-t", run_id=run_id, raw=domain,
                          type="domain", normalized=domain))
    session.commit()
    return run


def _finding(session, run_id, target_id, key, value, plugin="dns",
             category="dns"):
    f = FindingRow(run_id=run_id, target_id=target_id, plugin_id=plugin,
                   category=category, key=key, value=value,
                   source="test", source_url=None)
    session.add(f)
    session.commit()
    return f


def test_hunter_target_cap_holds(db, monkeypatch):
    monkeypatch.setattr(engine, "MAX_HUNTER_TARGETS", 3)
    run = _mk_engine_run(db, "run-cap-1", "cap.test")
    for i in range(6):
        _finding(db, "run-cap-1", "run-cap-1-t", "subdomain",
                 f"s{i}.cap.test")
    accum = engine.new_accum()
    engine.hunter_expand(db, run, accum)
    assert len(accum["hunter_targets"]) == 3
    targets = db.query(TargetRow).filter_by(run_id="run-cap-1").all()
    assert len(targets) == 4  # seed + exactly the capped 3
    assert accum["cap_hits"] == 3
    # capped assets still joined the known set (memory compounds;
    # only this run's target creation is capped)
    from app.agentdata import store
    assert store.known_total(db, "recon", "cap.test") >= 7


def test_selection_respected_by_hunters(db):
    run = _mk_engine_run(db, "run-sel-1", "sel.test",
                         plugin_ids=["dns", "tls"])
    _finding(db, "run-sel-1", "run-sel-1-t", "subdomain", "api.sel.test")
    _finding(db, "run-sel-1", "run-sel-1-t", "email", "admin@sel.test",
             plugin="emails", category="email")
    _finding(db, "run-sel-1", "run-sel-1-t", "tech", "WordPress 6.4.2",
             plugin="webtech", category="web")
    accum = engine.new_accum()
    engine.hunter_expand(db, run, accum)
    jobs = db.query(PluginJob).filter_by(run_id="run-sel-1").all()
    assert jobs, "selected plugins should still dispatch"
    assert {j.plugin_id for j in jobs} <= {"dns", "tls"}
    # the subdomain became a target and got the selected plugins
    api = db.query(TargetRow).filter_by(
        run_id="run-sel-1", normalized="api.sel.test").first()
    assert api is not None
    api_plugins = {j.plugin_id for j in jobs if j.target_id == api.id}
    assert api_plugins == {"dns", "tls"}
    # the email asset's rules hold no selected plugin: no target
    assert db.query(TargetRow).filter_by(
        run_id="run-sel-1", normalized="admin@sel.test").first() is None
    # chaining (WordPress -> cms_probes/cves/backup) respects it too
    assert accum["chained_jobs"] == 0


def test_reverse_ip_chain_stops_at_depth_two(db):
    run = _mk_engine_run(db, "run-rev-1", "rev.test")
    accum = engine.new_accum()
    # Pass 1: the seed's DNS gives an IP (lineage depth 1). It
    # expands - including reverse_ip on the new IP target.
    _finding(db, "run-rev-1", "run-rev-1-t", "a", "203.0.113.7")
    engine.hunter_expand(db, run, accum)
    ip_t = db.query(TargetRow).filter_by(
        run_id="run-rev-1", normalized="203.0.113.7").first()
    assert ip_t is not None
    assert accum["target_depths"][ip_t.id] == 1
    assert any(j.plugin_id == "reverse_ip" and j.target_id == ip_t.id
               for j in db.query(PluginJob)
               .filter_by(run_id="run-rev-1").all())
    # Pass 2: reverse_ip on that IP reports a cohosted neighbor
    # (depth 2, reverse-chained). The neighbor itself is verified.
    _finding(db, "run-rev-1", ip_t.id, "cohosted_domain",
             "neighbor.example", plugin="reverse_ip", category="graph")
    engine.hunter_expand(db, run, accum)
    nb_t = db.query(TargetRow).filter_by(
        run_id="run-rev-1", normalized="neighbor.example").first()
    assert nb_t is not None
    assert accum["target_depths"][nb_t.id] == 2
    assert nb_t.id in accum["target_reverse"]
    assert db.query(PluginJob).filter_by(
        run_id="run-rev-1", target_id=nb_t.id).count() > 0
    # Pass 3: under the neighbor, a fresh IP (would be depth 3 in a
    # reverse chain) and a SECOND reverse-IP hop both stay unexpanded.
    _finding(db, "run-rev-1", nb_t.id, "a", "203.0.113.9")
    _finding(db, "run-rev-1", nb_t.id, "cohosted_domain",
             "second.example", plugin="reverse_ip", category="graph")
    engine.hunter_expand(db, run, accum)
    norms = {t.normalized for t in
             db.query(TargetRow).filter_by(run_id="run-rev-1").all()}
    assert "203.0.113.9" not in norms
    assert "second.example" not in norms
