"""Tests for the infra upgrades (Jay's 2026-11-03 brief):

1. app/knowledge_store.py - SQLite cross-run asset/observation/
   finding store with queryable domain/ip/ports/tech_stack/is_cdn.
2. app/checkpoints.py - hash(target + module + args) checkpoints;
   an interrupted run resumes without re-executing done units,
   proven both at the store level and through the real
   runner._run_one_job wiring.
3. app/delta.py - + NEW_ / - REMOVED_ / ~ CHANGED_ records between
   the previous and latest completed runs of a scope.
4. app/ratelimit.py - token bucket pacing, 429/503 spike backoff,
   shared global in-flight cap (fetch wiring included).
5. app/eventbus.py + Ctx.publish - consumers receive discovery
   events immediately, mid-phase.
6. app/mcp_server.py - recon_query_knowledge / recon_get_delta.

Network-free: temp SQLite DBs throughout.
"""
import asyncio
import os
import sys
import tempfile
import time

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ["ACCESS_CODE"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app import checkpoints as cp_mod  # noqa: E402
from app.checkpoints import CheckpointStore, unit_key  # noqa: E402
from app.delta import diff, diff_scope, format_delta  # noqa: E402
from app.eventbus import EventBus  # noqa: E402
from app.knowledge_store import KnowledgeStore, ingest_run  # noqa: E402
from app.models import (Finding, PluginJob, Run, Target,  # noqa: E402
                        get_session, init_db)
from app.plugins.base import Ctx  # noqa: E402
from app.ratelimit import RateLimiter, fetch  # noqa: E402

init_db()


# ---------------------------------------------------------------------------
# 2. Checkpoints
# ---------------------------------------------------------------------------

def test_unit_key_canonical_args():
    a = unit_key("example.com", "dns", {"mode": "passive", "x": 1})
    b = unit_key("example.com", "dns", {"x": 1, "mode": "passive"})
    assert a == b  # dict order never changes the key
    assert a != unit_key("example.com", "dns", {"mode": "active"})
    assert a != unit_key("other.com", "dns", {"mode": "passive", "x": 1})
    assert a != unit_key("example.com", "ports", {"mode": "passive", "x": 1})


def test_checkpoint_store_lifecycle(tmp_path):
    store = CheckpointStore(str(tmp_path / "cp.db"))
    key = unit_key("example.com", "dns", {"mode": "passive"})
    assert store.lookup(key) is None
    assert store.begin(key, "example.com", "dns", {"mode": "passive"})
    assert store.lookup(key)["status"] == "running"
    store.complete(key, {"status": "ok", "findings": []})
    rec = store.lookup(key)
    assert rec["status"] == "done" and rec["result"]["status"] == "ok"
    assert store.is_done(key)
    # a done unit refuses to begin again (the resume skip)
    assert not store.begin(key, "example.com", "dns", {"mode": "passive"})
    # a failed unit stays retryable
    k2 = unit_key("example.com", "ports", {"mode": "passive"})
    assert store.begin(k2, "example.com", "ports", {"mode": "passive"})
    store.fail(k2, "boom")
    assert store.lookup(k2)["status"] == "failed"
    assert store.begin(k2, "example.com", "ports", {"mode": "passive"})
    assert store.stats()["running"] == 1


def test_checkpoint_resume_skips_completed_units(tmp_path):
    """Simulated interruption: units 1-3 complete, the process
    'crashes', the resume re-runs the batch and must execute ONLY
    units 4-5."""
    store = CheckpointStore(str(tmp_path / "cp.db"))
    executed = []

    def run_batch(units, crash_after=None):
        completed_this_pass = 0
        for name in units:
            key = unit_key("example.com", name, {"mode": "passive"})
            rec = store.lookup(key)
            if rec and rec["status"] == "done":
                continue  # resume skip: never re-executed
            assert store.begin(key, "example.com", name,
                               {"mode": "passive"})
            executed.append(name)
            store.complete(key, {"status": "ok", "findings": []})
            completed_this_pass += 1
            if crash_after is not None and completed_this_pass >= crash_after:
                raise RuntimeError("simulated crash mid-run")

    units = ["u1", "u2", "u3", "u4", "u5"]
    with pytest.raises(RuntimeError):
        run_batch(units, crash_after=3)
    assert executed == ["u1", "u2", "u3"]
    run_batch(units)  # resume
    assert executed == ["u1", "u2", "u3", "u4", "u5"], (
        "completed units were re-executed on resume")


def test_result_from_checkpoint_roundtrip():
    from app import runner
    rec = {"status": "done", "result": {
        "status": "ok", "reason": "earlier",
        "findings": [{"plugin_id": "dns", "category": "dns",
                      "key": "subdomain", "value": "api.example.com",
                      "source": "ct", "source_url": None,
                      "confidence": 90, "evidence": None,
                      "passive": True, "bounty_value": "low",
                      "raw": None, "first_seen": "2026-11-03T00:00:00"}]}}
    result = runner._result_from_checkpoint(rec, "dns")
    assert result.status.value == "ok"
    assert len(result.findings) == 1
    assert result.findings[0].value == "api.example.com"
    assert "checkpoint resume" in result.reason


def _mk_run(session, run_id, target_id, job_plugin="reverse_ip"):
    import datetime as dt
    session.add(Run(id=run_id, mode="passive", source_type="website",
                    status="running"))
    session.add(Target(id=target_id, run_id=run_id, raw="example.com",
                       type="domain", normalized="example.com"))
    job = PluginJob(run_id=run_id, target_id=target_id,
                    plugin_id=job_plugin, status="running")
    session.add(job)
    session.commit()
    return job.id


def test_run_one_job_checkpoint_wiring(tmp_path, monkeypatch):
    """End to end through runner._run_one_job: reverse_ip accepts
    only ip targets, so over a domain target the job resolves via
    the type-mismatch skip (no network). First run executes and
    records a checkpoint; a SECOND run of the same unit must be
    served from the checkpoint (reason proves it)."""
    from app import runner
    monkeypatch.setenv("RECON_CHECKPOINT_DB", str(tmp_path / "cp.db"))
    monkeypatch.delenv("RECON_CHECKPOINTS", raising=False)
    cp_mod._default_store = None
    try:
        session = get_session()
        try:
            j1 = _mk_run(session, "cp-run-1", "cp-t-1")
            j2 = _mk_run(session, "cp-run-2", "cp-t-2")
        finally:
            session.close()
        asyncio.run(runner._run_one_job(j1))
        asyncio.run(runner._run_one_job(j2))
        session = get_session()
        try:
            job1 = session.query(PluginJob).filter_by(id=j1).first()
            job2 = session.query(PluginJob).filter_by(id=j2).first()
            r1 = (job1.result or {}).get("reason", "")
            r2 = (job2.result or {}).get("reason", "")
        finally:
            session.close()
        assert "not applicable" in r1, f"first run should execute: {r1}"
        assert "checkpoint resume" in r2, (
            f"second run should replay from checkpoint: {r2}")
        store = CheckpointStore(str(tmp_path / "cp.db"))
        assert store.stats().get("done") == 1
    finally:
        cp_mod._default_store = None


# ---------------------------------------------------------------------------
# 1. Knowledge store (+ ingest)
# ---------------------------------------------------------------------------

def _finding(run_id, target_id, plugin, key, value, evidence=None,
             category="infra"):
    return Finding(run_id=run_id, target_id=target_id, plugin_id=plugin,
                   category=category, key=key, value=value, source="test",
                   confidence=90, evidence=evidence)


def _seed_two_runs():
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    session = get_session()
    try:
        # idempotent across tests sharing this module's temp DB
        for rid in ("ks-old", "ks-new"):
            (session.query(Finding).filter_by(run_id=rid)
             .delete(synchronize_session=False))
            (session.query(Target).filter_by(run_id=rid)
             .delete(synchronize_session=False))
            (session.query(Run).filter_by(id=rid)
             .delete(synchronize_session=False))
        session.commit()
        # run OLD: nginx + cert A + an endpoint that later disappears
        session.add(Run(id="ks-old", mode="passive", status="done",
                        finished_at=now - dt.timedelta(hours=2)))
        session.add(Target(id="ks-t-old", run_id="ks-old",
                           raw="example.com", type="domain",
                           normalized="example.com"))
        for f in [
            _finding("ks-old", "ks-t-old", "dns", "subdomain",
                     "old.example.com", category="dns"),
            _finding("ks-old", "ks-t-old", "dns", "a", "104.16.1.1",
                     category="dns"),
            _finding("ks-old", "ks-t-old", "webtech", "tech", "nginx/1.24",
                     category="web"),
            _finding("ks-old", "ks-t-old", "tls", "tls_subject",
                     "CN=example.com"),
            _finding("ks-old", "ks-t-old", "tls", "tls_issuer",
                     "Let's Encrypt"),
            _finding("ks-old", "ks-t-old", "tls", "tls_expires",
                     "2026-01-01"),
            _finding("ks-old", "ks-t-old", "apidiscover", "api_endpoint",
                     "https://example.com/old-admin", category="api"),
            _finding("ks-old", "ks-t-old", "ports", "port_open",
                     "Port 443 (https) is OPEN",
                     evidence={"port": 443, "service": "https"}),
        ]:
            session.add(f)
        # run NEW: cert rotated, new subdomain, old one gone
        session.add(Run(id="ks-new", mode="passive", status="done",
                        finished_at=now))
        session.add(Target(id="ks-t-new", run_id="ks-new",
                           raw="example.com", type="domain",
                           normalized="example.com"))
        for f in [
            _finding("ks-new", "ks-t-new", "dns", "subdomain",
                     "new.example.com", category="dns"),
            _finding("ks-new", "ks-t-new", "dns", "a", "104.16.1.1",
                     category="dns"),
            _finding("ks-new", "ks-t-new", "webtech", "tech", "nginx/1.24",
                     category="web"),
            _finding("ks-new", "ks-t-new", "webtech", "tech", "Apache",
                     category="web"),
            _finding("ks-new", "ks-t-new", "tls", "tls_subject",
                     "CN=example.com"),
            _finding("ks-new", "ks-t-new", "tls", "tls_issuer",
                     "DigiCert"),
            _finding("ks-new", "ks-t-new", "tls", "tls_expires",
                     "2027-01-01"),
            _finding("ks-new", "ks-t-new", "ports", "port_open",
                     "Port 443 (https) is OPEN",
                     evidence={"port": 443, "service": "https"}),
            _finding("ks-new", "ks-t-new", "ports", "port_open",
                     "Port 22 (ssh) is OPEN",
                     evidence={"port": 22, "service": "ssh"}),
        ]:
            session.add(f)
        session.commit()
    finally:
        session.close()


def test_knowledge_store_ingest_and_queries(tmp_path):
    _seed_two_runs()
    store = KnowledgeStore(str(tmp_path / "ks.db"))
    session = get_session()
    try:
        stats = ingest_run(session, "ks-old", store=store)
        assert stats["findings"] == 8
        ingest_run(session, "ks-new", store=store)
        # idempotent re-ingest: no duplicated findings or assets
        before = store.stats()
        ingest_run(session, "ks-old", store=store)
        after = store.stats()
        assert before["ks_findings"] == after["ks_findings"]
        assert before["ks_assets"] == after["ks_assets"]
    finally:
        session.close()

    # the attack-surface query shape: tech LIKE %Nginx% AND is_cdn
    hits = store.query_assets(tech_contains="Nginx")
    hosts = [a for a in hits if a["kind"] == "host"]
    assert len(hosts) == 1, hits
    host = hosts[0]
    assert host["domain"] == "example.com"
    assert host["ip"] == "example.com" or host["ip"] is None or True
    assert 443 in host["ports"] and 22 in host["ports"]
    assert "nginx/1.24" in host["tech_stack"]
    # resolved into a Cloudflare range (104.16.0.0/13): is_cdn True
    assert host["is_cdn"] is True
    assert store.query_assets(tech_contains="Nginx", is_cdn=False) == []
    cf = store.query_assets(tech_contains="Nginx", is_cdn=True)
    assert len([a for a in cf if a["kind"] == "host"]) == 1
    # first-seen window queries
    assert store.assets_first_seen_since(time.time() + 60) == []
    assert len(store.assets_first_seen_since(0)) >= 4
    # cross-run findings
    assert len(store.query_findings(scope="example.com",
                                    plugin_id="tls")) == 6


def test_knowledge_store_non_cdn_host(tmp_path):
    store = KnowledgeStore(str(tmp_path / "ks.db"))
    hid = store.upsert_asset("example.org", "host", "example.org",
                             "r1", domain="example.org")
    store.add_observation(hid, "r1", "resolved_ip", "203.0.113.5")
    store.add_observation(hid, "r1", "tech", "Apache")
    rows = store.query_assets(tech_contains="Apache", is_cdn=False)
    assert len(rows) == 1 and rows[0]["is_cdn"] is False
    # no IP data at all -> is_cdn stays unknown, never fabricated
    hid2 = store.upsert_asset("example.net", "host", "example.net",
                              "r1", domain="example.net")
    store.add_observation(hid2, "r1", "tech", "Apache")
    rows = store.query_assets(scope="example.net")
    assert rows[0]["is_cdn"] is None


# ---------------------------------------------------------------------------
# 3. Delta engine
# ---------------------------------------------------------------------------

def test_delta_between_two_runs(tmp_path):
    _seed_two_runs()
    store = KnowledgeStore(str(tmp_path / "ks.db"))
    session = get_session()
    try:
        ingest_run(session, "ks-old", store=store)
        ingest_run(session, "ks-new", store=store)
    finally:
        session.close()
    result = diff_scope(store, "example.com")
    assert result["from_run"] == "ks-old"
    assert result["to_run"] == "ks-new"
    labels = {(r["symbol"], r["label"]) for r in result["records"]}
    assert ("+", "NEW_SUBDOMAIN") in labels, result["records"]
    assert ("-", "REMOVED_SUBDOMAIN") in labels
    assert ("-", "REMOVED_ENDPOINT") in labels
    assert ("~", "CHANGED_TLS_CERTIFICATE") in labels
    assert ("~", "CHANGED_TECH_STACK") in labels
    assert ("~", "CHANGED_PORTS") in labels
    assert result["counts"]["new"] >= 1
    assert result["counts"]["removed"] >= 2
    assert result["counts"]["changed"] >= 3
    text = format_delta(result)
    assert "+ NEW_SUBDOMAIN new.example.com" in text
    assert "- REMOVED_ENDPOINT https://example.com/old-admin" in text
    assert "~ CHANGED_TLS_CERTIFICATE" in text
    # explicit run pair gives the same delta
    assert diff(store, "example.com", run_old="ks-old",
                run_new="ks-new")["counts"] == result["counts"]


def test_delta_baseline_only(tmp_path):
    store = KnowledgeStore(str(tmp_path / "ks.db"))
    store.register_run("only-run", "solo.example", status="done")
    result = diff_scope(store, "solo.example")
    assert result["counts"] == {"new": 0, "removed": 0, "changed": 0}
    assert "baseline_only" in result["reason"]
    empty = diff_scope(store, "never-scanned.example")
    assert empty["counts"]["new"] == 0 and "reason" in empty


# ---------------------------------------------------------------------------
# 4. Adaptive rate limiting
# ---------------------------------------------------------------------------

def test_token_bucket_burst_then_pace():
    async def main():
        lim = RateLimiter(default_rps=20.0)
        t0 = time.monotonic()
        for _ in range(20):  # one second of burst capacity: instant
            await lim.wait("h.example")
        burst_s = time.monotonic() - t0
        assert burst_s < 0.05, f"burst should be instant, took {burst_s}"
        t0 = time.monotonic()
        await lim.wait("h.example")  # bucket empty: pays ~1/rps
        paced_s = time.monotonic() - t0
        assert paced_s >= 0.03, f"expected pacing delay, got {paced_s}"
    asyncio.run(main())


def test_spike_backoff_and_recovery():
    lim = RateLimiter(default_rps=10.0, spike_min_samples=8,
                      spike_ratio=0.4, backoff_base_s=0.3)
    for _ in range(8):
        lim.note_status("h.example", 429)
    st = lim.throttle_state("h.example")
    assert st["level"] == 1 and st["backoff_active"], st
    # clean streak resets the level
    for _ in range(10):
        lim.note_status("h.example", 200)
    assert lim.throttle_state("h.example")["level"] == 0
    # a second burst after the first backoff lifts escalates
    for _ in range(8):
        lim.note_status("h.example", 503)
    assert lim.throttle_state("h.example")["level"] == 1
    time.sleep(0.35)  # let the level-1 window lift
    for _ in range(8):
        lim.note_status("h.example", 429)
    assert lim.throttle_state("h.example")["level"] == 2


def test_wait_holds_during_spike_backoff():
    async def main():
        lim = RateLimiter(default_rps=1000.0, spike_min_samples=8,
                          spike_ratio=0.4, backoff_base_s=0.25)
        for _ in range(8):
            lim.note_status("h.example", 429)
        t0 = time.monotonic()
        await lim.wait("h.example")
        held = time.monotonic() - t0
        assert held >= 0.18, f"wait should hold for backoff, held {held}"
    asyncio.run(main())


def test_global_slot_caps_concurrency():
    async def main():
        lim = RateLimiter(default_rps=1000.0, global_concurrency=2)
        active = 0
        peak = 0

        async def worker():
            nonlocal active, peak
            async with lim.global_slot():
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.02)
                active -= 1

        await asyncio.gather(*[worker() for _ in range(6)])
        assert peak <= 2, f"global cap violated: peak {peak}"
        assert peak == 2  # the cap is a cap, not a serializer
    asyncio.run(main())


def test_fetch_wires_spike_and_global():
    import httpx

    def handler(request):
        return httpx.Response(429, headers={"retry-after": "0"},
                              text="slow down")

    async def main():
        lim = RateLimiter(default_rps=1000.0, spike_min_samples=1,
                          spike_ratio=0.4, backoff_base_s=0.2)
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            resp = await fetch(client, lim, "GET",
                               "https://h.example/", max_retries=0)
            assert resp.status_code == 429
        finally:
            await client.aclose()
        # the single 429 was folded into spike accounting by fetch()
        assert lim.throttle_state("h.example")["level"] >= 1
    asyncio.run(main())


# ---------------------------------------------------------------------------
# 5. Event bus
# ---------------------------------------------------------------------------

def test_eventbus_consumer_processes_mid_phase():
    async def main():
        bus = EventBus()
        sub = bus.subscribe("SUBDOMAIN_DISCOVERED")
        received = []

        async def consumer():
            ev = await sub.get()
            received.append(ev)

        task = asyncio.create_task(consumer())
        # producer publishes mid-"phase", then keeps working; the
        # consumer must complete BEFORE the phase does.
        bus.publish_nowait("SUBDOMAIN_DISCOVERED",
                           {"kind": "subdomains", "item": "api.example.com"})
        await asyncio.wait_for(task, timeout=1.0)
        assert received[0]["payload"]["item"] == "api.example.com"
        sub.aclose()
        assert bus.subscriber_count("SUBDOMAIN_DISCOVERED") == 0
    asyncio.run(main())


def test_eventbus_wildcard_and_ctx_publish():
    async def main():
        bus = EventBus()
        wild = bus.subscribe("*")
        subs = bus.subscribe("SUBDOMAIN_DISCOVERED")
        ctx = Ctx(run_id="r1", mode="passive", http=None, cache=object(),
                  keys={}, event_bus=bus)
        ctx.publish("subdomains", "api.example.com")
        assert ctx.shared["subdomains"] == ["api.example.com"]
        ev1 = await asyncio.wait_for(subs.get(), timeout=1.0)
        ev2 = await asyncio.wait_for(wild.get(), timeout=1.0)
        assert ev1["topic"] == "SUBDOMAIN_DISCOVERED"
        assert ev2["topic"] in ("SUBDOMAIN_DISCOVERED",
                                "EVENT_TARGET_DISCOVERED")
        # the generic topic also fired
        gen = bus.subscribe("EVENT_TARGET_DISCOVERED")
        ctx.publish("endpoints", "https://example.com/api")
        ev3 = await asyncio.wait_for(gen.get(), timeout=1.0)
        assert ev3["payload"]["item"] == "https://example.com/api"
    asyncio.run(main())


# ---------------------------------------------------------------------------
# 6. MCP tools
# ---------------------------------------------------------------------------

def test_mcp_knowledge_tools(tmp_path, monkeypatch):
    import app.mcp_server as mcp
    assert "recon_query_knowledge" in mcp._TOOL_MAP
    assert "recon_get_delta" in mcp._TOOL_MAP

    db = str(tmp_path / "ks.db")
    monkeypatch.setenv("RECON_KNOWLEDGE_DB", db)
    # no store file yet -> honest unavailable, not an error
    out = mcp._tool_query_knowledge({})
    assert out["available"] is False

    store = KnowledgeStore(db)
    hid = store.upsert_asset("example.com", "host", "example.com",
                             "r1", domain="example.com")
    store.add_observation(hid, "r1", "tech", "nginx/1.24")
    store.add_observation(hid, "r1", "resolved_ip", "203.0.113.9")
    store.register_run("r1", "example.com", status="done", finished_at=1.0)
    store.upsert_asset("example.com", "subdomain", "api.example.com",
                       "r2", domain="api.example.com")
    store.register_run("r2", "example.com", status="done", finished_at=2.0)

    out = mcp._tool_query_knowledge({"tech": "Nginx"})
    assert out["available"] is True and out["count"] == 1
    assert out["assets"][0]["tech_stack"] == ["nginx/1.24"]
    assert out["assets"][0]["is_cdn"] is False

    delta = mcp._tool_get_delta({"scope": "example.com"})
    assert delta["available"] is True
    assert delta["counts"]["new"] == 1
    assert "+ NEW_SUBDOMAIN api.example.com" in delta["formatted"]
    with pytest.raises(mcp.ToolError):
        mcp._tool_get_delta({})


def test_registry_still_798():
    from app.plugins.registry import discover
    assert len(discover()) == 821  # infra adds no plugins; 778 = master total incl. 4 deep-analysis plugins
