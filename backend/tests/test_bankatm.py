"""Bank/ATM mode tests (source_type="bankatm").

Jay's spec: ONE input, NO options - a URL/domain or a location, and the
mode does the rest. Covers: input parsing (URL vs location), Overpass
parsing with fixtures, operator->domain resolution, the bank_surface
leak/panel scanners, the financial set contract, and the enqueue path
(location run lists POIs as findings and enqueues the full financial
set on resolved operator domains only; a selection is never taken).
Network-free: geo + emit are stubbed.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app import bankatm, geo  # noqa: E402
from app.bankdomains import resolve_domain  # noqa: E402
from app.plugins.bank_surface import (find_internal_leaks,  # noqa: E402
                                      match_fleet_platforms)


# -- input parsing -------------------------------------------------------

def test_parse_domain_and_url():
    p = bankatm.parse_bankatm_input("rbcroyalbank.com")
    assert p["kind"] == "domain" and p["target_type"] == "domain"
    assert p["normalized"] == "rbcroyalbank.com"
    p = bankatm.parse_bankatm_input("https://www.td.com/ca/en/personal")
    assert p["kind"] == "domain" and p["target_type"] == "url"


def test_parse_locations():
    for text in ("Winnipeg, MB", "ATMs near Osborne Village, Winnipeg",
                 "123 Main St, Winnipeg", "49.8951,-97.1384"):
        p = bankatm.parse_bankatm_input(text)
        assert p["kind"] == "location", text
        assert p["location"] == text


def test_parse_first_line_and_empty():
    p = bankatm.parse_bankatm_input("\n  bmo.com\nignored second line")
    assert p["kind"] == "domain" and p["normalized"] == "bmo.com"
    assert bankatm.parse_bankatm_input("   ")["raw"] == ""


# -- operator -> domain resolution ---------------------------------------

def test_resolve_canadian_banks():
    assert resolve_domain(operator="RBC Royal Bank") == "rbcroyalbank.com"
    assert resolve_domain(name="TD Bank") == "td.com"
    assert resolve_domain(name="Scotiabank") == "scotiabank.com"
    assert resolve_domain(brand="BMO") == "bmo.com"
    assert resolve_domain(name="CIBC") == "cibc.com"
    assert resolve_domain(name="Caisse Desjardins") == "desjardins.com"
    assert resolve_domain(operator="ATB Financial") == "atb.com"
    assert resolve_domain(name="Simplii Financial") == "simplii.com"
    assert resolve_domain(name="Tangerine") == "tangerine.ca"


def test_resolve_us_banks_and_networks():
    assert resolve_domain(name="Chase Bank") == "chase.com"
    assert resolve_domain(name="Bank of America") == "bankofamerica.com"
    assert resolve_domain(name="Wells Fargo") == "wellsfargo.com"
    assert resolve_domain(name="Citibank") == "citi.com"
    assert resolve_domain(name="U.S. Bank") == "usbank.com"
    assert resolve_domain(operator="Cardtronics") == "cardtronics.com"


def test_resolve_website_wins_and_normalizes():
    # The POI's own website tag is ground truth and beats the mapping;
    # a leading www. is stripped so it dedupes against mapping results.
    assert resolve_domain(name="TD Bank",
                          website="https://www.example-bank.com/x") \
        == "example-bank.com"
    assert resolve_domain(website="td.com") == "td.com"


def test_resolve_unknown_and_short_key_safety():
    assert resolve_domain(name="Random Corner Store ATM") is None
    assert resolve_domain(name="Hotel California") is None
    assert resolve_domain() is None
    # short keys match as whole tokens only
    assert resolve_domain(name="TD") == "td.com"
    assert resolve_domain(name="Stadium") is None


# -- Overpass parsing ------------------------------------------------------

OVERPASS_FIXTURE = {"elements": [
    {"type": "node", "lat": 49.89, "lon": -97.14,
     "tags": {"amenity": "atm", "brand": "RBC",
              "operator": "RBC Royal Bank",
              "addr:housenumber": "100", "addr:street": "Main St",
              "addr:city": "Winnipeg"}},
    {"type": "node", "lat": 49.89, "lon": -97.14,
     "tags": {"amenity": "atm", "brand": "RBC",
              "operator": "RBC Royal Bank"}},  # dupe of the first
    {"type": "way", "center": {"lat": 49.90, "lon": -97.15},
     "tags": {"amenity": "bank", "name": "TD Bank",
              "website": "https://www.td.com"}},
    {"type": "node", "lat": 49.91, "lon": -97.16,
     "tags": {"amenity": "atm", "name": "Corner Store ATM"}},
    {"type": "node", "lat": 49.92, "lon": -97.17,
     "tags": {"amenity": "cafe", "name": "Not A Bank"}},
    {"type": "node",
     "tags": {"amenity": "atm", "name": "No Coords ATM"}},
]}


def test_overpass_parse_bank_atm():
    pois = geo.parse_bank_atm_elements(OVERPASS_FIXTURE)
    assert len(pois) == 3  # dupe, cafe and coord-less entries dropped
    kinds = sorted(p["poi_type"] for p in pois)
    assert kinds == ["atm", "atm", "bank"]
    rbc = next(p for p in pois if p["operator"] == "RBC Royal Bank")
    assert rbc["address"] == "100 Main St Winnipeg"
    assert rbc["brand"] == "RBC"
    td = next(p for p in pois if p["name"] == "TD Bank")
    assert td["website"] == "https://www.td.com"
    assert td["lat"] == 49.90  # way center used


def test_overpass_parse_cap():
    pois = geo.parse_bank_atm_elements(OVERPASS_FIXTURE, cap=2)
    assert len(pois) == 2


NOMINATIM_FIXTURE = [
    {"class": "amenity", "type": "bank", "lat": "49.8955",
     "lon": "-97.1392", "display_name": "RBC, Portage Ave, Winnipeg",
     "extratags": {"name": "RBC", "operator": "RBC Royal Bank"},
     "address": {"road": "Portage Ave", "city": "Winnipeg"}},
    {"class": "amenity", "type": "bank", "lat": "49.9500",
     "lon": "-97.2000", "display_name": "Too Far Bank",
     "extratags": {"name": "Faraway Bank"}, "address": {}},
    {"class": "amenity", "type": "atm", "lat": "49.8955",
     "lon": "-97.1392", "display_name": "wrong type for this call",
     "extratags": {"name": "ATM"}, "address": {}},
]


def test_nominatim_parse_bank_atm():
    pois = geo.parse_nominatim_bank_atm(
        NOMINATIM_FIXTURE, "bank", 49.8951, -97.1384, 5000)
    assert len(pois) == 1  # far one filtered by radius, atm by type
    p = pois[0]
    assert p["name"] == "RBC" and p["poi_type"] == "bank"
    assert p["operator"] == "RBC Royal Bank"  # extratags kept
    assert "Portage Ave" in p["address"]


def test_find_bank_atm_layered_fallback(monkeypatch):
    # Nominatim and Overpass both empty -> legacy find_pois is the
    # last resort and its results are normalized to the POI shape.
    import asyncio as _aio

    async def empty(*a, **k):
        return []

    async def fake_find_pois(lat, lon, poi_type, radius_m=5000):
        if poi_type == "atm":
            return [{"name": "Legacy ATM", "lat": 49.89, "lon": -97.14,
                     "address": "1 Main St", "operator": "",
                     "website": "", "phone": "", "opening_hours": ""}]
        return []

    monkeypatch.setattr(geo, "_bank_atm_via_nominatim", empty)
    monkeypatch.setattr(geo, "_bank_atm_via_overpass", empty)
    monkeypatch.setattr(geo, "find_pois", fake_find_pois)
    pois = _aio.run(geo.find_bank_atm_pois(49.8951, -97.1384))
    assert len(pois) == 1
    assert pois[0]["poi_type"] == "atm" and pois[0]["brand"] == ""


# -- bank_surface scanners -------------------------------------------------

def test_internal_leak_scanner():
    text = ("branch appliance 192.168.4.21, app 10.1.2.3, "
            "edge 172.16.0.9, not-private 172.32.0.9, public 8.8.8.8, "
            "files at files01.corp, portal intranet.example.com, "
            "dev http://localhost:8080/admin, docs at nas.lan")
    leaks = dict((k, v) for k, v in find_internal_leaks(text))
    vals = [v for _, v in find_internal_leaks(text)]
    assert "192.168.4.21" in vals and "10.1.2.3" in vals
    assert "172.16.0.9" in vals
    assert "172.32.0.9" not in vals  # outside RFC1918 172.16/12
    assert "8.8.8.8" not in vals
    assert "files01.corp" in vals and "nas.lan" in vals
    assert any(v.startswith("http://localhost") for v in vals)
    assert leaks  # non-empty


def test_internal_leak_scanner_clean():
    assert find_internal_leaks("Call us at 204-555-0100 or visit "
                               "203.0.113.10 for details") == []


def test_fleet_platform_matcher():
    assert "KAL Kalignite" in match_fleet_platforms("Powered by Kalignite")
    assert "Postilion (ACI Postilion)" in \
        match_fleet_platforms("postilion endpoint")
    assert match_fleet_platforms("a perfectly ordinary bank page") == []


# -- financial set contract --------------------------------------------------

def test_financial_set_contract():
    from app.plugins.registry import all_plugins, discover
    discover()
    by_id = {p.id: p for p in all_plugins()}
    for pid in bankatm.FINANCIAL_PLUGIN_IDS:
        assert pid in by_id, f"{pid} missing from registry"
        accepts = by_id[pid].accepts
        assert "domain" in accepts or "url" in accepts, pid
    # exclusions (plan gating) narrow the set, order preserved
    ids = bankatm.financial_plugin_ids(list(by_id), excluded=["dns"])
    assert "dns" not in ids and ids[0] == "bank"
    assert bankatm.MAX_POIS == 25 and bankatm.MAX_DOMAINS == 5


# -- enqueue integration -----------------------------------------------------

@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.models as models
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    eng = create_engine(f"sqlite:///{tmp_path}/t.db")
    models.Base.metadata.create_all(bind=eng)
    models.SessionLocal = sessionmaker(bind=eng, autoflush=False,
                                       autocommit=False)
    return models


@pytest.fixture()
def events(monkeypatch):
    from app import runner
    seen = []

    async def fake_emit(run_id, event, data):
        seen.append((event, data))

    monkeypatch.setattr(runner, "_emit", fake_emit)
    return seen


def _mk_run(models, run_id):
    s = models.SessionLocal()
    try:
        s.add(models.Run(id=run_id, mode="active", status="running",
                         source_type="bankatm", summary={}))
        s.commit()
    finally:
        s.close()


def test_enqueue_domain_run(db, events):
    from app import runner
    _mk_run(db, "ba-domain")
    asyncio.run(runner._enqueue_bankatm_run(
        "ba-domain", "rbcroyalbank.com", "active", None))
    s = db.SessionLocal()
    try:
        targets = s.query(db.Target).filter_by(run_id="ba-domain").all()
        assert len(targets) == 1 and targets[0].type == "domain"
        jobs = s.query(db.PluginJob).filter_by(run_id="ba-domain").all()
        want = set(bankatm.FINANCIAL_PLUGIN_IDS)
        assert {j.plugin_id for j in jobs} == want
        assert all(j.target_id == targets[0].id for j in jobs)
        run = s.query(db.Run).filter_by(id="ba-domain").first()
        assert run.summary["bankatm"]["input_kind"] == "domain"
        assert run.summary["bankatm"]["domain"] == "rbcroyalbank.com"
        # both module authorizations recorded for the bank/atm gates
        meta = run.summary["queue_meta"]
        assert meta["module_overrides"]["bank"] == "authorized"
        assert meta["module_overrides"]["atm"] == "authorized"
        assert meta["plugin_ids"] == list(bankatm.FINANCIAL_PLUGIN_IDS)
    finally:
        s.close()


def test_enqueue_location_run(db, events, monkeypatch):
    from app import runner
    _mk_run(db, "ba-loc")

    async def fake_geocode(location):
        return {"lat": 49.8951, "lon": -97.1384,
                "display_name": "Winnipeg, MB, Canada"}

    async def fake_pois(lat, lon, radius_m, cap):
        return [
            {"name": "RBC Royal Bank", "lat": 49.89, "lon": -97.14,
             "address": "100 Main St", "operator": "RBC Royal Bank",
             "brand": "RBC", "website": "", "phone": "",
             "opening_hours": "", "poi_type": "atm"},
            {"name": "TD Bank", "lat": 49.90, "lon": -97.15,
             "address": "200 Portage Ave", "operator": "",
             "brand": "", "website": "https://www.td.com", "phone": "",
             "opening_hours": "", "poi_type": "bank"},
            {"name": "Corner Store ATM", "lat": 49.91, "lon": -97.16,
             "address": "", "operator": "", "brand": "", "website": "",
             "phone": "", "opening_hours": "", "poi_type": "atm"},
        ]

    monkeypatch.setattr(geo, "geocode", fake_geocode)
    monkeypatch.setattr(geo, "find_bank_atm_pois", fake_pois)
    asyncio.run(runner._enqueue_bankatm_run(
        "ba-loc", "Winnipeg, MB", "active", None))
    s = db.SessionLocal()
    try:
        targets = s.query(db.Target).filter_by(run_id="ba-loc").all()
        pois_t = [t for t in targets if t.type == "poi"]
        doms_t = [t for t in targets if t.type == "domain"]
        assert len(pois_t) == 3
        assert {t.normalized for t in doms_t} == {"rbcroyalbank.com",
                                                  "td.com"}
        jobs = s.query(db.PluginJob).filter_by(run_id="ba-loc").all()
        # the financial set runs on operator domains ONLY - never POIs
        assert {j.target_id for j in jobs} == {t.id for t in doms_t}
        assert {j.plugin_id for j in jobs} == \
            set(bankatm.FINANCIAL_PLUGIN_IDS)
        geo_f = s.query(db.Finding).filter_by(
            run_id="ba-loc", plugin_id="geo").all()
        assert len(geo_f) == 3
        by_name = {f.evidence["name"]: f.evidence for f in geo_f}
        assert by_name["RBC Royal Bank"]["resolved_domain"] == \
            "rbcroyalbank.com"
        assert by_name["RBC Royal Bank"]["domain_assessed"] is True
        assert by_name["TD Bank"]["resolved_domain"] == "td.com"
        corner = by_name["Corner Store ATM"]
        assert corner["resolved_domain"] is None
        assert "no public domain resolved" in corner["note"]
        run = s.query(db.Run).filter_by(id="ba-loc").first()
        info = run.summary["bankatm"]
        assert info["input_kind"] == "location"
        assert info["resolved_domains"] == ["rbcroyalbank.com", "td.com"]
        assert len(info["locations"]) == 3
    finally:
        s.close()


def test_enqueue_location_no_domains_closes_run(db, events, monkeypatch):
    from app import runner
    _mk_run(db, "ba-nodom")

    async def fake_geocode(location):
        return {"lat": 49.8951, "lon": -97.1384,
                "display_name": "Winnipeg, MB, Canada"}

    async def fake_pois(lat, lon, radius_m, cap):
        return [{"name": "Corner Store ATM", "lat": 49.91, "lon": -97.16,
                 "address": "", "operator": "", "brand": "", "website": "",
                 "phone": "", "opening_hours": "", "poi_type": "atm"}]

    monkeypatch.setattr(geo, "geocode", fake_geocode)
    monkeypatch.setattr(geo, "find_bank_atm_pois", fake_pois)
    asyncio.run(runner._enqueue_bankatm_run(
        "ba-nodom", "Winnipeg, MB", "active", None))
    s = db.SessionLocal()
    try:
        assert s.query(db.PluginJob).filter_by(run_id="ba-nodom").count() == 0
        run = s.query(db.Run).filter_by(id="ba-nodom").first()
        assert run.status == "done"
        assert run.summary["findings"] == 1
    finally:
        s.close()


# -- API contract --------------------------------------------------------------

def test_api_accepts_bankatm(db, monkeypatch):
    import app.main as main_mod
    from fastapi.testclient import TestClient

    calls = []

    async def fake_launch(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(main_mod, "launch_run", fake_launch)
    monkeypatch.setattr(main_mod, "_wake_worker", lambda: None)
    client = TestClient(main_mod.app)
    # bankatm targets are external by design; flip the app to LIVE
    # (sandbox would reject a public location before the mode runs).
    r = client.put("/api/settings/mode", json={"mode": "live"})
    assert r.status_code == 200, r.text
    r = client.post("/api/runs", json={
        "targets": "Winnipeg, MB", "mode": "active", "plugins": None,
        "source_type": "bankatm"})
    assert r.status_code == 200, r.text
    assert r.json()["run_id"]
    s = db.SessionLocal()
    try:
        run = s.query(db.Run).filter_by(
            id=r.json()["run_id"]).first()
        assert run is not None and run.source_type == "bankatm"
    finally:
        s.close()
    # a bogus source type is still rejected
    r = client.post("/api/runs", json={
        "targets": "x", "mode": "active", "source_type": "nope"})
    assert r.status_code == 400
