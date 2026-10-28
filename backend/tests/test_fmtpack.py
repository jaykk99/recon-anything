"""Unit gate for the fx_* format & graph pack (12 detectors).

Every fx plugin runs through the REAL Ctx against a canary served
via httpx MockTransport (tests/fmtpack_samples.py): schema files
linked from the canary homepage, cookies carrying real serialized
markers, graph services answering on their conventional ports. Each
detector must fire on the canary, stay silent on the clean site,
and no full planted value may appear in any finding (masked prefix
+ length only). Detection only: the canary SPARQL service answers a
service-description GET; no query is ever issued by these plugins.
"""
import asyncio
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fmtpack_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.fmtpack import FX_IDS  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

CANARY = "canary.test"
PORTS = "ports.test"   # origin 404s; services live on their ports
BAIT = "bait.test"     # links a .proto that is not a proto
CLEAN = "clean.test"


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    port = request.url.port
    path = request.url.path or "/"

    if host == CLEAN:
        if path in ("/", "/index.html"):
            return httpx.Response(
                200, content=samples.CLEAN_HTML,
                headers={"Content-Type": "text/html"},
                request=request)
        return httpx.Response(404, content="not found",
                              request=request)

    if host == BAIT:
        if path == "/":
            return httpx.Response(
                200,
                content=("<html><body><a href=\"/schemas/api.proto"
                         "\">api.proto</a></body></html>"),
                headers={"Content-Type": "text/html"},
                request=request)
        if path == "/schemas/api.proto":
            return httpx.Response(
                200, content="<html><body>not a proto</body></html>",
                headers={"Content-Type": "text/html"},
                request=request)
        return httpx.Response(404, content="not found",
                              request=request)

    if host in (CANARY, PORTS):
        if port == 7474:
            return httpx.Response(
                200, content=json.dumps(samples.NEO4J_JSON),
                headers={"Content-Type": "application/json"},
                request=request)
        if port == 8529 and path == "/_api/version":
            return httpx.Response(
                200, content=json.dumps(samples.ARANGO_JSON),
                headers={"Content-Type": "application/json"},
                request=request)
        if port == 8182:
            return httpx.Response(
                400, content=json.dumps(samples.GREMLIN_JSON),
                headers={"Content-Type": "application/json"},
                request=request)
        if port == 8890 and path == "/sparql":
            return httpx.Response(
                200, content=samples.SPARQL_TURTLE,
                headers={"Content-Type": "text/turtle"},
                request=request)
        if port is not None:
            return httpx.Response(404, content="not found",
                                  request=request)
        if host == PORTS:
            return httpx.Response(404, content="not found",
                                  request=request)
        # canary origin
        if path in ("/", "/index.html"):
            return httpx.Response(
                200, content=samples.CANARY_HTML,
                headers=[("Content-Type", "text/html"),
                         ("Set-Cookie",
                          f"FXJAVA={samples.JAVA_COOKIE_VALUE}; "
                          "Path=/; HttpOnly"),
                         ("Set-Cookie",
                          f"prefs={samples.PHP_COOKIE_VALUE}; "
                          "Path=/")],
                request=request)
        if path == "/assets/app.js":
            return httpx.Response(
                200, content=samples.CANARY_JS,
                headers={"Content-Type": "application/javascript"},
                request=request)
        if path in samples.ROUTES:
            return httpx.Response(
                200, content=samples.ROUTES[path],
                headers={"Content-Type": "text/plain"},
                request=request)
        if path in ("/sparql", "/query"):
            return httpx.Response(
                200, content=samples.SPARQL_TURTLE,
                headers={"Content-Type": "text/turtle"},
                request=request)
        if path == "/_api/version":
            return httpx.Response(
                200, content=json.dumps(samples.ARANGO_JSON),
                headers={"Content-Type": "application/json"},
                request=request)
        return httpx.Response(404, content="not found",
                              request=request)

    return httpx.Response(404, content="", request=request)


def _ctx(mode: str = "active") -> Ctx:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_handler),
        follow_redirects=True, trust_env=False)
    return Ctx(run_id="fmtpack-test", mode=mode, http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run(pid: str, host: str, mode: str = "active"):
    cls = discover()[pid]
    ctx = _ctx(mode)
    target = Target(raw=f"https://{host}/", type="url",
                    normalized=f"https://{host}/")
    try:
        return asyncio.run(cls().run(target, ctx))
    finally:
        asyncio.run(ctx.http.aclose())


def _by_key(result, key):
    return [f for f in result.findings if f.key == key]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_exactly_12_new_detectors_registered():
    fx = sorted(k for k in discover() if k.startswith("fx_"))
    assert fx == sorted(FX_IDS)
    assert len(fx) == 12
    # 575 through the gx pack + 12 fx (+5 xml_* reader pack)
    # +10 da_* (deep-artifacts pack); +5 ai_* (AI-crawler pack)
    assert len(discover()) == 617  # 616 + 1 exposed-secret expansion on master (ac254f2)


# ---------------------------------------------------------------------------
# Family 1+3: schema files fire on the canary (linked from homepage)
# ---------------------------------------------------------------------------

def test_proto_schema_fires_with_names():
    r = _run("fx_proto_schema", CANARY)
    hits = _by_key(r, "proto_schema_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert "FxPayments" in ev["services"]
    assert "Charge" in ev["rpc_methods"]
    assert "ChargeRequest" in ev["messages"]


def test_avro_schema_fires_with_names():
    r = _run("fx_avro_schema", CANARY)
    hits = _by_key(r, "avro_schema_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert "FxPaymentEvent" in ev["records"]
    assert "FxEventMeta" in ev["records"]  # nested record walked
    assert "card_token" in ev["fields"]
    assert ev["namespace"] == "fx.events"


def test_thrift_schema_fires_with_names():
    r = _run("fx_thrift_schema", CANARY)
    hits = _by_key(r, "thrift_schema_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert "FxLedger" in ev["services"]
    assert "FxAccount" in ev["structs"]


def test_flatbuffers_schema_fires_with_names():
    r = _run("fx_flatbuffers_schema", CANARY)
    hits = _by_key(r, "flatbuffers_schema_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert "FxSprite" in ev["tables"]
    assert "FxVec3" in ev["structs"]


def test_capnp_schema_fires_with_names():
    r = _run("fx_capnp_schema", CANARY)
    hits = _by_key(r, "capnp_schema_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert "FxPerson" in ev["structs"]
    assert "FxDirectory" in ev["interfaces"]


def test_xsd_schema_fires_with_names():
    r = _run("fx_xsd_schema", CANARY)
    hits = _by_key(r, "xsd_schema_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert "FxInvoice" in ev["elements"]
    assert "FxInvoiceType" in ev["complex_types"]
    assert "FxCurrencyCode" in ev["simple_types"]


def test_dtd_schema_fires_with_names():
    r = _run("fx_dtd_schema", CANARY)
    hits = _by_key(r, "dtd_schema_exposed")
    assert hits, r.reason
    ev = hits[0].evidence
    assert "fx-note" in ev["elements"]
    assert "fxco" in ev["entities"]


def test_schema_parse_gate_rejects_html_bait():
    # A linked file named .proto whose body is HTML must NOT fire.
    r = _run("fx_proto_schema", BAIT)
    assert not r.findings, [f.value for f in r.findings]


# ---------------------------------------------------------------------------
# Family 2: passive deserialization surfaces
# ---------------------------------------------------------------------------

def test_deserialization_all_five_surfaces_fire():
    r = _run("fx_deserialization_surface", CANARY)
    keys = {f.key for f in r.findings}
    assert "java_serialized_object" in keys, r.reason
    assert "php_serialized_data" in keys
    assert "python_pickle_data" in keys
    assert "dotnet_binaryformatter_data" in keys
    assert "aspnet_viewstate" in keys


def test_deserialization_never_stores_full_values():
    r = _run("fx_deserialization_surface", CANARY)
    blob = json.dumps([f.__dict__ for f in r.findings])
    for planted in (samples.JAVA_COOKIE_VALUE,
                    samples.PHP_COOKIE_VALUE,
                    samples.PICKLE_B64,
                    samples.VIEWSTATE_VALUE,
                    samples.BINARYFORMATTER_VALUE):
        assert planted not in blob
    for f in r.findings:
        assert len(f.evidence["sample_prefix"]) <= 16
        assert f.evidence["value_length"] > 16


# ---------------------------------------------------------------------------
# Family 4: graph endpoints - origin (canary) and port (ports) shapes
# ---------------------------------------------------------------------------

def test_sparql_fires_on_origin_description():
    r = _run("fx_sparql_endpoint", CANARY)
    hits = _by_key(r, "sparql_endpoint_open")
    assert hits, r.reason
    assert hits[0].evidence["datasets"] >= 1
    assert "sd:Service" in hits[0].evidence["markers"]


def test_sparql_fires_on_fuseki_port():
    r = _run("fx_sparql_endpoint", PORTS)
    hits = _by_key(r, "sparql_endpoint_open")
    assert hits, r.reason
    assert ":8890" in hits[0].evidence["url"]


def test_neo4j_fires_on_discovery_port():
    r = _run("fx_neo4j_open", PORTS)
    hits = _by_key(r, "neo4j_discovery_open")
    assert hits, r.reason
    assert hits[0].evidence["bolt"] == "bolt://canary.test:7687"
    assert hits[0].evidence["neo4j_version"] == "5.12.0"


def test_arangodb_fires_on_origin_and_port():
    r = _run("fx_arangodb_open", CANARY)
    hits = _by_key(r, "arangodb_open")
    assert hits, r.reason
    assert hits[0].evidence["version"] == "3.11.4"
    r2 = _run("fx_arangodb_open", PORTS)
    assert _by_key(r2, "arangodb_open"), r2.reason


def test_gremlin_fires_on_server_port():
    r = _run("fx_gremlin_open", PORTS)
    hits = _by_key(r, "gremlin_server_open")
    assert hits, r.reason
    assert "no gremlin script supplied" in \
        hits[0].evidence["status_message"]


def test_graph_probes_silent_in_passive_mode():
    for pid in ("fx_sparql_endpoint", "fx_neo4j_open",
                "fx_arangodb_open", "fx_gremlin_open"):
        r = _run(pid, CANARY, mode="passive")
        assert r.findings == [], (pid, r.findings)


# ---------------------------------------------------------------------------
# Clean site: every fx detector silent; schema miners fire in
# passive mode too (harvested links only)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pid", FX_IDS)
def test_clean_site_silent(pid):
    r = _run(pid, CLEAN)
    assert r.status not in ("error", "raised"), (pid, r.reason)
    assert r.findings == [], (
        pid, [f.value for f in r.findings])


def test_schema_miners_fire_in_passive_mode_via_links():
    r = _run("fx_proto_schema", CANARY, mode="passive")
    assert _by_key(r, "proto_schema_exposed"), r.reason
