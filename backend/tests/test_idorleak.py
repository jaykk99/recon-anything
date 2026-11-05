"""IDOR surface mapper + error-response disclosure detector tests.

Fixture: a mock API server (httpx MockTransport through the real Ctx)
covering the four required shapes:
  (a) /api/v1/orders/{1042,1043} - sequential numeric IDs whose 422 is
      a CLEAN generic error -> surface finding only.
  (b) /api/v1/reports/3862641/reference.json - the HackerOne #3862641
      pattern family: the 422 DENIES the request but leaks the private
      report in context.subject -> combined IDOR/error-leak finding,
      leaked values shown in full.
  (c) /api/v1/users/<uuid> - unguessable IDs, generic 404 -> low-tier
      surface finding only.
  (d) /reports/{report_id}/reference.json + /invoices/{id} in an
      OpenAPI spec -> template surface findings sourced from the spec;
      the reports template merges with the concrete JS-discovered URL
      into one pattern group.
"""
import asyncio
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.idorleak import (  # noqa: E402
    IdorLeakPlugin, analyze_error_body, classify_segment,
    ids_look_sequential, split_id_path)
from app.ratelimit import RateLimiter  # noqa: E402

HOST = "mock.test"
BASE = f"https://{HOST}"
UUID = "3f6a2c1e-7a1b-4c2d-9e3f-0123456789ab"

HOME = """<!DOCTYPE html><html><head>
<script src="/static/app.js"></script>
</head><body><h1>Mock API</h1></body></html>"""

APP_JS = """
fetch('/api/v1/orders/1042');
fetch('/api/v1/orders/1043');
fetch('/api/v1/reports/3862641/reference.json');
fetch('/api/v1/users/%s');
const SPEC = '/openapi.json';
""" % UUID

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Mock API", "version": "1.0.0"},
    "paths": {
        "/reports/{report_id}/reference.json": {
            "post": {"summary": "reference a report"}},
        "/invoices/{id}": {"get": {"summary": "one invoice"}},
        "/health": {"get": {"summary": "health"}},
    },
}

CLEAN_422 = {"error": "access_denied",
             "message": "You are not authorized to view this order."}

LEAKY_422 = {
    "error": "unprocessable_entity",
    "message": "Access denied",
    "context": {
        "subject": {
            "id": 3862641,
            "title": "Private report: auth bypass in checkout",
            "description": "Steps to reproduce the bypass on the "
                           "production checkout flow.",
            "reporter_email": "researcher@private.example",
            "visibility": "private",
        }
    },
}


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/":
        return httpx.Response(200, content=HOME,
                              headers={"Content-Type": "text/html"},
                              request=request)
    if path == "/static/app.js":
        return httpx.Response(200, content=APP_JS,
                              headers={"Content-Type": "text/javascript"},
                              request=request)
    if path == "/openapi.json":
        return httpx.Response(200, content=json.dumps(SPEC),
                              headers={"Content-Type": "application/json"},
                              request=request)
    if path in ("/api/v1/orders/1042", "/api/v1/orders/1043"):
        return httpx.Response(422, content=json.dumps(CLEAN_422),
                              headers={"Content-Type": "application/json"},
                              request=request)
    if path == "/api/v1/reports/3862641/reference.json":
        return httpx.Response(422, content=json.dumps(LEAKY_422),
                              headers={"Content-Type": "application/json"},
                              request=request)
    if path == f"/api/v1/users/{UUID}":
        return httpx.Response(404, content=json.dumps(
            {"error": "not_found", "message": "User not found."}),
            headers={"Content-Type": "application/json"}, request=request)
    return httpx.Response(404, content=json.dumps(
        {"error": "not_found", "message": "Not found."}),
        headers={"Content-Type": "application/json"}, request=request)


def _ctx() -> Ctx:
    ctx = Ctx(run_id="idorleak-test", mode="passive",
              http=httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                                     follow_redirects=True, trust_env=False),
              cache=Cache(), keys={}, limiter=RateLimiter(),
              evidence_dir="/tmp", source_type="website")
    # What a phase-1 crawl of this site would have published.
    ctx.publish("js_files", f"{BASE}/static/app.js")
    ctx.publish("endpoints", f"{BASE}/api/v1/orders/1042")
    ctx.publish("endpoints", f"{BASE}/login")
    return ctx


def _run():
    async def go():
        ctx = _ctx()
        try:
            target = Target(raw=f"{BASE}/", type="url", normalized=f"{BASE}/")
            return await IdorLeakPlugin().run(target, ctx)
        finally:
            await ctx.http.aclose()
    return asyncio.run(go())


@pytest.fixture(scope="module")
def result():
    return _run()


def _by_key(result, key):
    return [f for f in result.findings if f.key == key]


def _surface_for(result, pattern):
    return [f for f in _by_key(result, "idor_surface")
            if f.evidence.get("endpoint_pattern") == pattern]


# ---------------------------------------------------------------------------
# (a) sequential IDs + clean 422 => surface only
# ---------------------------------------------------------------------------

def test_sequential_surface_only(result):
    hits = _surface_for(result, "/orders/{id}")
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["id_type"] == "numeric"
    assert ev["sequential_ids"] is True
    assert ev["observed_ids"] == [1042, 1043]
    assert ev["severity"] == "high"
    assert "js_bundle" in ev["exposure_sources"]
    # clean 422 => no leak finding of any kind for this pattern
    for f in result.findings:
        if f.key in ("error_response_disclosure", "idor_error_leak_path"):
            assert f.evidence.get("endpoint_pattern") != "/orders/{id}"


# ---------------------------------------------------------------------------
# (b) reference.json + leaky 422 => combined path, values in full
# ---------------------------------------------------------------------------

def test_combined_leak_path(result):
    hits = [f for f in _by_key(result, "idor_error_leak_path")
            if f.evidence.get("endpoint_pattern")
            == "/reports/{id}/reference.json"]
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["severity"] == "high"
    assert ev["error_status"] == 422
    assert ev["reference_json_endpoint"] is True
    assert ev["id_type"] == "numeric"
    leaked = ev["leaked_fields"]
    # Jay's rule: values in full, never masked.
    assert leaked["context.subject.title"] == \
        "Private report: auth bypass in checkout"
    assert leaked["context.subject.reporter_email"] == \
        "researcher@private.example"
    assert leaked["context.subject.description"].startswith(
        "Steps to reproduce")
    assert "context.subject.title" in ev["leaked_field_paths"]
    # The finding text itself shows the leaked data.
    assert "auth bypass in checkout" in hits[0].value
    # Combined finding replaces the standalone leak/surface pair.
    assert not [f for f in _by_key(result, "error_response_disclosure")
                if "reports" in (f.source_url or "")]
    assert not _surface_for(result, "/reports/{id}/reference.json")


def test_combined_group_merges_spec_and_js(result):
    hits = [f for f in _by_key(result, "idor_error_leak_path")
            if f.evidence.get("endpoint_pattern")
            == "/reports/{id}/reference.json"]
    ev = hits[0].evidence
    # Spec template (/reports/{report_id}/reference.json, POST) and the
    # concrete JS URL (/api/v1/reports/3862641/reference.json) are ONE
    # group after mount-prefix normalization.
    assert "openapi_spec" in ev["exposure_sources"]
    assert "js_bundle" in ev["exposure_sources"]
    assert ev["spec_methods"] == ["POST"]


# ---------------------------------------------------------------------------
# (c) UUID endpoint => low-tier surface only
# ---------------------------------------------------------------------------

def test_uuid_surface_low_tier(result):
    hits = _surface_for(result, "/users/{id}")
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["id_type"] == "uuid"
    assert ev["severity"] == "low"
    assert ev["sequential_ids"] is False


# ---------------------------------------------------------------------------
# (d) spec-only template endpoint
# ---------------------------------------------------------------------------

def test_spec_template_surface(result):
    hits = _surface_for(result, "/invoices/{id}")
    assert len(hits) == 1
    ev = hits[0].evidence
    assert ev["id_type"] == "template"
    assert ev["exposure_sources"] == ["openapi_spec"]
    assert ev["spec_methods"] == ["GET"]


# ---------------------------------------------------------------------------
# Unit: segment / path classification
# ---------------------------------------------------------------------------

def test_classify_segment():
    assert classify_segment("3862641") == ("numeric", "3862641")
    assert classify_segment("3862641.json") == ("numeric", "3862641")
    assert classify_segment(UUID) == ("uuid", UUID)
    assert classify_segment("{report_id}") == ("template", "report_id")
    assert classify_segment(":id") == ("template", "id")
    assert classify_segment("reference.json") is None
    assert classify_segment("users") is None
    assert classify_segment("v2") is None


def test_split_id_path():
    info = split_id_path("/api/v1/reports/3862641/reference.json")
    assert info["pattern"] == "/reports/{id}/reference.json"
    assert info["id_kind"] == "numeric"
    assert info["reference_json"] is True
    info = split_id_path("/reports/{report_id}/reference.json")
    assert info["pattern"] == "/reports/{id}/reference.json"
    assert info["id_kind"] == "template"
    info = split_id_path("/api/v1/users/" + UUID)
    assert info["pattern"] == "/users/{id}"
    assert info["id_kind"] == "uuid"
    assert split_id_path("/api/v1/users") is None
    assert split_id_path("/1042/details") is None  # no resource segment


def test_ids_look_sequential():
    assert ids_look_sequential([1042, 1043]) is True
    assert ids_look_sequential([1042]) is False
    assert ids_look_sequential([100, 900000]) is False


# ---------------------------------------------------------------------------
# Unit: error-body analysis
# ---------------------------------------------------------------------------

def test_analyze_clean_errors():
    assert analyze_error_body(json.dumps(CLEAN_422)) is None
    assert analyze_error_body(json.dumps(
        {"detail": "You do not have permission to perform this action."})
    ) is None
    # Rails validation envelope: field names + messages, no object data.
    assert analyze_error_body(json.dumps(
        {"errors": {"title": ["can't be blank"]}})) is None
    assert analyze_error_body("<html><body>404 Not Found</body></html>") \
        is None
    assert analyze_error_body("") is None


def test_analyze_leaky_error():
    hit = analyze_error_body(json.dumps(LEAKY_422))
    assert hit is not None
    assert hit["containers"] == ["context"]
    assert hit["sensitive"] is True
    assert hit["leaked_fields"]["context.subject.id"] == 3862641
    assert hit["leaked_fields"]["context.subject.visibility"] == "private"


def test_analyze_top_level_object_leak():
    body = {"error": "forbidden", "id": 7,
            "user": {"id": 7, "email": "victim@example.test",
                     "name": "Victim User"}}
    hit = analyze_error_body(json.dumps(body))
    assert hit is not None
    assert hit["leaked_fields"]["user.email"] == "victim@example.test"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_plugin_registered():
    from app.plugins.registry import discover
    assert "idorleak" in discover()
