"""Regression: apidiscover must survive list-shaped JSON API responses.

The fixture's /wp-json/wp/v2/users returns a top-level JSON list (like
real WP/OData APIs). apidiscover treated every JSON doc as an OpenAPI
candidate and called .get("paths") on the parsed value - raising
AttributeError out of run() and zeroing the plugin for the target.
"""
import asyncio

from app.plugins.apidiscover import ApiDiscoverPlugin


def test_parse_openapi_survives_list_json():
    p = ApiDiscoverPlugin()
    findings, api_map = [], {}
    p._parse_openapi('[{"id": 1, "slug": "admin"}]', "http://x/users",
                     findings, api_map, True)
    assert findings == [] and api_map == {}
    # and a real OpenAPI doc still parses
    p._parse_openapi('{"paths": {"/a": {"get": {}}}}', "http://x/doc",
                     findings, api_map, True)
    assert "/a" in api_map


def test_plugin_produces_on_fixture():
    from plugin_fixtures import run_plugin_fixture, url_target
    # Same timeout rule as the fixture gate: min(plugin.timeout_s, 60).
    status, findings, err = asyncio.run(run_plugin_fixture(
        ApiDiscoverPlugin, url_target(), "passive", timeout=60))
    assert status == "ok", err
    assert findings, "apidiscover must produce findings on the fixture"
