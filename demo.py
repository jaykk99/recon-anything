"""Mocked end-to-end pipeline test.

The sandbox has no direct internet (transparent TLS proxy, DNS blocked),
so this test injects canned HTTP responses and verifies the full
pipeline: classify -> plugins -> findings -> DB -> graph -> export.
"""
import asyncio
import json
import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

CRT_JSON = json.dumps([
    {"name_value": "example.com"},
    {"name_value": "*.www.example.com\nwww.example.com"},
    {"name_value": "api.example.com"},
])
RDAP_JSON = json.dumps({
    "events": [
        {"eventAction": "registration", "eventDate": "1992-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
    ],
    "status": ["active"],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
    "nameservers": [{"ldhName": "a.iana-servers.net"}],
})
WAYBACK_JSON = json.dumps([
    ["timestamp", "original", "statuscode"],
    ["20200101000000", "https://example.com/", "200"],
    ["20210601000000", "https://example.com/api/docs", "200"],
    ["20220101000000", "https://example.com/admin", "200"],
])
HOME_HTML = """<html><head><title>Example Domain</title>
<script src="/_next/static/chunks/app.js"></script>
<script>fetch("/api/v1/users"); var key="AIzaSyD-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";</script>
</head><body><h1>Example</h1></body></html>"""
JS_BUNDLE = '//# sourceMappingURL=app.js.map\nfetch("/api/v1/orders"); const ep="/graphql";'
SOURCEMAP = json.dumps({"version": 3, "sources": ["webpack://app/src/index.ts",
                        "webpack://app/node_modules/lib/x.js"],
                        "sourcesContent": ["const stripe='pk_test_1234567890abcdef';"]})
ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup.zip\n"
OPENAPI = json.dumps({"openapi": "3.0.0",
                      "paths": {"/api/v1/users": {"get": {}}, "/api/v1/orders": {"post": {}}}})


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "crt.sh" in url:
        return httpx.Response(200, json=json.loads(CRT_JSON))
    if "data.iana.org/rdap" in url:
        return httpx.Response(200, json=json.loads(RDAP_JSON))
    if "web.archive.org/cdx" in url and "example.com/*" in url:
        return httpx.Response(200, json=json.loads(WAYBACK_JSON))
    if "web.archive.org/cdx" in url:
        return httpx.Response(200, json=[])
    if url == "https://example.com" or url == "https://example.com/":
        return httpx.Response(200, text=HOME_HTML,
                              headers={"server": "ECS", "set-cookie": "sess=abc; Path=/"})
    if url.endswith("/robots.txt"):
        return httpx.Response(200, text=ROBOTS)
    if url.endswith("/_next/static/chunks/app.js"):
        return httpx.Response(200, text=JS_BUNDLE)
    if url.endswith("app.js.map"):
        return httpx.Response(200, text=SOURCEMAP)
    if url.endswith("/openapi.json"):
        return httpx.Response(200, text=OPENAPI)
    if url.endswith("/graphql") and request.method == "POST":
        body = {"data": {"__schema": {
            "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
            "types": [{"name": "Query", "kind": "OBJECT"},
                      {"name": "User", "kind": "OBJECT"}]}}}
        return httpx.Response(200, json=body)
    if "/api/v1/users" in url or url.endswith("/api/users"):
        return httpx.Response(200, text="{}")
    if request.method == "OPTIONS":
        return httpx.Response(200, headers={"allow": "GET, POST"})
    return httpx.Response(404, text="not found")


async def main():
    from app.models import init_db, get_session, Run
    from app.graph import graph_payload
    from app.reporting import findings_dump, to_csv, to_markdown, executive_summary

    init_db()
    # patch the shared httpx client via monkeypatching execute_run's client creation
    import app.runner as runner_mod

    real_execute = runner_mod.execute_run

    async def patched(run_id, targets_raw, mode, plugin_ids=None,
                      module_overrides=None, keys=None):
        # inject mock transport by patching httpx.AsyncClient in runner
        orig_client = httpx.AsyncClient

        class MockClient(orig_client):
            def __init__(self, *a, **k):
                k["transport"] = httpx.MockTransport(handler)
                super().__init__(*a, **k)

        runner_mod.httpx.AsyncClient = MockClient
        try:
            await real_execute(run_id, targets_raw, mode, plugin_ids,
                               module_overrides, keys)
        finally:
            runner_mod.httpx.AsyncClient = orig_client

    run_id = "testrun123"
    session = get_session()
    if not session.query(Run).filter_by(id=run_id).first():
        session.add(Run(id=run_id, mode="passive", status="running"))
        session.commit()
    session.close()

    await patched(run_id, "example.com", "passive",
                  ["subdomains", "rdap", "wayback", "webtech", "jsminer",
                   "apidiscover", "artifacts", "leaks", "pivots"],
                  keys={})

    session = get_session()
    findings = findings_dump(session, run_id)
    print(f"FINDINGS: {len(findings)}")
    by_plugin = {}
    for f in findings:
        by_plugin.setdefault(f["plugin"], 0)
        by_plugin[f["plugin"]] += 1
    for p, n in sorted(by_plugin.items()):
        print(f"  {p:12} {n}")
    # spot check key findings
    keys_seen = {(f["plugin"], f["key"]) for f in findings}
    checks = [
        ("subdomains", "subdomain"),
        ("rdap", "whois_registrar"),
        ("wayback", "wayback_first_seen"),
        ("webtech", "tech"),
        ("webtech", "robots_disallow"),
        ("jsminer", "api_endpoint"),
        ("jsminer", "sourcemap_file"),
        ("jsminer", "google_api_key"),
        ("apidiscover", "openapi_paths"),
        ("apidiscover", "graphql_introspection"),
        ("apidiscover", "endpoint"),
        ("leaks", "dork"),
        ("artifacts", None),  # may be empty, fine
    ]
    ok = True
    for plugin, key in checks:
        if key is None:
            continue
        found = any(p == plugin and k == key for p, k in keys_seen)
        print(f"  [{'OK' if found else 'MISS'}] {plugin}.{key}")
        ok = ok and found
    # graph
    g = graph_payload(session, run_id)
    print(f"GRAPH: {len(g['nodes'])} nodes, {len(g['edges'])} edges")
    # exports
    run = session.query(Run).filter_by(id=run_id).first()
    md = to_markdown(run, [], findings)
    csv_out = to_csv(findings)
    print(f"EXPORT: md {len(md)} chars, csv {len(csv_out)} chars")
    print("SUMMARY:", json.dumps(executive_summary(findings))[:200])
    session.close()
    print("PIPELINE:", "PASS" if ok and g["nodes"] else "FAIL")
    return ok


if __name__ == "__main__":
    asyncio.run(main())
