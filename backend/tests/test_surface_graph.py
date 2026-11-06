"""Tests for app/surface_graph.py + GET /api/runs/{id}/surface-graph.

The interactive attack-surface graph (anti-Maltego): nodes for
domains/subdomains/IPs/ports/certs/tech plus HUMINT nodes from public
data only (WHOIS org, published email, public account), per-node
findings with verification commands, and correlation attack paths
resolved to ordered node ids for highlighting.
"""
import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name
os.environ["ACCESS_CODE"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.models import Finding, Run, Target, get_session, init_db  # noqa: E402
from app.surface_graph import surface_graph_payload  # noqa: E402

RUN_ID = "surfacetest1"
TID = "target-1"


def _seed():
    init_db()
    s = get_session()
    try:
        if s.query(Run).filter_by(id=RUN_ID).first():
            return
        s.add(Run(id=RUN_ID, mode="active", status="done", summary={}))
        s.add(Target(id=TID, run_id=RUN_ID, raw="example.com",
                     type="domain", normalized="example.com"))

        def f(plugin, category, key, value, **kw):
            return Finding(run_id=RUN_ID, target_id=TID, plugin_id=plugin,
                           category=category, key=key, value=value,
                           source=kw.get("source", plugin),
                           source_url=kw.get("source_url"),
                           confidence=kw.get("confidence", 80),
                           evidence=kw.get("evidence"),
                           passive=kw.get("passive", True))

        rows = [
            f("subdomains", "dns", "subdomain", "api.example.com"),
            f("dns", "dns", "a", "93.184.216.34", confidence=95),
            f("cmdtools", "infra", "open_port",
              "api.example.com:443 (https) open", confidence=95),
            f("tls", "infra", "tls_issuer", "Let's Encrypt"),
            f("webtech", "web", "tech", "nginx"),
            f("rdap", "infra", "whois_registrant_org", "Example Inc"),
            f("emails", "identity", "email_found",
              "admin@example.com found on /contact", confidence=70),
            f("usernames", "identity", "username_found",
              "@exampleco exists on GitHub", confidence=75),
            f("secrets", "leak", "aws_access_key", "AKIAEXAMPLE123456",
              confidence=90),
        ]
        s.add_all(rows)
        s.flush()
        secret_id = s.query(Finding).filter_by(key="aws_access_key") \
            .first().id
        port_id = s.query(Finding).filter_by(key="open_port").first().id
        s.add(f("correlation", "graph", "attack_path",
                "Exposed key behind public API",
                evidence={
                    "severity": "high", "path_id": "path-test-1",
                    "path_name": "Exposed key behind public API",
                    "chain_steps": ["API host is public",
                                    "Key is exposed on it"],
                    "components": [
                        {"plugin": "cmdtools", "key": "open_port",
                         "value": "api.example.com:443 (https) open",
                         "finding_id": port_id},
                        {"plugin": "secrets", "key": "aws_access_key",
                         "value": "AKIAEXAMPLE123456",
                         "finding_id": secret_id},
                    ]}))
        # assetgraph plugin output: a wallet node the key mapping misses
        s.add(f("assetgraph", "graph", "asset_map",
                "Attack surface map: 2 nodes, 1 edges for example.com",
                evidence={"graph": {
                    "root": "example.com",
                    "nodes": [
                        {"id": "domain_x", "type": "domain",
                         "label": "example.com", "value": "example.com"},
                        {"id": "wallet_y", "type": "wallet",
                         "label": "bc1qexamplewallet",
                         "value": "bc1qexamplewallet"}],
                    "edges": [{"from": "domain_x", "to": "wallet_y",
                               "rel": "publishes_wallet"}]}}))
        s.commit()
    finally:
        s.close()


@pytest.fixture(scope="module")
def payload():
    _seed()
    s = get_session()
    try:
        return surface_graph_payload(s, RUN_ID)
    finally:
        s.close()


def _by_kind(payload, kind):
    return [n for n in payload["nodes"] if n["kind"] == kind]


def test_core_node_kinds_present(payload):
    kinds = {n["kind"] for n in payload["nodes"]}
    for expected in ("target", "subdomain", "ip", "port", "cert",
                     "tech", "org", "email", "username", "financial"):
        assert expected in kinds, f"missing node kind {expected}"


def test_humint_nodes_from_public_data_only(payload):
    emails = _by_kind(payload, "email")
    assert [n["label"] for n in emails] == ["admin@example.com"]
    assert all(n["humint"] for n in emails)
    orgs = _by_kind(payload, "org")
    assert orgs and orgs[0]["label"] == "Example Inc" and orgs[0]["humint"]
    users = _by_kind(payload, "username")
    assert users and users[0]["label"] == "@exampleco"
    assert users[0]["meta"]["platform"] == "GitHub"
    assert payload["counts"]["humint"] >= 3


def test_port_node_hangs_off_its_host(payload):
    ports = _by_kind(payload, "port")
    assert ports and ports[0]["label"] == "api.example.com:443"
    hosts = {n["label"]: n["id"] for n in payload["nodes"]}
    port_id = ports[0]["id"]
    rels = {(e["src"], e["dst"], e["relation"]) for e in payload["edges"]}
    assert (hosts["api.example.com"], port_id, "hosts port") in rels


def test_node_findings_carry_verification_commands(payload):
    ports = _by_kind(payload, "port")
    findings = ports[0]["findings"]
    assert findings and findings[0]["key"] == "open_port"
    assert isinstance(findings[0]["commands"], list)
    # every attached finding exposes the click-detail shape
    for n in payload["nodes"]:
        for fd in n["findings"]:
            assert "commands" in fd and "value" in fd and "plugin" in fd


def test_secret_values_stay_masked(payload):
    blob = str(payload)
    assert "AKIAEXAMPLE123456" not in blob


def test_attack_path_resolves_to_ordered_nodes(payload):
    assert len(payload["attack_paths"]) == 1
    path = payload["attack_paths"][0]
    assert path["name"] == "Exposed key behind public API"
    assert path["steps"] == ["API host is public", "Key is exposed on it"]
    node_ids = path["node_ids"]
    assert len(node_ids) >= 3  # root + port + secret's node (root)
    kinds = {n["id"]: n["kind"] for n in payload["nodes"]}
    assert kinds[node_ids[0]] == "target"
    assert "port" in [kinds[i] for i in node_ids]


def test_cert_issuer_edge(payload):
    certs = _by_kind(payload, "cert")
    assert certs and certs[0]["label"] == "Let's Encrypt"
    rels = {e["relation"] for e in payload["edges"]}
    assert "issued by" in rels


def test_api_endpoint():
    _seed()
    with TestClient(app) as c:
        r = c.get(f"/api/runs/{RUN_ID}/surface-graph")
        assert r.status_code == 200
        body = r.json()
        assert body["counts"]["nodes"] > 0
        assert body["attack_paths"]
        r404 = c.get("/api/runs/doesnotexist/surface-graph")
        assert r404.status_code == 404
